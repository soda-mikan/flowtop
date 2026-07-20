use std::{path::Path, time::Duration};

use chrono::Local;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::{
    aggregate::{
        snapshot::MetricSnapshot,
        timeseries::{Metric, TimeSeriesStore},
    },
    collector::CollectorCapabilities,
    config::Config,
};

use super::graph::{chart_lines, sparkline};

pub struct TuiState {
    pub displayed: MetricSnapshot,
    pub paused: bool,
    pub details: bool,
    pub help: bool,
    pub health: bool,
    pub ascii: bool,
    pub backend: &'static str,
    pub degraded: bool,
    pub diagnostic: Option<String>,
    pub interval: Duration,
    pub record: Option<String>,
    frozen_history: Option<TimeSeriesStore>,
}

impl TuiState {
    pub fn new(
        snapshot: MetricSnapshot,
        config: &Config,
        capabilities: &CollectorCapabilities,
    ) -> Self {
        Self {
            displayed: snapshot,
            paused: false,
            details: true,
            help: false,
            health: false,
            ascii: config.ascii,
            backend: capabilities.backend,
            degraded: capabilities.degraded,
            diagnostic: capabilities.diagnostic.clone(),
            interval: config.interval,
            record: config.record.as_deref().map(path_label),
            frozen_history: None,
        }
    }

    pub fn update(&mut self, snapshot: MetricSnapshot) {
        if !self.paused {
            self.displayed = snapshot;
        }
    }

    pub fn toggle_pause(&mut self, history: &TimeSeriesStore, latest: &MetricSnapshot) {
        if self.paused {
            self.paused = false;
            self.frozen_history = None;
            self.displayed = latest.clone();
        } else {
            self.paused = true;
            self.frozen_history = Some(history.clone());
        }
    }

    pub fn reset_history(&mut self, history: &TimeSeriesStore) {
        if self.paused {
            self.frozen_history = Some(history.clone());
        }
    }

    fn visible_history<'a>(&'a self, history: &'a TimeSeriesStore) -> &'a TimeSeriesStore {
        self.frozen_history.as_ref().unwrap_or(history)
    }
}

fn path_label(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

pub fn draw(frame: &mut Frame<'_>, state: &TuiState, live_history: &TimeSeriesStore) {
    let area = frame.area();
    let history = state.visible_history(live_history);
    if area.height < 36 || area.width < 70 {
        draw_compact(frame, area, state, history);
        return;
    }

    let show_details = state.details || state.help || state.health;
    let constraints = if show_details {
        vec![
            Constraint::Length(3),
            Constraint::Min(20),
            Constraint::Length(3),
            Constraint::Length(1),
        ]
    } else {
        vec![
            Constraint::Length(3),
            Constraint::Min(20),
            Constraint::Length(1),
        ]
    };
    let rows = Layout::vertical(constraints).split(area);
    draw_header(frame, rows[0], state);

    let charts = Layout::vertical([
        Constraint::Ratio(5, 14),
        Constraint::Ratio(3, 14),
        Constraint::Ratio(2, 14),
        Constraint::Ratio(4, 14),
    ])
    .split(rows[1]);

    draw_metric_panel(
        frame,
        charts[0],
        "TCP Connections",
        &[
            MetricSpec::new(
                "Accepted ESTAB",
                optional_count(state.displayed.tcp.accepted_established),
                Metric::Accepted,
            ),
            MetricSpec::new(
                "Connected ESTAB",
                optional_count(state.displayed.tcp.connected_established),
                Metric::Connected,
            ),
            MetricSpec::new(
                "Unknown ESTAB",
                state.displayed.tcp.unknown_established.to_string(),
                Metric::Unknown,
            ),
            MetricSpec::new(
                "TIME-WAIT",
                state.displayed.tcp.time_wait.to_string(),
                Metric::TimeWait,
            ),
            MetricSpec::new(
                "CLOSE-WAIT",
                state.displayed.tcp.close_wait.to_string(),
                Metric::CloseWait,
            ),
        ],
        state,
        history,
    );

    draw_metric_panel(
        frame,
        charts[1],
        "TCP Activity (events/s)",
        &[
            MetricSpec::new(
                "Accept/s",
                optional_event_rate(state.displayed.tcp.accepted_per_sec),
                Metric::AcceptRate,
            ),
            MetricSpec::new(
                "Connect/s",
                optional_event_rate(state.displayed.tcp.connected_per_sec),
                Metric::ConnectRate,
            ),
            MetricSpec::new(
                "Close/s",
                optional_event_rate(state.displayed.tcp.closed_per_sec),
                Metric::CloseRate,
            ),
        ],
        state,
        history,
    );

    draw_metric_panel(
        frame,
        charts[2],
        "Network (interface bytes)",
        &[
            MetricSpec::new(
                "RX",
                format_rate(state.displayed.network.host_rx_bytes_per_sec),
                Metric::Rx,
            ),
            MetricSpec::new(
                "TX",
                format_rate(state.displayed.network.host_tx_bytes_per_sec),
                Metric::Tx,
            ),
        ],
        state,
        history,
    );

    draw_metric_panel(
        frame,
        charts[3],
        "System",
        &[
            MetricSpec::new(
                "CPU",
                format!("{:.1}%", state.displayed.system.cpu_total_percent),
                Metric::Cpu,
            ),
            MetricSpec::new(
                "MEM",
                format!("{:.1}%", state.displayed.system.memory_used_percent),
                Metric::Memory,
            ),
            MetricSpec::new(
                "Disk Read",
                format_rate(state.displayed.system.disk_read_bytes_per_sec),
                Metric::DiskRead,
            ),
            MetricSpec::new(
                "Disk Write",
                format_rate(state.displayed.system.disk_write_bytes_per_sec),
                Metric::DiskWrite,
            ),
        ],
        state,
        history,
    );

    if show_details {
        draw_details(frame, rows[2], state);
        draw_footer(frame, rows[3], state);
    } else {
        draw_footer(frame, rows[2], state);
    }
}

struct MetricSpec<'a> {
    label: &'a str,
    value: String,
    metric: Metric,
}

impl<'a> MetricSpec<'a> {
    fn new(label: &'a str, value: String, metric: Metric) -> Self {
        Self {
            label,
            value,
            metric,
        }
    }
}

fn draw_metric_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    metrics: &[MetricSpec<'_>],
    state: &TuiState,
    history: &TimeSeriesStore,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_owned());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 || metrics.is_empty() {
        return;
    }

    let show_axis = inner.height > metrics.len() as u16;
    let panel_rows = if show_axis {
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner)
    } else {
        Layout::vertical([Constraint::Min(1), Constraint::Length(0)]).split(inner)
    };
    let metric_constraints = vec![Constraint::Ratio(1, metrics.len() as u32); metrics.len()];
    let metric_rows = Layout::vertical(metric_constraints).split(panel_rows[0]);
    let use_gaps = panel_rows[0].height >= metrics.len().saturating_mul(4) as u16;
    let label_height = metric_rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            if use_gaps && index + 1 < metrics.len() {
                row.height.saturating_sub(1)
            } else {
                row.height
            }
        })
        .min()
        .unwrap_or(0);
    let label_width = if label_height == 2 && inner.width >= 70 {
        34
    } else if inner.width >= 70 {
        22
    } else {
        16
    };

    for (index, (metric, row)) in metrics.iter().zip(metric_rows.iter().copied()).enumerate() {
        let row = if use_gaps && index + 1 < metrics.len() {
            Rect {
                height: row.height.saturating_sub(1),
                ..row
            }
        } else {
            row
        };
        if row.height == 0 {
            continue;
        }
        let columns = Layout::horizontal([
            Constraint::Length(label_width.min(row.width)),
            Constraint::Min(1),
        ])
        .split(row);
        let max_value = history
            .max_value(metric.metric)
            .map(|value| format_metric_value(metric.metric, value))
            .unwrap_or_else(|| "N/A".to_owned());
        let label = Paragraph::new(
            metric_label_lines(metric.label, &metric.value, &max_value, label_height)
                .into_iter()
                .map(Line::from)
                .collect::<Vec<_>>(),
        );
        let color = metric_color(metric.metric);
        frame.render_widget(label.style(Style::default().fg(color)), columns[0]);

        let graph_area = columns[1];
        let buckets = history.buckets(metric.metric, graph_area.width as usize);
        let lines: Vec<Line<'_>> = chart_lines(
            &buckets,
            graph_area.width as usize,
            graph_area.height as usize,
            state.ascii,
        )
        .into_iter()
        .map(Line::from)
        .collect();
        frame.render_widget(
            Paragraph::new(lines).style(Style::default().fg(color)),
            graph_area,
        );
    }

    if show_axis {
        let columns = Layout::horizontal([
            Constraint::Length(label_width.min(panel_rows[1].width)),
            Constraint::Min(1),
        ])
        .split(panel_rows[1]);
        frame.render_widget(
            Paragraph::new(time_axis(
                &state.displayed,
                history,
                columns[1].width as usize,
                state.paused,
                state.ascii,
            ))
            .style(Style::default().fg(Color::DarkGray)),
            columns[1],
        );
    }
}

fn metric_label_lines(label: &str, value: &str, max_value: &str, height: u16) -> Vec<String> {
    if height >= 3 {
        vec![
            format!(" {label}"),
            format!(" Now {value:>12}"),
            format!(" Max {max_value:>12}"),
        ]
    } else if height == 2 {
        vec![
            format!(" {label}"),
            format!(" Now {value:>10} Max {max_value:>10}"),
        ]
    } else {
        vec![format!(" {label} {value} Max {max_value}")]
    }
}

fn metric_color(metric: Metric) -> Color {
    match metric {
        Metric::Accepted => Color::Cyan,
        Metric::Connected => Color::LightBlue,
        Metric::Unknown => Color::Yellow,
        Metric::TimeWait => Color::Magenta,
        Metric::CloseWait => Color::Red,
        Metric::AcceptRate => Color::Cyan,
        Metric::ConnectRate => Color::LightBlue,
        Metric::CloseRate => Color::Red,
        Metric::Rx => Color::Green,
        Metric::Tx => Color::Cyan,
        Metric::Cpu => Color::Yellow,
        Metric::Memory => Color::Magenta,
        Metric::DiskRead => Color::LightBlue,
        Metric::DiskWrite => Color::Red,
    }
}

fn format_metric_value(metric: Metric, value: f64) -> String {
    match metric {
        Metric::Accepted
        | Metric::Connected
        | Metric::Unknown
        | Metric::TimeWait
        | Metric::CloseWait => format!("{value:.0}"),
        Metric::AcceptRate | Metric::ConnectRate | Metric::CloseRate => format_event_rate(value),
        Metric::Rx | Metric::Tx | Metric::DiskRead | Metric::DiskWrite => format_rate(value),
        Metric::Cpu | Metric::Memory => format!("{value:.1}%"),
    }
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let status = if state.paused {
        format!(
            " PAUSED@{}",
            state
                .displayed
                .timestamp
                .with_timezone(&Local)
                .format("%H:%M:%S")
        )
    } else {
        String::new()
    };
    let degraded = if state.degraded { " degraded" } else { "" };
    let record = state
        .record
        .as_ref()
        .map(|path| format!(" record={path}"))
        .unwrap_or_default();
    let title = format!(
        " flowtop  backend={}{} interval={} elapsed={}{}{} ",
        state.backend,
        degraded,
        humantime::format_duration(state.interval),
        format_elapsed(state.displayed.elapsed_ms),
        record,
        status,
    );
    frame.render_widget(
        Paragraph::new("").block(Block::default().borders(Borders::ALL).title(Span::styled(
            title,
            Style::default().add_modifier(Modifier::BOLD),
        ))),
        area,
    );
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let lines = if state.help {
        vec![
            Line::from(
                "q quit | p pause display | r reset history | d details | ? help | e health",
            ),
            Line::from("Collection and recording continue while the display is paused."),
        ]
    } else if state.health {
        vec![
            Line::from(format!(
                "lost events={}  collector errors={}",
                state.displayed.health.lost_events, state.displayed.health.collection_errors
            )),
            Line::from(state.diagnostic.as_deref().unwrap_or("collector healthy")),
        ]
    } else {
        vec![Line::from(format!(
            " SYN-SENT {}  SYN-RECV {}  FIN-WAIT-1 {}  FIN-WAIT-2 {}  LAST-ACK {}  LISTEN {}  LOST {}  ERR {}",
            state.displayed.tcp.syn_sent,
            state.displayed.tcp.syn_recv,
            state.displayed.tcp.fin_wait_1,
            state.displayed.tcp.fin_wait_2,
            state.displayed.tcp.last_ack,
            state.displayed.tcp.listen,
            state.displayed.health.lost_events,
            state.displayed.health.collection_errors,
        ))]
    };
    frame.render_widget(panel("Details", lines), area);
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, state: &TuiState) {
    let style = if state.paused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    frame.render_widget(
        Paragraph::new(" q quit | p pause | r reset graph | d details | ? help | e health")
            .style(style),
        area,
    );
}

fn draw_compact(frame: &mut Frame<'_>, area: Rect, state: &TuiState, history: &TimeSeriesStore) {
    let width = area.width.saturating_sub(39) as usize;
    let lines = vec![
        Line::from(format!(
            "backend={}{} elapsed={}{}",
            state.backend,
            if state.degraded { " degraded" } else { "" },
            format_elapsed(state.displayed.elapsed_ms),
            if state.paused { " PAUSED" } else { "" },
        )),
        metric_line(
            "Accepted",
            optional_count(state.displayed.tcp.accepted_established),
            history,
            Metric::Accepted,
            width,
            state.ascii,
        ),
        metric_line(
            "Connected",
            optional_count(state.displayed.tcp.connected_established),
            history,
            Metric::Connected,
            width,
            state.ascii,
        ),
        metric_line(
            "Unknown",
            state.displayed.tcp.unknown_established.to_string(),
            history,
            Metric::Unknown,
            width,
            state.ascii,
        ),
        metric_line(
            "Accept/s",
            optional_event_rate(state.displayed.tcp.accepted_per_sec),
            history,
            Metric::AcceptRate,
            width,
            state.ascii,
        ),
        metric_line(
            "Connect/s",
            optional_event_rate(state.displayed.tcp.connected_per_sec),
            history,
            Metric::ConnectRate,
            width,
            state.ascii,
        ),
        metric_line(
            "Close/s",
            optional_event_rate(state.displayed.tcp.closed_per_sec),
            history,
            Metric::CloseRate,
            width,
            state.ascii,
        ),
        metric_line(
            "RX",
            format_rate(state.displayed.network.host_rx_bytes_per_sec),
            history,
            Metric::Rx,
            width,
            state.ascii,
        ),
        metric_line(
            "TX",
            format_rate(state.displayed.network.host_tx_bytes_per_sec),
            history,
            Metric::Tx,
            width,
            state.ascii,
        ),
        Line::from(format!(
            " CPU {:.1}% MEM {:.1}% Disk R {} W {}",
            state.displayed.system.cpu_total_percent,
            state.displayed.system.memory_used_percent,
            format_rate(state.displayed.system.disk_read_bytes_per_sec),
            format_rate(state.displayed.system.disk_write_bytes_per_sec)
        )),
        Line::from(" q quit | p pause | r reset | ? help"),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" flowtop "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn panel<'a>(title: &'a str, lines: Vec<Line<'a>>) -> Paragraph<'a> {
    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title))
}

fn metric_line<'a>(
    label: &'a str,
    value: String,
    history: &TimeSeriesStore,
    metric: Metric,
    width: usize,
    ascii: bool,
) -> Line<'a> {
    let graph = sparkline(&history.buckets(metric, width), width, ascii);
    let max_value = history
        .max_value(metric)
        .map(|value| format_metric_value(metric, value))
        .unwrap_or_else(|| "N/A".to_owned());
    Line::from(vec![
        Span::raw(format!(" {label:<10} {value:>10} Max {max_value:>10}  ")),
        Span::styled(graph, Style::default().fg(metric_color(metric))),
    ])
}

fn time_axis(
    snapshot: &MetricSnapshot,
    history: &TimeSeriesStore,
    width: usize,
    paused: bool,
    ascii: bool,
) -> String {
    if width == 0 {
        return String::new();
    }
    let (start_ns, end_ns) = history
        .time_bounds()
        .unwrap_or((snapshot.monotonic_ns, snapshot.monotonic_ns));
    let wall_time = |monotonic_ns: u64| {
        let delta_ms = snapshot.monotonic_ns.saturating_sub(monotonic_ns) / 1_000_000;
        let delta_ms = delta_ms.min(i64::MAX as u64) as i64;
        (snapshot.timestamp - chrono::Duration::milliseconds(delta_ms))
            .with_timezone(&Local)
            .format("%H:%M:%S")
            .to_string()
    };
    let left = format!("start {}", wall_time(start_ns));
    let right = format!(
        "{} {}",
        if paused { "paused" } else { "now" },
        wall_time(end_ns)
    );
    if width <= right.chars().count() {
        return right.chars().take(width).collect();
    }
    if width < left.chars().count() + right.chars().count() + 1 {
        return format!("{right:>width$}");
    }
    let separator = if ascii { '-' } else { '─' };
    format!(
        "{left}{}{right}",
        separator
            .to_string()
            .repeat(width - left.chars().count() - right.chars().count())
    )
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "N/A".into(), |value| value.to_string())
}

fn optional_event_rate(value: Option<f64>) -> String {
    value.map_or_else(|| "N/A".into(), format_event_rate)
}

fn format_event_rate(events_per_second: f64) -> String {
    if events_per_second >= 1_000_000.0 {
        format!("{:.1}M/s", events_per_second / 1_000_000.0)
    } else if events_per_second >= 1_000.0 {
        format!("{:.1}k/s", events_per_second / 1_000.0)
    } else {
        format!("{events_per_second:.1}/s")
    }
}

pub fn format_rate(bytes_per_second: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    if bytes_per_second >= GIB {
        format!("{:.1} GiB/s", bytes_per_second / GIB)
    } else if bytes_per_second >= MIB {
        format!("{:.1} MiB/s", bytes_per_second / MIB)
    } else if bytes_per_second >= KIB {
        format!("{:.1} KiB/s", bytes_per_second / KIB)
    } else {
        format!("{bytes_per_second:.0} B/s")
    }
}

fn format_elapsed(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else {
        format!("{minutes}m{seconds:02}s")
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use flowtop_common::{
        SCHEMA_VERSION,
        metrics::{NetworkMetrics, SystemMetrics, TcpMetrics},
    };
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::{aggregate::snapshot::HealthMetrics, config::Scope};

    fn snapshot(monotonic_ns: u64, cpu: f64) -> MetricSnapshot {
        MetricSnapshot {
            record_type: "snapshot",
            schema_version: SCHEMA_VERSION,
            timestamp: Utc::now(),
            elapsed_ms: monotonic_ns / 1_000_000,
            monotonic_ns,
            scope: Scope::Host,
            tcp: TcpMetrics {
                accepted_per_sec: Some(cpu),
                connected_per_sec: Some(cpu / 2.0),
                closed_per_sec: Some(cpu + 1.0),
                ..TcpMetrics::default()
            },
            network: NetworkMetrics::default(),
            system: SystemMetrics {
                cpu_total_percent: cpu,
                ..SystemMetrics::default()
            },
            process: None,
            health: HealthMetrics::default(),
        }
    }

    fn state(displayed: MetricSnapshot) -> TuiState {
        TuiState {
            displayed,
            paused: false,
            details: true,
            help: false,
            health: false,
            ascii: false,
            backend: "proc",
            degraded: true,
            diagnostic: None,
            interval: Duration::from_secs(1),
            record: None,
            frozen_history: None,
        }
    }

    #[test]
    fn formats_iec_rates() {
        assert_eq!(format_rate(1024.0), "1.0 KiB/s");
        assert_eq!(format_rate(1024.0 * 1024.0), "1.0 MiB/s");
    }

    #[test]
    fn formats_max_values_by_metric_kind() {
        assert_eq!(format_metric_value(Metric::Connected, 12.0), "12");
        assert_eq!(format_metric_value(Metric::AcceptRate, 12.34), "12.3/s");
        assert_eq!(format_metric_value(Metric::Rx, 2048.0), "2.0 KiB/s");
        assert_eq!(format_metric_value(Metric::Cpu, 12.34), "12.3%");
    }

    #[test]
    fn formats_large_event_rates() {
        assert_eq!(format_event_rate(1_250.0), "1.2k/s");
        assert_eq!(format_event_rate(2_500_000.0), "2.5M/s");
    }

    #[test]
    fn two_line_metric_labels_keep_values_off_the_label_line() {
        let lines = metric_label_lines("Accept/s", "0.0/s", "8.0/s", 2);
        assert_eq!(lines[0], " Accept/s");
        assert!(lines[1].contains("Now"));
        assert!(lines[1].contains("0.0/s"));
        assert!(lines[1].contains("Max"));
        assert!(lines[1].contains("8.0/s"));
    }

    #[test]
    fn pause_freezes_snapshot_and_visible_history() {
        let first = snapshot(1_000_000_000, 10.0);
        let second = snapshot(2_000_000_000, 20.0);
        let mut history = TimeSeriesStore::new(8);
        history.push_snapshot(&first);
        let mut state = state(first.clone());

        state.toggle_pause(&history, &first);
        history.push_snapshot(&second);
        state.update(second.clone());

        assert_eq!(state.displayed.monotonic_ns, first.monotonic_ns);
        assert_eq!(
            state.visible_history(&history).time_bounds(),
            Some((first.monotonic_ns, first.monotonic_ns))
        );

        state.toggle_pause(&history, &second);
        assert_eq!(state.displayed.monotonic_ns, second.monotonic_ns);
        assert_eq!(
            state.visible_history(&history).time_bounds(),
            Some((first.monotonic_ns, second.monotonic_ns))
        );
    }

    #[test]
    fn axis_places_current_time_at_right_edge() {
        let snapshot = snapshot(2_000_000_000, 20.0);
        let mut history = TimeSeriesStore::new(8);
        history.push_snapshot(&snapshot);
        let axis = time_axis(&snapshot, &history, 60, false, false);
        assert_eq!(axis.chars().count(), 60);
        assert!(axis.contains("start "));
        assert!(axis.contains("now "));
        assert!(
            axis.ends_with(
                &snapshot
                    .timestamp
                    .with_timezone(&Local)
                    .format("%H:%M:%S")
                    .to_string()
            )
        );
    }

    #[test]
    fn tall_terminal_allocates_multiple_rows_to_charts() {
        let first = snapshot(1_000_000_000, 10.0);
        let second = snapshot(2_000_000_000, 20.0);
        let mut history = TimeSeriesStore::new(8);
        history.push_snapshot(&first);
        history.push_snapshot(&second);
        let mut state = state(second);
        state.details = false;

        let backend = TestBackend::new(120, 44);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, &history))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let rendered: Vec<String> = (0..44)
            .map(|y| {
                (0..120)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();

        assert!(rendered.iter().any(|line| line.contains("start ")));
        assert!(rendered.iter().any(|line| line.contains("now ")));
        assert!(rendered.iter().any(|line| line.contains("Max")));
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("TCP Activity (events/s)"))
        );
        assert!(rendered.iter().any(|line| line.contains("Accept/s")));
        assert!(
            !rendered
                .iter()
                .any(|line| line.contains("Connected ESTAB N/A"))
        );
        assert!(!rendered.iter().any(|line| line.contains("Accept/s 20.0/s")));
        assert!(!rendered.iter().any(|line| line.contains("Close/s 21.0/s")));
        assert_eq!(history.max_value(Metric::AcceptRate), Some(20.0));
        let chart_rows = rendered
            .iter()
            .filter(|line| line.contains('█') || line.contains('▁'))
            .count();
        assert!(chart_rows >= 8, "rendered only {chart_rows} chart rows");
        assert!(!rendered.iter().any(|line| line.contains("Details")));
    }

    #[test]
    fn compact_terminal_keeps_tcp_activity_visible() {
        let snapshot = snapshot(1_000_000_000, 10.0);
        let mut history = TimeSeriesStore::new(8);
        history.push_snapshot(&snapshot);
        let state = state(snapshot);

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, &history))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let rendered: String = (0..20)
            .flat_map(|y| (0..80).map(move |x| buffer[(x, y)].symbol()))
            .collect();

        assert!(rendered.contains("Accept/s"));
        assert!(rendered.contains("Connect/s"));
        assert!(rendered.contains("Close/s"));
    }

    #[test]
    fn adjacent_metric_series_use_distinct_colors() {
        assert_ne!(
            metric_color(Metric::Connected),
            metric_color(Metric::Unknown)
        );
        assert_ne!(metric_color(Metric::Rx), metric_color(Metric::Tx));
        assert_ne!(metric_color(Metric::Cpu), metric_color(Metric::Memory));
        assert_ne!(
            metric_color(Metric::AcceptRate),
            metric_color(Metric::ConnectRate)
        );
    }
}
