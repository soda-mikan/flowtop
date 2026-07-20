use chrono::{DateTime, Utc};
use flowtop_common::{
    SCHEMA_VERSION,
    metrics::{NetworkMetrics, ProcessMetrics, SystemMetrics, TcpMetrics},
    network::TcpState,
};
use serde::Serialize;

use crate::{
    collector::{CpuCounters, RawMetrics},
    config::Scope,
};

#[derive(Debug, Clone, Default, Serialize)]
pub struct HealthMetrics {
    pub lost_events: u64,
    pub collection_errors: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricSnapshot {
    pub record_type: &'static str,
    pub schema_version: &'static str,
    pub timestamp: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub monotonic_ns: u64,
    pub scope: Scope,
    pub tcp: TcpMetrics,
    pub network: NetworkMetrics,
    pub system: SystemMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessMetrics>,
    pub health: HealthMetrics,
}

pub struct Aggregator {
    scope: Scope,
    previous: Option<RawMetrics>,
}

impl Aggregator {
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            previous: None,
        }
    }

    pub fn aggregate(&mut self, raw: RawMetrics) -> MetricSnapshot {
        let elapsed_seconds = self.previous.as_ref().map_or(0.0, |previous| {
            raw.monotonic_ns.saturating_sub(previous.monotonic_ns) as f64 / 1_000_000_000.0
        });
        let rate = |current, previous| {
            if elapsed_seconds > 0.0 {
                counter_delta(current, previous) as f64 / elapsed_seconds
            } else {
                0.0
            }
        };

        let network = NetworkMetrics {
            host_rx_bytes_per_sec: self.previous.as_ref().map_or(0.0, |previous| {
                rate(raw.network_rx_bytes, previous.network_rx_bytes)
            }),
            host_tx_bytes_per_sec: self.previous.as_ref().map_or(0.0, |previous| {
                rate(raw.network_tx_bytes, previous.network_tx_bytes)
            }),
            process_rx_bytes_per_sec: raw.process.as_ref().and_then(|process| {
                let current = process.rx_bytes?;
                let previous = self.previous.as_ref()?.process.as_ref()?.rx_bytes?;
                Some(rate(current, previous))
            }),
            process_tx_bytes_per_sec: raw.process.as_ref().and_then(|process| {
                let current = process.tx_bytes?;
                let previous = self.previous.as_ref()?.process.as_ref()?.tx_bytes?;
                Some(rate(current, previous))
            }),
        };

        let cpu = self
            .previous
            .as_ref()
            .map(|previous| cpu_percentages(&raw.cpu, &previous.cpu))
            .unwrap_or_default();
        let memory_used = raw
            .memory
            .total_bytes
            .saturating_sub(raw.memory.available_bytes);
        let memory_percent = if raw.memory.total_bytes == 0 {
            0.0
        } else {
            memory_used as f64 / raw.memory.total_bytes as f64 * 100.0
        };
        let system = SystemMetrics {
            cpu_total_percent: cpu.total,
            cpu_user_percent: cpu.user,
            cpu_system_percent: cpu.system,
            cpu_iowait_percent: cpu.iowait,
            memory_used_bytes: memory_used,
            memory_available_bytes: raw.memory.available_bytes,
            memory_used_percent: memory_percent,
            disk_read_bytes_per_sec: self.previous.as_ref().map_or(0.0, |previous| {
                rate(raw.disk_read_sectors, previous.disk_read_sectors) * 512.0
            }),
            disk_write_bytes_per_sec: self.previous.as_ref().map_or(0.0, |previous| {
                rate(raw.disk_write_sectors, previous.disk_write_sectors) * 512.0
            }),
        };

        let process = raw.process.as_ref().map(|process| {
            let cpu_percent = self.previous.as_ref().and_then(|previous| {
                let previous_process = previous.process.as_ref()?;
                let total_delta = counter_delta(raw.cpu.total(), previous.cpu.total());
                (total_delta > 0).then(|| {
                    counter_delta(process.cpu_ticks, previous_process.cpu_ticks) as f64
                        / total_delta as f64
                        * raw.cpu_count.max(1) as f64
                        * 100.0
                })
            });
            ProcessMetrics {
                matching_pids: process.matching_pids,
                cpu_percent,
                rss_bytes: process.rss_bytes,
                disk_read_bytes_per_sec: self.previous.as_ref().and_then(|previous| {
                    let previous = previous.process.as_ref()?;
                    Some(rate(process.disk_read_bytes, previous.disk_read_bytes))
                }),
                disk_write_bytes_per_sec: self.previous.as_ref().and_then(|previous| {
                    let previous = previous.process.as_ref()?;
                    Some(rate(process.disk_write_bytes, previous.disk_write_bytes))
                }),
            }
        });

        let established = raw.tcp_count(TcpState::Established);
        let classified = raw
            .accepted_established
            .unwrap_or(0)
            .saturating_add(raw.connected_established.unwrap_or(0));
        let tcp = TcpMetrics {
            accepted_established: raw.accepted_established,
            connected_established: raw.connected_established,
            unknown_established: established.saturating_sub(classified),
            syn_sent: raw.tcp_count(TcpState::SynSent),
            syn_recv: raw.tcp_count(TcpState::SynRecv),
            time_wait: raw.tcp_count(TcpState::TimeWait),
            close_wait: raw.tcp_count(TcpState::CloseWait),
            fin_wait_1: raw.tcp_count(TcpState::FinWait1),
            fin_wait_2: raw.tcp_count(TcpState::FinWait2),
            last_ack: raw.tcp_count(TcpState::LastAck),
            closing: raw.tcp_count(TcpState::Closing),
            listen: raw.tcp_count(TcpState::Listen),
            opened_per_sec: optional_rate(
                raw.opened_total,
                self.previous.as_ref().and_then(|value| value.opened_total),
                elapsed_seconds,
            ),
            accepted_per_sec: optional_rate(
                raw.accepted_total,
                self.previous
                    .as_ref()
                    .and_then(|value| value.accepted_total),
                elapsed_seconds,
            ),
            connected_per_sec: optional_rate(
                raw.connected_total,
                self.previous
                    .as_ref()
                    .and_then(|value| value.connected_total),
                elapsed_seconds,
            ),
            closed_per_sec: optional_rate(
                raw.closed_total,
                self.previous.as_ref().and_then(|value| value.closed_total),
                elapsed_seconds,
            ),
        };

        let snapshot = MetricSnapshot {
            record_type: "snapshot",
            schema_version: SCHEMA_VERSION,
            timestamp: Utc::now(),
            elapsed_ms: raw.monotonic_ns / 1_000_000,
            monotonic_ns: raw.monotonic_ns,
            scope: self.scope.clone(),
            tcp,
            network,
            system,
            process,
            health: HealthMetrics {
                lost_events: raw.lost_events,
                collection_errors: raw.collection_errors,
            },
        };
        self.previous = Some(raw);
        snapshot
    }
}

fn optional_rate(current: Option<u64>, previous: Option<u64>, seconds: f64) -> Option<f64> {
    if seconds <= 0.0 {
        return None;
    }
    Some(counter_delta(current?, previous?) as f64 / seconds)
}

#[derive(Default)]
struct CpuPercentages {
    total: f64,
    user: f64,
    system: f64,
    iowait: f64,
}

fn cpu_percentages(current: &CpuCounters, previous: &CpuCounters) -> CpuPercentages {
    let total = counter_delta(current.total(), previous.total());
    if total == 0 {
        return CpuPercentages::default();
    }
    let percent = |value| value as f64 / total as f64 * 100.0;
    let idle = counter_delta(current.idle, previous.idle);
    let iowait = counter_delta(current.iowait, previous.iowait);
    CpuPercentages {
        total: percent(total.saturating_sub(idle).saturating_sub(iowait)),
        user: percent(
            counter_delta(current.user, previous.user)
                .saturating_add(counter_delta(current.nice, previous.nice)),
        ),
        system: percent(
            counter_delta(current.system, previous.system)
                .saturating_add(counter_delta(current.irq, previous.irq))
                .saturating_add(counter_delta(current.softirq, previous.softirq)),
        ),
        iowait: percent(iowait),
    }
}

pub fn counter_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        (u64::MAX - previous)
            .saturating_add(current)
            .saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{MemoryCounters, ProcessCounters};

    fn raw(ns: u64, rx: u64, idle: u64) -> RawMetrics {
        RawMetrics {
            monotonic_ns: ns,
            cpu: CpuCounters {
                user: 10,
                idle,
                ..CpuCounters::default()
            },
            cpu_count: 1,
            memory: MemoryCounters {
                total_bytes: 100,
                available_bytes: 40,
            },
            network_rx_bytes: rx,
            process: Some(ProcessCounters::default()),
            ..RawMetrics::default()
        }
    }

    #[test]
    fn calculates_rates_and_memory() {
        let mut aggregator = Aggregator::new(Scope::Host);
        aggregator.aggregate(raw(0, 100, 10));
        let snapshot = aggregator.aggregate(raw(1_000_000_000, 300, 20));
        assert_eq!(snapshot.network.host_rx_bytes_per_sec, 200.0);
        assert_eq!(snapshot.system.memory_used_percent, 60.0);
        assert_eq!(snapshot.system.cpu_total_percent, 0.0);
    }

    #[test]
    fn handles_counter_wrap() {
        assert_eq!(counter_delta(3, u64::MAX - 2), 6);
    }

    #[test]
    fn calculates_tcp_lifecycle_rates() {
        let mut first = raw(0, 0, 0);
        first.opened_total = Some(10);
        first.accepted_total = Some(4);
        first.connected_total = Some(6);
        first.closed_total = Some(3);

        let mut second = raw(1_000_000_000, 0, 0);
        second.opened_total = Some(17);
        second.accepted_total = Some(7);
        second.connected_total = Some(10);
        second.closed_total = Some(8);

        let mut aggregator = Aggregator::new(Scope::Host);
        aggregator.aggregate(first);
        let snapshot = aggregator.aggregate(second);

        assert_eq!(snapshot.tcp.opened_per_sec, Some(7.0));
        assert_eq!(snapshot.tcp.accepted_per_sec, Some(3.0));
        assert_eq!(snapshot.tcp.connected_per_sec, Some(4.0));
        assert_eq!(snapshot.tcp.closed_per_sec, Some(5.0));
    }

    #[test]
    fn leaves_proc_direction_unclassified() {
        let mut raw = raw(0, 0, 0);
        raw.tcp_states.insert(TcpState::Established as u8, 7);
        let snapshot = Aggregator::new(Scope::Host).aggregate(raw);
        assert_eq!(snapshot.tcp.accepted_established, None);
        assert_eq!(snapshot.tcp.connected_established, None);
        assert_eq!(snapshot.tcp.unknown_established, 7);
    }
}
