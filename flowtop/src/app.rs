use std::{io, time::Duration};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use tokio::time::{Instant, MissedTickBehavior};

use crate::{
    aggregate::{snapshot::Aggregator, timeseries::TimeSeriesStore},
    collector::{Collector, CollectorCapabilities},
    config::Config,
    record::{Recorder, RunMetadata},
    tui::{TerminalSession, TuiState, draw},
};

pub async fn run(
    config: Config,
    collector: &mut dyn Collector,
    capabilities: CollectorCapabilities,
    mut recorder: Option<Box<dyn Recorder>>,
) -> Result<()> {
    let metadata = RunMetadata::new(&config, &capabilities);
    if let Some(recorder) = recorder.as_mut() {
        recorder.write_metadata(&metadata)?;
    }

    let mut aggregator = Aggregator::new(config.scope.clone());
    let initial = aggregator.aggregate(collector.snapshot().await?);
    if let Some(recorder) = recorder.as_mut() {
        recorder.write_snapshot(&initial)?;
    }

    if config.no_ui {
        run_no_ui(config, collector, aggregator, initial, &mut recorder).await
    } else {
        run_tui(
            config,
            collector,
            capabilities,
            aggregator,
            initial,
            &mut recorder,
        )
        .await
    }
}

async fn run_no_ui(
    config: Config,
    collector: &mut dyn Collector,
    mut aggregator: Aggregator,
    initial: crate::aggregate::snapshot::MetricSnapshot,
    recorder: &mut Option<Box<dyn Recorder>>,
) -> Result<()> {
    print_snapshot(&initial)?;
    let mut sample_tick =
        tokio::time::interval_at(Instant::now() + config.interval, config.interval);
    sample_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut flush_tick = tokio::time::interval_at(
        Instant::now() + config.flush_interval,
        config.flush_interval,
    );
    flush_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let deadline = tokio::time::sleep(config.duration.unwrap_or(Duration::MAX));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = &mut deadline => break,
            _ = flush_tick.tick() => flush_recorder(recorder),
            _ = sample_tick.tick() => {
                let snapshot = aggregator.aggregate(collector.snapshot().await?);
                write_snapshot(recorder, &snapshot);
                print_snapshot(&snapshot)?;
            }
        }
    }
    write_final_snapshot(collector, &mut aggregator, recorder, true).await?;
    flush_recorder(recorder);
    Ok(())
}

async fn run_tui(
    config: Config,
    collector: &mut dyn Collector,
    capabilities: CollectorCapabilities,
    mut aggregator: Aggregator,
    initial: crate::aggregate::snapshot::MetricSnapshot,
    recorder: &mut Option<Box<dyn Recorder>>,
) -> Result<()> {
    let mut terminal = TerminalSession::enter()?;
    let mut history = TimeSeriesStore::new(4096);
    history.push_snapshot(&initial);
    let mut latest = initial.clone();
    let mut state = TuiState::new(initial, &config, &capabilities);

    let mut sample_tick =
        tokio::time::interval_at(Instant::now() + config.interval, config.interval);
    sample_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut render_tick = tokio::time::interval(config.refresh_rate);
    render_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut flush_tick = tokio::time::interval_at(
        Instant::now() + config.flush_interval,
        config.flush_interval,
    );
    flush_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let deadline = tokio::time::sleep(config.duration.unwrap_or(Duration::MAX));
    tokio::pin!(deadline);

    let mut quit = false;
    while !quit {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => quit = true,
            _ = &mut deadline => quit = true,
            _ = flush_tick.tick() => flush_recorder(recorder),
            _ = sample_tick.tick() => {
                let snapshot = aggregator.aggregate(collector.snapshot().await?);
                write_snapshot(recorder, &snapshot);
                history.push_snapshot(&snapshot);
                latest = snapshot.clone();
                state.update(snapshot);
            }
            _ = render_tick.tick() => {
                while event::poll(Duration::ZERO).context("poll terminal input")? {
                    if let Event::Key(key) = event::read().context("read terminal input")?
                        && key.kind == KeyEventKind::Press
                    {
                        match (key.code, key.modifiers) {
                            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                quit = true;
                            }
                            (KeyCode::Char('p'), _) => {
                                state.toggle_pause(&history, &latest);
                            }
                            (KeyCode::Char('r'), _) => {
                                history.reset();
                                state.reset_history(&history);
                            }
                            (KeyCode::Char('d'), _) => state.details = !state.details,
                            (KeyCode::Char('?'), _) => state.help = !state.help,
                            (KeyCode::Char('e'), _) => state.health = !state.health,
                            _ => {}
                        }
                    }
                }
                terminal
                    .terminal_mut()
                    .draw(|frame| draw(frame, &state, &history))
                    .context("draw terminal frame")?;
            }
        }
    }

    write_final_snapshot(collector, &mut aggregator, recorder, false).await?;
    flush_recorder(recorder);
    Ok(())
}

async fn write_final_snapshot(
    collector: &mut dyn Collector,
    aggregator: &mut Aggregator,
    recorder: &mut Option<Box<dyn Recorder>>,
    print: bool,
) -> Result<()> {
    let snapshot = aggregator.aggregate(collector.snapshot().await?);
    write_snapshot(recorder, &snapshot);
    if print {
        print_snapshot(&snapshot)?;
    }
    Ok(())
}

fn write_snapshot(
    recorder: &mut Option<Box<dyn Recorder>>,
    snapshot: &crate::aggregate::snapshot::MetricSnapshot,
) {
    let failed = recorder
        .as_mut()
        .and_then(|recorder| recorder.write_snapshot(snapshot).err());
    if let Some(error) = failed {
        eprintln!("flowtop: recording stopped: {error:#}");
        *recorder = None;
    }
}

fn flush_recorder(recorder: &mut Option<Box<dyn Recorder>>) {
    let failed = recorder
        .as_mut()
        .and_then(|recorder| recorder.flush().err());
    if let Some(error) = failed {
        eprintln!("flowtop: recording stopped during flush: {error:#}");
        *recorder = None;
    }
}

fn print_snapshot(snapshot: &crate::aggregate::snapshot::MetricSnapshot) -> Result<()> {
    serde_json::to_writer(io::stdout().lock(), snapshot).context("write snapshot to stdout")?;
    println!();
    Ok(())
}
