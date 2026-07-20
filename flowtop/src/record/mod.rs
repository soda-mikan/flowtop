use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use flowtop_common::SCHEMA_VERSION;
use serde::Serialize;

use crate::{
    aggregate::snapshot::MetricSnapshot,
    cli::RecordFormatArg,
    collector::CollectorCapabilities,
    config::{Config, Scope},
};

#[derive(Debug, Serialize)]
pub struct RunMetadata {
    pub record_type: &'static str,
    pub schema_version: &'static str,
    pub flowtop_version: &'static str,
    pub hostname: String,
    pub kernel: String,
    pub started_at: DateTime<Utc>,
    pub interval_ms: u64,
    pub backend: &'static str,
    pub degraded: bool,
    pub direction_available: bool,
    pub process_network_available: bool,
    pub scope: Scope,
    pub labels: BTreeMap<String, String>,
}

impl RunMetadata {
    pub fn new(config: &Config, capabilities: &CollectorCapabilities) -> Self {
        Self {
            record_type: "metadata",
            schema_version: SCHEMA_VERSION,
            flowtop_version: env!("CARGO_PKG_VERSION"),
            hostname: read_trimmed("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into()),
            kernel: read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into()),
            started_at: Utc::now(),
            interval_ms: config.interval.as_millis().min(u128::from(u64::MAX)) as u64,
            backend: capabilities.backend,
            degraded: capabilities.degraded,
            direction_available: capabilities.direction,
            process_network_available: capabilities.process_network,
            scope: config.scope.clone(),
            labels: config.labels.clone(),
        }
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

pub trait Recorder {
    fn write_metadata(&mut self, metadata: &RunMetadata) -> Result<()>;
    fn write_snapshot(&mut self, snapshot: &MetricSnapshot) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

pub fn open_recorder(config: &Config) -> Result<Option<Box<dyn Recorder>>> {
    let (Some(path), Some(format)) = (&config.record, config.record_format) else {
        return Ok(None);
    };
    let file = open_file(path, config.append)?;
    let recorder: Box<dyn Recorder> = match format {
        RecordFormatArg::Jsonl => Box::new(JsonlRecorder::new(file)),
        RecordFormatArg::Csv => Box::new(CsvRecorder::new(file, config.append)),
    };
    Ok(Some(recorder))
}

fn open_file(path: &Path, append: bool) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .with_context(|| format!("open record file {}", path.display()))
}

struct JsonlRecorder {
    writer: BufWriter<File>,
}

impl JsonlRecorder {
    fn new(file: File) -> Self {
        Self {
            writer: BufWriter::new(file),
        }
    }

    fn write<T: Serialize>(&mut self, value: &T) -> Result<()> {
        serde_json::to_writer(&mut self.writer, value).context("serialize JSONL record")?;
        self.writer
            .write_all(b"\n")
            .context("write JSONL newline")?;
        Ok(())
    }
}

impl Recorder for JsonlRecorder {
    fn write_metadata(&mut self, metadata: &RunMetadata) -> Result<()> {
        self.write(metadata)
    }

    fn write_snapshot(&mut self, snapshot: &MetricSnapshot) -> Result<()> {
        self.write(snapshot)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush().context("flush JSONL record")
    }
}

struct CsvRecorder {
    writer: csv::Writer<BufWriter<File>>,
}

impl CsvRecorder {
    fn new(file: File, append: bool) -> Self {
        Self {
            writer: csv::WriterBuilder::new()
                .has_headers(!append)
                .from_writer(BufWriter::new(file)),
        }
    }
}

impl Recorder for CsvRecorder {
    fn write_metadata(&mut self, _metadata: &RunMetadata) -> Result<()> {
        // CSV metadata is represented by the scope fields and CLI invocation; JSONL
        // is the format to use when run labels must be embedded in the stream.
        Ok(())
    }

    fn write_snapshot(&mut self, snapshot: &MetricSnapshot) -> Result<()> {
        self.writer
            .serialize(CsvSnapshot::from(snapshot))
            .context("serialize CSV snapshot")?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush().context("flush CSV record")
    }
}

#[derive(Serialize)]
struct CsvSnapshot {
    schema_version: &'static str,
    timestamp: String,
    elapsed_ms: u64,
    scope_type: &'static str,
    scope_value: Option<String>,
    accepted_established: Option<u64>,
    connected_established: Option<u64>,
    unknown_established: u64,
    syn_sent: u64,
    syn_recv: u64,
    time_wait: u64,
    close_wait: u64,
    fin_wait_1: u64,
    fin_wait_2: u64,
    last_ack: u64,
    listen: u64,
    opened_per_sec: Option<f64>,
    accepted_per_sec: Option<f64>,
    connected_per_sec: Option<f64>,
    closed_per_sec: Option<f64>,
    host_rx_bytes_per_sec: f64,
    host_tx_bytes_per_sec: f64,
    process_rx_bytes_per_sec: Option<f64>,
    process_tx_bytes_per_sec: Option<f64>,
    cpu_total_percent: f64,
    cpu_user_percent: f64,
    cpu_system_percent: f64,
    cpu_iowait_percent: f64,
    memory_used_bytes: u64,
    memory_available_bytes: u64,
    memory_used_percent: f64,
    disk_read_bytes_per_sec: f64,
    disk_write_bytes_per_sec: f64,
    lost_events: u64,
    collection_errors: u64,
}

impl From<&MetricSnapshot> for CsvSnapshot {
    fn from(snapshot: &MetricSnapshot) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp: snapshot.timestamp.to_rfc3339(),
            elapsed_ms: snapshot.elapsed_ms,
            scope_type: snapshot.scope.type_name(),
            scope_value: snapshot.scope.value(),
            accepted_established: snapshot.tcp.accepted_established,
            connected_established: snapshot.tcp.connected_established,
            unknown_established: snapshot.tcp.unknown_established,
            syn_sent: snapshot.tcp.syn_sent,
            syn_recv: snapshot.tcp.syn_recv,
            time_wait: snapshot.tcp.time_wait,
            close_wait: snapshot.tcp.close_wait,
            fin_wait_1: snapshot.tcp.fin_wait_1,
            fin_wait_2: snapshot.tcp.fin_wait_2,
            last_ack: snapshot.tcp.last_ack,
            listen: snapshot.tcp.listen,
            opened_per_sec: snapshot.tcp.opened_per_sec,
            accepted_per_sec: snapshot.tcp.accepted_per_sec,
            connected_per_sec: snapshot.tcp.connected_per_sec,
            closed_per_sec: snapshot.tcp.closed_per_sec,
            host_rx_bytes_per_sec: snapshot.network.host_rx_bytes_per_sec,
            host_tx_bytes_per_sec: snapshot.network.host_tx_bytes_per_sec,
            process_rx_bytes_per_sec: snapshot.network.process_rx_bytes_per_sec,
            process_tx_bytes_per_sec: snapshot.network.process_tx_bytes_per_sec,
            cpu_total_percent: snapshot.system.cpu_total_percent,
            cpu_user_percent: snapshot.system.cpu_user_percent,
            cpu_system_percent: snapshot.system.cpu_system_percent,
            cpu_iowait_percent: snapshot.system.cpu_iowait_percent,
            memory_used_bytes: snapshot.system.memory_used_bytes,
            memory_available_bytes: snapshot.system.memory_available_bytes,
            memory_used_percent: snapshot.system.memory_used_percent,
            disk_read_bytes_per_sec: snapshot.system.disk_read_bytes_per_sec,
            disk_write_bytes_per_sec: snapshot.system.disk_write_bytes_per_sec,
            lost_events: snapshot.health.lost_events,
            collection_errors: snapshot.health.collection_errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregate::snapshot::{HealthMetrics, MetricSnapshot},
        config::Scope,
    };
    use flowtop_common::metrics::{NetworkMetrics, SystemMetrics, TcpMetrics};
    use tempfile::NamedTempFile;

    fn snapshot() -> MetricSnapshot {
        MetricSnapshot {
            record_type: "snapshot",
            schema_version: SCHEMA_VERSION,
            timestamp: Utc::now(),
            elapsed_ms: 1000,
            monotonic_ns: 1_000_000_000,
            scope: Scope::Host,
            tcp: TcpMetrics {
                unknown_established: 3,
                ..TcpMetrics::default()
            },
            network: NetworkMetrics::default(),
            system: SystemMetrics::default(),
            process: None,
            health: HealthMetrics::default(),
        }
    }

    #[test]
    fn jsonl_has_one_object_per_line() {
        let file = NamedTempFile::new().unwrap();
        let mut recorder = JsonlRecorder::new(file.reopen().unwrap());
        recorder.write_snapshot(&snapshot()).unwrap();
        recorder.flush().unwrap();
        let contents = std::fs::read_to_string(file.path()).unwrap();
        let value: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(value["record_type"], "snapshot");
        assert!(value["tcp"]["accepted_established"].is_null());
        assert!(value["tcp"]["connected_per_sec"].is_null());
    }

    #[test]
    fn csv_writes_null_direction_as_empty_field() {
        let file = NamedTempFile::new().unwrap();
        let mut recorder = CsvRecorder::new(file.reopen().unwrap(), false);
        recorder.write_snapshot(&snapshot()).unwrap();
        recorder.flush().unwrap();
        let contents = std::fs::read_to_string(file.path()).unwrap();
        assert!(contents.starts_with("schema_version,timestamp,elapsed_ms"));
        assert!(
            contents.contains("opened_per_sec,accepted_per_sec,connected_per_sec,closed_per_sec")
        );
        assert!(contents.contains(",,,3,"));
    }
}
