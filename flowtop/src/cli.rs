use std::{path::PathBuf, str::FromStr, time::Duration};

use clap::{ArgAction, Parser, ValueEnum};

use crate::error::FlowtopError;

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum BackendArg {
    #[default]
    Auto,
    Ebpf,
    Proc,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum RecordFormatArg {
    Jsonl,
    Csv,
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "flowtop",
    version,
    about = "A lightweight network-first top for Linux performance testing",
    long_about = None
)]
pub struct Cli {
    /// Collection interval (100ms..=60s).
    #[arg(short = 'i', long, default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,

    /// Stop after this duration.
    #[arg(short = 'd', long, value_parser = parse_duration)]
    pub duration: Option<Duration>,

    /// Disable the terminal UI.
    #[arg(long)]
    pub no_ui: bool,

    /// Use ASCII-only graphs.
    #[arg(long)]
    pub ascii: bool,

    /// Terminal refresh rate.
    #[arg(long, default_value = "250ms", value_parser = parse_duration)]
    pub refresh_rate: Duration,

    /// Observe one process ID.
    #[arg(short = 'p', long, conflicts_with_all = ["process", "cgroup"])]
    pub pid: Option<u32>,

    /// Observe all processes whose /proc/PID/comm exactly matches NAME.
    #[arg(long, conflicts_with_all = ["pid", "cgroup"])]
    pub process: Option<String>,

    /// Include descendants of matching processes.
    #[arg(long)]
    pub include_children: bool,

    /// Observe a cgroup v2 path (planned for v0.2).
    #[arg(long, conflicts_with_all = ["pid", "process"])]
    pub cgroup: Option<PathBuf>,

    /// Limit host throughput to an interface.
    #[arg(long)]
    pub interface: Option<String>,

    /// Include loopback together with all interfaces.
    #[arg(long, conflicts_with = "interface")]
    pub all_interfaces: bool,

    /// Observe a network namespace (planned for v0.2).
    #[arg(long)]
    pub netns: Option<String>,

    /// Record snapshots to PATH.
    #[arg(short = 'o', long)]
    pub record: Option<PathBuf>,

    /// Record format; inferred from the .jsonl or .csv extension by default.
    #[arg(long, requires = "record")]
    pub format: Option<RecordFormatArg>,

    /// Flush buffered records at this interval.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    pub flush_interval: Duration,

    /// Append instead of replacing the record file.
    #[arg(long, requires = "record")]
    pub append: bool,

    /// Add KEY=VALUE metadata. May be repeated.
    #[arg(long = "metadata", action = ArgAction::Append)]
    pub metadata: Vec<String>,

    /// Collector backend.
    #[arg(long, value_enum, default_value = "auto")]
    pub backend: BackendArg,

    /// Infer pre-existing connection direction (not enabled in v0.1).
    #[arg(long)]
    pub infer_existing_direction: bool,

    /// Fail instead of degrading from eBPF to proc.
    #[arg(long)]
    pub strict: bool,

    /// Include verbose eBPF diagnostics in errors.
    #[arg(long)]
    pub debug_ebpf: bool,
}

impl Cli {
    pub fn validate(&self) -> Result<(), FlowtopError> {
        if !(Duration::from_millis(100)..=Duration::from_secs(60)).contains(&self.interval) {
            return Err(FlowtopError::InvalidInterval(format!(
                "{:?}",
                self.interval
            )));
        }
        if !(Duration::from_millis(50)..=Duration::from_secs(60)).contains(&self.refresh_rate) {
            return Err(FlowtopError::InvalidRefreshRate(format!(
                "{:?}",
                self.refresh_rate
            )));
        }
        if !(Duration::from_millis(50)..=Duration::from_secs(60)).contains(&self.flush_interval) {
            return Err(FlowtopError::InvalidFlushInterval(format!(
                "{:?}",
                self.flush_interval
            )));
        }
        if self.include_children && self.pid.is_none() && self.process.is_none() {
            return Err(FlowtopError::IncludeChildrenRequiresScope);
        }
        if self.cgroup.is_some() {
            return Err(FlowtopError::CgroupNotImplemented);
        }
        if self.netns.is_some() {
            return Err(FlowtopError::NetnsNotImplemented);
        }
        if self.infer_existing_direction {
            return Err(FlowtopError::EbpfUnavailable {
                reason: "--infer-existing-direction is not implemented in v0.1".into(),
            });
        }
        for entry in &self.metadata {
            let (key, _) = entry
                .split_once('=')
                .ok_or_else(|| FlowtopError::InvalidMetadata(entry.clone()))?;
            if key.trim().is_empty() {
                return Err(FlowtopError::InvalidMetadata(entry.clone()));
            }
        }
        Ok(())
    }

    pub fn record_format(&self) -> Result<Option<RecordFormatArg>, FlowtopError> {
        let Some(path) = &self.record else {
            return Ok(None);
        };
        if let Some(format) = self.format {
            return Ok(Some(format));
        }
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("jsonl") | Some("json") => Ok(Some(RecordFormatArg::Jsonl)),
            Some("csv") => Ok(Some(RecordFormatArg::Csv)),
            _ => Err(FlowtopError::RecordFormatUnknown(path.clone())),
        }
    }

    pub fn metadata_labels(
        &self,
    ) -> Result<std::collections::BTreeMap<String, String>, FlowtopError> {
        self.metadata
            .iter()
            .map(|entry| {
                let (key, value) = entry
                    .split_once('=')
                    .ok_or_else(|| FlowtopError::InvalidMetadata(entry.clone()))?;
                Ok((String::from_str(key).unwrap(), value.to_owned()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn rejects_sub_100ms_interval() {
        let cli = Cli::try_parse_from(["flowtop", "--interval", "99ms"]).unwrap();
        assert!(matches!(
            cli.validate(),
            Err(FlowtopError::InvalidInterval(_))
        ));
    }

    #[test]
    fn mutually_exclusive_scopes_are_rejected() {
        assert!(Cli::try_parse_from(["flowtop", "--pid", "1", "--process", "init"]).is_err());
    }

    #[test]
    fn infers_csv_extension() {
        let cli = Cli::try_parse_from(["flowtop", "--record", "out.csv"]).unwrap();
        assert_eq!(cli.record_format().unwrap(), Some(RecordFormatArg::Csv));
    }
}
