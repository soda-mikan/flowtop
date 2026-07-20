use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use serde::Serialize;

use crate::cli::{BackendArg, Cli, RecordFormatArg};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Scope {
    Host,
    Pid(u32),
    Process(String),
}

impl Scope {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Pid(_) => "pid",
            Self::Process(_) => "process",
        }
    }

    pub fn value(&self) -> Option<String> {
        match self {
            Self::Host => None,
            Self::Pid(pid) => Some(pid.to_string()),
            Self::Process(name) => Some(name.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub interval: Duration,
    pub duration: Option<Duration>,
    pub no_ui: bool,
    pub ascii: bool,
    pub refresh_rate: Duration,
    pub scope: Scope,
    pub include_children: bool,
    pub interface: Option<String>,
    pub all_interfaces: bool,
    pub record: Option<PathBuf>,
    pub record_format: Option<RecordFormatArg>,
    pub flush_interval: Duration,
    pub append: bool,
    pub labels: BTreeMap<String, String>,
    pub backend: BackendArg,
    pub strict: bool,
    pub debug_ebpf: bool,
}

impl TryFrom<Cli> for Config {
    type Error = crate::error::FlowtopError;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        cli.validate()?;
        let record_format = cli.record_format()?;
        let labels = cli.metadata_labels()?;
        let scope = if let Some(pid) = cli.pid {
            Scope::Pid(pid)
        } else if let Some(name) = &cli.process {
            Scope::Process(name.clone())
        } else {
            Scope::Host
        };
        Ok(Self {
            interval: cli.interval,
            duration: cli.duration,
            no_ui: cli.no_ui,
            ascii: cli.ascii,
            refresh_rate: cli.refresh_rate,
            scope,
            include_children: cli.include_children,
            interface: cli.interface,
            all_interfaces: cli.all_interfaces,
            record: cli.record,
            record_format,
            flush_interval: cli.flush_interval,
            append: cli.append,
            labels,
            backend: cli.backend,
            strict: cli.strict,
            debug_ebpf: cli.debug_ebpf,
        })
    }
}
