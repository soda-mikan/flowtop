use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum FlowtopError {
    #[error("flowtop supports Linux only; current OS is {0}")]
    UnsupportedOs(&'static str),
    #[error("invalid collection interval {0}; expected 100ms..=60s")]
    InvalidInterval(String),
    #[error("invalid refresh rate {0}; expected 50ms..=60s")]
    InvalidRefreshRate(String),
    #[error("invalid flush interval {0}; expected 50ms..=60s")]
    InvalidFlushInterval(String),
    #[error("--include-children requires --pid or --process")]
    IncludeChildrenRequiresScope,
    #[error("PID {0} does not exist or is not readable")]
    PidNotFound(u32),
    #[error("cgroup scope is not implemented in v0.1; use --pid or host scope")]
    CgroupNotImplemented,
    #[error("network namespace scope is not implemented in v0.1")]
    NetnsNotImplemented,
    #[error(
        "eBPF backend unavailable: {reason}. Try --backend proc or run with the required Linux capabilities"
    )]
    EbpfUnavailable { reason: String },
    #[error("record format cannot be inferred from {0}; use --format jsonl or --format csv")]
    RecordFormatUnknown(PathBuf),
    #[error("invalid metadata {0:?}; expected KEY=VALUE")]
    InvalidMetadata(String),
}
