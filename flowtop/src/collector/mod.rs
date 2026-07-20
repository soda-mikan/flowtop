mod ebpf;
pub mod procfs;

use std::collections::BTreeMap;

use anyhow::Result;
use async_trait::async_trait;
use flowtop_common::network::TcpState;

use crate::{cli::BackendArg, config::Config, error::FlowtopError};

#[derive(Debug, Clone, Default)]
pub struct CpuCounters {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuCounters {
    pub fn total(&self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryCounters {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessCounters {
    pub matching_pids: usize,
    pub cpu_ticks: u64,
    pub rss_bytes: Option<u64>,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RawMetrics {
    pub monotonic_ns: u64,
    pub cpu: CpuCounters,
    pub cpu_count: usize,
    pub memory: MemoryCounters,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub disk_read_sectors: u64,
    pub disk_write_sectors: u64,
    pub tcp_states: BTreeMap<u8, u64>,
    pub accepted_established: Option<u64>,
    pub connected_established: Option<u64>,
    pub opened_total: Option<u64>,
    pub accepted_total: Option<u64>,
    pub connected_total: Option<u64>,
    pub closed_total: Option<u64>,
    pub process: Option<ProcessCounters>,
    pub lost_events: u64,
    pub collection_errors: u64,
}

impl RawMetrics {
    pub fn tcp_count(&self, state: TcpState) -> u64 {
        self.tcp_states.get(&(state as u8)).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct CollectorCapabilities {
    pub backend: &'static str,
    pub degraded: bool,
    pub direction: bool,
    pub process_network: bool,
    pub diagnostic: Option<String>,
}

#[async_trait]
pub trait Collector: Send {
    async fn initialize(&mut self) -> Result<CollectorCapabilities>;
    async fn snapshot(&mut self) -> Result<RawMetrics>;
    async fn shutdown(&mut self) -> Result<()>;
}

pub async fn build_collector(
    config: &Config,
) -> Result<(Box<dyn Collector>, CollectorCapabilities)> {
    match config.backend {
        BackendArg::Proc => initialize_proc(config).await,
        BackendArg::Ebpf => match initialize_ebpf(config).await {
            Ok(result) => Ok(result),
            Err(error) => Err(FlowtopError::EbpfUnavailable {
                reason: format!("{error:#}"),
            }
            .into()),
        },
        BackendArg::Auto => match initialize_ebpf(config).await {
            Ok(result) => Ok(result),
            Err(error) if config.strict => Err(FlowtopError::EbpfUnavailable {
                reason: format!("{error:#}"),
            }
            .into()),
            Err(error) => {
                let (collector, mut capabilities) = initialize_proc(config).await?;
                capabilities.diagnostic = Some(format!("eBPF fallback: {error:#}"));
                Ok((collector, capabilities))
            }
        },
    }
}

async fn initialize_proc(config: &Config) -> Result<(Box<dyn Collector>, CollectorCapabilities)> {
    let mut collector = procfs::ProcCollector::new(config.clone())?;
    let capabilities = collector.initialize().await?;
    Ok((Box::new(collector), capabilities))
}

async fn initialize_ebpf(config: &Config) -> Result<(Box<dyn Collector>, CollectorCapabilities)> {
    let mut collector = ebpf::EbpfCollector::new(config.clone())?;
    let capabilities = collector.initialize().await?;
    Ok((Box::new(collector), capabilities))
}
