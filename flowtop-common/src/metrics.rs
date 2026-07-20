#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TcpMetrics {
    pub accepted_established: Option<u64>,
    pub connected_established: Option<u64>,
    pub unknown_established: u64,
    pub syn_sent: u64,
    pub syn_recv: u64,
    pub time_wait: u64,
    pub close_wait: u64,
    pub fin_wait_1: u64,
    pub fin_wait_2: u64,
    pub last_ack: u64,
    pub closing: u64,
    pub listen: u64,
    pub opened_per_sec: Option<f64>,
    pub accepted_per_sec: Option<f64>,
    pub connected_per_sec: Option<f64>,
    pub closed_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetworkMetrics {
    pub host_rx_bytes_per_sec: f64,
    pub host_tx_bytes_per_sec: f64,
    pub process_rx_bytes_per_sec: Option<f64>,
    pub process_tx_bytes_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SystemMetrics {
    pub cpu_total_percent: f64,
    pub cpu_user_percent: f64,
    pub cpu_system_percent: f64,
    pub cpu_iowait_percent: f64,
    pub memory_used_bytes: u64,
    pub memory_available_bytes: u64,
    pub memory_used_percent: f64,
    pub disk_read_bytes_per_sec: f64,
    pub disk_write_bytes_per_sec: f64,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProcessMetrics {
    pub matching_pids: usize,
    pub cpu_percent: Option<f64>,
    pub rss_bytes: Option<u64>,
    pub disk_read_bytes_per_sec: Option<f64>,
    pub disk_write_bytes_per_sec: Option<f64>,
}
