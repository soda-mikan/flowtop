use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use flowtop_common::network::TcpState;

use super::{
    Collector, CollectorCapabilities, CpuCounters, MemoryCounters, ProcessCounters, RawMetrics,
};
use crate::{
    config::{Config, Scope},
    error::FlowtopError,
    filter::process::{process_io_totals, process_rss_bytes, resolve_pids, socket_inodes},
};

pub struct ProcCollector {
    config: Config,
    proc_root: PathBuf,
    sys_root: PathBuf,
    started_at: Instant,
}

impl ProcCollector {
    pub fn new(config: Config) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(FlowtopError::UnsupportedOs(std::env::consts::OS).into());
        }
        Ok(Self {
            config,
            proc_root: PathBuf::from("/proc"),
            sys_root: PathBuf::from("/sys"),
            started_at: Instant::now(),
        })
    }

    fn collect(&self) -> Result<RawMetrics> {
        let stat = fs::read_to_string(self.proc_root.join("stat")).context("read /proc/stat")?;
        let (cpu, cpu_count) = parse_cpu_stat(&stat)?;
        let meminfo =
            fs::read_to_string(self.proc_root.join("meminfo")).context("read /proc/meminfo")?;
        let memory = parse_meminfo(&meminfo)?;
        let net_dev =
            fs::read_to_string(self.proc_root.join("net/dev")).context("read /proc/net/dev")?;
        let (network_rx_bytes, network_tx_bytes) = parse_net_dev(
            &net_dev,
            self.config.interface.as_deref(),
            self.config.all_interfaces,
        )?;
        let diskstats =
            fs::read_to_string(self.proc_root.join("diskstats")).context("read /proc/diskstats")?;
        let (disk_read_sectors, disk_write_sectors) = parse_diskstats(&diskstats, |name| {
            is_default_disk_device(&self.sys_root, name)
        });

        let selected_processes = resolve_pids(
            &self.proc_root,
            &self.config.scope,
            self.config.include_children,
        )?;
        let inode_filter = (!matches!(self.config.scope, Scope::Host))
            .then(|| socket_inodes(&self.proc_root, &selected_processes));
        let (tcp_states, tcp_errors) = self.read_tcp_states(inode_filter.as_ref());

        let process = (!matches!(self.config.scope, Scope::Host)).then(|| {
            let (disk_read_bytes, disk_write_bytes) =
                process_io_totals(&self.proc_root, &selected_processes);
            ProcessCounters {
                matching_pids: selected_processes.len(),
                cpu_ticks: selected_processes
                    .iter()
                    .map(|process| process.cpu_ticks)
                    .sum(),
                rss_bytes: process_rss_bytes(&self.proc_root, &selected_processes),
                disk_read_bytes,
                disk_write_bytes,
                rx_bytes: None,
                tx_bytes: None,
            }
        });

        Ok(RawMetrics {
            monotonic_ns: self
                .started_at
                .elapsed()
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
            cpu,
            cpu_count,
            memory,
            network_rx_bytes,
            network_tx_bytes,
            disk_read_sectors,
            disk_write_sectors,
            tcp_states,
            accepted_established: None,
            connected_established: None,
            opened_total: None,
            accepted_total: None,
            connected_total: None,
            closed_total: None,
            process,
            lost_events: 0,
            collection_errors: tcp_errors,
        })
    }

    fn read_tcp_states(&self, inode_filter: Option<&HashSet<u64>>) -> (BTreeMap<u8, u64>, u64) {
        let mut states = BTreeMap::new();
        let mut errors = 0;
        for relative in ["net/tcp", "net/tcp6"] {
            match fs::read_to_string(self.proc_root.join(relative)) {
                Ok(contents) => merge_tcp_states(&mut states, &contents, inode_filter),
                Err(_) => errors += 1,
            }
        }
        (states, errors)
    }
}

#[async_trait]
impl Collector for ProcCollector {
    async fn initialize(&mut self) -> Result<CollectorCapabilities> {
        if let Scope::Pid(pid) = self.config.scope
            && !self.proc_root.join(pid.to_string()).exists()
        {
            return Err(FlowtopError::PidNotFound(pid).into());
        }
        // Fail early with a useful path-specific diagnostic.
        let _ = self.collect()?;
        Ok(CollectorCapabilities {
            backend: "proc",
            degraded: true,
            direction: false,
            process_network: false,
            diagnostic: Some(
                "accepted/connected direction and process RX/TX are unavailable".into(),
            ),
        })
    }

    async fn snapshot(&mut self) -> Result<RawMetrics> {
        self.collect()
    }

    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

pub fn parse_cpu_stat(input: &str) -> Result<(CpuCounters, usize)> {
    let mut lines = input.lines();
    let total = lines.next().context("missing aggregate cpu line")?;
    let mut fields = total.split_whitespace();
    if fields.next() != Some("cpu") {
        bail!("first /proc/stat line is not aggregate cpu");
    }
    let values: Vec<u64> = fields
        .take(8)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .context("invalid aggregate cpu counter")?;
    if values.len() < 4 {
        bail!("short aggregate cpu line");
    }
    let value = |index: usize| values.get(index).copied().unwrap_or(0);
    let cpu_count = input
        .lines()
        .skip(1)
        .take_while(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|name| name.strip_prefix("cpu").is_some_and(|id| !id.is_empty()))
        })
        .count()
        .max(1);
    Ok((
        CpuCounters {
            user: value(0),
            nice: value(1),
            system: value(2),
            idle: value(3),
            iowait: value(4),
            irq: value(5),
            softirq: value(6),
            steal: value(7),
        },
        cpu_count,
    ))
}

pub fn parse_meminfo(input: &str) -> Result<MemoryCounters> {
    let mut total_kib = None;
    let mut available_kib = None;
    for line in input.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value = rest
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok());
        match key {
            "MemTotal" => total_kib = value,
            "MemAvailable" => available_kib = value,
            _ => {}
        }
    }
    Ok(MemoryCounters {
        total_bytes: total_kib.context("MemTotal missing")?.saturating_mul(1024),
        available_bytes: available_kib
            .context("MemAvailable missing")?
            .saturating_mul(1024),
    })
}

pub fn parse_net_dev(
    input: &str,
    selected: Option<&str>,
    all_interfaces: bool,
) -> Result<(u64, u64)> {
    let mut rx = 0_u64;
    let mut tx = 0_u64;
    let mut matched = false;
    for line in input.lines().skip(2) {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if let Some(selected) = selected {
            if name != selected {
                continue;
            }
        } else if !all_interfaces && name == "lo" {
            continue;
        }
        let fields: Vec<&str> = counters.split_whitespace().collect();
        if fields.len() < 16 {
            continue;
        }
        let Some(interface_rx) = fields[0].parse::<u64>().ok() else {
            continue;
        };
        let Some(interface_tx) = fields[8].parse::<u64>().ok() else {
            continue;
        };
        matched = true;
        rx = rx.saturating_add(interface_rx);
        tx = tx.saturating_add(interface_tx);
    }
    if !matched && let Some(selected) = selected {
        bail!("interface {selected} not found in /proc/net/dev");
    }
    Ok((rx, tx))
}

pub fn parse_diskstats(input: &str, mut include: impl FnMut(&str) -> bool) -> (u64, u64) {
    let mut read_sectors = 0_u64;
    let mut write_sectors = 0_u64;
    for line in input.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || !include(fields[2]) {
            continue;
        }
        read_sectors =
            read_sectors.saturating_add(fields[5].parse::<u64>().ok().unwrap_or_default());
        write_sectors =
            write_sectors.saturating_add(fields[9].parse::<u64>().ok().unwrap_or_default());
    }
    (read_sectors, write_sectors)
}

fn is_default_disk_device(sys_root: &Path, name: &str) -> bool {
    if ["loop", "ram", "zram", "fd", "sr", "dm-", "md"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return false;
    }
    sys_root.join("block").join(name).exists()
}

pub fn merge_tcp_states(
    states: &mut BTreeMap<u8, u64>,
    input: &str,
    inode_filter: Option<&HashSet<u64>>,
) {
    for line in input.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some(state) = u8::from_str_radix(fields[3], 16).ok() else {
            continue;
        };
        let Some(inode) = fields[9].parse::<u64>().ok() else {
            continue;
        };
        if inode_filter.is_some_and(|filter| !filter.contains(&inode)) {
            continue;
        }
        *states.entry(TcpState::from_linux(state) as u8).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_and_count() {
        let (cpu, count) = parse_cpu_stat(
            "cpu  10 2 3 40 5 6 7 8\ncpu0 1 0 0 4 0 0 0 0\ncpu1 1 0 0 4 0 0 0 0\nintr 1\n",
        )
        .unwrap();
        assert_eq!(cpu.total(), 81);
        assert_eq!(count, 2);
    }

    #[test]
    fn sums_selected_network_interfaces() {
        let input = "header\nheader\n lo: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n";
        assert_eq!(parse_net_dev(input, None, false).unwrap(), (100, 200));
        assert_eq!(parse_net_dev(input, None, true).unwrap(), (110, 220));
        assert_eq!(parse_net_dev(input, Some("lo"), false).unwrap(), (10, 20));
    }

    #[test]
    fn filters_tcp_by_socket_inode() {
        let input = "header\n0: local remote 01 x x x x x 77\n1: local remote 06 x x x x x 88\n";
        let mut states = BTreeMap::new();
        merge_tcp_states(&mut states, input, Some(&HashSet::from([77])));
        assert_eq!(states.get(&(TcpState::Established as u8)), Some(&1));
        assert_eq!(states.get(&(TcpState::TimeWait as u8)), None);
    }

    #[test]
    fn parses_memory_in_kib() {
        let memory = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 250 kB\n").unwrap();
        assert_eq!(memory.total_bytes, 1_024_000);
        assert_eq!(memory.available_bytes, 256_000);
    }
}
