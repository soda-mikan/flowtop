use anyhow::{Result, bail};
use async_trait::async_trait;

use super::{Collector, CollectorCapabilities, RawMetrics};
use crate::{config::Config, error::FlowtopError};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use {
    anyhow::Context,
    aya::{
        Ebpf, Pod,
        maps::{HashMap as AyaHashMap, PerCpuArray, RingBuf},
        programs::{KProbe, TracePoint},
    },
    flowtop_common::{
        event::{EventType, FlowEvent},
        network::{ConnectionDirection, ConnectionMeta, TcpState},
    },
    std::{
        collections::HashSet,
        fs,
        path::{Path, PathBuf},
    },
};

pub struct EbpfCollector {
    config: Config,
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    state: Option<LinuxEbpfState>,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
struct LinuxEbpfState {
    proc: super::procfs::ProcCollector,
    bpf: Ebpf,
    opened_total: u64,
    accepted_total: u64,
    connected_total: u64,
    closed_total: u64,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
#[repr(transparent)]
#[derive(Clone, Copy)]
struct ConnectionPod(ConnectionMeta);

#[cfg(all(feature = "ebpf", target_os = "linux"))]
unsafe impl Pod for ConnectionPod {}

impl EbpfCollector {
    pub fn new(config: Config) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(FlowtopError::UnsupportedOs(std::env::consts::OS).into());
        }
        Ok(Self {
            config,
            #[cfg(all(feature = "ebpf", target_os = "linux"))]
            state: None,
        })
    }
}

#[async_trait]
impl Collector for EbpfCollector {
    async fn initialize(&mut self) -> Result<CollectorCapabilities> {
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        {
            let diagnostic = if self.config.debug_ebpf {
                " (debug diagnostics requested)"
            } else {
                ""
            };
            bail!("this binary was built without Linux eBPF support{diagnostic}");
        }

        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        {
            verify_state_tracepoint_layout()?;
            let object = find_ebpf_object()?;
            let mut bpf = Ebpf::load_file(&object)
                .with_context(|| format!("load eBPF object {}", object.display()))?;
            attach_kprobe(&mut bpf, "connect_v4", "tcp_v4_connect")?;
            attach_kprobe(&mut bpf, "connect_v6", "tcp_v6_connect")?;
            attach_kprobe(&mut bpf, "accept_return", "inet_csk_accept")?;
            let program: &mut TracePoint = bpf
                .program_mut("state_change")
                .context("eBPF program state_change missing")?
                .try_into()?;
            program.load().context("load state_change tracepoint")?;
            program
                .attach("sock", "inet_sock_set_state")
                .context("attach sock:inet_sock_set_state")?;

            let mut proc = super::procfs::ProcCollector::new(self.config.clone())?;
            proc.initialize().await?;
            self.state = Some(LinuxEbpfState {
                proc,
                bpf,
                opened_total: 0,
                accepted_total: 0,
                connected_total: 0,
                closed_total: 0,
            });
            Ok(CollectorCapabilities {
                backend: "ebpf",
                degraded: false,
                direction: true,
                process_network: false,
                diagnostic: self
                    .config
                    .debug_ebpf
                    .then(|| format!("loaded {}", object.display())),
            })
        }
    }

    async fn snapshot(&mut self) -> Result<RawMetrics> {
        #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
        bail!("eBPF collector is not initialized");

        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        {
            let state = self
                .state
                .as_mut()
                .context("eBPF collector not initialized")?;
            let mut raw = state.proc.snapshot().await?;
            let selected_pids = selected_pids(&self.config)?;
            drain_lifecycle_events(state, selected_pids.as_ref())?;

            let connections = AyaHashMap::<_, u64, ConnectionPod>::try_from(
                state
                    .bpf
                    .map("CONNECTIONS")
                    .context("CONNECTIONS map missing")?,
            )?;
            let mut accepted = 0_u64;
            let mut connected = 0_u64;
            for entry in connections.iter() {
                let (_, meta) = entry.context("read CONNECTIONS entry")?;
                if selected_pids
                    .as_ref()
                    .is_some_and(|pids| !pids.contains(&meta.0.tgid))
                    || meta.0.state != TcpState::Established as u8
                {
                    continue;
                }
                match meta.0.direction {
                    value if value == ConnectionDirection::InboundAccepted as u8 => accepted += 1,
                    value if value == ConnectionDirection::OutboundInitiated as u8 => {
                        connected += 1
                    }
                    _ => {}
                }
            }
            raw.accepted_established = Some(accepted);
            raw.connected_established = Some(connected);
            raw.opened_total = Some(state.opened_total);
            raw.accepted_total = Some(state.accepted_total);
            raw.connected_total = Some(state.connected_total);
            raw.closed_total = Some(state.closed_total);
            raw.lost_events = read_lost_events(&state.bpf).unwrap_or_else(|_| {
                raw.collection_errors = raw.collection_errors.saturating_add(1);
                0
            });
            Ok(raw)
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        if let Some(state) = self.state.as_mut() {
            state.proc.shutdown().await?;
        }
        Ok(())
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn attach_kprobe(bpf: &mut Ebpf, program_name: &str, function: &str) -> Result<()> {
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF program {program_name} missing"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("load {program_name}"))?;
    // The section type encoded by #[kprobe]/#[kretprobe] controls probe mode.
    program
        .attach(function, 0)
        .with_context(|| format!("attach probe {function}"))?;
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn find_ebpf_object() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("FLOWTOP_EBPF_OBJECT") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(executable) = std::env::current_exe() {
        candidates.push(executable.with_file_name("flowtop-ebpf.o"));
    }
    candidates.push(PathBuf::from("/usr/lib/flowtop/flowtop-ebpf.o"));
    candidates.into_iter().find(|path| path.is_file()).context(
        "flowtop-ebpf.o not found; set FLOWTOP_EBPF_OBJECT or install it beside the binary",
    )
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn verify_state_tracepoint_layout() -> Result<()> {
    let candidates = [
        Path::new("/sys/kernel/tracing/events/sock/inet_sock_set_state/format"),
        Path::new("/sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format"),
    ];
    let contents = candidates
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .context("read sock:inet_sock_set_state tracepoint format")?;
    for (field, expected) in [("skaddr", 8), ("oldstate", 16), ("newstate", 20)] {
        let actual = tracepoint_field_offset(&contents, field)
            .with_context(|| format!("tracepoint field {field} missing"))?;
        if actual != expected {
            bail!(
                "sock:inet_sock_set_state field {field} offset is {actual}, expected {expected}; refusing an unsafe attach"
            );
        }
    }
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn tracepoint_field_offset(contents: &str, name: &str) -> Option<usize> {
    contents.lines().find_map(|line| {
        let (field, rest) = line.split_once(";\toffset:")?;
        field
            .split_whitespace()
            .last()
            .is_some_and(|field| field.trim_start_matches('*') == name)
            .then(|| rest.split(';').next()?.trim().parse().ok())?
    })
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn selected_pids(config: &Config) -> Result<Option<HashSet<u32>>> {
    if matches!(config.scope, crate::config::Scope::Host) {
        return Ok(None);
    }
    Ok(Some(
        crate::filter::process::resolve_pids(
            Path::new("/proc"),
            &config.scope,
            config.include_children,
        )?
        .into_iter()
        .map(|process| process.pid)
        .collect(),
    ))
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn drain_lifecycle_events(
    state: &mut LinuxEbpfState,
    selected_pids: Option<&HashSet<u32>>,
) -> Result<()> {
    let mut opened = 0_u64;
    let mut accepted = 0_u64;
    let mut connected = 0_u64;
    let mut closed = 0_u64;
    {
        let map = state.bpf.map_mut("EVENTS").context("EVENTS map missing")?;
        let mut ring = RingBuf::try_from(map)?;
        while let Some(item) = ring.next() {
            if item.len() != std::mem::size_of::<FlowEvent>() {
                continue;
            }
            let event = unsafe { (item.as_ptr().cast::<FlowEvent>()).read_unaligned() };
            if selected_pids.is_some_and(|pids| !pids.contains(&event.tgid)) {
                continue;
            }
            match event.event_type {
                value if value == EventType::ConnectEstablished as u8 => {
                    opened += 1;
                    connected += 1;
                }
                value if value == EventType::AcceptEstablished as u8 => {
                    opened += 1;
                    accepted += 1;
                }
                value if value == EventType::ConnectionClosed as u8 => closed += 1,
                _ => {}
            }
        }
    }
    state.opened_total = state.opened_total.saturating_add(opened);
    state.accepted_total = state.accepted_total.saturating_add(accepted);
    state.connected_total = state.connected_total.saturating_add(connected);
    state.closed_total = state.closed_total.saturating_add(closed);
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn read_lost_events(bpf: &Ebpf) -> Result<u64> {
    let values = PerCpuArray::<_, u64>::try_from(
        bpf.map("LOST_EVENTS").context("LOST_EVENTS map missing")?,
    )?
    .get(&0, 0)?;
    Ok(values.iter().copied().sum())
}

#[cfg(all(test, feature = "ebpf", target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_tracepoint_offsets() {
        let format = "field:const void * skaddr;\toffset:8;\tsize:8;\tsigned:0;\nfield:int oldstate;\toffset:16;\tsize:4;\tsigned:1;";
        assert_eq!(tracepoint_field_offset(format, "skaddr"), Some(8));
        assert_eq!(tracepoint_field_offset(format, "oldstate"), Some(16));
    }
}
