use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use flowtop_common::{
    event::{EventType, FlowEvent},
    network::{ConnectionDirection, ConnectionMeta, TcpState},
};

use crate::maps::{CONNECTIONS, DIRECTIONS, EVENTS, count_lost_event};

// Stable fields preceding the tracepoint payload occupy eight bytes. These
// offsets must be checked against
// /sys/kernel/tracing/events/sock/inet_sock_set_state/format at startup.
const SKADDR_OFFSET: usize = 8;
const OLD_STATE_OFFSET: usize = 16;
const NEW_STATE_OFFSET: usize = 20;

#[tracepoint]
pub fn state_change(ctx: TracePointContext) -> u32 {
    handle_state_change(ctx).unwrap_or(1)
}

fn handle_state_change(ctx: TracePointContext) -> Result<u32, u32> {
    let key: u64 = unsafe { ctx.read_at(SKADDR_OFFSET) }.map_err(|_| 1_u32)?;
    let old_state: i32 = unsafe { ctx.read_at(OLD_STATE_OFFSET) }.map_err(|_| 1_u32)?;
    let new_state: i32 = unsafe { ctx.read_at(NEW_STATE_OFFSET) }.map_err(|_| 1_u32)?;
    let now = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let direction =
        unsafe { DIRECTIONS.get(key).copied() }.unwrap_or(ConnectionDirection::Unknown as u8);

    let mut meta = unsafe { CONNECTIONS.get(key).copied() }.unwrap_or_else(|| ConnectionMeta {
        created_at_ns: now,
        ..ConnectionMeta::default()
    });
    meta.socket_cookie = 0;
    if meta.tgid == 0 {
        meta.tgid = (pid_tgid >> 32) as u32;
        meta.pid = pid_tgid as u32;
    }
    meta.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    meta.direction = direction;
    meta.state = TcpState::from_linux(new_state as u8) as u8;
    meta.last_state_change_ns = now;

    let mut event = FlowEvent::zeroed();
    event.timestamp_ns = now;
    event.pid = meta.pid;
    event.tgid = meta.tgid;
    event.cgroup_id = meta.cgroup_id;
    event.event_type = if new_state as u8 == TcpState::Close as u8 {
        EventType::ConnectionClosed as u8
    } else if new_state as u8 == TcpState::Established as u8
        && direction == ConnectionDirection::OutboundInitiated as u8
    {
        EventType::ConnectEstablished as u8
    } else {
        EventType::StateChanged as u8
    };
    event.old_state = old_state as u8;
    event.new_state = new_state as u8;
    event.direction = direction;

    if EVENTS.output::<FlowEvent>(&event, 0).is_err() {
        count_lost_event();
    }
    if new_state as u8 == TcpState::Close as u8 {
        // Attempt both removals even if an LRU map has already evicted one of
        // the entries. Returning an error must not leave the other map stale.
        let connection_result = CONNECTIONS.remove(key);
        let direction_result = DIRECTIONS.remove(key);
        if connection_result.is_err() || direction_result.is_err() {
            return Err(1_u32);
        }
    } else {
        CONNECTIONS.insert(key, meta, 0).map_err(|_| 1_u32)?;
    }
    Ok(0)
}
