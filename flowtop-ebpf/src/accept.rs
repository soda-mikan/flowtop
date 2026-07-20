use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kretprobe,
    programs::RetProbeContext,
};
use flowtop_common::{
    event::{EventType, FlowEvent},
    network::{ConnectionDirection, ConnectionMeta, TcpState},
};

use crate::maps::{CONNECTIONS, DIRECTIONS, EVENTS, count_lost_event};

#[kretprobe]
pub fn accept_return(ctx: RetProbeContext) -> u32 {
    track_accept(ctx).unwrap_or(1)
}

fn track_accept(ctx: RetProbeContext) -> Result<u32, u32> {
    let socket: *const u8 = ctx.ret::<*const u8>();
    if socket.is_null() {
        return Ok(0);
    }
    let key = socket as u64;
    DIRECTIONS
        .insert(key, ConnectionDirection::InboundAccepted as u8, 0)
        .map_err(|_| 1_u32)?;

    let now = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let mut meta = unsafe { CONNECTIONS.get(key).copied() }.unwrap_or_else(|| ConnectionMeta {
        created_at_ns: now,
        state: TcpState::Established as u8,
        ..ConnectionMeta::default()
    });
    meta.socket_cookie = 0;
    meta.tgid = (pid_tgid >> 32) as u32;
    meta.pid = pid_tgid as u32;
    meta.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    meta.direction = ConnectionDirection::InboundAccepted as u8;
    meta.last_state_change_ns = now;
    CONNECTIONS.insert(key, meta, 0).map_err(|_| 1_u32)?;

    let mut event = FlowEvent::zeroed();
    event.timestamp_ns = now;
    event.pid = meta.pid;
    event.tgid = meta.tgid;
    event.cgroup_id = meta.cgroup_id;
    event.event_type = EventType::AcceptEstablished as u8;
    event.new_state = meta.state;
    event.direction = meta.direction;
    if EVENTS.output::<FlowEvent>(&event, 0).is_err() {
        count_lost_event();
    }
    Ok(0)
}
