use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use flowtop_common::network::ConnectionDirection;

use crate::maps::DIRECTIONS;

#[kprobe]
pub fn connect_v4(ctx: ProbeContext) -> u32 {
    track_connect(ctx).unwrap_or(1)
}

#[kprobe]
pub fn connect_v6(ctx: ProbeContext) -> u32 {
    track_connect(ctx).unwrap_or(1)
}

fn track_connect(ctx: ProbeContext) -> Result<u32, u32> {
    let socket: *const u8 = ctx.arg(0).ok_or(1_u32)?;
    let key = socket as u64;
    DIRECTIONS
        .insert(key, ConnectionDirection::OutboundInitiated as u8, 0)
        .map_err(|_| 1_u32)?;
    Ok(0)
}
