use aya_ebpf::{
    macros::map,
    maps::{LruHashMap, PerCpuArray, RingBuf},
};
use flowtop_common::network::ConnectionMeta;

pub const MAX_TRACKED_SOCKETS: u32 = 262_144;

/// `struct sock *` is the Phase 0 key because inet_sock_set_state exposes the
/// socket pointer directly. The compatibility layer will replace this with the
/// socket cookie where the tracing helper is available.
#[map]
pub static DIRECTIONS: LruHashMap<u64, u8> = LruHashMap::with_max_entries(MAX_TRACKED_SOCKETS, 0);

#[map]
pub static CONNECTIONS: LruHashMap<u64, ConnectionMeta> =
    LruHashMap::with_max_entries(MAX_TRACKED_SOCKETS, 0);

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
pub static LOST_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

pub fn count_lost_event() {
    if let Some(counter) = LOST_EVENTS.get_ptr_mut(0) {
        unsafe { *counter = (*counter).saturating_add(1) };
    }
}
