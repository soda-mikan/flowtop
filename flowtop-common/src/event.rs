#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EventType {
    #[default]
    Unknown = 0,
    ConnectStarted = 1,
    ConnectEstablished = 2,
    AcceptEstablished = 3,
    StateChanged = 4,
    ConnectionClosed = 5,
    ProcessExited = 6,
}

/// Every byte has an explicit value. Producers must construct this with
/// `FlowEvent::zeroed()` before assigning fields.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FlowEvent {
    pub timestamp_ns: u64,
    pub socket_cookie: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub event_type: u8,
    pub old_state: u8,
    pub new_state: u8,
    pub direction: u8,
    pub _reserved: [u8; 4],
}

impl FlowEvent {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            pid: 0,
            tgid: 0,
            event_type: 0,
            old_state: 0,
            new_state: 0,
            direction: 0,
            _reserved: [0; 4],
        }
    }
}

const _: [(); 40] = [(); core::mem::size_of::<FlowEvent>()];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_event_has_no_uninitialized_payload() {
        let event = FlowEvent::zeroed();
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&event as *const FlowEvent).cast::<u8>(),
                core::mem::size_of::<FlowEvent>(),
            )
        };
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
