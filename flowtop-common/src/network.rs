#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type SocketCookie = u64;

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AddressFamily {
    #[default]
    Unknown = 0,
    Ipv4 = 2,
    Ipv6 = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransportProtocol {
    #[default]
    Unknown = 0,
    Tcp = 6,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ConnectionDirection {
    #[default]
    Unknown = 0,
    InboundAccepted = 1,
    OutboundInitiated = 2,
    InferredInbound = 3,
    InferredOutbound = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING-KEBAB-CASE"))]
pub enum TcpState {
    #[default]
    Unknown = 0,
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynRecv = 12,
}

impl TcpState {
    pub fn from_linux(value: u8) -> Self {
        match value {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            _ => Self::Unknown,
        }
    }
}

/// Fixed-size, verifier-friendly connection metadata shared with eBPF.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ConnectionMeta {
    pub socket_cookie: u64,
    pub cgroup_id: u64,
    pub netns_id: u64,
    pub created_at_ns: u64,
    pub last_state_change_ns: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub tgid: u32,
    pub pid: u32,
    /// Reserved for future UID attribution; Phase 0 producers leave this as zero.
    pub uid: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub family: u8,
    pub protocol: u8,
    pub direction: u8,
    pub state: u8,
    pub _reserved: [u8; 4],
}

const _: [(); 112] = [(); core::mem::size_of::<ConnectionMeta>()];
