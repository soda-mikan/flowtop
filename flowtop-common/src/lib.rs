#![cfg_attr(not(feature = "serde"), no_std)]

pub mod event;
pub mod metrics;
pub mod network;

pub const SCHEMA_VERSION: &str = "1";
