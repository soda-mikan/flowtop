# Changelog

All notable changes are documented here. This project follows Semantic Versioning.

## [Unreleased]

## [0.0.1-beta] - 2026-07-20

- Make direction tracking LRU-bounded and clean up both socket maps independently on CLOSE
- Document the privileged eBPF object trust path and lock dependency resolution in scripts
- Keep metric labels on their own line in height-constrained chart panels
- Add TCP Activity graphs for accepted, connected, and closed events per second
- Stabilize graph scrolling with timestamp-based horizontal placement
- Show the maximum recorded value alongside the current value for each chart
- Freeze both values and graph history while the display is paused
- Stretch history to an explicit start/now axis across the full chart width
- Allocate terminal height proportionally to multi-row TCP, network, and system charts
- Separate adjacent metric charts with adaptive gaps and per-series colors
- Rust workspace with shared fixed-layout eBPF/userspace types
- Aya connect, accept, and TCP-state Phase 0 probes
- honest proc fallback with host and PID/process-name collection
- Ratatui UI with bounded multi-resolution full-history graphs
- JSONL and CSV recording plus headless stdout
- graceful terminal and signal shutdown
- unit, integration, cross-target, lint, and CI scaffolding

Known limitations:

- Full verifier/load validation across Linux 5.15, 6.1, and a current LTS is incomplete
- Phase 0 uses bounded `struct sock *` keys; migration to socket-cookie identity remains planned
- Process RX/TX payload-byte accounting and cgroup/netns scopes are not implemented
