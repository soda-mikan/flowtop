# Architecture

## Data path

The userspace sampler owns one collector and requests an absolute-counter snapshot at the configured
interval. The aggregator calculates wrap-safe deltas and rates, creates the schema-v1 snapshot, and
then independently feeds the recorder and the display history. TUI redraws run on a separate refresh
interval; pausing only freezes the displayed snapshot.

Channels are not required in v0.1 because collection is a single bounded operation per tick and file
writes are buffered. A future high-volume event consumer must use bounded channels: recorder data may
not be dropped, while TUI frames may use latest-value semantics.

## eBPF Phase 0

The separately built `flowtop-ebpf` crate contains four programs:

| Program | Attach point | Purpose |
|---|---|---|
| `connect_v4` | kprobe `tcp_v4_connect` | mark socket as outbound |
| `connect_v6` | kprobe `tcp_v6_connect` | mark socket as outbound |
| `accept_return` | kretprobe `inet_csk_accept` | mark returned socket as inbound |
| `state_change` | tracepoint `sock:inet_sock_set_state` | maintain state and emit lifecycle events |

The Phase 0 map key is the `struct sock *` value exposed consistently by these hooks. This gives exact
origin classification during one socket lifetime but is not yet the design's preferred socket-cookie
identity. Both connection metadata and direction maps use an LRU limit of 262,144 entries, and cleanup
attempts both map removals independently on CLOSE. Migrating the compatibility layer to a tracing
context that supports `bpf_get_socket_cookie` is the primary Phase 0 follow-up.

Lifecycle events use a 40-byte `#[repr(C)]` structure with explicit reserved bytes. It is constructed
from an all-zero value before fields are assigned. High-frequency payload/packet events are never sent
to userspace. Current connection state stays in an LRU map; the ring buffer contains lifecycle changes
only, and a per-CPU counter records reservation failures. Userspace drains the ring on every sample
and maintains scoped cumulative accept, connect, and close counters. Rate deltas therefore retain
connections that have already left the LRU map before the next snapshot.

The loader verifies the tracepoint field offsets from tracefs before attach and refuses to run if they
do not match the compiled program. `auto` falls back to proc unless `--strict` is supplied.

## proc backend

The proc collector reads:

- `/proc/net/tcp` and `/proc/net/tcp6`
- `/proc/net/dev`
- `/proc/stat`
- `/proc/meminfo`
- `/proc/diskstats`
- `/proc/PID/{stat,statm,io,fd}` for process scopes

Socket-inode joins implement PID connection filtering. Connections without a live owning file
descriptor (notably some TIME-WAIT entries) cannot be assigned safely to a PID.

## Time series

Each metric stores `min`, `max`, weighted `avg`, and `last`. Every pair at level N is merged into one
bucket at level N+1. Each level is capped at 4096 buckets, so history storage is bounded. Rendering
chooses a level appropriate for terminal width and merges again only when necessary. Graphs use bucket
maxima so narrow displays retain spikes. Bucket timestamps determine horizontal placement, keeping
historical peaks moving monotonically left as the full-run timeline grows.
