# flowtop

`flowtop` is a lightweight, network-first `top` for Linux performance tests. It displays TCP
connection states, host RX/TX throughput, CPU, memory, and disk I/O in one Ratatui screen while
optionally recording the same snapshots as JSON Lines or CSV.

## Status

This repository contains the `0.0.1-beta` prerelease. It is suitable for evaluation and testing, but
the eBPF backend is not yet declared production-ready across the full kernel compatibility matrix.

- Aya probes for outbound `tcp_v4_connect` / `tcp_v6_connect`, inbound `inet_csk_accept`, and
  `sock:inet_sock_set_state`
- exact post-start direction classification from probe origin; unclassified/pre-start sockets stay
  `Unknown`
- `/proc` fallback with no direction guessing
- host and PID/process-name scopes (`--include-children` supported)
- host interface RX/TX, CPU, memory, disk I/O, and process CPU/RSS/disk I/O
- bounded multi-resolution full-run history with peak-preserving buckets
- event-rate graphs for short-lived accepted, connected, and closed TCP connections
- responsive Ratatui UI, pause/reset/details/help/health controls, and terminal recovery
- JSONL metadata/snapshots and stable-column CSV recording
- headless JSONL stdout with `--no-ui`

The eBPF probe object is compiled separately and must be installed beside the userspace binary.
Kernel verifier/load tests still need to be run on each supported Linux/kernel combination. Process
RX/TX payload-byte accounting and cgroup/netns scopes are not implemented in this beta.

## Requirements

- Linux 5.15 or newer; x86_64 is the initial release target
- BTF is recommended
- Rust stable for userspace
- Rust nightly, `rust-src`, and `bpf-linker` to build the eBPF object
- root or the capabilities required by the selected kernel and probe types

## Build

```bash
./scripts/setup-dev.sh
./scripts/build-ebpf.sh
cargo build --release --locked
```

`build-ebpf.sh` writes `target/release/flowtop-ebpf.o`. The release binary looks for that file next
to itself. A packaged installation may instead place it at `/usr/lib/flowtop/flowtop-ebpf.o`, or set
`FLOWTOP_EBPF_OBJECT` to an explicit path.

On a Linux validation host, a privileged load/attach smoke test can be run after the release build:

```bash
sudo ./scripts/test-ebpf-smoke.sh
```

This validates only the currently running kernel. See [compatibility](docs/compatibility.md) for the
full kernel matrix required before declaring the eBPF backend production-ready.

For a proc-only build:

```bash
cargo build --release --no-default-features --locked
```

## Usage

```bash
# Network-first TUI with eBPF, falling back honestly to /proc when unavailable
sudo ./target/release/flowtop

# Require eBPF instead of falling back
sudo ./target/release/flowtop --backend ebpf --strict

# Force the degraded proc backend
./target/release/flowtop --backend proc

# One PID and its descendants
sudo ./target/release/flowtop --pid 1234 --include-children

# All processes with an exact /proc/PID/comm match
sudo ./target/release/flowtop --process nginx

# Ten-minute JSONL recording
sudo ./target/release/flowtop --duration 10m --record result.jsonl

# Headless CSV recording and JSONL stdout
sudo ./target/release/flowtop --no-ui --interval 1s --record result.csv
```

Important options:

```text
-i, --interval <DURATION>       100ms..=60s [default: 1s]
-d, --duration <DURATION>
-p, --pid <PID>
    --process <NAME>
    --include-children
    --interface <NAME>
-o, --record <PATH>
    --format <jsonl|csv>
    --flush-interval <DURATION>
    --append
    --metadata <KEY=VALUE>
    --no-ui
    --ascii
    --backend <auto|ebpf|proc>
    --strict
    --debug-ebpf
```

The CLI rejects cgroup, netns, and direction-inference options with an explicit not-implemented
error rather than pretending they work.

## TUI controls

```text
q / Ctrl-C  quit
p           pause/resume display (collection and recording continue)
r           reset graph history
d           toggle details
?           toggle help
e           toggle collector health
```

## Metric semantics

- `Accepted ESTAB`: connections accepted after flowtop attached its probes.
- `Connected ESTAB`: connections initiated after flowtop attached its probes.
- `Unknown ESTAB`: pre-existing sockets and anything that cannot be classified safely.
- `Accept/s`, `Connect/s`, and `Close/s`: eBPF lifecycle events per second; these remain visible even
  when a connection begins and ends between two snapshots.
- Host RX/TX is interface bytes from `/proc/net/dev`.
- Process RX/TX is currently unavailable and serialized as `null`/an empty CSV field.
- Disk sectors from `/proc/diskstats` use the Linux 512-byte accounting unit.
- The proc backend displays Accepted/Connected as `N/A` and records them as `null`; it never
  re-labels an inferred direction as confirmed.

See [architecture](docs/architecture.md), [metrics](docs/metrics.md), and
[compatibility](docs/compatibility.md) for implementation details and known risks.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo +nightly clippy --manifest-path flowtop-ebpf/Cargo.toml --locked \
  -Z build-std=core --target bpfel-unknown-none -- -D warnings
cargo +nightly build --manifest-path flowtop-ebpf/Cargo.toml \
  --locked -Z build-std=core --target bpfel-unknown-none --release
```

## Security and privacy

flowtop is read-only observability software. It does not capture payloads, TLS plaintext, HTTP,
DNS names, or individual endpoint addresses in its record format. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0.
