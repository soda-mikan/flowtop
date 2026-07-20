#!/usr/bin/env sh
set -eu

# This is the unprivileged proc-backend check. Run test-ebpf-smoke.sh
# separately with the privileges required for a real kernel attach.
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo run --locked --quiet -- --backend proc --no-ui --interval 100ms --duration 250ms
