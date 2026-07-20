#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_path=${1:-"$repo_dir/target/release/flowtop-ebpf.o"}

cargo +nightly build \
    --manifest-path "$repo_dir/flowtop-ebpf/Cargo.toml" \
    --locked \
    -Z build-std=core \
    --target bpfel-unknown-none \
    --release
mkdir -p "$(dirname -- "$output_path")"
install -m 0644 \
    "$repo_dir/flowtop-ebpf/target/bpfel-unknown-none/release/flowtop-ebpf" \
    "$output_path"

printf '%s\n' "eBPF object: $output_path"
