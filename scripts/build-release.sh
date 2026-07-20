#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$repo_dir/scripts/build-ebpf.sh"
cargo build --manifest-path "$repo_dir/Cargo.toml" --release --locked
