#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
binary_path=${FLOWTOP_BINARY:-"$repo_dir/target/release/flowtop"}
object_path=${FLOWTOP_EBPF_OBJECT:-"$repo_dir/target/release/flowtop-ebpf.o"}

if [ "$(uname -s)" != "Linux" ]; then
    printf '%s\n' "error: the eBPF smoke test requires Linux" >&2
    exit 1
fi
if [ ! -x "$binary_path" ]; then
    printf '%s\n' "error: flowtop binary not found or not executable: $binary_path" >&2
    exit 1
fi
if [ ! -f "$object_path" ]; then
    printf '%s\n' "error: eBPF object not found: $object_path" >&2
    exit 1
fi

printf '%s\n' "eBPF smoke test: kernel=$(uname -r) binary=$binary_path object=$object_path"
FLOWTOP_EBPF_OBJECT="$object_path" "$binary_path" \
    --backend ebpf \
    --strict \
    --no-ui \
    --interval 100ms \
    --duration 500ms \
    >/dev/null
printf '%s\n' "eBPF load/attach smoke test passed"
