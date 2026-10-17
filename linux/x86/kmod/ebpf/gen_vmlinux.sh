#!/bin/sh
# Generate vmlinux.h from the running kernel's BTF.
set -eu

SRC="${1:-/sys/kernel/btf/vmlinux}"
OUT="${2:-vmlinux.h}"

if [ ! -r "$SRC" ]; then
    echo "BTF source not readable: $SRC" >&2
    exit 1
fi
if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool is required to dump BTF" >&2
    exit 1
fi

bpftool btf dump file "$SRC" format c > "$OUT"
echo "Generated $OUT from $SRC"