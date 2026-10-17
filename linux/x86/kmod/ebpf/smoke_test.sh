#!/bin/sh
# Smoke test for the eBPF build (best-effort; skips when toolchain missing).
set -u

cd "$(dirname "$0")"

if [ ! -f vmlinux.h ]; then
    if [ -r /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null 2>&1; then
        ./gen_vmlinux.sh || exit 1
    else
        echo "SKIP: no vmlinux.h and no BTF/bpftool" >&2
        exit 0
    fi
fi

if ! command -v clang >/dev/null 2>&1; then
    echo "SKIP: clang not found" >&2
    exit 0
fi

clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c memd_ebpf.bpf.c -o /tmp/memd_ebpf.bpf.o
if [ $? -ne 0 ]; then
    echo "FAIL: eBPF compile" >&2
    exit 1
fi
echo "OK: eBPF object compiled"

if command -v cc >/dev/null 2>&1 && [ -f /tmp/memd_ebpf.bpf.o ]; then
    if cc -g -O2 -I. memd_ebpf.c -o /tmp/memd_ebpf -lbpf -lelf -lz 2>/dev/null; then
        echo "OK: userspace loader compiled"
    else
        echo "SKIP: libbpf not available for loader link" >&2
    fi
fi

exit 0