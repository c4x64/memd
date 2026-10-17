#!/bin/sh
# Build the eBPF object and userspace loader.
set -eu

ARCH="${ARCH:-arm64}"
# Map common arch names to BPF arch define.
case "$ARCH" in
    aarch64|arm64) BPF_ARCH="arm64" ;;
    x86_64|amd64)  BPF_ARCH="x86" ;;
    *)              BPF_ARCH="$ARCH" ;;
esac

if [ ! -f vmlinux.h ]; then
    if [ -r /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null 2>&1; then
        ./gen_vmlinux.sh
    else
        echo "vmlinux.h missing and BTF/bpftool unavailable" >&2
        exit 1
    fi
fi

CC="${CC:-clang}"
CLANG="${CLANG:-clang}"

echo "Compiling eBPF program..."
"$CLANG" -g -O2 -target bpf \
    -D__TARGET_ARCH_${BPF_ARCH} \
    -I. \
    -c memd_ebpf.bpf.c \
    -o memd_ebpf.bpf.o

echo "Compiling userspace loader..."
"$CC" -g -O2 -I. \
    memd_ebpf.c \
    -o memd_ebpf \
    -lbpf -lelf -lz

echo "Built memd_ebpf.bpf.o and memd_ebpf"