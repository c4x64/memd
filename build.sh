#!/bin/bash
set -e

TOOLCHAIN=/Users/prabhas/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64
CC=$TOOLCHAIN/bin/aarch64-linux-android34-clang

echo "=== debugd_unsafe (syscall-mode fallback daemon) ==="
$CC -static -O2 -s -o /tmp/debugd_unsafe memd_us.c
echo "  $(wc -c < /tmp/debugd_unsafe) bytes"

echo "=== memtool (process memory inspector) ==="
$CC -static -O2 -s -o /tmp/memtool memd_dump.c
echo "  $(wc -c < /tmp/memtool) bytes"

echo ""
echo "=== Kernel module (memd_kern.ko) ==="
echo "  ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- \\"
echo "      make -C <kernel-tree> M=\$(pwd) modules"
