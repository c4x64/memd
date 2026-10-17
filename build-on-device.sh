#!/bin/sh
# build-on-device.sh — compile rwbridge against the running kernel's headers.
# Used as a fallback when a prebuilt artifact (SPX) cannot load.
# Requires root, kernel headers, and a working C toolchain.
# Not stable on all devices; some OEMs strip kernel build info from the device.
set -eu

MODNAME="rwbridge"
KVER="$(uname -r)"
KDIR=""
for cand in \
    "/lib/modules/${KVER}/build" \
    "/data/local/tmp/linux-headers-${KVER}" \
    "/sdcard/linux-headers-${KVER}" \
    "${PREFIX}/lib/modules/${KVER}/build" \
    "/system/lib/modules/${KVER}/build"; do
    if [ -d "$cand" ] && [ -f "$cand/Makefile" ]; then KDIR="$cand"; break; fi
done

if [ -z "$KDIR" ]; then
    # Try BTF: many Android 5.10+ kernels expose /sys/kernel/btf/vmlinux
    if [ -r /sys/kernel/btf/vmlinux ] && command -v bpftool >/dev/null 2>&1; then
        echo "BTF found; generating vmlinux.h from running kernel..."
        BTFSRC="/sys/kernel/btf/vmlinux"
        BTFOUT="$(pwd)/vmlinux.h"
        if bpftool btf dump file "$BTFSRC" format c > "$BTFOUT" 2>/dev/null; then
            echo "Generated $BTFOUT from BTF."
            # Use the generated header as a minimal "kernel tree"
            KDIR="$(pwd)/btf-tree"
            rm -rf "$KDIR"
            mkdir -p "$KDIR/include"
            cp "$BTFOUT" "$KDIR/include/vmlinux.h"
            # Minimal Makefile for external module build
            cat > "$KDIR/Makefile" <<'EOF'
obj-m := rwbridge.o
KDIR ?= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean
EOF
            # Note: we still need a real KDIR for kbuild; BTF gives types but not build system
            # Fall through to real KDIR requirement below
        else
            echo "bpftool dump failed."
        fi
    fi

    if [ -z "$KDIR" ]; then
        for cand in \
            "/lib/modules/${KVER}/build" \
            "/data/local/tmp/linux-headers-${KVER}" \
            "/sdcard/linux-headers-${KVER}" \
            "${PREFIX}/lib/modules/${KVER}/build" \
            "/system/lib/modules/${KVER}/build"; do
            if [ -d "$cand" ] && [ -f "$cand/Makefile" ]; then KDIR="$cand"; break; fi
        done
    fi

    if [ -z "$KDIR" ]; then
        echo "Kernel headers not found for ${KVER}."
        if [ -r /proc/config.gz ]; then
            echo "Kernel config is available, but headers/build tree are missing."
        else
            echo "No /proc/config.gz either; OEM stripped kernel build info."
        fi
        if [ -r /sys/kernel/btf/vmlinux ]; then
            echo "BTF exists at /sys/kernel/btf/vmlinux — consider eBPF instead of .ko modules."
        fi
        echo "Stock Android DKMS is generally not supported."
        echo "Use a custom kernel/NetHunter or install headers in /data/local/tmp/linux-headers-${KVER}."
        exit 1
    fi
fi

# Toolchain detection (gcc preferred, clang fallback).
if command -v gcc >/dev/null 2>&1; then
    CC="gcc"
elif command -v clang >/dev/null 2>&1; then
    CC="clang"
else
    echo "No C compiler found (install gcc/clang or Termux toolchain)."
    exit 1
fi
if command -v ccache >/dev/null 2>&1; then
    CC="ccache $CC"
fi

echo "============================================================"
echo " Building rwbridge for ${KVER}"
echo " DO NOT touch or shut down this device while building."
echo "============================================================"

cd "$(dirname "$0")/kmod"
make clean >/dev/null 2>&1 || true
# Keep the build polite: do not saturate the CPU on low-power devices.
NPROC=$(nproc 2>/dev/null || echo 1)
JOBS=$(( NPROC / 2 ))
[ "$JOBS" -lt 1 ] && JOBS=1
nice -n 19 make -j"$JOBS" CC="$CC" KDIR="$KDIR" KMI="on-device" modules

if [ -f rwbridge.ko ]; then
    echo "Build succeeded: $(pwd)/rwbridge.ko"
else
    echo "Build failed"
    exit 1
fi
