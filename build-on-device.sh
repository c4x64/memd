#!/bin/sh
# build-on-device.sh — compile rwbridge against the running kernel's headers.
# Used as a fallback when a prebuilt artifact (SPX) cannot load.
# Requires root, kernel headers, and a working C toolchain.

set -eu

MODNAME="rwbridge"
KVER="$(uname -r)"
KDIR="/lib/modules/${KVER}/build"

if [ ! -d "$KDIR" ]; then
    echo "Kernel headers not found at $KDIR"
    echo "Install headers for ${KVER} (e.g. linux-headers-${KVER}) and retry."
    exit 1
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
nice -n 19 make -j"$JOBS" KDIR="$KDIR" KMI="on-device" modules

if [ -f rwbridge.ko ]; then
    echo "Build succeeded: $(pwd)/rwbridge.ko"
else
    echo "Build failed"
    exit 1
fi
