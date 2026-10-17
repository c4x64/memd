#!/bin/sh
# rwbridge run-linux.sh — minimal loader for standard (non-Android) Linux.
#
# Unlike run.sh (Android: vermagic patching, /data/local/tmp staging,
# CFI bypass notes for GKI), a normal Linux build is compiled against
# the running kernel's own headers, so no vermagic rewrite is needed.
# This script only stages, insmods, and verifies the module.
#
# Requires root. Usage: ./run-linux.sh [path/to/rwbridge.ko]

set -eu

MODNAME="rwbridge"
STAGE_DIR="${TMPDIR:-/tmp}"
CACHE="$STAGE_DIR/rwbridge-cached.ko"
KO="${1:-}"

# DKMS/on-device build is the primary method: build once, cache the
# resulting module, and reuse the cache on subsequent runs.
if [ -z "$KO" ]; then
    if [ ! -f "$CACHE" ]; then
        echo "No cached module; building for $(uname -r)"
        echo "DO NOT touch or shut down this device while building."
        _here=$(cd "$(dirname "$0")" && pwd)
        if [ -x "$_here/build-on-device.sh" ]; then
            "$_here/build-on-device.sh" || { echo "On-device build failed"; exit 1; }
            for c in "$_here/kmod/rwbridge.ko" "$_here/rwbridge.ko"; do
                if [ -f "$c" ]; then cp -f "$c" "$CACHE"; break; fi
            done
        else
            echo "No on-device build helper available"
            exit 1
        fi
    fi
    KO="$CACHE"
fi

[ -n "$KO" ] && [ -f "$KO" ] || { echo "rwbridge.ko not found"; exit 1; }

if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    echo "rwbridge already loaded"
    exit 0
fi

echo "kernel: $(uname -r)"
echo "loading $KO"
if ! insmod "$KO"; then
    echo "Prebuilt module failed to load; attempting on-device build."
    echo "DO NOT touch or shut down this device while building."
    _here=$(cd "$(dirname "$0")" && pwd)
    if [ -x "$_here/build-on-device.sh" ]; then
        "$_here/build-on-device.sh" || { echo "On-device build failed"; exit 1; }
        KO="$_here/kmod/rwbridge.ko"
        [ -f "$KO" ] || { echo "Built module not found"; exit 1; }
        insmod "$KO" || { echo "insmod failed after on-device build"; exit 1; }
    else
        echo "No on-device build helper available"
        exit 1
    fi
fi

if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    echo "rwbridge loaded successfully"
else
    echo "rwbridge failed to load"
    exit 1
fi
