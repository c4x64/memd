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
KO="${1:-}"

if [ -z "$KO" ]; then
    for c in ./rwbridge.ko ./kmod/rwbridge.ko ./dl/kmod/rwbridge.ko ./kmod_bin/rwbridge.ko; do
        if [ -f "$c" ]; then KO="$c"; break; fi
    done
fi

[ -n "$KO" ] && [ -f "$KO" ] || { echo "rwbridge.ko not found"; exit 1; }

if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    echo "rwbridge already loaded"
    exit 0
fi

echo "kernel: $(uname -r)"
echo "loading $KO"
insmod "$KO" || { echo "insmod failed"; exit 1; }

if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    echo "rwbridge loaded successfully"
else
    echo "rwbridge failed to load"
    exit 1
fi
