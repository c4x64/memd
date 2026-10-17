#!/bin/sh
# ExampleModule: basic MEMD interaction via shell.
# Requires root and a loaded rwbridge module.

echo "=== MEMD Example (Shell) ==="

# Check if module is loaded
if ! grep -q "^rwbridge " /proc/modules 2>/dev/null; then
    echo "rwbridge module not loaded. Loading..."
    if [ -f /data/local/tmp/rwbridge.ko ]; then
        insmod /data/local/tmp/rwbridge.ko 2>&1 && echo "Loaded." || echo "Load failed."
    else
        echo "No rwbridge.ko found in /data/local/tmp/"
        exit 1
    fi
else
    echo "rwbridge already loaded."
fi

# Show module info
echo "--- Module info ---"
cat /sys/module/rwbridge/version 2>/dev/null || echo "(no version file)"
cat /sys/module/rwbridge/coresize 2>/dev/null | xargs -I{} echo "coresize: {} bytes"

# Show kernel version
echo "--- Kernel ---"
uname -r

# Demonstrate kptr_restrict handling
echo "--- kptr_restrict ---"
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "(not available)"

echo "=== Example complete ==="
# branch-ExampleModule/example.sh[∂]