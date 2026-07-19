#!/system/bin/sh
# test.sh — find libil2cpp, VA→PA, read via /dev/memd
# Usage: sh test.sh <pid> <offset>

PID=$1
OFF=$2
TOOL=/data/local/tmp/memtool

if [ -z "$PID" ] || [ -z "$OFF" ]; then
  echo "Usage: $0 <pid> <offset>"
  exit 1
fi

# Step 1 — find libil2cpp r-xp base from /proc/$PID/maps
LINE=$($TOOL maps $PID 2>/dev/null | grep "libil2cpp" | grep "r-xp" | head -1)
if [ -z "$LINE" ]; then
  echo "error: libil2cpp not found in pid $PID"
  exit 1
fi
BASE_HEX=$(echo "$LINE" | awk '{split($1,a,"-"); print a[1]}')
echo "libil2cpp.so  base: 0x$BASE_HEX"

# Step 2 — VA = base + offset (use awk for hex math)
VA=$(awk -v b="$BASE_HEX" -v o="$OFF" 'BEGIN { printf "0x%x", ("0x" b) + o }')
echo "offset: 0x$OFF  →  VA: $VA"

# Step 3 — VA→PA via pagemap
echo ""
echo "--- VA→PA ---"
PA_LINE=$($TOOL va2pa $PID $VA 2>/dev/null)
echo "$PA_LINE"

# Try to extract PA from JSON output for machine parsing
PA_JSON=$($TOOL --json va2pa $PID $VA 2>/dev/null)
PADDR=$(echo "$PA_JSON" | awk -F'"paddr":"' '{if(NF>1){split($2,a,"\""); print a[1]}}')

if [ -z "$PADDR" ]; then
  echo "error: page not present (QEMU guest?)"
  exit 1
fi

# Step 4 — read from physical address via /dev/memd
echo ""
echo "--- /dev/memd phys read ---"
$TOOL phys $PADDR 64 2>&1
