#!/system/bin/sh
# verify VA->PA + /proc/pid/mem return matching data
# reads offset 0x20 from the shell binary

TOOL=/data/local/tmp/memtool
MYPID=$$

echo "target: PID $MYPID (/system/bin/sh)"
echo ""

# 1. Read via auto path (offset command)
echo "=== 1. offset 0x20 via auto path ==="
$TOOL offset $MYPID sh 0x20 64 2>&1
echo ""

# 2. Extract VA from JSON
JSON=$($TOOL --json offset $MYPID sh 0x20 16 2>/dev/null)
VA=$(echo "$JSON" | awk -F'"base_addr":"' '{split($2,a,"\""); print a[1]}')
echo "=== 2. extracted VA: $VA ==="
echo ""

# 3. Read same VA directly via /proc/pid/mem
echo "=== 3. read VA directly ==="
$TOOL read $MYPID $VA 64 2>&1
echo ""

# 4. VA->PA translation
echo "=== 4. VA->PA pagemap ==="
$TOOL va2pa $MYPID $VA 2>&1

echo ""
echo "---"
echo "Match means both paths read identical data at offset 0x20."
