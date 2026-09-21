#!/bin/sh
# probe-patch.sh — loader-contract probes via transplant patching.
#
# Builds no code and needs no kernel tree: takes a CI-built rwbridge.ko,
# locates init_module/cleanup_module with nm, and rewrites the first 8
# bytes of the chosen entry to a canonical probe body. Binutils only
# (CROSS_COMPILE prefix env, e.g. aarch64-linux-gnu- or the NDK llvm-;
# defaults to unprefixed nm/readelf/objdump on PATH).
#
# Probes (evidence use):
#   spin-init     init = yield + branch-to-self. insmod HANGS => init ran.
#                 Instant Live => init skipped (loader never calls it).
#   nonzero-init  init = mov w0,#-1 + ret. Load FAILS => init ran and its
#                 return propagated. Live anyway => init skipped/ignored.
#   trivial-init  init = mov w0,#0 + ret. Splits icall-vs-body: Live load
#                 proves the init call path works; later op deaths are then
#                 body/caller-path, not entry.
#   trivial-exit  exit = mov w0,#0 + ret. rmmod SURVIVES => exit call path
#                 clean (earlier rmmod death was the body). Reboot anyway
#                 => the exit call path itself traps.
#
# Usage: probe-patch.sh <input.ko> <probe> <output.ko>
# Verified against: 6.1.23-android14-4 GKI (init skipped there — see README
# "Loader-contract map"). Offsets are resolved per-file via nm: never
# hardcode entry addresses, they move every build.
set -e

NM="${CROSS_COMPILE}nm"
READELF="${CROSS_COMPILE}readelf"
OBJDUMP="${CROSS_COMPILE}objdump"

die() { echo "probe-patch: $*" >&2; exit 1; }

[ $# -eq 3 ] || die "usage: $0 <input.ko> <probe> <output.ko>"
IN="$1"; PROBE="$2"; OUT="$3"
[ -f "$IN" ] || die "no such file: $IN"

case "$PROBE" in
  spin-init|nonzero-init|trivial-init) SYM="init_module" ;;
  trivial-exit) SYM="cleanup_module" ;;
  *) die "unknown probe '$PROBE' (want spin-init|nonzero-init|trivial-init|trivial-exit)" ;;
esac

# Entry vaddr from symtab (T init_module/cleanup_module must exist).
VADDR_HEX=$($NM "$IN" 2>/dev/null | awk -v s="$SYM" '$3==s && $2=="T" {print $1; exit}')
[ -n "$VADDR_HEX" ] || die "symbol '$SYM' (T) not found in $IN"

# .text file offset (readelf -S prints "[Nr] Name ..." so Name is $3, Off $6).
TEXT_OFF_HEX=$($READELF -S "$IN" 2>/dev/null | awk '$3==".text" {print $6; exit}')
[ -n "$TEXT_OFF_HEX" ] || die ".text section not found in $IN"

# 8-byte LE bodies (aarch64).
case "$PROBE" in
  spin-init)    BODY_HEX="3f2003d5ffff1f17" ;;  # yield ; b .-4
  nonzero-init) BODY_HEX="00008012c0035fd6" ;;  # mov w0,#-1 ; ret
  trivial-init|trivial-exit) BODY_HEX="000080d2c0035fd6" ;;  # mov w0,#0 ; ret
esac

cp "$IN" "$OUT"
python3 - "$OUT" "$TEXT_OFF_HEX" "$VADDR_HEX" "$BODY_HEX" <<'EOF'
import sys
path, text_off, vaddr, body = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16), bytes.fromhex(sys.argv[4])
d = bytearray(open(path, 'rb').read())
off = text_off + vaddr
assert off + 8 <= len(d), "entry outside file"
d[off:off + 8] = body
open(path, 'wb').write(bytes(d))
print("patched %s @file+%#x (%d bytes)" % (path, off, len(d)))
EOF

echo "-- verify ($SYM head):"
$OBJDUMP -d --disassemble-symbols="$SYM" "$OUT" 2>/dev/null | head -8
