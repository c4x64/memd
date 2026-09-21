#!/system/bin/sh
# rwbridge run.sh — install the UNIVERSAL single-build .ko on any 5.10+ kernel.
#
# There is exactly one rwbridge.ko (no per-KMI matrix). Three things that
# used to be compile-time are resolved here, at runtime:
#   1. vermagic — the baked placeholder is patched in a temp copy to match
#      the running kernel (dmesg-feedback retry if extras differ), then
#      insmod runs clean (no --force, ever).
#   2. kernel layout data — per-kernel offsets (task_struct, mm_struct,
#      page-table geometry) travel in each E/Y op's arguments (explicit,
#      stateless; see README "Bring-up on a new kernel"). Nothing is
#      baked per-KMI and nothing is derived by blind sweeps.
#   3. diagnostics — printk candidates are surveyed (informational; the
#      module imports none), every risky action is journaled with
#      expectation + outcome to /sdcard/MemoryD/J*.log (sync-before-risk,
#      post-reboot forensics), and the session log is saved to
#      /sdcard/MemoryD/N.log (next free number). On CFI kernels the
#      journal + kernel-side surfaces ARE the log: custom params trap,
#      so they are never touched there.
#
# Requires root. Nothing persists (no boot scripts); worst case is one reboot.
# Layout: this script + rwbridge.ko side by side (CI artifact, /data/local/tmp).

MODNAME="rwbridge"
KO=""
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TMPKO="/data/local/tmp/rwbridge-run.ko"

log() { echo "[rwbridge] $1"; }
die() { echo "[rwbridge] ERROR: $1"; exit 1; }

# 0b. Op journal — the logging system that survives hostile kernels.
# Every risky action is recorded with timestamp + expectation + outcome,
# persisted incrementally (sync before anything that can reboot). On CFI
# kernels custom-param reads trap, so this journal plus kernel-side
# surfaces (coresize/initstate/int params/dmesg/uptime) ARE the log.
JDIR="/sdcard/MemoryD"
JFILE=""
jinit() {
    mkdir -p "$JDIR" 2>/dev/null
    _jn=0
    if [ -d "$JDIR" ]; then
        for _f in "$JDIR"/J*.log; do
            [ -f "$_f" ] || continue
            _b=$(basename "$_f" .log); _b=${_b#J}
            case "$_b" in ''|*[!0-9]*) continue ;; esac
            if [ "$_b" -ge "$_jn" ] 2>/dev/null; then _jn=$((_b + 1)); fi
        done
        JFILE="$JDIR/J$_jn.log"
    fi
}
jlog() {
    # $1=op $2=expect $3=outcome
    _line="$(date '+%T' 2>/dev/null) | $1 | expect: $2 | got: $3"
    echo "[rwbridge] $_line"
    if [ -n "$JFILE" ]; then
        echo "$_line" >> "$JFILE" 2>/dev/null
    fi
}
# jop records intent + syncs BEFORE the risky action (panic = no sync,
# so post-reboot forensics shows exactly what was attempted).
jop() { jlog "$1" "$2" "attempting"; sync 2>/dev/null; }
saferead() {
    # kernel-side or CFI-safe read only; never custom callbacks here
    cat "$1" 2>/dev/null || echo "(unreadable: $1)"
}
jinit

# 0. Already loaded — leave it alone.
if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    log "already loaded, skipping"
    exit 0
fi

# 1. Locate the universal .ko: explicit $1 wins, else side by side.
if [ -n "$1" ] && [ -f "$1" ]; then
    KO="$1"
else
    for c in "${SCRIPT_DIR}/rwbridge.ko" "${SCRIPT_DIR}/kmod_bin/rwbridge.ko"; do
        if [ -f "$c" ]; then KO="$c"; break; fi
    done
fi
[ -n "$KO" ] || die "rwbridge.ko not found (pass path as \$1 or place next to run.sh)"

KVER=$(uname -r)
log "kernel: $KVER"

# 2. CFI safety gate (/proc/config.gz present on GKI).
# Non-CFI kernels: always fine. CFI kernels: every kernel->module sysfs
# access and rmmod trap deterministically (each op reboots, not just the
# first); init is skipped by the loader. Without pstore the panic string
# is lost on reboot, so the config flag itself is the diagnosis.
CFI="unknown"
if [ -f /proc/config.gz ]; then
    if gzip -dc /proc/config.gz 2>/dev/null | grep -q "^CONFIG_CFI_CLANG=y"; then
        CFI="yes"
    else
        CFI="no"
    fi
fi
if [ "$CFI" = "yes" ]; then
    log "WARNING: CFI-enforcing kernel — every sysfs access reboots;"
    log "  this kernel needs a CFI build (source needs no change, flags only)."
    log "  Confirm via /proc/config.gz (dmesg does not survive reboot). Continuing in 3s..."
    sleep 3
else
    log "CFI: $CFI (proceeding)"
fi

# 3. Resolve the TARGET vermagic value.
# Priority: full vermagic from any on-device .ko (exact, incl. extras —
# read via locator+read_cstr since toybox `strings` misses some files).
TARGET_VM=""
for d in /vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules \
         /vendor/lib/modules/*/extra; do
    [ -d "$d" ] || continue
    for k in "$d"/*.ko; do
        [ -f "$k" ] || continue
        # Copy first: some tool domains cannot read /vendor directly
        # (cp works where od/dd/strings get EACCES).
        cp -f "$k" /data/local/tmp/rwref.ko 2>/dev/null || continue
        _vo=$(od -A d -t u1 -v /data/local/tmp/rwref.ko 2>/dev/null | awk '
        BEGIN { split("118 101 114 109 97 103 105 99 61", t, " "); found=0; pos=0 }
        {
            for (i = 2; i <= NF; i++) {
                a = $1 + i - 2; v = $i + 0
                w[pos % 9] = v; wa[pos % 9] = a; pos++
                if (!found && pos >= 9) {
                    ok = 1
                    for (k2 = 0; k2 < 9; k2++)
                        if (w[(pos - 9 + k2) % 9] != t[k2+1]) { ok = 0; break }
                    if (ok) { print wa[(pos - 9) % 9]; exit }
                }
            }
        }')
        [ -n "$_vo" ] || continue
        V=$(read_cstr /data/local/tmp/rwref.ko "$_vo" 2>/dev/null)
        case "$V" in
            vermagic=*) TARGET_VM="$V"; break 2;;
        esac
    done
done
rm -f /data/local/tmp/rwref.ko 2>/dev/null
# ... fallback: uname -r + GKI-standard extras.
if [ -z "$TARGET_VM" ]; then
    TARGET_VM="vermagic=${KVER} SMP preempt mod_unload aarch64"
    log "no on-device .ko for vermagic reference; using fallback"
fi
log "target: $TARGET_VM"

# 4. Patch a temp copy (binary-safe; python3 fast path, dd fallback).
cp -f "$KO" "$TMPKO" || die "cannot stage temp copy"
chmod 600 "$TMPKO"

# u64 LE field IO with builtins + one dd per op. Values must stay
# under 2^31 (true for every .ko offset/size here — files are < 1MB).
# r64le FILE OFFSET -> prints decimal. w64le FILE SEEK VALUE.
# Octal escapes are composed arithmetically ($(( )) is fork-free);
# a single builtin printf emits all 8 bytes (NULs included), one dd
# places them. No awk binary output, no $()-forks per byte.
r64le() {
    dd if="$1" bs=1 skip="$2" count=8 2>/dev/null | od -A n -t u1 -v 2>/dev/null | awk '{ v=0; m=1; for(i=1;i<=NF && i<=8;i++){ v+=$i*m; m*=256 } print v }'
}
w64le() {
    _wf="$1"; _ws="$2"; _wv=$3; _f=""; _k=0
    while [ $_k -lt 8 ]; do
        _b=$((_wv % 256)); _wv=$((_wv / 256))
        _f="$_f\\$((_b / 64))$(((_b / 8) % 8))$(($_b % 8))"
        _k=$((_k + 1))
    done
    printf "$_f" | dd of="$_wf" bs=1 seek="$_ws" conv=notrunc 2>/dev/null
}
# extend_vermagic KO V J WANT — splice a longer vermagic in by shifting
# the file tail and patching the section table + e_shoff. File offsets
# all stay under 2^31. Mirrors patchvm.py (byte-identical results).
extend_vermagic() {
    _eko="$1"; _ev="$2"; _ej="$3"; _ewant="$4"
    _ewant_len=$(printf '%s' "$_ewant" | wc -c)
    _delta=$((_ewant_len + 1 - (_ej - _ev + 1)))
    [ "$_delta" -gt 0 ] || { echo "extend called with no growth"; return 1; }
    _esh=$(r64le "$_eko" 40)
    _e2=$(dd if="$_eko" bs=1 skip=58 count=4 2>/dev/null | od -A n -t u1 -v 2>/dev/null | awk '{ print $1+$2*256+$3*65536+$4*16777216 }')
    _eentsz=$((_e2 % 65536)); _enum=$((_e2 / 65536))
    [ "$_eentsz" = "64" ] || { echo "bad shentsize $_eentsz"; return 1; }
    [ "$_enum" -gt 0 ] && [ "$_enum" -lt 100 ] || { echo "bad shnum $_enum"; return 1; }
    [ "$_esh" -gt "$_ev" ] || { echo "weird layout (shdr table before vermagic)"; return 1; }
    # Dump the whole table once: "idx off size" per section.
    _tbl=$(dd if="$_eko" bs=1 skip="$_esh" count=$((_enum * 64)) 2>/dev/null | od -A d -t u1 -v 2>/dev/null | awk -v n="$_enum" '
        { for (i=2; i<=NF; i++) b[m++]=$i }
        END {
            for (s=0; s<n; s++) {
                o=0; z=0
                for (k=0; k<8; k++) { o+=b[s*64+24+k]*pwr(k); z+=b[s*64+32+k]*pwr(k) }
                print s, o, z
            }
        }
        function pwr(k,  r,i) { r=1; for (i=0;i<k;i++) r*=256; return r }')
    [ -n "$_tbl" ] || { echo "cannot read section table"; return 1; }
    # Splice: head + want + NUL + tail.
    _tmpnew="$_eko.new"
    head -c "$_ev" "$_eko" > "$_tmpnew" 2>/dev/null || return 1
    printf '%s' "$_ewant" >> "$_tmpnew" 2>/dev/null || return 1
    printf '\000' >> "$_tmpnew" 2>/dev/null || return 1
    tail -c +$((_ej + 2)) "$_eko" >> "$_tmpnew" 2>/dev/null || return 1
    _nesh=$((_esh + _delta))
    # Patch e_shoff in ehdr + shifted sections. Containing section grows.
    # (Heredoc loop: stays in this shell so counters survive.)
    w64le "$_tmpnew" 40 "$_nesh" || return 1
    _ncontain=0; _wfail=0
    while read -r _si _off _sz; do
        if [ "$_off" -gt "$_ev" ]; then
            w64le "$_tmpnew" $((_nesh + _si * 64 + 24)) $(($_off + _delta)) || _wfail=1
        fi
        if [ "$_off" -le "$_ev" ] && [ "$_ev" -lt "$((_off + _sz))" ]; then
            _ncontain=$((_ncontain + 1)); _csi=$_si; _csz=$_sz
        fi
    done <<EOF_TBL
$_tbl
EOF_TBL
    [ "$_wfail" = "0" ] || { echo "section table patch failed"; return 1; }
    [ "$_ncontain" = "1" ] || { echo "containing-section ambiguity $_ncontain"; return 1; }
    w64le "$_tmpnew" $((_nesh + _csi * 64 + 32)) $(($_csz + _delta)) || return 1
    # Validate exactly like python: the want string appears exactly
    # once at V (read back through read_cstr, no `strings` involved).
    if [ "$(read_cstr "$_tmpnew" "$_ev" 2>/dev/null)" != "$_ewant" ]; then
        echo "extend validation failed"; return 1
    fi
    mv -f "$_tmpnew" "$_eko" 2>/dev/null || return 1
    echo "extended .modinfo by $_delta (signed-off-bytes match patchvm)"
    return 0
}

# read_cstr FILE OFFSET — print the NUL-terminated ASCII string there.
# (toybox `strings` is unreliable on some .ko files, so od/awk it:
# bytes -> octal escapes -> one builtin printf realizes them. No
# $()-forks per byte; NUL terminates by construction, never captured.)
read_cstr() {
    _esc=$(dd if="$1" bs=1 skip="$2" count=160 2>/dev/null | od -A n -t u1 -v 2>/dev/null | awk '
        { for (i=1; i<=NF; i++) {
              if ($i == 0) exit
              v=$i+0; d2=int(v/64); r=v-d2*64; d1=int(r/8); d0=r-d1*8
              printf "\\%d%d%d", d2, d1, d0
          } }')
    [ -n "$_esc" ] || return 1
    printf "$_esc"
}
patch_vermagic() {
    _ko="$1"; _want="$2"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$_ko" "$_want" <<'PYEOF'
import sys
ko, want = sys.argv[1], sys.argv[2].encode()
b = bytearray(open(ko, 'rb').read())
i = b.find(b'vermagic=')
assert i >= 0, "no vermagic in ko"
j = b.find(b'\x00', i)
have_len = j - i
want_b = want.encode() if isinstance(want, str) else want
assert len(want_b) <= have_len, "target vermagic longer than baked (%d > %d)" % (len(want_b), have_len)
b[i:i+len(want_b)] = want_b
for k in range(i+len(want_b), j): b[k] = 0
open(ko, 'wb').write(b)
print("patched %d bytes (field %d)" % (len(want_b), have_len))
PYEOF
        return $?
    fi
    # dd fallback (busybox/toybox-safe): locate offset + NUL terminator
    # with od (grep -abo is unreliable on binary files in toybox; tr
    # cannot handle NUL bytes portably). Streaming 9-byte window so
    # matches spanning od lines still hit. All arithmetic stays under
    # 2^31 (.ko files are < 1MB). All lengths include the "vermagic="
    # prefix on both sides.
    _loc=$(od -A d -t u1 -v "$_ko" 2>/dev/null | awk '
    BEGIN { split("118 101 114 109 97 103 105 99 61", t, " "); found=0; pos=0 }
    {
        for (i = 2; i <= NF; i++) {
            a = $1 + i - 2; v = $i + 0
            w[pos % 9] = v; wa[pos % 9] = a; pos++
            if (!found && pos >= 9) {
                ok = 1
                for (k = 0; k < 9; k++)
                    if (w[(pos - 9 + k) % 9] != t[k+1]) { ok = 0; break }
                if (ok) { V = wa[(pos - 9) % 9]; found = 1 }
            } else if (found && v == 0) { print V, a; exit }
        }
    }')
    [ -n "$_loc" ] || { echo "cannot locate vermagic"; return 1; }
    _off=${_loc%% *}; _end=${_loc##* }
    # _end is absolute (od -A d); field length excludING the NUL is
    # (_end - _off), +1 counting it. (A relative-offset bug here once
    # zeroed kilobytes past the field — this arithmetic is load-bearing.)
    _have=$((_end - _off + 1))
    _want_len=$(printf '%s' "$_want" | wc -c)
    if [ "$_want_len" -gt "$_have" ]; then
        # Baked field too short (UTS cap): ELF-extend .modinfo.
        extend_vermagic "$_ko" "$_off" "$_end" "$_want" || return 1
        return 0
    fi
    printf '%s' "$_want" | dd of="$_ko" bs=1 seek="$_off" conv=notrunc 2>/dev/null || return 1
    _pad=$((_have - _want_len))
    if [ "$_pad" -gt 0 ]; then
        dd if=/dev/zero of="$_ko" bs=1 seek=$((_off + _want_len)) count="$_pad" conv=notrunc 2>/dev/null || return 1
    fi
    echo "patched $_want_len bytes (field $_have)"
    return 0
}

patch_vermagic "$TMPKO" "$TARGET_VM" || die "vermagic patch failed"
log "vermagic patched"

# 5. Staged-trust flags (see README): stability soak first (load +
# idle, no scans), then read-only sessions, writes last. Plain kernel
# int params (no custom parse code on either side).
# NOTE: the kopts string channel is RETIRED (reads of module-arg memory
# wedge some loaders; the module answers -EPERM). RWBRIDGE_KOPTS is
# ignored with a warning; per-kernel layout data travels via E/Y op
# arguments (explicit, stateless), never via insmod.
INSMOD_OPTS=""
if [ -n "$RWBRIDGE_KOPTS" ]; then
    log "WARN: RWBRIDGE_KOPTS retired — layout data goes in E/Y op args now"
fi
# Bring-up modes (staged trust — see README): stability soak first
# (load + idle, no scans), then read-only sessions, writes last.
if [ -n "$RWBRIDGE_STABILITY" ]; then
    INSMOD_OPTS="${INSMOD_OPTS:+$INSMOD_OPTS }stability=1"
    log "stability soak requested"
fi
if [ -n "$RWBRIDGE_READONLY" ]; then
    INSMOD_OPTS="${INSMOD_OPTS:+$INSMOD_OPTS }readonly=1"
    log "read-only session requested"
fi
if [ -z "$INSMOD_OPTS" ]; then
    log "flags: none (full session)"
fi

# 6. Printk-family candidate search (informational).
# The module imports no printk-family symbol, so this never blocks loading;
# it only records what this kernel offers, for the log header.
printk_candidates() {
    grep -E ' (_printk|printk|printk_deferred|vprintk|printk_once)$' /proc/kallsyms 2>/dev/null \
        | awk '{print $3}' | sort -u | tr '\n' ' '
}
CANDS=$(printk_candidates)
if [ -z "$CANDS" ]; then
    CANDS="(none exported — module unaffected: zero-import logging)"
fi
log "printk candidates on this kernel: $CANDS"

# 7. Persist the session log: /sdcard/MemoryD/<next>.log where <next> is one
# past the highest existing numeric name (0.log first, then 1, 2, ...).
# Best-effort: an unwritable sdcard never fails the install.
dump_log() {
    _why="$1"
    _dir="/sdcard/MemoryD"
    mkdir -p "$_dir" 2>/dev/null
    _next=0
    if [ -d "$_dir" ]; then
        for _f in "$_dir"/*.log; do
            [ -f "$_f" ] || continue
            _b=$(basename "$_f" .log)
            case "$_b" in
                ''|*[!0-9]*) continue ;;
            esac
            if [ "$_b" -ge "$_next" ] 2>/dev/null; then
                _next=$((_b + 1))
            fi
        done
    fi
    LASTLOG="$_dir/$_next.log"
    {
        echo "=== rwbridge session log ($_why) ==="
        echo "date: $(date 2>/dev/null)"
        echo "kernel: $(uname -r)"
        echo "journal: $JFILE"
        echo "printk candidates: $CANDS"
        if [ "$CFI" = "yes" ]; then
            echo "--- CFI kernel: custom params (log/stage/status/out) SKIPPED (trap) ---"
            echo "--- safe surface ---"
            echo "coresize=$(saferead /sys/module/rwbridge/coresize)"
            echo "initstate=$(saferead /sys/module/rwbridge/initstate)"
            echo "stability=$(saferead /sys/module/rwbridge/parameters/stability)"
            echo "readonly=$(saferead /sys/module/rwbridge/parameters/readonly)"
            echo "uptime=$(cat /proc/uptime 2>/dev/null)"
            echo "kallsyms_syms=$(grep -c rwbridge /proc/kallsyms 2>/dev/null)"
        else
            echo "--- module log param ---"
            cat /sys/module/rwbridge/parameters/log 2>/dev/null || echo "(module not loaded)"
            echo "--- stage/status ---"
            echo "stage=$(cat /sys/module/rwbridge/parameters/stage 2>/dev/null)"
            echo "status=$(cat /sys/module/rwbridge/parameters/status 2>/dev/null)"
        fi
        echo "--- dmesg (rwbridge) ---"
        dmesg 2>/dev/null | grep -i rwbridge | tail -30
    } > "$LASTLOG" 2>/dev/null
    if [ -f "$LASTLOG" ]; then
        log "session log: $LASTLOG"
    else
        log "note: could not write $LASTLOG (sdcard unwritable?)"
        LASTLOG="(unwritten)"
    fi
}

# 7b. Dispatch-slot surgery (single-artifact fat behavior).
# A 5.10-built __this_module carries .init/.exit at +0x150/+0x300; 6.x
# kernels read them elsewhere (6.1: +0x140/+0x3D8) — without adaptation
# init is skipped (NULL) and rmmod jumps wild. Derive the target slots
# per-device from an on-device reference .ko (symbol-name matching, never
# hardcoded offsets): grow this_module if needed + rewrite the two relas.
# HARD GATES: CFI=yes → skip (dispatch would load-panic, worse than
# silent-Live); major!=6 → skip (5.x needs nothing); no python3/no
# reference → skip (silent-Live as today). Idempotent (no-op when matching).
maybe_surgery() {
    _ko="$1"
    _kmajor=$(uname -r 2>/dev/null | cut -d. -f1)
    if [ "$CFI" = "yes" ]; then
        jlog "surgery" "dispatch slots" "SKIPPED (CFI: dispatch would load-panic)"
        return 0
    fi
    if [ "$_kmajor" != "6" ]; then
        jlog "surgery" "dispatch slots" "SKIPPED (major $_kmajor needs nothing)"
        return 0
    fi
    command -v python3 >/dev/null 2>&1 || {
        jlog "surgery" "dispatch slots" "SKIPPED (no python3)"
        return 0
    }
    for _d in /vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules; do
        [ -d "$_d" ] || continue
        for _k in "$_d"/*.ko; do
            [ -f "$_k" ] || continue
            cp -f "$_k" /data/local/tmp/rwref.ko 2>/dev/null || continue
            _out=$(python3 - /data/local/tmp/rwref.ko "$_ko" <<'PYEOF' 2>&1
import struct, sys
ref, tgt = sys.argv[1], sys.argv[2]
def parse(fname):
    try: d = bytearray(open(fname, 'rb').read())
    except Exception: return None
    if d[:4] != b'\x7fELF': return None
    e_shoff, = struct.unpack_from('<Q', d, 0x28)
    e_shentsize, e_shnum = struct.unpack_from('<HH', d, 0x3A)
    shstr_idx, = struct.unpack_from('<H', d, 0x3E)
    ss_foff, = struct.unpack_from('<Q', d, e_shoff + shstr_idx*e_shentsize + 24)
    def secname(off): return d[ss_foff+off:].split(b'\x00')[0].decode()
    secs = {}
    for n in range(e_shnum):
        o = e_shoff + n*e_shentsize
        nm = secname(struct.unpack_from('<I', d, o)[0])
        _, st, _, _, so, ss = struct.unpack_from('<IIQQQQ', d, o)
        secs[nm] = (n, o, st, so, ss)
    sym = strt = None
    for nm, (n, o, st, so, ss) in secs.items():
        if st == 2: sym = (so, ss)
        if nm == '.strtab': strt = (so, ss)
    return {'d': d, 'e_shoff': e_shoff, 'e_shentsize': e_shentsize,
            'e_shnum': e_shnum, 'secs': secs, 'sym': sym, 'strt': strt}
def symname(p, idx):
    so, ss = p['sym']; sto, sts = p['strt']
    sn, = struct.unpack_from('<I', p['d'], so + idx*24)
    return p['d'][sto+sn:].split(b'\x00')[0].decode()
def slots(p):
    if '.rela.gnu.linkonce.this_module' not in p['secs']: return None
    n, o, st, so, ss = p['secs']['.rela.gnu.linkonce.this_module']
    out = {}
    for i in range(ss // 24):
        eo = so + i*24
        r_off, r_info = struct.unpack_from('<QQ', p['d'], eo)
        nm = symname(p, r_info >> 32)
        if nm in ('init_module', 'cleanup_module'): out[nm] = r_off
    return out if len(out) == 2 else None
rp = parse(ref)
sl = slots(rp) if rp else None
if sl is None:
    print('SKIP: no slot relas in reference')
    sys.exit(1)
p = parse(tgt)
cur = slots(p)
if cur is None:
    print('SKIP: target slots unreadable')
    sys.exit(1)
if cur == sl:
    print('SKIP: already matching (no-op)')
    sys.exit(1)
d = p['d']
n, o, st, so, ss = p['secs']['.gnu.linkonce.this_module']
GROW = 0x100
need = max(sl.values()) + 8
if need > ss:
    ins_at = so + ss
    d[ins_at:ins_at] = b'\x00' * GROW
    newoff = p['e_shoff'] + GROW
    struct.pack_into('<Q', d, 0x28, newoff)
    for m in range(p['e_shnum']):
        oo = newoff + m*p['e_shentsize']
        sso, sss = struct.unpack_from('<QQ', d, oo + 24)
        if sso >= ins_at and sss: struct.pack_into('<Q', d, oo + 24, sso + GROW)
        if m == n: struct.pack_into('<Q', d, oo + 32, sss + GROW)
    for nm2 in list(p['secs'].keys()):
        n2, _, st2, _, _ = p['secs'][nm2]
        oo2 = newoff + n2*p['e_shentsize']
        so2, ss2 = struct.unpack_from('<QQ', d, oo2 + 24)
        p['secs'][nm2] = (n2, oo2, st2, so2, ss2)
        if st2 == 2: p['sym'] = (so2, ss2)
        if nm2 == '.strtab': p['strt'] = (so2, ss2)
rn, ro, rst, rso, rss = p['secs']['.rela.gnu.linkonce.this_module']
for i in range(rss // 24):
    eo = rso + i*24
    r_off, r_info = struct.unpack_from('<QQ', d, eo)
    nm = symname(p, r_info >> 32)
    if nm in sl and r_off != sl[nm]: struct.pack_into('<Q', d, eo, sl[nm])
open(tgt, 'wb').write(bytes(d))
print('APPLIED init=%#x exit=%#x' % (sl['init_module'], sl['cleanup_module']))
PYEOF
)
            rm -f /data/local/tmp/rwref.ko 2>/dev/null
            case "$_out" in
                APPLIED*) jlog "surgery" "dispatch slots" "$_out"; return 0 ;;
                SKIP*) continue ;;
                *) continue ;;
            esac
        done
    done
    jlog "surgery" "dispatch slots" "SKIPPED (no usable reference .ko)"
    return 0
}

# 8. Load (never --force) + verify, with dmesg-feedback vermagic retry.
# If the kernel rejects our extras guess (e.g. it expects a `modversions`
# token we didn't bake), dmesg names the exact string it wants
# ("should be '...'") — re-patch the temp copy to that and retry once.
# This keeps vermagic fully runtime: no build matrix, no guessing.
try_insmod() {
    # sync first: if insmod panics the device, everything echoed so far
    # must already be on disk for post-reboot forensics (panic = no sync).
    sync 2>/dev/null
    # Dispatch-slot surgery (6.x, CFI-off only; no-op otherwise).
    maybe_surgery "$TMPKO"
    # shellcheck disable=SC2086
    eval insmod '"$TMPKO"' $INSMOD_OPTS 2>/dev/null
    return $?
}

jop "insmod" "rc=0, Live"
if ! try_insmod; then
    jlog "insmod" "rc=0, Live" "FAILED, entering dmesg-feedback retry"
    WANT=$(dmesg 2>/dev/null | grep -o "should be '[^']*'" | tail -1 | sed "s/^should be '//;s/'\$//")
    # dmesg prints the expected string WITHOUT the "vermagic=" tag, but the
    # patch offset points AT the tag — restore the prefix or the tag is
    # destroyed and the retry artifact is malformed (no vermagic at all).
    case "$WANT" in
        vermagic=*) ;;
        ?*) WANT="vermagic=$WANT" ;;
    esac
    if [ -n "$WANT" ]; then
        log "kernel wants different vermagic; re-patching and retrying once"
        log "want: $WANT"
        cp -f "$KO" "$TMPKO" || die "cannot re-stage temp copy"
        chmod 600 "$TMPKO"
        patch_vermagic "$TMPKO" "$WANT" || die "vermagic re-patch failed"
        if ! try_insmod; then
            dump_log "insmod-retry"
            die "insmod failed twice (see dmesg + $LASTLOG)"
        fi
    else
        dump_log "insmod"
        die "insmod failed (see dmesg + $LASTLOG)"
    fi
fi
rm -f "$TMPKO"
sleep 1
if [ "$CFI" = "yes" ]; then
    # Custom stage/status getters trap on CFI kernels — verify via the
    # kernel-side int param instead (proven readable+writable, zero
    # module-code execution).
    STAB=$(saferead /sys/module/rwbridge/parameters/stability)
    jlog "verify" "Live + readable int params" "initstate=$(saferead /sys/module/rwbridge/initstate) stability=$STAB"
    log "loaded (CFI: verified via kernel-side surface; custom params untouched)"
else
    STAGE=$(cat /sys/module/rwbridge/parameters/stage 2>/dev/null)
    jlog "verify" "stage readable" "stage=$STAGE"
    log "loaded; stage=$STAGE"
    if [ "$STAGE" != "ok" ]; then
        log "note: derivation did not complete"
        log "  fix: use explicit E/Y ops with this kernel's offset table (see README)"
    fi
fi

dump_log "install"
echo "[rwbridge] done"
