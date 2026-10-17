#!/bin/sh
# rwbridge run-linux.sh — generic Linux loader with prebuilt runtime patching.
#
# Primary load path for prebuilts on same-major kernels: take a prebuilt
# .ko (cached, bundled, or user-supplied), patch it at runtime for the
# running kernel, and insmod it. Patching covers:
#   1. vermagic rewrite            (UTS release + extras)
#   2. CRC (modversions) fixup     (__versions section, per-symbol CRCs
#                                  from the running kernel's Module.symvers)
#   3. ASLR slide relocation       (KASLR slide applied to absolute
#                                  RELA addends / kernel-range addresses)
#   4. symbol import resolution    (undefined imports resolved against
#                                  /proc/kallsyms, converted to absolute
#                                  relocs so non-exported symbols work)
# Same major.minor as the running kernel is required for patching; on a
# major mismatch (or any patch/load failure) we fall back to the existing
# on-device build path, preserving prior behaviour.
#
# Requires root. Usage: ./run-linux.sh [path/to/rwbridge.ko]

set -u

MODNAME="rwbridge"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
STAGE_DIR="${TMPDIR:-/tmp}"
CACHE="$STAGE_DIR/rwbridge-cached.ko"
KO="${1:-}"
KVER=$(uname -r 2>/dev/null || echo unknown)

# Journal (survives hostile kernels, mirrors run.sh).
JDIR="/tmp/MemoryD"
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
    _line="$(date '+%T' 2>/dev/null) | $1 | expect: $2 | got: $3"
    echo "[rwbridge] $_line"
    if [ -n "$JFILE" ]; then echo "$_line" >> "$JFILE" 2>/dev/null; fi
}
jop() { jlog "$1" "$2" "attempting"; sync 2>/dev/null; }
jinit

# kptr_restrict lowering for /proc/kallsyms readability.
if [ -f /proc/sys/kernel/kptr_restrict ]; then
    echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
fi

dump_log() {
    echo "[rwbridge] --- dmesg (tail) ---"
    dmesg 2>/dev/null | tail -20
}

validate_elf() {
    # $1 = path; returns 0 if sane ELF64 module
    python3 - "$1" <<'PYEOF'
import sys, struct
p = sys.argv[1]
try:
    b = open(p, 'rb').read()
except OSError:
    print("validate: cannot read"); sys.exit(1)
if len(b) < 64 or b[:4] != b'\x7fELF' or b[4] != 2 or b[5] != 1:
    print("validate: bad ELF header"); sys.exit(1)
e_shoff = struct.unpack_from('<Q', b, 40)[0]
e_shnum = struct.unpack_from('<H', b, 60)[0]
e_shentsize = struct.unpack_from('<H', b, 58)[0]
if e_shentsize != 64 or e_shnum == 0 or e_shnum > 4096:
    print("validate: bad section table"); sys.exit(1)
if e_shoff + e_shnum * 64 > len(b):
    print("validate: section table out of range"); sys.exit(1)
# check vermagic present
i = b.find(b'vermagic=')
if i < 0:
    print("validate: no vermagic"); sys.exit(1)
j = b.find(b'\x00', i)
if j < 0:
    print("validate: unterminated vermagic"); sys.exit(1)
print("validate: ok (sections=%d, vermagic=%s)" % (e_shnum, b[i:j].decode('ascii','replace')))
sys.exit(0)
PYEOF
}

ko_major_minor() {
    python3 - "$1" <<'PYEOF'
import sys
p = sys.argv[1]
try:
    b = open(p, 'rb').read()
except OSError:
    print(""); sys.exit(0)
i = b.find(b'vermagic=')
if i < 0:
    print(""); sys.exit(0)
j = b.find(b'\x00', i)
if j < 0:
    print(""); sys.exit(0)
v = b[i:j].decode('ascii', 'replace')
m = v.split('=', 1)[1].split()[0] if '=' in v else ''
parts = m.split('.')
print(parts[0] + '.' + parts[1] if len(parts) >= 2 else m)
PYEOF
}

print_env_diagnostics() {
    log "kernel: $KVER (major.minor=$RUN_MM)"
    log "arch: $(uname -m 2>/dev/null)"
    log "modules dir: $(ls -d /lib/modules/$(uname -r) 2>/dev/null || echo missing)"
    if [ -r /proc/config.gz ]; then
        if gzip -dc /proc/config.gz 2>/dev/null | grep -q "^CONFIG_MODVERSIONS=y"; then
            log "CONFIG_MODVERSIONS=y (CRCs enforced)"
        else
            log "CONFIG_MODVERSIONS not set (CRCs not enforced)"
        fi
    else
        log "no /proc/config.gz (config unknown)"
    fi
    if [ -r /proc/kallsyms ]; then
        _n=$(wc -l < /proc/kallsyms 2>/dev/null)
        log "/proc/kallsyms: $_n symbols"
    else
        log "/proc/kallsyms unreadable"
    fi
}
print_env_diagnostics

# ---------------------------------------------------------------------------
# Additional diagnostics / helpers for robust loading
# ---------------------------------------------------------------------------
resolve_symbol_table() {
    python3 - <<'PYEOF2'
import os
names = ["printk", "_printk", "filp_open", "kernel_read", "filp_close",
         "kallsyms_lookup_name", "module_layout", "_text", "stext",
         "access_process_vm", "find_vma"]
ks = {}
try:
    with open('/proc/kallsyms') as f:
        for line in f:
            p = line.split()
            if len(p) >= 3:
                try:
                    a = int(p[0], 16)
                except ValueError:
                    continue
                if a and p[2] not in ks:
                    ks[p[2]] = a
except OSError:
    pass
print("[rwbridge] symbol resolution table:")
for n in names:
    if n in ks:
        print("[rwbridge]   %-24s = 0x%x" % (n, ks[n]))
    else:
        print("[rwbridge]   %-24s = UNRESOLVED" % n)
if '_text' in ks:
    slide = ks['_text'] - 0xffffff8008000000
    print("[rwbridge]   estimated KASLR slide = 0x%x" % (slide & 0xffffffffffffffff))
PYEOF2
}
resolve_symbol_table

find_kernel_symvers() {
    for cand in         "/lib/modules/$KVER/build/Module.symvers"         "/lib/modules/$KVER/Module.symvers"         "/usr/src/linux-headers-$KVER/Module.symvers"         "/usr/src/linux-$KVER/Module.symvers"         "/data/local/tmp/Module.symvers"; do
        if [ -f "$cand" ]; then
            echo "$cand"
            return 0
        fi
    done
    for g in /lib/modules/*/build/Module.symvers; do
        [ -f "$g" ] && { echo "$g"; return 0; }
    done
    return 1
}
SV=$(find_kernel_symvers 2>/dev/null)
if [ -n "$SV" ]; then
    log "Module.symvers: $SV ($(wc -l < "$SV" 2>/dev/null) entries)"
else
    log "Module.symvers not found; CRC fixup will be best-effort"
fi

verify_load() {
    _t="${1:-5}"
    _i=0
    while [ "$_i" -lt "$_t" ]; do
        if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
            return 0
        fi
        sleep 1 2>/dev/null
        _i=$((_i + 1))
    done
    return 1
}

fallback_modprobe() {
    if command -v modprobe >/dev/null 2>&1; then
        log "trying modprobe $MODNAME"
        modprobe "$MODNAME" 2>/dev/null && return 0
    fi
    return 1
}

_arch=$(uname -m 2>/dev/null)
case "$_arch" in
    aarch64|arm64) ;;
    *)
        log "WARNING: architecture $_arch is not the supported arm64 target; loading may fail"
        ;;
esac

log() { echo "[rwbridge] $*"; }
die() { echo "[rwbridge] ERROR: $*"; exit 1; }

RUN_MM=$(echo "$KVER" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')

# ---------------------------------------------------------------------------
# patch_prebuilt: run all four runtime patches on $1 -> $2. Returns 0 on
# success. Implemented in Python (stdlib only) so it runs on any device
# with python3.
# ---------------------------------------------------------------------------
patch_prebuilt() {
    _in="$1"; _out="$2"
    python3 - "$_in" "$_out" "$KVER" <<'PYEOF'
import os, sys, struct, glob, re

def fail(msg):
    print("patch: " + msg, file=sys.stderr)
    sys.exit(1)

in_path, out_path, kver = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    raw = open(in_path, 'rb').read()
except OSError as e:
    fail("cannot read %s: %s" % (in_path, e))
data = bytearray(raw)

# ---- ELF64 LE validation ----
if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
    fail("not an ELF64 little-endian file")
e_shoff = struct.unpack_from('<Q', data, 40)[0]
e_shentsize = struct.unpack_from('<H', data, 58)[0]
e_shnum = struct.unpack_from('<H', data, 60)[0]
e_shstrndx = struct.unpack_from('<H', data, 62)[0]
if e_shentsize != 64 or e_shnum == 0 or e_shnum > 4096:
    fail("bad section header table")

def shdr(i):
    off = e_shoff + i * e_shentsize
    return struct.unpack_from('<IIQQQQIIQQ', data, off)

shstr = shdr(e_shstrndx)
shstr_off, shstr_sz = shstr[4], shstr[5]

def secname(i):
    nm = shdr(i)[0]
    end = data.find(b'\x00', shstr_off + nm)
    if end < 0:
        end = shstr_off + shstr_sz
    return data[shstr_off + nm:end].decode('ascii', 'replace')

sec_index = {}
for i in range(e_shnum):
    sec_index[secname(i)] = i

def sec_bytes(name):
    if name not in sec_index:
        return None
    s = shdr(sec_index[name])
    off, sz = s[4], s[5]
    if off + sz > len(data):
        return None
    return bytearray(data[off:off + sz]), off, sz

# ---- kallsyms parse ----
kallsyms = {}
try:
    with open('/proc/kallsyms', 'r', errors='replace') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if addr == 0:
                continue
            typ = parts[1]
            name = parts[2]
            if typ in ('T', 't', 'W', 'w', 'R', 'r', 'D', 'd', 'B', 'b'):
                if name not in kallsyms:
                    kallsyms[name] = addr
except OSError:
    pass

# ---- reference vermagic from device ----
def find_ref_vermagic():
    candidates = []
    for root in ('/lib/modules', '/usr/lib/modules', '/vendor/lib/modules'):
        if not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            for fn in files:
                if fn.endswith('.ko'):
                    candidates.append(os.path.join(dirpath, fn))
    for p in candidates:
        try:
            b = open(p, 'rb').read()
        except OSError:
            continue
        i = b.find(b'vermagic=')
        if i < 0:
            continue
        j = b.find(b'\x00', i)
        if j < 0:
            continue
        v = b[i:j].decode('ascii', 'replace')
        if v.startswith('vermagic='):
            return v
    return None

ref_vm = find_ref_vermagic()
if ref_vm is not None:
    # replace the leading version token with the running kernel's
    want_vm = re.sub(r'^vermagic=\S+', 'vermagic=' + kver, ref_vm)
else:
    want_vm = "vermagic=%s SMP preempt mod_unload aarch64" % kver

# ---- vermagic patch (in-place or ELF-extend) ----
i = data.find(b'vermagic=')
if i < 0:
    fail("no vermagic field in module")
j = data.find(b'\x00', i)
if j < 0:
    fail("unterminated vermagic field")
have_len = j - i  # excludes NUL
want_b = want_vm.encode('ascii', 'replace')
# ensure vermagic= prefix present
if not want_b.startswith(b'vermagic='):
    want_b = b'vermagic=' + want_b

def extend_vermagic(data, i, j, want_b):
    # returns new bytearray or None on failure
    want_len = len(want_b)
    have_len2 = j - i
    if want_len <= have_len2:
        return None  # no extend needed
    delta = want_len - have_len2
    # section table location
    esh = struct.unpack_from('<Q', data, 40)[0]
    eh = struct.unpack_from('<HH', data, 58)[0]  # shentsize, shnum? actually 58: shentsize H, shnum H
    # read both
    shentsize = struct.unpack_from('<H', data, 58)[0]
    shnum = struct.unpack_from('<H', data, 60)[0]
    if shentsize != 64:
        return None
    if not (0 < shnum < 1000):
        return None
    if not (esh > i):
        return None
    # read section table offsets/sizes
    tbl = []
    for s in range(shnum):
        base = esh + s * 64
        off = struct.unpack_from('<Q', data, base + 24)[0]
        sz = struct.unpack_from('<Q', data, base + 32)[0]
        tbl.append((s, off, sz))
    # splice
    new = bytearray()
    new += data[:i]
    new += want_b
    new += b'\x00'
    new += data[j + 1:]
    nesh = esh + delta
    # patch e_shoff
    struct.pack_into('<Q', new, 40, nesh)
    # patch sections
    wfail = False
    ncontain = 0
    csi = -1
    csz = 0
    for (s, off, sz) in tbl:
        if off > i:
            struct.pack_into('<Q', new, nesh + s * 64 + 24, off + delta)
        if off <= i < off + sz:
            ncontain += 1
            csi = s
            csz = sz
    if ncontain != 1:
        return None
    struct.pack_into('<Q', new, nesh + csi * 64 + 32, csz + delta)
    # validate
    off2 = new.find(want_b, i)
    if off2 != i:
        return None
    # check read-back through NUL
    endn = new.find(b'\x00', i)
    if new[i:endn] != want_b:
        return None
    return new

if len(want_b) <= have_len:
    data[i:i + len(want_b)] = want_b
    for k in range(i + len(want_b), j):
        data[k] = 0
else:
    newdata = extend_vermagic(data, i, j, want_b)
    if newdata is None:
        fail("vermagic field too short and ELF-extend failed")
    data = newdata
    # recompute shdr context not needed; sections already patched in new data
print("vermagic patched -> %s" % want_vm, file=sys.stderr)

# ---- CRC (modversions) fixup ----
# find Module.symvers
symvers_paths = []
kver2 = kver
for cand in (
    "/lib/modules/%s/build/Module.symvers" % kver2,
    "/lib/modules/%s/Module.symvers" % kver2,
    "/usr/src/linux-headers-%s/Module.symvers" % kver2,
    "/usr/src/linux-%s/Module.symvers" % kver2,
    "/data/local/tmp/Module.symvers",
    "Module.symvers",
):
    if os.path.isfile(cand):
        symvers_paths.append(cand)
# glob fallback
for g in glob.glob("/lib/modules/*/build/Module.symvers"):
    if g not in symvers_paths:
        symvers_paths.append(g)

crc_map = {}
for sp in symvers_paths:
    try:
        with open(sp, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                cols = line.split()
                # format: CRC symbol module [exporttype] (crc may be 0x..)
                if len(cols) < 2:
                    continue
                crcstr = cols[0]
                sym = cols[1]
                try:
                    crc = int(crcstr, 16) if crcstr.lower().startswith('0x') else int(crcstr, 16)
                except ValueError:
                    try:
                        crc = int(crcstr, 10)
                    except ValueError:
                        continue
                if sym not in crc_map:
                    crc_map[sym] = crc
    except OSError:
        continue

# __versions section: array of {crc:unsigned long, name:char[MODULE_NAME_LEN]}
# MODULE_NAME_LEN is 56 on 64-bit? struct modversion_info size 64 (8+56).
MODVER_ENTRY = 64
MODVER_NAMELEN = 56
versions_name = "__versions"
if versions_name in sec_index and crc_map:
    off, sz = sec_bytes(versions_name)[1], None
    # sec_bytes returns (bytearray, off, sz)? we defined returns bytearray,off,sz
    res = sec_bytes(versions_name)
    if res is not None:
        vbytes, voff, vsz = res
        nentries = vsz // MODVER_ENTRY
        fixed = 0
        for e in range(nentries):
            base = voff + e * MODVER_ENTRY
            # crc at base (8 bytes LE)
            name_off = base + 8
            name_raw = data[name_off:name_off + MODVER_NAMELEN]
            nul = name_raw.find(b'\x00')
            if nul < 0:
                nul = MODVER_NAMELEN
            name = name_raw[:nul].decode('ascii', 'replace')
            if not name:
                continue
            if name in crc_map:
                struct.pack_into('<Q', data, base, crc_map[name])
                fixed += 1
        print("crc fixup: updated %d/%d entries from %s" % (fixed, nentries, symvers_paths[:1]), file=sys.stderr)

# ---- ASLR slide relocation ----
# compute slide from _text
slide = 0
if '_text' in kallsyms:
    # common aarch64 kernel text base
    DEFAULT_BASE = 0xffffff8008000000
    slide = kallsyms['_text'] - DEFAULT_BASE
elif 'stext' in kallsyms:
    slide = kallsyms['stext'] - 0xffffff8008000000

# RELA sections
rela_sections = [nm for nm in sec_index if nm.startswith('.rela')]
abs_types = (257, 258, 1)  # R_AARCH64_ABS64, ABS32, and generic ABS? keep 257/258
# We'll handle R_AARCH64_ABS64 (257) primarily.
for rname in rela_sections:
    res = sec_bytes(rname)
    if res is None:
        continue
    rbytes, roff, rsz = res
    entsize = shdr(sec_index[rname])[9]
    if entsize == 0:
        entsize = 24
    nrel = rsz // entsize
    # find linked section? not needed
    for e in range(nrel):
        pos = roff + e * entsize
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, pos)
        rtype = r_info & 0xffffffff
        symidx = r_info >> 32
        # absolute reloc types on aarch64
        if rtype in (257, 258) and symidx == 0:
            # absolute: apply slide to addend if in kernel range
            if slide != 0 and r_addend >= 0xffffff8000000000:
                r_addend = r_addend + slide
                struct.pack_into('<QQq', data, pos, r_offset, r_info, r_addend)
        # symbol import resolution handled below

# ---- symbol import resolution against kallsyms ----
# need symtab + strtab
symtab_name = None
for cand in ('.symtab', '.dynsym'):
    if cand in sec_index:
        symtab_name = cand
        break

strtab_name = None
if symtab_name:
    s = shdr(sec_index[symtab_name])
    link = s[6]
    # link is strtab section index
    strtab_name = secname(link)

resolved = 0
if symtab_name and strtab_name:
    sym_off, sym_sz = sec_bytes(symtab_name)[1], sec_bytes(symtab_name)[2]
    # sec_bytes returns (bytearray, off, sz)
    s_bytes, s_off, s_sz = sec_bytes(symtab_name)
    str_bytes, str_off, str_sz = sec_bytes(strtab_name)
    nsym = s_sz // 24
    # map sym index -> name
    def sym_name(idx):
        if idx >= nsym:
            return ''
        soff = s_off + idx * 24
        st_name = struct.unpack_from('<I', data, soff)[0]
        if st_name == 0:
            return ''
        end = data.find(b'\x00', str_off + st_name)
        if end < 0:
            end = str_off + str_sz
        return data[str_off + st_name:end].decode('ascii', 'replace')
    # STN_ABS = 0
    for rname in rela_sections:
        res = sec_bytes(rname)
        if res is None:
            continue
        rbytes, roff, rsz = res
        entsize = shdr(sec_index[rname])[9]
        if entsize == 0:
            entsize = 24
        nrel = rsz // entsize
        for e in range(nrel):
            pos = roff + e * entsize
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, pos)
            rtype = r_info & 0xffffffff
            symidx = r_info >> 32
            if symidx == 0:
                continue
            name = sym_name(symidx)
            if not name:
                continue
            # check if undefined symbol: st_shndx == 0
            soff = s_off + symidx * 24
            st_shndx = struct.unpack_from('<H', data, soff + 6)[0]  # st_shndx at offset 6 in sym (after name I, info B, other B)
            # struct sym: st_name I(4), st_info B, st_other B, st_shndx H, st_value Q, st_size Q -> shndx at 6
            if st_shndx != 0:
                continue
            if name not in kallsyms:
                continue
            # convert to absolute
            addr = kallsyms[name]
            new_info = (0 << 32) | rtype
            new_addend = r_addend + addr
            struct.pack_into('<QQq', data, pos, r_offset, new_info, new_addend)
            resolved += 1
    print("symbol import resolution: resolved %d undefined imports via /proc/kallsyms" % resolved, file=sys.stderr)

# write output
try:
    open(out_path, 'wb').write(data)
except OSError as e:
    fail("cannot write %s: %s" % (out_path, e))
print("patched: %s -> %s" % (in_path, out_path), file=sys.stderr)
sys.exit(0)
PYEOF
    return $?
}


# ---------------------------------------------------------------------------
# candidate prebuilts: same major.minor as running kernel
# ---------------------------------------------------------------------------
find_prebuilt_candidates() {
    # explicit arg already handled by caller; search common locations
    for c in \
        "$CACHE" \
        "$STAGE_DIR/rwbridge-cached.ko" \
        "$STAGE_DIR/rwbridge-prebuilt.ko" \
        "$SCRIPT_DIR/rwbridge-prebuilt.ko" \
        "$SCRIPT_DIR/rwbridge-universal.ko" \
        "$SCRIPT_DIR/rwbridge.ko" \
        "$SCRIPT_DIR/kmod/rwbridge.ko" \
        "$SCRIPT_DIR/kmod/rwbridge-universal.ko" \
        "$SCRIPT_DIR/dl/kmod/rwbridge.ko" \
        "$SCRIPT_DIR/dl/kmod/rwbridge-universal.ko" \
        "$SCRIPT_DIR/kmod_bin/rwbridge.ko" \
        "$SCRIPT_DIR/kmod_bin/rwbridge-universal.ko"; do
        [ -f "$c" ] && printf '%s\n' "$c"
    done
    # any *.ko in script dir (dedup handled by caller via set)
    for c in "$SCRIPT_DIR"/*.ko "$SCRIPT_DIR"/kmod/*.ko "$SCRIPT_DIR"/dl/kmod/*.ko "$SCRIPT_DIR"/kmod_bin/*.ko; do
        [ -f "$c" ] && printf '%s\n' "$c"
    done
    # cached modules from previous runs
    for c in /tmp/rwbridge*.ko /var/tmp/rwbridge*.ko; do
        [ -f "$c" ] && printf '%s\n' "$c"
    done
}

# ---------------------------------------------------------------------------
# already loaded?
# ---------------------------------------------------------------------------
if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    log "already loaded, skipping"
    exit 0
fi

# ---------------------------------------------------------------------------
# Primary path: prebuilt .ko patched for same-major kernel
# ---------------------------------------------------------------------------
LOADED=0
for cand in $(find_prebuilt_candidates); do
    [ -f "$cand" ] || continue
    cm=$(ko_major_minor "$cand")
    # accept if unknown (cannot determine) or same major.minor
    if [ -n "$cm" ] && [ "$cm" != "$RUN_MM" ]; then
        log "prebuilt $cand major $cm != running $RUN_MM; skipping (mismatch kept as-is)"
        continue
    fi
    log "trying prebuilt (same-major): $cand"
    tmp="$STAGE_DIR/rwbridge-prebuilt-run.ko"
    rm -f "$tmp"
    if patch_prebuilt "$cand" "$tmp" "$KVER"; then
        if [ -f "$tmp" ]; then
            jop "insmod" "rc=0"
            if insmod "$tmp" 2>/dev/null; then
                LOADED=1
                rm -f "$tmp"
                break
            fi
            jlog "insmod" "rc=0" "FAILED, dmesg-feedback retry"
            WANT=$(dmesg 2>/dev/null | sed -n "s/.*should be '\([^']*\)'.*/\1/p" | tail -1)
            case "$WANT" in
                vermagic=*) ;;
                ?*) WANT="vermagic=$WANT" ;;
            esac
            if [ -n "$WANT" ]; then
                log "kernel wants different vermagic; re-patching and retrying once"
                cp -f "$cand" "$tmp" 2>/dev/null
                # re-run full patch with a hint: patch vermagic field directly
                python3 - "$tmp" "$WANT" <<'PYEOF'
import sys
p, want = sys.argv[1], sys.argv[2]
b = bytearray(open(p,'rb').read())
i = b.find(b'vermagic=')
if i >= 0:
    j = b.find(b'\x00', i)
    if j >= 0:
        wb = want.encode()
        if len(wb) <= j - i:
            b[i:i+len(wb)] = wb
            for k in range(i+len(wb), j):
                b[k] = 0
            open(p,'wb').write(b)
PYEOF
                if insmod "$tmp" 2>/dev/null; then
                    LOADED=1
                    rm -f "$tmp"
                    break
                fi
            fi
            log "insmod failed for patched prebuilt $cand; trying next"
            rm -f "$tmp"
        fi
    else
        log "patch failed for $cand; trying next"
        rm -f "$tmp"
    fi
done

if [ "$LOADED" = "1" ]; then
    if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
        jlog "verify" "modules present" "Live"
        log "loaded prebuilt successfully"
        # socket proto probe
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "
import socket
for fam in range(12, 28):
    try:
        s = socket.socket(fam, socket.SOCK_SEQPACKET); s.close(); continue
    except OSError as e:
        if e.errno != 126: continue
    try:
        s = socket.socket(fam, socket.SOCK_RAW); s.close()
        print('proto-live fam=%d' % fam); raise SystemExit(0)
    except OSError:
        continue
raise SystemExit(1)
" 2>/dev/null && log "proto serving" || log "proto check inconclusive"
        fi
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# Fallback: existing on-device build path (preserved for mismatch / failure)
# ---------------------------------------------------------------------------
log "prebuilt path did not load; falling back to on-device build"
if [ -z "$KO" ]; then
    if [ ! -f "$CACHE" ]; then
        log "No cached module; building for $KVER"
        log "DO NOT touch or shut down this device while building."
        if [ -x "$SCRIPT_DIR/build-on-device.sh" ]; then
            "$SCRIPT_DIR/build-on-device.sh" || { log "On-device build failed"; exit 1; }
            for c in "$SCRIPT_DIR/kmod/rwbridge.ko" "$SCRIPT_DIR/rwbridge.ko"; do
                if [ -f "$c" ]; then cp -f "$c" "$CACHE"; break; fi
            done
        else
            log "No on-device build helper available"
            exit 1
        fi
    fi
    KO="$CACHE"
fi

[ -n "$KO" ] && [ -f "$KO" ] || { log "rwbridge.ko not found"; exit 1; }

if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    log "rwbridge already loaded"
    exit 0
fi

log "kernel: $KVER"
log "loading $KO"
if ! insmod "$KO"; then
    log "Prebuilt module failed to load; attempting on-device build."
    log "DO NOT touch or shut down this device while building."
    if [ -x "$SCRIPT_DIR/build-on-device.sh" ]; then
        "$SCRIPT_DIR/build-on-device.sh" || { log "On-device build failed"; exit 1; }
        KO="$SCRIPT_DIR/kmod/rwbridge.ko"
        [ -f "$KO" ] || { log "Built module not found"; exit 1; }
        insmod "$KO" || { log "insmod failed after on-device build"; exit 1; }
    else
        log "No on-device build helper available"
        exit 1
    fi
fi

if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    log "rwbridge loaded successfully"
    exit 0
else
    log "rwbridge failed to load"
    exit 1
fi

# ---------------------------------------------------------------------------
# Additional robustness helpers (appended)
# ---------------------------------------------------------------------------
ensure_stage_dir() {
    if [ ! -d "$STAGE_DIR" ]; then
        mkdir -p "$STAGE_DIR" 2>/dev/null || STAGE_DIR="/tmp"
    fi
    if [ ! -w "$STAGE_DIR" ]; then
        STAGE_DIR="/tmp"
        mkdir -p "$STAGE_DIR" 2>/dev/null
    fi
    log "stage dir: $STAGE_DIR"
}
ensure_stage_dir

check_kernel_compatibility() {
    _ok=1
    if [ ! -r /proc/modules ]; then
        log "compat: /proc/modules unreadable"
        _ok=0
    fi
    if [ ! -r /proc/kallsyms ]; then
        log "compat: /proc/kallsyms unreadable (symbol features degraded)"
    fi
    case "$(uname -m 2>/dev/null)" in
        aarch64|arm64) ;;
        *) log "compat: non-arm64 host (best-effort only)" ;;
    esac
    case "$KVER" in
        [0-9]*.[0-9]*.[0-9]*) ;;
        *) log "compat: unparseable uname -r ($KVER)"; _ok=0 ;;
    esac
    if [ "$_ok" = "1" ]; then
        log "compat: basic checks passed"
    else
        log "compat: basic checks FAILED"
    fi
    return 0
}
check_kernel_compatibility

print_loaded_rwbridge() {
    if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
        _info=$(grep "^${MODNAME} " /proc/modules 2>/dev/null)
        log "loaded: $_info"
    else
        log "not loaded"
    fi
}

cleanup_stage() {
    for f in "$STAGE_DIR"/rwbridge-prebuilt-run.ko \
             "$STAGE_DIR"/rwbridge-run.ko; do
        [ -f "$f" ] && rm -f "$f" 2>/dev/null
    done
}
trap cleanup_stage EXIT HUP INT TERM

validate_patched_or_die() {
    # $1 = path
    if ! validate_elf "$1" >/dev/null 2>&1; then
        log "patched module failed ELF validation: $1"
        validate_elf "$1" || true
        return 1
    fi
    return 0
}

# Re-run validation on any staged module before load (best-effort).
for _c in "$STAGE_DIR"/rwbridge-prebuilt-run.ko; do
    [ -f "$_c" ] || continue
    validate_patched_or_die "$_c" || true
done

# Final summary
log "run-linux.sh: flow complete (kernel=$KVER, major=$RUN_MM)"

verify_socket_proto() {
    # Probe the driver's socket protocol family. Returns 0 if live.
    if ! command -v python3 >/dev/null 2>&1; then
        return 0
    fi
    python3 -c "
import socket
for fam in range(12, 28):
    try:
        s = socket.socket(fam, socket.SOCK_SEQPACKET)
        s.close()
        continue
    except OSError as e:
        if e.errno != 126:
            continue
    try:
        s = socket.socket(fam, socket.SOCK_RAW)
        s.close()
        print('proto-live fam=%d' % fam)
        raise SystemExit(0)
    except OSError:
        continue
raise SystemExit(1)
" 2>/dev/null
}

post_load_bootstrap() {
    # Deliver filp_open/kernel_read/filp_close addresses to the driver.
    if ! command -v python3 >/dev/null 2>&1; then
        return 0
    fi
    if ! verify_socket_proto >/dev/null 2>&1; then
        return 0
    fi
    python3 -c "
import socket, fcntl, struct
addrs = {}
try:
    with open('/proc/kallsyms', errors='replace') as f:
        for line in f:
            p = line.split()
            if len(p) == 3 and p[1] in 'TtWw' and p[2] in ('filp_open','kernel_read','filp_close'):
                addrs[p[2]] = int(p[0], 16)
except OSError:
    pass
if not all(addrs.get(k) for k in ('filp_open','kernel_read','filp_close')):
    raise SystemExit(2)
fam = None
for cand in range(12, 28):
    try:
        s = socket.socket(cand, socket.SOCK_SEQPACKET); s.close(); continue
    except OSError as e:
        if e.errno != 126: continue
    try:
        s = socket.socket(cand, socket.SOCK_RAW); fam = cand; break
    except OSError:
        continue
if fam is None:
    raise SystemExit(3)
NR, SZ, TYPE = 40, 32, ord('W')
IOC = 0xC0000000 | (SZ << 16) | (TYPE << 8) | NR
buf = bytearray(struct.pack('<QQQi4x', addrs['filp_open'], addrs['kernel_read'], addrs['filp_close'], 0))
s = socket.socket(fam, socket.SOCK_RAW)
fcntl.ioctl(s.fileno(), IOC, buf)
res = struct.unpack_from('<i', buf, 24)[0]
s.close()
print('bootstrap-rc=%d' % res)
raise SystemExit(0 if res == 0 else 4)
" 2>/dev/null
}

retry_load_sequence() {
    # Generic retry wrapper: try insmod on a patched copy up to N times.
    _ko="$1"; _n="${2:-3}"; _i=0
    while [ "$_i" -lt "$_n" ]; do
        _tmp="$STAGE_DIR/rwbridge-retry-$_i.ko"
        cp -f "$_ko" "$_tmp" 2>/dev/null || return 1
        patch_prebuilt "$_tmp" "$_tmp" "$KVER" >/dev/null 2>&1 || true
        if insmod "$_tmp" 2>/dev/null; then
            rm -f "$_tmp"
            return 0
        fi
        rm -f "$_tmp"
        _i=$((_i + 1))
        sleep 1 2>/dev/null
    done
    return 1
}

# If loaded, run bootstrap (best-effort, never fatal).
if grep -q "^${MODNAME} " /proc/modules 2>/dev/null; then
    post_load_bootstrap >/dev/null 2>&1 || true
    print_loaded_rwbridge
fi

# Extra candidate discovery: scan /data/local/tmp for any .ko.
for _c in /data/local/tmp/*.ko; do
    [ -f "$_c" ] || continue
    _cm=$(ko_major_minor "$_c")
    if [ -z "$_cm" ] || [ "$_cm" = "$RUN_MM" ]; then
        log "extra candidate: $_c (major=$_cm)"
    fi
done

log "run-linux.sh: post-load phase done"

# Final verification summary
log "verification: modules entry = $(grep -c "^${MODNAME} " /proc/modules 2>/dev/null)"
log "verification: kallsyms entries = $(wc -l < /proc/kallsyms 2>/dev/null)"
log "run-linux.sh completed"

# end of run-linux.sh
log "exit"

# Helper: print sha256 of a file if available
file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" 2>/dev/null
    else
        echo "sha256 unavailable"
    fi
}

# Helper: size in bytes
file_size() {
    if [ -f "$1" ]; then
        wc -c < "$1" 2>/dev/null
    else
        echo 0
    fi
}
