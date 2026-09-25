#!/usr/bin/env python3
"""check_universal.py — per-KMI static gate for rwbridge.ko.
Fails (exit 1) if the module drifted off the matrix contract:
  - __versions section with real CRCs (pins build past its KMI; the
    runtime vermagic patch cannot fix CRC mismatches).
  - undefined symbols NOT exported by that KMI generation's own
   System.map (exact ground truth: the donor tree the artifact was
   built against).
  - missing vermagic placeholder (runtime patch needs it).
BTI pads are checked inline by the Makefile, not here.
Usage: check_universal.py rwbridge.ko <nm-undef-file> <KMI> <System.map>
"""
import re
import struct
import sys


def die(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def main():
    ko_path, undef_path, kmi, sysmap_path = sys.argv[1:5]
    b = open(ko_path, 'rb').read()
    if b[0:4] != b"\x7fELF" or b[4] != 2:
        die("not a 64-bit ELF")
    e_shoff, = struct.unpack_from("<Q", b, 0x28)
    e_shentsize, = struct.unpack_from("<H", b, 0x3A)
    e_shnum, = struct.unpack_from("<H", b, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", b, 0x3E)
    if e_shentsize != 64 or e_shnum == 0 or e_shnum > 400:
        die("unexpected section table shape")
    s = e_shoff + e_shstrndx * 64
    st_off, = struct.unpack_from("<Q", b, s + 24)

    def secname(off):
        j = b.find(b"\x00", st_off + off)
        return b[st_off + off:j].decode()

    for si in range(e_shnum):
        base = e_shoff + si * 64
        if secname(struct.unpack_from("<I", b, base)[0]) != "__versions":
            continue
        size = struct.unpack_from("<Q", b, base + 32)[0]
        if size != 0:
            die("__versions has CRCs (%d bytes; pins build past %s)" % (size, kmi))
        print("note: empty __versions present (no CRCs)")
        break
    else:
        print("note: no __versions section")

    exported = set()
    for line in open(sysmap_path, errors="replace"):
        m = re.match(r"^[0-9a-fA-F]+ [A-Za-z] (\S+)", line)
        if m:
            exported.add(m.group(1))
    if not exported:
        die("empty System.map?")
    # vermagic placeholder must fit the longest real targets: UTS part
    # (after 'vermagic=' up to first space) needs room (~55+ chars).
    # Baked short + runtime-long target = unpatchable = NO-GO at install.
    i = b.find(b'vermagic=')
    if i < 0:
        die("no vermagic string")
    j = b.find(b' ', i)
    uts = b[i + 9:j if j > 0 else i + 200]
    if len(uts) < 55:
        die("vermagic UTS too short (%d chars; need >= 55 for target room)" % len(uts))
    print("vermagic room: %d chars" % len(uts))

    kmi = sys.argv[3] if len(sys.argv) > 3 else ""
    bad = []
    cfi_bad = []
    for line in open(undef_path):
        sym = line.split()
        if not sym:
            continue
        sym = sym[-1].split('.')[0]
        if sym not in exported:
            bad.append(sym)
    if bad:
        die("imports missing from %s System.map: %s" % (kmi, " ".join(sorted(set(bad)))))
    # All 8 artifacts (incl. -dbg, identical code to plain) must be free
    # of CFI/ubsan imports: DDK CFI instrumentation must have been
    # neutralized above or the module cannot load on non-enforcing
    # kernels. Enforcing kernels are handled at runtime (cfi_bypass).
    for line in open(undef_path):
        sym = line.split()
        if not sym:
            continue
        sym = sym[-1].split('.')[0]
        if 'cfi' in sym.lower() or 'ubsan' in sym.lower():
            cfi_bad.append(sym)
    if cfi_bad:
        die("CFI imports in artifact: " + " ".join(sorted(set(cfi_bad))))
    print("KMI %s checks passed" % kmi)


main()
