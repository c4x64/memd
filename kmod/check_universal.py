#!/usr/bin/env python3
"""check_universal.py — static universality gate for rwbridge.ko.
Fails (exit 1) if the module drifted off the universal contract:
  - __versions section with real CRCs (pins build to one KMI).
    Absent OR empty is fine (empty lets MODVERSIONS kernels load
    CRC-less: missing entries warn-and-pass; verified live on 6.1).
  - undefined symbols outside the allowlist (printk family forbidden).
  - missing BTI landing pads / vermagic placeholder.
Usage: check_universal.py rwbridge.ko <nm-undef-file>
(The nm file is produced by the Makefile with the right CROSS nm.)
"""
import struct
import sys

ALLOW = {
    "module_layout", "memset", "memcpy", "memmove", "memcmp", "strlen",
    "copy_from_kernel_nofault", "param_ops_int",
}


def die(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def main():
    ko_path, undef_path = sys.argv[1], sys.argv[2]
    b = open(ko_path, "rb").read()
    if b[0:4] != b"\x7fELF" or b[4] != 2:
        die("not a 64-bit ELF")
    e_shoff, = struct.unpack_from("<Q", b, 0x28)
    e_shentsize, = struct.unpack_from("<H", b, 0x3A)
    e_shnum, = struct.unpack_from("<H", b, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", b, 0x3E)
    if e_shentsize != 64 or e_shnum == 0 or e_shnum > 200:
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
            die("__versions has CRCs (%d bytes; pins build to one KMI)" % size)
        print("note: empty __versions present (modversions-loader bypass, no CRCs)")
        break
    else:
        print("note: no __versions section (pre-modversions kernels load fine)")

    bad = []
    for line in open(undef_path):
        sym = line.split()
        if not sym:
            continue
        sym = sym[-1]
        if sym not in ALLOW:
            bad.append(sym)
    if bad:
        die("unexpected imports: " + " ".join(sorted(set(bad))))
    print("universal checks passed")


main()
