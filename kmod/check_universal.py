#!/usr/bin/env python3
"""check_universal.py — per-KMI static gate for rwbridge.ko.
Fails (exit 1) if the module drifted off the matrix contract:
  - __versions section missing or empty (per-symbol CRCs are REQUIRED:
    kernels without CONFIG_MODULE_FORCE_LOAD refuse version-less
    modules with a silent -ENOEXEC no override flag can bypass —
    proven on 6.1 ranchu. Same-KMI kernels share CRCs by GKI contract,
    so intact versions load clean with the runtime-patched vermagic).
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
    if len(sys.argv) != 5:
        die("usage: check_universal.py <ko> <undef> <KMI> <System.map>")
    ko_path, undef_path, kmi, sysmap_path = sys.argv[1:5]
    try:
        b = open(ko_path, 'rb').read()
    except OSError as e:
        die("cannot read %s: %s" % (ko_path, e))
    if b[0:4] != b"\x7fELF" or b[4] != 2:
        die("not a 64-bit ELF")
    try:
        e_shoff, = struct.unpack_from("<Q", b, 0x28)
        e_shentsize, = struct.unpack_from("<H", b, 0x3A)
        e_shnum, = struct.unpack_from("<H", b, 0x3C)
        e_shstrndx, = struct.unpack_from("<H", b, 0x3E)
    except struct.error:
        die("truncated ELF header")
    if e_shentsize != 64 or e_shnum == 0 or e_shnum > 400:
        die("unexpected section table shape")
    if e_shstrndx >= e_shnum:
        die("bad e_shstrndx (%d >= shnum %d)" % (e_shstrndx, e_shnum))
    if e_shoff <= 0 or e_shoff + e_shnum * 64 > len(b):
        die("section table out of range")
    s = e_shoff + e_shstrndx * 64
    if s + 64 > len(b):
        die("shstr section header out of range")
    st_off, = struct.unpack_from("<Q", b, s + 24)
    st_size, = struct.unpack_from("<Q", b, s + 32)
    if st_off <= 0 or st_off + st_size > len(b):
        die("shstrtab out of range")

    def secname(off):
        start = st_off + off
        if start < 0 or start >= len(b):
            die("section name offset out of range")
        j = b.find(b"\x00", start)
        if j < 0 or j > st_off + st_size:
            die("unterminated section name")
        try:
            return b[start:j].decode()
        except UnicodeDecodeError:
            die("bad section name encoding")

    for si in range(e_shnum):
        base = e_shoff + si * 64
        if secname(struct.unpack_from("<I", b, base)[0]) != "__versions":
            continue
        size = struct.unpack_from("<Q", b, base + 32)[0]
        if size == 0:
            die("__versions is empty (no CRCs: no-FORCE_LOAD kernels "
                "refuse with silent -ENOEXEC)")
        print("note: __versions present with CRCs (%d bytes)" % size)
        break
    else:
        die("no __versions section (no-FORCE_LOAD kernels refuse)")

    exported = set()
    try:
        sysmap_lines = open(sysmap_path, errors="replace").read().splitlines()
    except OSError as e:
        die("cannot read %s: %s" % (sysmap_path, e))
    for line in sysmap_lines:
        m = re.match(r"^[0-9a-fA-F]+ [A-Za-z] (\S+)", line)
        if m:
            exported.add(m.group(1))
    if not exported:
        die("empty System.map?")
    # NOTE: a _printk baseline-map requirement used to live here. It is
    # gone: all logging routes through runtime-resolved vprintk, so no
    # printk-family import exists anywhere (zero _printk/printk undefs
    # verified per artifact).
    # vermagic placeholder must fit the longest real targets: UTS part
    # (after 'vermagic=' up to first space) needs room (~55+ chars).
    # Baked short + runtime-long target = unpatchable = NO-GO at install.
    i = b.find(b'vermagic=')
    if i < 0:
        die("no vermagic string")
    k = b.find(b'\x00', i)
    if k < 0:
        die("unterminated vermagic string")
    j = b.find(b' ', i)
    if j < 0 or j > k:
        j = k
    uts = b[i + 9:j].split(b'\x00')[0]
    if len(uts) < 55:
        die("vermagic UTS too short (%d chars; need >= 55 for target room)" % len(uts))
    print("vermagic room: %d chars" % len(uts))

    kmi = sys.argv[3] if len(sys.argv) > 3 else ""
    try:
        undef_lines = open(undef_path, errors="replace").read().splitlines()
    except OSError as e:
        die("cannot read %s: %s" % (undef_path, e))
    if not any(l.split() for l in undef_lines):
        die("empty undef file (nm produced no symbols?)")
    bad = []
    cfi_bad = []
    for line in undef_lines:
        sym = line.split()
        if not sym:
            continue
        sym = sym[-1].split('.')[0]
        if sym not in exported:
            bad.append(sym)
    if bad:
        die("imports missing from %s System.map: %s" % (kmi, " ".join(sorted(set(bad)))))
    # All shipped artifacts (incl. -dbg, identical code to plain) must be free
    # of CFI/ubsan imports: DDK CFI instrumentation must have been
    # neutralized above or the module cannot load on non-enforcing
    # kernels. Enforcing kernels are handled at runtime (cfi_bypass).
    for line in undef_lines:
        sym = line.split()
        if not sym:
            continue
        sym = sym[-1].split('.')[0]
        if 'cfi' in sym.lower() or 'ubsan' in sym.lower():
            cfi_bad.append(sym)
    if cfi_bad:
        die("CFI imports in artifact: " + " ".join(sorted(set(cfi_bad))))
    # Every artifact: deny imports proven missing or GKI-protected on
    # trimmed kernels (ranchu 6.1: unknown-symbol load refusal). These
    # go through the socket bootstrap table or runtime pointers instead.
    denied_all = {"filp_open", "kernel_read", "filp_close", "vprintk",
                  "set_memory_x", "do_send_sig_info",
                  "__put_cred", "send_signal",
                  "vmalloc_exec", "input_dev_valid", "pte_read", "pte_exec",
                  "pte_swp_offset", "pte_swp_type", "_printk", "is_swap_pte",
                  "krealloc_array", "pte_user"}
    found_all = []
    for line in undef_lines:
        sym = line.split()
        if not sym:
            continue
        sym = sym[-1].split('.')[0]
        if sym in denied_all:
            found_all.append(sym)
    if found_all:
        die("denied imports (use bootstrap/runtime indirection): " +
            " ".join(sorted(set(found_all))))
    # Universal image only: deny imports that vendor kernels strip even
    # when GKI exports them (proven on Samsung 5.15). pfn_valid goes
    # through memd_pfn_ok (runtime chain); MMIO uses volatile access;
    # kprobes must never appear (loader-rejected GOT relocs).
    if kmi == "universal" or kmi == "universal-test":
        denied = {"pfn_valid", "__log_read_mmio", "__log_post_read_mmio",
                  "register_kprobe", "unregister_kprobe",
                  "kallsyms_lookup_name"}
        found = []
        for line in undef_lines:
            sym = line.split()
            if not sym:
                continue
            sym = sym[-1].split('.')[0]
            if sym in denied:
                found.append(sym)
        if found:
            die("universal-denied imports: " + " ".join(sorted(set(found))))
    print("KMI %s checks passed" % kmi)


main()
# kmod/check_universal.py[∂]
