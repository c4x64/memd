#!/usr/bin/env python3
"""Gate: client.h must match the kernel headers exactly.

Compares, for every product ioctl:
  - the (name, number, struct) triple of each MEMD_IOCTL_*/MEMD_BP_IOCTL_*
    define between kmod/ headers and client.h;
  - every referenced command struct, field-by-field after canonicalizing
    userspace/kernel type spellings (u32<->uint32_t, atomic_t<->int32_t,
    __user dropped, whitespace/comments collapsed);
  - shared integer constants (WMT_*, MEMD_DISP_*, gyro/hwbp enums).

Intentionally excluded (asserted absent from client.h): DMA_BUF_CREATE
(MEMD_DISABLE_DMABUF in product builds) and DISP_READBACK (test-only).

Exit 1 with specifics on any drift. Run in CI (compat-check job).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

KERN_FILES = [
    "kmod/memd/ioctl/memd_ioctl.h",
    "kmod/memd/utils/memd_hwbp.h",
    "kmod/memd/utils/memd_gyro.h",
    "kmod/memd/utils/memd_sigforce.h",
    "kmod/memd/utils/memd_inject.h",
    "kmod/memd/display/memd_display.h",
    "kmod/memd/mm/memd_bindproc.c",
]
CLIENT = "client.h"

# Bindproc structs live under short names in kmod (bp_*) but are exposed
# to userspace with the memd_ prefix; layouts are identical.
STRUCT_ALIAS = {
    "bp_read_memory_cmd": "memd_bp_read_memory_cmd",
    "bp_write_memory_cmd": "memd_bp_write_memory_cmd",
}

# Deliberately product-absent (gate asserts they stay out of client.h).
EXCLUDED_OPS = {"MEMD_IOCTL_DMA_BUF_CREATE", "MEMD_IOCTL_DISP_READBACK"}

TYPEMAP = {
    "u8": "uint8_t", "u16": "uint16_t", "u32": "uint32_t", "u64": "uint64_t",
    "__u8": "uint8_t", "__u16": "uint16_t", "__u32": "uint32_t",
    "__u64": "uint64_t",
    "unsigned long": "uint64_t", "unsigned int": "uint32_t",
    "int": "int32_t", "atomic_t": "int32_t", "_Bool": "bool",
}


def read(p):
    with open(os.path.join(ROOT, p)) as f:
        return f.read()


def strip_comments(s):
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    return s


def canon_type(text):
    text = strip_comments(text)
    text = re.sub(r"__user\b", "", text)
    # \d+ keeps array extents in the canon: name[256] and name[128]
    # must not compare equal (they size the ioctl code differently),
    # and neither may alias a scalar field on a shared ioctl number.
    toks = re.findall(r"[A-Za-z_]\w*|\d+|\*|\[|\]|\(|\)|,|;", text)
    out = []
    i = 0
    while i < len(toks):
        if toks[i] == "unsigned" and i + 1 < len(toks) and \
                toks[i + 1] in ("long", "int"):
            out.append("uint64_t" if toks[i + 1] == "long" else "uint32_t")
            i += 2
            continue
        out.append(TYPEMAP.get(toks[i], toks[i]))
        i += 1
    return "".join(out)


def extract_structs(src):
    """name -> canonicalized body (handles one nesting level)."""
    src = strip_comments(src)
    found = {}
    for m in re.finditer(r"struct\s+(\w+)\s*\{", src):
        name, depth, j = m.group(1), 0, m.end() - 1
        for k in range(j, len(src)):
            if src[k] == "{":
                depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0:
                    found[name] = canon_type(src[m.end():k])
                    break
    return found


def extract_ops(src):
    """op-name -> (code-key, struct-or-int).

    code-key folds the ioctl type char ('W' vs 'B') into the number so
    the socket ('W') and bindproc ('B') namespaces never alias each
    other; struct names pass through STRUCT_ALIAS so the kmod bp_*
    short names compare against client.h's memd_bp_* mirrors."""
    ops = {}
    for m in re.finditer(
            r"#define\s+(MEMD_IOCTL_\w+|MEMD_BP_IOCTL_\w+)\s+"
            r"_IO[WR]*\(\s*'([WB])'\s*,\s*(\d+)\s*,\s*(?:struct\s+(\w+)|(int))\s*\)",
            src):
        struct = m.group(4) or m.group(5)
        ops[m.group(1)] = (m.group(2) + m.group(3),
                            STRUCT_ALIAS.get(struct, struct))
    return ops


def extract_consts(src, prefixes):
    consts = {}
    for m in re.finditer(r"#define\s+((?:MEMD_)?(?:%s)\w*)\s+(\d+)"
                         % "|".join(prefixes), src):
        consts[m.group(1)] = m.group(2)
    return consts


def main():
    errors = []
    ksrc = "\n".join(read(p) for p in KERN_FILES)
    csrc = read(CLIENT)

    kops, cops = extract_ops(ksrc), extract_ops(csrc)
    for name, (nr, struct) in sorted(kops.items()):
        if name in EXCLUDED_OPS:
            if name in cops:
                errors.append("%s must stay out of client.h" % name)
            continue
        if name not in cops:
            errors.append("missing in client.h: %s" % name)
        elif cops[name] != (nr, struct):
            errors.append("op mismatch %s: kernel %s vs client %s"
                          % (name, (nr, struct), cops[name]))
    for name in sorted(cops):
        if name not in kops and name not in EXCLUDED_OPS:
            errors.append("client.h has unknown op: %s" % name)

    kstructs, cstructs = extract_structs(ksrc), extract_structs(csrc)
    # Kernel short names compare under their client.h aliases.
    knorm = {STRUCT_ALIAS.get(n, n): b for n, b in kstructs.items()}
    # Structs referenced only by deliberately excluded ops stay out too.
    excluded_structs = {s for n, (nr, s) in kops.items()
                        if n in EXCLUDED_OPS}
    needed = sorted(set(s for _, s in kops.values()) - {"int"}
                    - excluded_structs)
    for name in needed:
        if name not in knorm:
            errors.append("kernel struct not found: %s" % name)
        elif name not in cstructs:
            errors.append("client.h missing struct: %s" % name)
        elif cstructs[name] != knorm[name]:
            errors.append("struct drift: %s" % name)

    # Shared (type, nr) pairs are by design (e.g. W21/W22/W23): the size
    # field inside _IOWR keeps the full codes distinct. Two different op
    # names with byte-identical struct bodies would still produce
    # identical codes -- a real dispatch collision -- so fail on that.
    by_code = {}
    for name, (code, struct) in sorted(kops.items()):
        by_code.setdefault(code, []).append((name, struct))
    for code, members in sorted(by_code.items()):
        bodies = {}
        for name, struct in members:
            body = knorm.get(struct)
            if body is None:
                continue
            if body in bodies:
                errors.append(
                    "ioctl code collision on '%s': %s and %s share a body"
                    % (code, bodies[body], name))
            else:
                bodies[body] = name

    kconsts = extract_consts("\n".join([
        read("kmod/memd/utils/memd_utils.h"),
        read("kmod/memd/display/memd_display.h"),
        read("kmod/memd/utils/memd_gyro.h"),
        read("kmod/memd/utils/memd_hwbp.h"),
    ]), ["WMT_", "MEMD_DISP_", "MEMD_GYRO_", "MEMD_TOUCH_",
          "MEMD_VIRTUAL_INPUT_TYPE_", "MEMD_HWBP_"])
    cconsts = extract_consts(csrc, ["WMT_", "MEMD_DISP_", "MEMD_GYRO_",
                                    "MEMD_TOUCH_", "MEMD_VIRTUAL_INPUT_TYPE_",
                                    "MEMD_HWBP_"])
    norm = lambda d: {(k[5:] if k.startswith("MEMD_WMT_") else k): v
                      for k, v in d.items()}
    kn, cn = norm(kconsts), norm(cconsts)
    for k, v in sorted(kn.items()):
        if k.startswith("WMT_") or k.startswith("MEMD_"):
            if k not in cn:
                errors.append("client.h missing const: %s" % k)
            elif cn[k] != v:
                errors.append("const drift %s: %s vs %s" % (k, v, cn[k]))

    print("check-client-h: %d ops, %d structs, %d consts checked"
          % (len(kops), len(needed), len(kn)))
    if errors:
        print("check-client-h FAIL:")
        for e in errors[:25]:
            print("  - " + e)
        return 1
    print("check-client-h OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
# .github/scripts/check_client_h.py[∂]
