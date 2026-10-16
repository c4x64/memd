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


# ---- LP64 byte-layout cross-check: exact offsets/sizes, not eyeballing ----
# Every command struct is laid out here in Python under LP64 rules and the
# kernel and client.h results are byte-compared field by field. LP64 is the
# right model for both sides: arm64 Android and the client hosts agree on
# every type used here (fixed-width ints, pid_t/uid_t 4B, pointers /
# size_t / uintptr_t / unsigned long 8B, _Bool/bool/char 1B).

_LP64_SCALARS = {
    "bool": (1, 1), "_Bool": (1, 1), "char": (1, 1),
    "signed char": (1, 1), "unsigned char": (1, 1),
    "int8_t": (1, 1), "uint8_t": (1, 1), "__u8": (1, 1), "u8": (1, 1),
    "int16_t": (2, 2), "uint16_t": (2, 2), "__u16": (2, 2), "u16": (2, 2),
    "short": (2, 2), "unsigned short": (2, 2),
    "int": (4, 4), "unsigned int": (4, 4),
    "int32_t": (4, 4), "uint32_t": (4, 4), "__u32": (4, 4), "u32": (4, 4),
    "pid_t": (4, 4), "uid_t": (4, 4), "atomic_t": (4, 4), "float": (4, 4),
    "long": (8, 8), "unsigned long": (8, 8),
    "long long": (8, 8), "unsigned long long": (8, 8),
    "int64_t": (8, 8), "uint64_t": (8, 8), "__u64": (8, 8), "u64": (8, 8),
    "size_t": (8, 8), "ssize_t": (8, 8),
    "uintptr_t": (8, 8), "intptr_t": (8, 8), "double": (8, 8),
}

# Golden sizes pin the layout engine itself: if the parser mis-modelled
# LP64, both sides could agree wrongly. 352/24 mirror tools/lxgr_load.py
# LOADSO_FMT/UNLOAD_FMT; 32 is static_asserted in memd.hpp.
_GOLDEN_SIZES = {
    "memd_loadso_cmd": 352,
    "memd_loadso_unload_cmd": 24,
    "memd_bootstrap_cmd": 32,
}


def _align_up(n, a):
    return (n + a - 1) // a * a


def _split_top(text, sep):
    """Split on sep at brace/paren/bracket depth 0."""
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def raw_structs(src):
    """name -> raw body (comments stripped, type spellings intact)."""
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
                    found[name] = src[m.end():k]
                    break
    return found


def _scalar_layout(base):
    base = re.sub(r"\b__user\b", "", base)
    base = re.sub(r"\b(const|volatile)\b", "", base)
    base = re.sub(r"\bsigned\s+char\b", "char", base)
    base = re.sub(r"\s+", " ", base).strip()
    try:
        return _LP64_SCALARS[base]
    except KeyError:
        raise ValueError("layout: unknown scalar type %r" % base)


def _array_len(declarator):
    m = re.search(r"\[(\d+)\]\s*$", declarator)
    return int(m.group(1)) if m else 1


def _layout_body(body, resolved, depth=0):
    """(fields, size, align) for one struct/union body.

    fields: [(label, offset, size)]; resolved: name -> (size, align)."""
    if depth > 8:
        raise ValueError("layout: nesting too deep")
    is_union = False
    members = []  # (size, align, label)
    for decl in _split_top(body, ";"):
        decl = decl.strip()
        if not decl:
            continue
        if "{" in decl:
            m = re.match(r"(struct|union)\s*(\w+)?\s*\{(.*)\}\s*(.*)$",
                         decl, re.S)
            if not m:
                raise ValueError("layout: cannot parse nested %r" % decl[:60])
            kind, inner, rest = m.group(1), m.group(3), m.group(4).strip()
            sub_fields, sub_size, sub_align = _layout_body(
                inner, resolved, depth + 1)
            if kind == "union":
                # Union: every member starts at 0; size is the largest
                # member, align the strictest member.
                align = sub_align
                size = 0
                for _, _, sz in sub_fields:
                    size = max(size, sz)
            else:
                size, align = sub_size, sub_align
            label = rest if rest else "anon-%s" % kind
            if rest:
                n = _array_len(rest)
                label = re.sub(r"\s*\[.*", "", rest).strip() or label
                size *= n
            members.append((size, align, label or "anon"))
            continue
        # Function pointer, optionally __user-annotated: int (*__user fn)(void *)
        # -- always a pointer. (__user is an address-space annotation, not
        # part of the name; the canon gate strips it the same way.)
        m = re.search(r"\(\*\s*(?:__user\s+)?(\w+)\s*\)", decl)
        if m:
            members.append((8, 8, m.group(1)))
            continue
        parts = _split_top(decl, ",")
        base = None
        for i, part in enumerate(parts):
            part = part.strip()
            if i == 0:
                if "*" in part:
                    base, _, declarator = part.rpartition("*")
                    declarator = declarator.strip()
                    size, align = 8, 8
                else:
                    tokens = part.rsplit(None, 1)
                    if len(tokens) != 2:
                        raise ValueError(
                            "layout: cannot parse decl %r" % part[:60])
                    base, declarator = tokens
                    if "*" in declarator:
                        size, align = 8, 8
                        declarator = declarator.replace("*", "").strip()
                    elif base.startswith("struct "):
                        sname = base.split(None, 1)[1]
                        if sname not in resolved:
                            raise ValueError(
                                "layout: unresolved struct %s" % sname)
                        size, align = resolved[sname]
                    else:
                        size, align = _scalar_layout(base)
                base = base.strip()
            else:
                declarator = part
                if "*" in declarator:
                    size, align = 8, 8
                    declarator = declarator.replace("*", "").strip()
                elif base.startswith("struct "):
                    sname = base.split(None, 1)[1]
                    if sname not in resolved:
                        raise ValueError(
                            "layout: unresolved struct %s" % sname)
                    size, align = resolved[sname]
                else:
                    size, align = _scalar_layout(base)
            n = _array_len(declarator)
            label = re.sub(r"\s*\[.*", "", declarator).strip()
            label = re.sub(r"\b__user\b", "", label).strip()
            label = re.sub(r"\s+", " ", label)
            members.append((size * n, align, label))
    # Lay out sequentially (struct semantics); unions handled by caller.
    fields, offset, max_align = [], 0, 1
    for size, align, label in members:
        offset = _align_up(offset, align)
        fields.append((label, offset, size))
        offset += size
        max_align = max(max_align, align)
    return fields, _align_up(offset, max_align), max_align


def compute_layouts(raw, wanted):
    """raw name->body to name -> (fields, size, align); dependency-ordered.

    Only `wanted` structs (plus their transitive struct dependencies) are
    resolved, so kernel-only helpers in the same headers (ioctl_cmd_map
    with its handler typedef, mapped_page_info with list_head, ...) never
    enter the LP64 model."""
    wanted = set(wanted)
    resolved, pending = {}, {}
    # Seed with wanted structs present in raw; deps are pulled in lazily.
    stack = sorted(wanted)
    while stack:
        name = stack.pop()
        if name in resolved or name in pending:
            continue
        if name not in raw:
            continue  # absence is reported by the canon gate
        pending[name] = raw[name]
        # Pre-seed struct dependencies so single-pass resolution works.
        for dep in re.findall(r"struct\s+(\w+)\s+\w+", strip_comments(raw[name])):
            if dep not in resolved and dep not in pending:
                stack.append(dep)
    while pending:
        progress = False
        for name in sorted(pending):
            try:
                fields, size, align = _layout_body(pending[name], resolved)
            except ValueError as error:
                if "unresolved struct" not in str(error):
                    raise
                # Pull the missing dependency in if the headers have it.
                m = re.search(r"unresolved struct (\w+)", str(error))
                if m and m.group(1) in raw and m.group(1) not in pending:
                    pending[m.group(1)] = raw[m.group(1)]
                continue
            resolved[name] = (size, align)
            resolved[name + "\x00fields"] = fields
            del pending[name]
            progress = True
        if not progress:
            raise ValueError("layout: circular/unknown structs: %s"
                             % sorted(pending))
    out = {}
    for name in wanted:
        if name in raw and name in resolved:
            size, align = resolved[name]
            out[name] = (resolved[name + "\x00fields"], size, align)
    return out


def find_size_collisions(kops, klay, knorm):
    """Flag shared (type, nr) pairs whose structs encode the same _IOWR code.

    The _IOWR number folds in the struct SIZE, so any two ops sharing a
    (type, nr) key with equal layout sizes dispatch to the same code --
    even when their field layouts differ completely. The older canon-body
    check above only catches byte-identical bodies; this LP64 size check
    closes the same-size/different-layout hole (e.g. a hypothetical
    8-byte {int a; int b;} vs 8-byte {short x[4];} on one number).
    Body-identical pairs are already reported above and skipped here.
    """
    errors = []
    by_code = {}
    for name, (code, struct) in sorted(kops.items()):
        if name in EXCLUDED_OPS:
            continue
        by_code.setdefault(code, []).append((name, struct))
    for code, members in sorted(by_code.items()):
        if len(members) < 2:
            continue
        sizes = {}
        for name, struct in members:
            if struct == "int":
                sizes[name] = (struct, 4)
            elif struct in klay:
                sizes[name] = (struct, klay[struct][1])
            # Absent structs are reported by the canon gate; skip here.
        seen = {}
        for name, (struct, size) in sorted(sizes.items()):
            if size in seen:
                other, ostruct = seen[size]
                if knorm.get(struct) == knorm.get(ostruct):
                    continue  # body-identical: already reported above
                errors.append(
                    "ioctl code collision on '%s': %s (%s, %d bytes) and "
                    "%s (%s, %d bytes) encode the same _IOWR number "
                    "despite different layouts"
                    % (code, other, ostruct, size, name, struct, size))
            else:
                seen[size] = (name, struct)
    return errors


def compare_layouts(knorm, clay, needed):
    """Byte-compare kernel vs client layouts. Returns error strings."""
    errors = []
    for name in needed:
        if name not in knorm or name not in clay:
            continue  # missing-struct errors are reported by the canon gate
        kfields, ksize, _ = knorm[name]
        cfields, csize, _ = clay[name]
        if ksize != csize:
            errors.append("layout size drift: %s kernel %d vs client %d"
                          % (name, ksize, csize))
        kmap = {label: (off, sz) for label, off, sz in kfields}
        cmap = {label: (off, sz) for label, off, sz in cfields}
        for label, (koff, ksz) in sorted(kmap.items()):
            if label.startswith("anon-"):
                continue
            if label not in cmap:
                errors.append("layout field drift: %s.%s missing in client"
                              % (name, label))
            elif cmap[label] != (koff, ksz):
                errors.append(
                    "layout field drift: %s.%s kernel @%d+%d vs client @%d+%d"
                    % (name, label, koff, ksz,
                       cmap[label][0], cmap[label][1]))
        for label in sorted(cmap):
            if not label.startswith("anon-") and label not in kmap:
                errors.append("layout field drift: %s.%s extra in client"
                              % (name, label))
        if name in _GOLDEN_SIZES and ksize != _GOLDEN_SIZES[name]:
            errors.append("layout golden mismatch: %s is %d, want %d "
                          "(parser or headers changed)"
                          % (name, ksize, _GOLDEN_SIZES[name]))
    return errors


def format_layouts(layouts, needed):
    lines = []
    for name in needed:
        if name not in layouts:
            continue
        fields, size, _ = layouts[name]
        desc = " ".join("%s@%d+%d" % (label, off, sz)
                        for label, off, sz in fields)
        lines.append("    %-28s size %3d | %s" % (name, size, desc))
    return lines


def synthetic_size_collision_selftest():
    """Prove the size gate catches what the body gate misses.

    Builds two synthetic structs with EQUAL size (8) but DIFFERENT
    layouts sharing one (type, nr) key, then runs both the canon-body
    check and find_size_collisions over them:
      - the body check must MISS (bodies differ) -- the Round-4 hole;
      - the LP64 size check must FLAG (sizes equal => same _IOWR code).
    Returns 0 when the gate behaves that way, 1 otherwise. Run with:
        python3 .github/scripts/check_client_h.py --self-test
    """
    raw = {
        # 8 bytes: a@0+4 b@4+4.
        "synth_alpha_cmd": "uint32_t a; uint32_t b;",
        # 8 bytes: w@0+8. Same size, one field instead of two.
        "synth_beta_cmd": "uint64_t w;",
    }
    kops = {
        "MEMD_IOCTL_SYNTH_ALPHA": ("W99", "synth_alpha_cmd"),
        "MEMD_IOCTL_SYNTH_BETA": ("W99", "synth_beta_cmd"),
    }
    try:
        klay = compute_layouts(raw, set(raw))
    except ValueError as error:
        print("self-test FAIL: layout engine rejected synthetics: %s" % error)
        return 1
    for struct, want in (("synth_alpha_cmd", 8), ("synth_beta_cmd", 8)):
        got = klay[struct][1]
        if got != want:
            print("self-test FAIL: %s laid out as %d, want %d"
                  % (struct, got, want))
            return 1
    knorm = {n: canon_type(b) for n, b in raw.items()}
    # The legacy body check sees different bodies => silent (the hole).
    bodies = {knorm["synth_alpha_cmd"], knorm["synth_beta_cmd"]}
    body_would_flag = len(bodies) < 2
    size_errors = find_size_collisions(kops, klay, knorm)
    print("self-test synthetics: alpha %s | beta %s"
          % (" ".join("%s@%d+%d" % (l, o, s) for l, o, s in klay["synth_alpha_cmd"][0]),
             " ".join("%s@%d+%d" % (l, o, s) for l, o, s in klay["synth_beta_cmd"][0])))
    print("self-test body gate would flag: %s (want False = the old hole)"
          % body_would_flag)
    print("self-test size gate errors: %r" % (size_errors,))
    if body_would_flag:
        print("self-test FAIL: synthetics unexpectedly body-identical")
        return 1
    if not size_errors:
        print("self-test FAIL: size gate missed the same-size pair")
        return 1
    print("self-test PASS: same-size/different-layout pair FAILS the gate")
    return 0


def main():
    if "--self-test" in sys.argv:
        return synthetic_size_collision_selftest()
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
    # (Same-size/different-layout pairs slip past this body check; they
    # are caught by the LP64 size gate in the layout section below.)
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
    # LP64 byte-layout gate: exact offsets/sizes per struct, both sides.
    # Catches padding/reorder drift the canon (whitespace-folded) gate
    # cannot see. Runs anywhere (pure Python LP64 model, no toolchain).
    klnorm = {}
    knorm_lay = {}
    try:
        kraw_all = {}
        for p in KERN_FILES:
            kraw_all.update(raw_structs(read(p)))
        craw = raw_structs(csrc)
        klay = compute_layouts(
            kraw_all,
            set(s for _, s in kops.values()) - {"int"} - excluded_structs)
        clay = compute_layouts(craw, set(needed))
        klnorm = {STRUCT_ALIAS.get(n, n): v for n, v in klay.items()}
    except ValueError as error:
        errors.append("layout engine: %s" % error)
    else:
        errors.extend(compare_layouts(klnorm, clay, needed))
        # Shared-number size gate: same (type, nr) + same LP64 size means
        # the same full _IOWR code, whatever the field layouts. Runs on
        # the kernel side (dispatch truth); client mirrors are covered by
        # the byte-compare above.
        knorm_raw = {STRUCT_ALIAS.get(n, n): b for n, b in kstructs.items()}
        knorm_lay = {STRUCT_ALIAS.get(n, n): v for n, v in klay.items()}
        errors.extend(find_size_collisions(kops, knorm_lay, knorm_raw))
    # Evidence for the shared numbers (W21/W22/W23): sizes must differ.
    shared_evidence = []
    for code in ("W21", "W22", "W23"):
        members = sorted(
            "%s=%s:%sB" % (name, struct,
                           knorm_lay[struct][1] if struct in knorm_lay else "?")
            for name, (nr, struct) in sorted(kops.items())
            if nr == code and name not in EXCLUDED_OPS)
        if members:
            shared_evidence.append("%s: %s" % (code, " vs ".join(members)))
    print("check-client-h shared-number sizes: %s" % "; ".join(shared_evidence))
    # Exact offsets/sizes report: the evidence, not eyeballing.
    print("check-client-h layouts (LP64, kernel side):")
    for line in format_layouts(klnorm, needed):
        print(line)
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
