#!/usr/bin/env python3
"""check_spx_matrix.py — fail loud if SPX packed flavors drift from the matrix.

Compares the packed job set from generate_matrix.py (excluding the
test-only universal-test artifact, which gen_ko_list.py never packs)
against the flavors[] table parsed from kmod/spx.c, plus the
SPX_NFLAVORS count. SPX shorthand (a13-5.10) maps to matrix KMI
(android13-5.10); universal maps to itself.
Usage: python3 .github/scripts/check_spx_matrix.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_matrix import generate_matrix


def expand(shorthand):
    if shorthand == "universal":
        return "universal"
    m = re.match(r"a(\d+)-(.+)", shorthand)
    if not m:
        return shorthand
    return "android%s-%s" % (m.group(1), m.group(2))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    spx_path = os.path.join(repo, "linux", "arm", "kmod", "spx.c")
    try:
        src = open(spx_path).read()
    except OSError as e:
        print("FAIL: cannot read %s: %s" % (spx_path, e))
        return 1
    names = re.findall(r'flavors\[\d+\]\.name\s*=\s*"([^"]+)"', src)
    m = re.search(r"#define\s+SPX_NFLAVORS\s+(\d+)", src)
    if not m:
        print("FAIL: SPX_NFLAVORS not found in spx.c")
        return 1
    nflavors = int(m.group(1))
    if nflavors != len(names):
        print("FAIL: SPX_NFLAVORS=%d but %d flavors[] names parsed" %
              (nflavors, len(names)))
        return 1
    packed = sorted(j["kmi"] for j in generate_matrix()["include"]
                    if j["kmi"] != "universal-test")
    expanded = sorted(expand(n) for n in names)
    if nflavors != len(packed):
        print("FAIL: SPX_NFLAVORS=%d but matrix packs %d: %s" %
              (nflavors, len(packed), packed))
        return 1
    if expanded != packed:
        print("FAIL: SPX/matrix drift")
        print("  spx:    %s" % expanded)
        print("  matrix: %s" % packed)
        return 1
    print("SPX flavors match matrix (%d packed)" % len(packed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
# .github/scripts/check_spx_matrix.py[∂]
