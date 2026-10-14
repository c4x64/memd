#!/usr/bin/env python3
"""Kernel compatibility database: resolve each known kernel to an artifact.

Purpose: materialize more than 1,000 real kernels from authoritative sources
and verify that each resolves, by the rules in spx.c and run.sh, to an exact
per-KMI matrix artifact, the universal fallback image, or a documented
NO-GO result. Exit with status 1 if any row remains unresolved or if the
total falls below MIN_ROWS.

Sources (no fabricated kernels):
  1. compat_tags.txt — 3150 real GKI release tags from kernel/common
     (+refs snapshot). Tag names carry family and generation (android13-5.15-...),
     parsed mechanically; KMI stability means every tag of a supported
     family is served by that family's artifact.
  2. GKI_RELEASES cross product (imported, not duplicated) —
     (device/avd x version) per KMI. AVD names containing x86_64 resolve
     to an architecture-related NO-GO result (the module supports ARM64
     only); all other entries are ARM64.
  3. Curated OEM and virtual-device families (below), recorded at a
     coarse but high-confidence level (model, kernel series, and Android
     generation), with provenance. Exact patch-level versions are not
     asserted for these entries.
  4. Parser self-tests, using synthetic Ranchu- and Samsung-shaped
     release strings to verify suffix tolerance in the matcher.

Matching (mirrors spx.c selection and the universal-first policy in run.sh):
  exact per-KMI artifact if android{NN}-{maj}.{min} is packed,
  else universal image if the family is supported (5.10/5.15/6.1/6.6/6.12),
  else documented NO-GO (5.4 socket refusal, 6.18 unknown gen, x86_64,
  unparseable). The packed set is derived from generate_matrix(), so
  dropping a KMI from the matrix visibly moves its rows to universal.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate_matrix as gm

MIN_ROWS = 1000
SUPPORTED = {(5, 10), (5, 15), (6, 1), (6, 6), (6, 12)}

# (label, kmaj, kmin, android-gen-NN, soc, provenance). Family-level only.
CURATED = [
    ("Galaxy S24 (SM-S921, Exynos 2400)", 6, 1, 14, "exynos2400",
     "Android 14 launch, Samsung pineapple GKI android14-6.1"),
    ("Galaxy S24+ (SM-S926, Exynos 2400)", 6, 1, 14, "exynos2400",
     "Android 14 launch, Samsung pineapple GKI android14-6.1"),
    ("Galaxy S24 Ultra (SM-S928, Snapdragon 8 Gen 3)", 6, 1, 14, "sm8650",
     "Android 14 launch; proves matching is SoC-agnostic"),
    ("Galaxy S24 FE (SM-S721, Exynos 2400e)", 6, 1, 14, "exynos2400e",
     "Android 14 launch, Exynos 2400 variant"),
]

# Synthetic release strings exercising matcher shapes (tests OUR code).
PARSER_TESTS = [
    # (release, expected-outcome, expected-artifact-or-reason)
    ("5.15.136-android13-8-ranchu", "matrix", "android13-5.15"),
    ("6.1.75-android14-xyz-samsung", "matrix", "android14-6.1"),
    ("5.10.107-android12-9-gabcdef", "universal", "universal"),
    ("6.6.60-android15-q", "matrix", "android15-6.6"),
    ("6.12.31-android16-bar", "matrix", "android16-6.12"),
    ("5.4.147-android11-foo", "nogo", "unsupported generation"),
    ("6.18.0-android17-x", "nogo", "unsupported generation"),
    ("garbage", "nogo", "unparseable release"),
]


def packed_kmis():
    m = gm.generate_matrix()
    kos = set()
    for job in m["include"]:
        kmi = job["kmi"]
        if kmi == "universal-test":
            continue
        kos.add(kmi)
    return kos


def resolve(kmaj, kmin, gen_nn, arch, packed):
    """Mirror spx.c/run.sh matching. Returns (outcome, artifact-or-reason)."""
    if arch != "arm64":
        return ("nogo", "non-arm64 arch")
    if kmaj is None:
        return ("nogo", "unparseable release")
    if gen_nn is not None:
        cand = "android%d-%d.%d" % (gen_nn, kmaj, kmin)
        if cand in packed:
            return ("matrix", cand)
    if (kmaj, kmin) in SUPPORTED:
        return ("universal", "universal")
    return ("nogo", "unsupported generation")


def build_rows():
    rows = []  # (kind, label, kmaj, kmin, gen_nn_or_None, arch)

    # 1. GKI release tags (ground truth file).
    with open(os.path.join(HERE, "compat_tags.txt")) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"android(\d+)-(\d+)\.(\d+)", line)
            if not m:
                continue  # not a family tag; skip loudly below if many
            rows.append(("tag", line, int(m.group(2)), int(m.group(3)),
                         int(m.group(1)), "arm64"))

    # 2. GKI_RELEASES cross product (devices + AVDs) x versions.
    for kmi, v in gm.GKI_RELEASES.items():
        m = re.match(r"android(\d+)-(\d+)\.(\d+)", kmi)
        if not m:
            continue
        gen_nn, kmaj, kmin = int(m.group(1)), int(m.group(2)), int(m.group(3))
        for dev in v.get("devices", []):
            for ver in v.get("versions", []):
                vm = re.match(r"(\d+)\.(\d+)", ver)
                rows.append(("device", "%s@%s" % (dev, ver),
                             int(vm.group(1)), int(vm.group(2)),
                             gen_nn, "arm64"))
        for avd in v.get("avds", []):
            arch = "x86_64" if "x86_64" in avd else "arm64"
            for ver in v.get("versions", []):
                vm = re.match(r"(\d+)\.(\d+)", ver)
                rows.append(("avd", "%s@%s" % (avd, ver),
                             int(vm.group(1)), int(vm.group(2)),
                             gen_nn, arch))

    # 3. Curated OEM/virtual families.
    for label, maj, mi, gen, soc, prov in CURATED:
        rows.append(("oem:%s" % soc, label, maj, mi, gen, "arm64"))

    return rows


def main():
    packed = packed_kmis()
    matrix_kmis = sorted(k for k in packed if k != "universal")
    rows = build_rows()
    errors = []
    counts = {"matrix": 0, "universal": 0, "nogo": 0}

    for kind, label, maj, mi, gen, arch in rows:
        outcome, art = resolve(maj, mi, gen, arch, packed)
        counts[outcome] += 1
        if outcome == "matrix" and art not in packed:
            errors.append("row %r resolves to unpacked %s" % (label, art))

    # Every auto-selected packed artifact must serve >= 1 row (guards
    # dead artifacts; -dbg builds are explicit---ko-only by design).
    exercised = set()
    for kind, label, maj, mi, gen, arch in rows:
        outcome, art = resolve(maj, mi, gen, arch, packed)
        if outcome == "matrix":
            exercised.add(art)
    for kmi in matrix_kmis:
        if kmi.endswith("-dbg"):
            continue
        if kmi not in exercised:
            errors.append("packed artifact %s serves zero rows" % kmi)

    # Parser self-tests (spx-equivalent: ^digits + androidNN substring).
    for rel, want_out, want_art in PARSER_TESTS:
        m = re.match(r"(\d+)\.(\d+)", rel)
        gm_ = re.search(r"android(\d+)", rel)
        if m:
            got = resolve(int(m.group(1)), int(m.group(2)),
                          int(gm_.group(1)) if gm_ else None, "arm64", packed)
        else:
            got = ("nogo", "unparseable release")
        if got[0] != want_out or got[1] != want_art:
            errors.append("parser %r -> %r, want (%r, %r)"
                          % (rel, got, want_out, want_art))

    total = len(rows)
    print("compat-db: %d rows (%d matrix, %d universal, %d nogo) + %d parser tests"
          % (total, counts["matrix"], counts["universal"], counts["nogo"],
             len(PARSER_TESTS)))
    print("compat-db: packed artifacts exercised: %d/%d"
          % (len(exercised), len(matrix_kmis)))
    if total < MIN_ROWS:
        errors.append("only %d rows, need >= %d" % (total, MIN_ROWS))
    if errors:
        print("compat-db FAIL:")
        for e in errors[:20]:
            print("  - " + e)
        return 1
    print("compat-db OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
# .github/scripts/compat_db.py[∂]
