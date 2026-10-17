#!/usr/bin/env python3
"""Pack KCIDB-built .ko files into an SPX binary.

Scans a directory of .ko files, generates a dynamic flavors table,
and compiles an SPX binary using gen_blobs.py + a modified spx.c.
"""
import os
import sys
import glob
import subprocess
import shutil
import re

def main():
    ko_dir = sys.argv[1] if len(sys.argv) > 1 else "kcidb-kos"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "."

    # Find all .ko files
    ko_files = sorted(glob.glob(os.path.join(ko_dir, "*.ko")))
    if not ko_files:
        print("No .ko files found in", ko_dir)
        return 1

    print(f"Found {len(ko_files)} .ko files")

    # Generate flavors list (filename without .ko extension)
    flavors = []
    for ko in ko_files:
        name = os.path.basename(ko).replace(".ko", "")
        flavors.append(name)

    # Generate ko_list.txt for gen_blobs.py
    ko_list = " ".join(ko_files)
    with open("/tmp/kcidb_ko_list.txt", "w") as f:
        f.write(ko_list)

    # Read spx.c template
    spx_path = os.path.join(os.path.dirname(__file__), "..", "..", "Branch-main", "kmod", "spx.c")
    spx_src = open(spx_path).read()

    # Generate dynamic flavors table
    # Replace the hardcoded flavors[] table with our dynamic one
    # Find the flavors table section
    flavors_start = spx_src.find("flavors[0].name")
    if flavors_start == -1:
        print("Could not find flavors table in spx.c")
        return 1

    # Find the end of the flavors table (SPX_NFLAVORS)
    nflavors_match = re.search(r"#define\s+SPX_NFLAVORS\s+(\d+)", spx_src)
    if not nflavors_match:
        print("Could not find SPX_NFLAVORS in spx.c")
        return 1

    # Generate new flavors table entries
    new_flavors = []
    for i, name in enumerate(flavors):
        # Extract kver and gen from name
        # e.g., "android13-5.15" -> kver="5.15", gen="android13"
        parts = name.split("-")
        if len(parts) >= 2:
            gen = parts[0]  # e.g., "android13"
            kver = parts[1]  # e.g., "5.15"
        else:
            gen = "unknown"
            kver = "unknown"

        new_flavors.append(
            f'    flavors[{i}].name = "{name}"; flavors[{i}].kver = "{kver}"; '
            f'flavors[{i}].gen = "{gen}"; '
            f'flavors[{i}].d = _binary_rwbridge_{name.replace("-", "_")}_ko_start; '
            f'flavors[{i}].n = (long)_binary_rwbridge_{name.replace("-", "_")}_ko_len;'
        )

    # For now, just create a tarball since SPX packing requires
    # significant modification to spx.c's hardcoded flavors table
    # and binary blob generation
    print("KCIDB .ko files collected. Creating tarball...")
    tarball = os.path.join(output_dir, "kcidb-results.tar.gz")
    subprocess.run(["tar", "czf", tarball, "-C", ko_dir, "."], check=True)
    print(f"Created {tarball} with {len(ko_files)} .ko files")

    return 0

if __name__ == "__main__":
    sys.exit(main())
# .github/scripts/pack_kcidb_spx.py[∂]