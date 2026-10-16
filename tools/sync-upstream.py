#!/usr/bin/env python3
"""sync-upstream.py — materialize PINNED upstream trees for reference only.

Reads third_party/pins.json, shallow-fetches each pinned SHA into
third_party/upstream/<name>/ (gitignored). Upstream code NEVER enters the
build; integration is behavioral re-implementation (see UPSTREAM.md:
DirtyFrag is unlicensed/all-rights-reserved, KernelSU is GPL-3.0
arm's-length). This script exists so reviewers diff exact trees during
pin-update reviews — nothing here compiles into the app.

Run manually:  python3 tools/sync-upstream.py
Never wired into build.sh (stays offline) or CI compile.

Failure modes are loud by design:
- fetched HEAD != pinned SHA  -> abort, pin moved or fetch poisoned.
- local patches in patches/<name>/*.patch fail `git apply --3way`
  against the fresh mirror -> abort, print conflicted files, require a
  MANUAL merge fix (resolve, refresh the patch, re-run, full test suite).
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = ROOT / "third_party" / "pins.json"
PATCHES = ROOT / "patches"


def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return r


def die(msg):
    print("SYNC FAIL: " + msg)
    sys.exit(1)


def main():
    try:
        pins = json.loads(PINS.read_text())["pins"]
        mirror = Path(json.loads(PINS.read_text())["mirror_dir"])
    except (OSError, KeyError, ValueError) as e:
        die("cannot read %s: %s" % (PINS, e))
    mirror_base = ROOT / mirror
    for p in pins:
        name, url, rev = p["name"], p["url"], p["rev"]
        dest = mirror_base / name
        print("== %s @ %s ==" % (name, rev))
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        r = run(["git", "init", "-q", str(dest)])
        if r.returncode != 0:
            die("git init failed for %s" % name)
        r = run(["git", "remote", "add", "origin", url], cwd=dest)
        if r.returncode != 0:
            die("remote add failed for %s" % name)
        r = run(["git", "fetch", "--depth", "1", "origin", rev], cwd=dest)
        if r.returncode != 0:
            die("fetch of pinned SHA failed for %s (pin moved or network): %s"
                % (name, r.stderr.strip().splitlines()[:3]))
        r = run(["git", "checkout", "-q", rev], cwd=dest)
        if r.returncode != 0:
            die("checkout failed for %s" % name)
        head = run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
        if head != rev:
            die("SHA mismatch for %s: want %s got %s" % (name, rev, head))
        print("verified %s" % head)
        patch_dir = PATCHES / name
        if patch_dir.is_dir():
            patches = sorted(patch_dir.glob("*.patch"))
            for patch in patches:
                r = run(["git", "apply", "--check", "--3way",
                         str(patch.resolve())], cwd=dest)
                if r.returncode != 0:
                    die("patch %s does NOT apply cleanly to fresh %s mirror.\n"
                        "MANUAL MERGE FIX REQUIRED: resolve inside %s, refresh "
                        "the patch, re-run sync, then full test suite.\n%s"
                        % (patch.name, name, dest,
                           r.stderr.strip().splitlines()[:10]))
                print("patch ok: %s" % patch.name)
    print("SYNC OK: mirrors verified under %s (reference only, not compiled)"
          % mirror_base)


if __name__ == "__main__":
    main()
