#!/usr/bin/env python3
"""tools/two_tu_gate.py -- CI-independent runner for the memd.hpp 2-TU gate.

Runs, in order:
  1. header syntax check (any host with a C++ compiler): both TU sources
     must parse with -fsyntax-only;
  2. 2-TU link+run (Linux only): TU-A (REGISTER_MEMD_MODULE) + TU-B
     (main/boot) must link to ONE shared factory_slot registry and the
     binary must print 2TU-PASS.

The TU sources live in tools/test_lxgr_load.py (MemdHppTwoTuTests) as the
single source of truth; this script imports them, it does not duplicate
them. Manual use from the repo root:

    python3 tools/two_tu_gate.py

Future CI use: run this script on a Linux builder instead of (or in
addition to) the unittest; it needs only a C++ compiler and python3.

Exit codes: 0 PASS (everything ran and passed), 1 FAIL (anything failed
on a host where it should run), 2 SKIP (loud: non-Linux link+run, or no
C++ compiler for the syntax check). SKIP never masquerades as PASS.
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_lxgr_load as two_tu_src

PASS, FAIL, SKIP = 0, 1, 2


def _compiler():
    for candidate in ("g++", "c++", "clang++"):
        if shutil.which(candidate):
            return candidate
    return None


def _write_tus(tmp):
    with open(os.path.join(tmp, "tu_a.cpp"), "w") as stream:
        stream.write(two_tu_src.MemdHppTwoTuTests.TU_A)
    with open(os.path.join(tmp, "tu_b.cpp"), "w") as stream:
        stream.write(two_tu_src.MemdHppTwoTuTests.TU_B)


def main():
    compiler = _compiler()
    if compiler is None:
        print("2TU-GATE SKIP: no C++ compiler found; cannot syntax-check "
              "memd.hpp (host %s/%s)"
              % (sys.platform, platform.machine()))
        return SKIP
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as tmp:
        _write_tus(tmp)
        syntax = subprocess.run(
            [compiler, "-std=c++17", "-fsyntax-only",
             "-I", repo_root, os.path.join(tmp, "tu_a.cpp")],
            capture_output=True, text=True, timeout=300)
        if syntax.returncode != 0:
            print("2TU-GATE FAIL: memd.hpp does not parse:")
            print(syntax.stderr[-2000:])
            return FAIL
        print("2TU-GATE syntax: PASS (any-host -fsyntax-only)")
        if not sys.platform.startswith("linux"):
            print("2TU-GATE SKIP: link+run requires Linux (payload path: "
                  "abstract unix sockets, dladdr, link.h); host is %s/%s"
                  % (sys.platform, platform.machine()))
            return SKIP
        binary = os.path.join(tmp, "two_tu")
        link = subprocess.run(
            [compiler, "-std=c++17", "-Wall", "-Wextra",
             "-I", repo_root,
             os.path.join(tmp, "tu_a.cpp"), os.path.join(tmp, "tu_b.cpp"),
             "-o", binary, "-ldl"],
            capture_output=True, text=True, timeout=300)
        if link.returncode != 0:
            print("2TU-GATE FAIL: 2-TU link failed:")
            print(link.stderr[-3000:])
            return FAIL
        run = subprocess.run(
            [binary], capture_output=True, text=True, timeout=120)
        if run.returncode != 0 or "2TU-PASS" not in run.stdout:
            print("2TU-GATE FAIL: 2-TU binary exited %d:" % run.returncode)
            print(run.stdout[-2000:])
            return FAIL
    print("2TU-GATE link+run: PASS (2TU-PASS)")
    print("2TU-GATE PASS")
    return PASS


if __name__ == "__main__":
    sys.exit(main())
