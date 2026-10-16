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

CI use: compat-check runs this script directly (exit 0/1/2 contract)
in addition to the unittest; it needs only a C++ compiler and python3.

Exit codes: 0 PASS (everything ran and passed), 1 FAIL (anything failed
on a host where it should run -- including a Linux host with no C++
compiler, where the toolchain is expected to exist), 2 SKIP (loud:
non-Linux link+run, or no C++ compiler on a non-Linux host for the
syntax check). SKIP never masquerades as PASS, and a missing compiler
on Linux never masquerades as SKIP.
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


def _selftest():
    """Pure-Python contract test: prove the SKIP/FAIL/PASS exit codes
    without needing Linux or a C++ compiler.

    Mocks the compiler probe (two_tu_gate._compiler) and the subprocess
    runner (subprocess.run); sys.platform is patched per case. Seven
    cases cover the contract in the module docstring:
      no-compiler non-Linux -> SKIP, no-compiler Linux -> FAIL,
      syntax-fail -> FAIL, syntax-ok non-Linux -> SKIP,
      Linux link-fail -> FAIL, Linux run-miss -> FAIL, Linux full -> PASS.
    Returns 0 when every case hits its contract code, 1 otherwise. Run:
        python3 tools/two_tu_gate.py --self-test
    """
    import unittest.mock as mock

    failures = []

    def fake_completed(rc=0, out="", err=""):
        return subprocess.CompletedProcess(args=["fake"], returncode=rc,
                                           stdout=out, stderr=err)

    def run_case(name, *, plat, compiler, syntax_rc=0, link_rc=0,
                 run_rc=0, run_out="2TU-PASS\n", want):
        def fake_run(cmd, **kwargs):
            joined = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "-fsyntax-only" in joined:
                return fake_completed(syntax_rc, "", ""
                                      if syntax_rc == 0 else "syntax boom")
            if "-o" in (cmd if isinstance(cmd, list) else []):
                return fake_completed(link_rc, "", ""
                                      if link_rc == 0 else "link boom")
            return fake_completed(run_rc, run_out, "")

        with mock.patch.object(sys, "platform", plat), \
             mock.patch.object(sys.modules[__name__], "_compiler",
                              return_value=compiler), \
             mock.patch.object(subprocess, "run", side_effect=fake_run):
            got = main()
        if got != want:
            failures.append("%s: got %d want %d" % (name, got, want))
        else:
            print("self-test %s: exit %d OK" % (name, got))

    run_case("no-compiler-darwin-SKIP", plat="darwin", compiler=None,
             want=SKIP)
    run_case("no-compiler-linux-FAIL", plat="linux", compiler=None,
             want=FAIL)
    run_case("syntax-fail-FAIL", plat="darwin", compiler="g++",
             syntax_rc=1, want=FAIL)
    run_case("syntax-ok-darwin-SKIP", plat="darwin", compiler="g++",
             want=SKIP)
    run_case("linux-link-fail-FAIL", plat="linux", compiler="g++",
             link_rc=1, want=FAIL)
    run_case("linux-run-miss-FAIL", plat="linux", compiler="g++",
             run_out="nope\n", want=FAIL)
    run_case("linux-run-rc-FAIL", plat="linux", compiler="g++",
             run_rc=3, run_out="2TU-PASS\n", want=FAIL)
    run_case("linux-full-PASS", plat="linux", compiler="g++", want=PASS)

    if failures:
        print("self-test FAIL (two_tu_gate contract):")
        for failure in failures:
            print("  - " + failure)
        return 1
    print("self-test PASS: SKIP/FAIL/PASS contract holds (8 cases, mocked)")
    return 0


def main():
    compiler = _compiler()
    if compiler is None:
        # No compiler at all: SKIP on hosts where the toolchain is
        # optional, FAIL on Linux where the gate is expected to run --
        # otherwise a broken Linux builder reports SKIP (exit 2) and CI
        # mistakes it for "not applicable".
        if sys.platform.startswith("linux"):
            print("2TU-GATE FAIL: no C++ compiler found on Linux; the "
                  "syntax check and 2-TU link+run must run here "
                  "(tried g++, c++, clang++)")
            return FAIL
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
    if "--self-test" in sys.argv:
        sys.exit(_selftest())
    sys.exit(main())
