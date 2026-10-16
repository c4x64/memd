import errno
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile

import lxgr_load


PROP = """id=lxgr.demo
name=Demo
version=v1
versionCode=2
author=test
"""


def make_module_zip(path, abis=("arm64-v8a",), prop=PROP):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("module.prop", prop)
        for abi in abis:
            archive.writestr("zygisk/%s.so" % abi, b"\x7fELF-FAKE-" + abi.encode())


class PropTests(unittest.TestCase):
    def test_parses_required_fields(self):
        props = lxgr_load.parse_module_prop(PROP)
        self.assertEqual(props["id"], "lxgr.demo")
        self.assertEqual(props["versionCode"], "2")

    def test_rejects_missing_id(self):
        with self.assertRaisesRegex(ValueError, "missing or not filesystem-safe"):
            lxgr_load.parse_module_prop("versionCode=1\n")

    def test_rejects_missing_version(self):
        with self.assertRaisesRegex(ValueError, "no versionCode"):
            lxgr_load.parse_module_prop("id=x\n")

    def test_rejects_traversal_id(self):
        for bad in ("../../evil", "/abs/path", "a/b", "", "x y"):
            with self.assertRaisesRegex(ValueError, "filesystem-safe", msg=bad):
                lxgr_load.parse_module_prop("id=%s\nversionCode=1\n" % bad)

    def test_accepts_dotted_id(self):
        props = lxgr_load.parse_module_prop("id=lxgr.demo-v1\nversionCode=1\n")
        self.assertEqual(props["id"], "lxgr.demo-v1")

    def test_check_module_id(self):
        self.assertEqual(lxgr_load.check_module_id("aB0._-"), "aB0._-")
        for bad in ("", "../x", "/abs", "a/b", "x y", "x;y"):
            with self.assertRaisesRegex(ValueError, "filesystem-safe", msg=bad):
                lxgr_load.check_module_id(bad)


class AbiTests(unittest.TestCase):
    def test_picks_arm64(self):
        names = ["module.prop", "zygisk/arm64-v8a.so", "zygisk/x86_64.so"]
        self.assertEqual(lxgr_load.pick_abi_lib(names, "arm64-v8a"), "zygisk/arm64-v8a.so")

    def test_refuses_unloadable_abi(self):
        with self.assertRaisesRegex(ValueError, "not executable"):
            lxgr_load.pick_abi_lib(["zygisk/x86_64.so"], "x86_64")

    def test_missing_lib(self):
        with self.assertRaisesRegex(ValueError, "no zygisk"):
            lxgr_load.pick_abi_lib(["module.prop"], "arm64-v8a")


class ZipLayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.zip_path = os.path.join(self.tmp.name, "demo.zip")
        make_module_zip(self.zip_path)

    def test_stage_extracts_and_records(self):
        root = os.path.join(self.tmp.name, "stage")
        module_id, staged, version = lxgr_load.stage_module(
            self.zip_path, root, "arm64-v8a"
        )
        self.assertEqual(module_id, "lxgr.demo")
        self.assertEqual(version, "2")
        self.assertTrue(staged.endswith(os.path.join("lxgr.demo", "payload.so")))
        with open(staged, "rb") as stream:
            self.assertTrue(stream.read().startswith(b"\x7fELF-FAKE-"))

    def test_stage_rejects_no_prop(self):
        bad = os.path.join(self.tmp.name, "bad.zip")
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("zygisk/arm64-v8a.so", b"x")
        with self.assertRaisesRegex(ValueError, "no module.prop"):
            lxgr_load.stage_module(bad, os.path.join(self.tmp.name, "s"), "arm64-v8a")

    def test_state_roundtrip(self):
        root = os.path.join(self.tmp.name, "stage")
        os.makedirs(os.path.join(root, "lxgr.demo"))
        path = lxgr_load.state_path(root, "lxgr.demo", 1234)
        with open(path, "w") as stream:
            json.dump({"handle": 57005}, stream)
        self.assertEqual(lxgr_load.read_state(root, "lxgr.demo", 1234)["handle"], 57005)
        self.assertEqual(lxgr_load.read_state(root, "lxgr.demo", 9999), {})


class StructTests(unittest.TestCase):
    def test_loadso_layout_matches_kernel(self):
        # pid@0 path@4 entry@260 flags@324 result@328 handle@336 entry@344.
        self.assertEqual(lxgr_load.LOADSO_SIZE, 352)
        buf = struct.pack(lxgr_load.LOADSO_FMT, 7, b"/x", b"e", 0, -5, 0x1234, 9)
        self.assertEqual(len(buf), 352)
        pid, path, entry, flags, result, handle, entry_result = struct.unpack(
            lxgr_load.LOADSO_FMT, buf
        )
        self.assertEqual((pid, result, handle, entry_result), (7, -5, 0x1234, 9))
        self.assertEqual(path.split(b"\0")[0], b"/x")

    def test_unload_layout_matches_kernel(self):
        # pid@0 handle@8 result@16 (24 bytes).
        self.assertEqual(lxgr_load.UNLOAD_SIZE, 24)
        buf = struct.pack(lxgr_load.UNLOAD_FMT, 7, 0xABCD, -3)
        self.assertEqual(struct.unpack(lxgr_load.UNLOAD_FMT, buf), (7, 0xABCD, -3))

    def test_ioctl_numbers(self):
        self.assertEqual(lxgr_load.iowr(38, 352), 0xC1605726)
        self.assertEqual(lxgr_load.iowr(41, 24), 0xC0185729)

    def test_load_rejects_overlong_inputs(self):
        with self.assertRaisesRegex(ValueError, "255"):
            lxgr_load.ioctl_load(None, 1, "/" + "x" * 300, "", False, False)
        with self.assertRaisesRegex(ValueError, "63"):
            lxgr_load.ioctl_load(None, 1, "/x", "e" * 70, False, False)
        with self.assertRaisesRegex(ValueError, "absolute"):
            lxgr_load.ioctl_load(None, 1, "relative/path", "", False, False)

    def test_hotswap_rejects_ephemeral(self):
        import argparse

        args = argparse.Namespace(ephemeral=True)
        self.assertEqual(lxgr_load.cmd_hotswap(args), 22)  # EINVAL


class ValidationTests(unittest.TestCase):
    def test_load_rejects_nul_bytes(self):
        with self.assertRaisesRegex(ValueError, "NUL"):
            lxgr_load.ioctl_load(None, 1, "/x\x00evil", "", False, False)
        with self.assertRaisesRegex(ValueError, "NUL"):
            lxgr_load.ioctl_load(None, 1, "/x", "e\x00vil", False, False)

    def test_load_rejects_bad_pid(self):
        for bad in (0, -1, True, 1 << 31, "123", None):
            with self.assertRaisesRegex(ValueError, "pid", msg=repr(bad)):
                lxgr_load.ioctl_load(None, bad, "/x", "", False, False)

    def test_unload_rejects_bad_pid_and_handle(self):
        for bad_pid in (0, -1, True, 1 << 31):
            with self.assertRaisesRegex(ValueError, "pid", msg=repr(bad_pid)):
                lxgr_load.ioctl_unload(None, bad_pid, 1)
        for bad_handle in (0, -5, True, 1 << 64, "123", None):
            with self.assertRaisesRegex(ValueError, "handle", msg=repr(bad_handle)):
                lxgr_load.ioctl_unload(None, 1, bad_handle)

    def test_stage_rejects_bad_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.zip")
            with open(bad, "wb") as stream:
                stream.write(b"not a zip")
            with self.assertRaisesRegex(ValueError, "invalid module zip"):
                lxgr_load.stage_module(bad, os.path.join(tmp, "s"), "arm64-v8a")

    def test_stage_rejects_oversize_prop(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = os.path.join(tmp, "big.zip")
            with zipfile.ZipFile(big, "w") as archive:
                archive.writestr(
                    "module.prop", "id=x\nversionCode=1\n" + "k=v\n" * 20000
                )
                archive.writestr("zygisk/arm64-v8a.so", b"\x7fELF")
            with self.assertRaisesRegex(ValueError, "too large"):
                lxgr_load.stage_module(big, os.path.join(tmp, "s"), "arm64-v8a")

    def test_stage_rejects_oversize_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = os.path.join(tmp, "big.zip")
            with zipfile.ZipFile(big, "w") as archive:
                archive.writestr("module.prop", PROP)
                archive.writestr("zygisk/arm64-v8a.so", b"\x7fELF-too-big")
            old_cap, lxgr_load.MAX_SO_BYTES = lxgr_load.MAX_SO_BYTES, 4
            try:
                with self.assertRaisesRegex(ValueError, "too large"):
                    lxgr_load.stage_module(big, os.path.join(tmp, "s"), "arm64-v8a")
            finally:
                lxgr_load.MAX_SO_BYTES = old_cap

    def test_pick_rejects_unknown_abi(self):
        with self.assertRaisesRegex(ValueError, "unsupported abi"):
            lxgr_load.pick_abi_lib(["module.prop"], "mips")

    def test_uninstall_rejects_nondict_state(self):
        import argparse

        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "stage")
            os.makedirs(os.path.join(root, "lxgr.demo"))
            with open(os.path.join(root, "lxgr.demo", "pid-7.json"), "w") as stream:
                stream.write("[1, 2]")
            args = argparse.Namespace(id="lxgr.demo", root=root, pid=7)
            self.assertEqual(lxgr_load.cmd_uninstall(args), errno.EINVAL)

    def test_uninstall_missing_state(self):
        import argparse

        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(id="lxgr.demo", root=tmp, pid=4242)
            self.assertEqual(lxgr_load.cmd_uninstall(args), errno.ENOENT)


class HotswapStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "stage")
        self.zip_path = os.path.join(self.tmp.name, "demo.zip")
        make_module_zip(self.zip_path)

    def _args(self, **over):
        import argparse

        base = dict(zip=self.zip_path, root=self.root, pid=99,
                    abi="arm64-v8a", entry="lxgr_main", su=False,
                    ephemeral=False, unlink=False)
        base.update(over)
        return argparse.Namespace(**base)

    def _seed(self, record):
        os.makedirs(os.path.join(self.root, "lxgr.demo"), exist_ok=True)
        lxgr_load.write_state(self.root, "lxgr.demo", 99, record)

    def test_pending_handles_tolerates_junk(self):
        self.assertEqual(lxgr_load.pending_handles({}), [])
        self.assertEqual(lxgr_load.pending_handles({"prev_handle": 7}), [7])
        self.assertEqual(
            lxgr_load.pending_handles({"prev_handles": [0, True, "x", 5, 5, 9]}),
            [5, 9],
        )

    def test_write_state_leaves_no_tmp(self):
        self._seed({"handle": 1})
        path = lxgr_load.state_path(self.root, "lxgr.demo", 99)
        self.assertFalse(os.path.exists(path + ".tmp"))
        self.assertEqual(lxgr_load.read_state(self.root, "lxgr.demo", 99)["handle"], 1)

    def test_install_carries_displaced_handle(self):
        import unittest.mock as mock

        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0xAAA})
        with mock.patch.object(lxgr_load, "ioctl_load", return_value=(0, 0xBBB, 0)), \
             mock.patch.object(lxgr_load, "find_driver_family"):
            self.assertEqual(lxgr_load.cmd_install(self._args()), 0)
        state = lxgr_load.read_state(self.root, "lxgr.demo", 99)
        self.assertEqual(state["handle"], 0xBBB)
        self.assertEqual(state["prev_handles"], [0xAAA])

    def test_double_failed_hotswap_keeps_chain(self):
        import unittest.mock as mock

        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0x111})
        handles = iter((0xAAA, 0xBBB))
        with mock.patch.object(
            lxgr_load, "ioctl_load",
            side_effect=lambda *a: (0, next(handles), 0)), \
             mock.patch.object(lxgr_load, "ioctl_unload", return_value=5), \
             mock.patch.object(lxgr_load, "find_driver_family"):
            self.assertEqual(lxgr_load.cmd_hotswap(self._args()), 5)
            first = lxgr_load.read_state(self.root, "lxgr.demo", 99)
            self.assertEqual(lxgr_load.cmd_hotswap(self._args()), 5)
            second = lxgr_load.read_state(self.root, "lxgr.demo", 99)
        self.assertEqual(first["prev_handles"], [0x111])
        # 0x111 survived the second unload failure too: still on record.
        self.assertEqual(second["handle"], 0xBBB)
        self.assertEqual(second["prev_handles"], [0xAAA, 0x111])

    def test_hotswap_success_clears_chain(self):
        import unittest.mock as mock

        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0x111,
                    "prev_handles": [0x222]})
        with mock.patch.object(lxgr_load, "ioctl_load", return_value=(0, 0xAAA, 0)), \
             mock.patch.object(lxgr_load, "ioctl_unload", return_value=0), \
             mock.patch.object(lxgr_load, "find_driver_family"):
            self.assertEqual(lxgr_load.cmd_hotswap(self._args()), 0)
        state = lxgr_load.read_state(self.root, "lxgr.demo", 99)
        self.assertEqual(state["handle"], 0xAAA)
        self.assertNotIn("prev_handles", state)
        self.assertNotIn("prev_handle", state)

    def test_uninstall_drains_legacy_prev(self):
        import argparse
        import unittest.mock as mock

        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0xAAA,
                    "prev_handle": 0xBBB})  # round-1 singular key
        seen = []
        with mock.patch.object(
            lxgr_load, "ioctl_unload",
            side_effect=lambda s, p, h: seen.append(h) or 0), \
             mock.patch.object(lxgr_load, "find_driver_family"):
            args = argparse.Namespace(id="lxgr.demo", root=self.root, pid=99)
            self.assertEqual(lxgr_load.cmd_uninstall(args), 0)
        self.assertEqual(sorted(seen), [0xAAA, 0xBBB])
        self.assertFalse(
            os.path.exists(lxgr_load.state_path(self.root, "lxgr.demo", 99)))

    def test_uninstall_partial_failure_keeps_survivors(self):
        import argparse
        import unittest.mock as mock

        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0xAAA,
                    "prev_handles": [0xBBB]})
        with mock.patch.object(
            lxgr_load, "ioctl_unload",
            side_effect=lambda s, p, h: 0 if h == 0xAAA else 5), \
             mock.patch.object(lxgr_load, "find_driver_family"):
            args = argparse.Namespace(id="lxgr.demo", root=self.root, pid=99)
            self.assertEqual(lxgr_load.cmd_uninstall(args), 5)
        state = lxgr_load.read_state(self.root, "lxgr.demo", 99)
        self.assertEqual(state["handle"], 0xBBB)
        self.assertNotIn("prev_handles", state)

    def test_write_state_rejects_oversize_chain(self):
        self._seed({"handle": 0})
        with self.assertRaisesRegex(ValueError, "exceeds"):
            lxgr_load.write_state(
                self.root, "lxgr.demo", 99,
                {"handle": 1,
                 "prev_handles": list(range(1, lxgr_load.MAX_PREV_HANDLES + 2))})
        # At-cap record still writes (boundary is inclusive).
        lxgr_load.write_state(
            self.root, "lxgr.demo", 99,
            {"handle": 1,
             "prev_handles": list(range(1, lxgr_load.MAX_PREV_HANDLES + 1))})
        self.assertEqual(
            len(lxgr_load.read_state(self.root, "lxgr.demo", 99)["prev_handles"]),
            lxgr_load.MAX_PREV_HANDLES)

    def test_install_refuses_full_chain_before_loading(self):
        import unittest.mock as mock

        full = list(range(0x200, 0x200 + lxgr_load.MAX_PREV_HANDLES))
        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0x111,
                    "prev_handles": full})
        with mock.patch.object(lxgr_load, "ioctl_load") as load, \
             mock.patch.object(lxgr_load, "find_driver_family"):
            with self.assertRaisesRegex(ValueError, "uninstall"):
                lxgr_load.cmd_install(self._args())
            load.assert_not_called()  # no stranded live handle
        state = lxgr_load.read_state(self.root, "lxgr.demo", 99)
        self.assertEqual(state["handle"], 0x111)
        self.assertEqual(state["prev_handles"], full)

    def test_install_at_cap_minus_one_succeeds(self):
        import unittest.mock as mock

        almost = list(range(0x200, 0x200 + lxgr_load.MAX_PREV_HANDLES - 1))
        self._seed({"id": "lxgr.demo", "version": "2", "handle": 0x111,
                    "prev_handles": almost})
        with mock.patch.object(lxgr_load, "ioctl_load", return_value=(0, 0xAAA, 0)), \
             mock.patch.object(lxgr_load, "find_driver_family"):
            self.assertEqual(lxgr_load.cmd_install(self._args()), 0)
        state = lxgr_load.read_state(self.root, "lxgr.demo", 99)
        self.assertEqual(len(state["prev_handles"]), lxgr_load.MAX_PREV_HANDLES)

    def test_hotswap_rejects_oversize_prop(self):
        big = os.path.join(self.tmp.name, "big.zip")
        with zipfile.ZipFile(big, "w") as archive:
            archive.writestr(
                "module.prop", "id=lxgr.demo\nversionCode=1\n" + "k=v\n" * 20000)
            archive.writestr("zygisk/arm64-v8a.so", b"\x7fELF")
        self.assertEqual(lxgr_load.cmd_hotswap(self._args(zip=big)), errno.EINVAL)

    def test_hotswap_rejects_no_prop(self):
        bad = os.path.join(self.tmp.name, "noprop.zip")
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("zygisk/arm64-v8a.so", b"\x7fELF")
        self.assertEqual(lxgr_load.cmd_hotswap(self._args(zip=bad)), errno.EINVAL)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MemdHppTwoTuTests(unittest.TestCase):
    """memd.hpp must compile, link and run across TWO translation units.

    The module registry (lxgr::detail::factory_slot) and the PLT-hook
    state deliberately have external linkage with a function-local static,
    so REGISTER_MEMD_MODULE in one TU and lxgr_main/boot in another meet
    on ONE registry. If either regressed to per-TU (static) linkage,
    payloads spanning translation units would silently lose their module
    and boot with -ENODEV.

    CI gate usage (Linux-only link+run; build.yml is intentionally NOT
    touched this round): run from tools/ on a Linux host --
        python3 -m unittest test_lxgr_load.MemdHppTwoTuTests -v
    CI-independent runner (manual + future CI): python3 tools/two_tu_gate.py
    reports PASS/SKIP/FAIL with exit 0/1/2; the TU_A/TU_B sources below are
    its single source of truth.
    On non-Linux hosts the link+run half SKIPS with a loud reason (the
    payload path needs Linux: abstract unix sockets, dladdr, link.h) and
    only the header syntax check runs.
    """

    TU_A = textwrap.dedent("""\
        #include "memd.hpp"
        class TwoTuMod : public zygisk::Module {
          public:
            void onLoad(zygisk::Api *api, JNIEnv *env) override {
                (void)api;
                (void)env;
            }
        };
        REGISTER_MEMD_MODULE(TwoTuMod);
        int tu_a_probe() {
            return lxgr::detail::factory_slot() ? 0 : 1;
        }
        void *tu_a_slot_addr() {
            return (void *)&lxgr::detail::factory_slot();
        }
        """)

    TU_B = textwrap.dedent("""\
        #include "memd.hpp"
        #include <cstdio>
        int tu_a_probe();
        void *tu_a_slot_addr();
        int main() {
            if (tu_a_probe() != 0) {
                std::printf("2TU-FAIL factory null in TU-A\\n");
                return 1;
            }
            if (!lxgr::detail::factory_slot()) {
                std::printf("2TU-FAIL factory null in TU-B\\n");
                return 2;
            }
            if (tu_a_slot_addr() != (void *)&lxgr::detail::factory_slot()) {
                std::printf("2TU-FAIL registry not shared across TUs\\n");
                return 3;
            }
            int r = zygisk::detail::boot_module(0x1234);
            if (r != 0) {
                std::printf("2TU-FAIL boot rc=%d\\n", r);
                return 4;
            }
            std::printf("2TU-PASS\\n");
            return 0;
        }
        """)

    def _compiler(self):
        for candidate in ("g++", "c++", "clang++"):
            if shutil.which(candidate):
                return candidate
        return None

    def _write_tus(self, tmp):
        with open(os.path.join(tmp, "tu_a.cpp"), "w") as stream:
            stream.write(self.TU_A)
        with open(os.path.join(tmp, "tu_b.cpp"), "w") as stream:
            stream.write(self.TU_B)

    def test_header_parses(self):
        """memd.hpp must parse everywhere (syntax-only; runs on any host)."""
        compiler = self._compiler()
        if compiler is None:
            # Same rule as tools/two_tu_gate.py: a missing compiler is a
            # loud SKIP off-Linux but a FAIL on Linux, where the gate is
            # expected to run (otherwise a broken builder hides as SKIP).
            if sys.platform.startswith("linux"):
                self.fail("on Linux but no C++ compiler found; gate cannot run")
            self.skipTest("no C++ compiler found; cannot syntax-check memd.hpp")
        with tempfile.TemporaryDirectory() as tmp:
            self._write_tus(tmp)
            proc = subprocess.run(
                [compiler, "-std=c++17", "-fsyntax-only",
                 "-I", REPO_ROOT, os.path.join(tmp, "tu_a.cpp")],
                capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0,
                         "memd.hpp failed to parse:\n%s" % proc.stderr[-2000:])

    def test_two_tu_link_and_run(self):
        """Link TU-A (REGISTER) + TU-B (main/boot) and RUN the binary.

        Linux-only: fails loudly anywhere else is wrong (the payload path
        needs Linux), so non-Linux hosts SKIP with the host limit stated.
        """
        if not sys.platform.startswith("linux"):
            self.skipTest(
                "2-TU link+run requires Linux (payload path: abstract "
                "unix sockets, dladdr, link.h); host is %s/%s -- "
                "header syntax check (test_header_parses) ran instead"
                % (sys.platform, platform.machine()))
        compiler = self._compiler()
        if compiler is None:
            self.fail("on Linux but no C++ compiler found; gate cannot run")
        with tempfile.TemporaryDirectory() as tmp:
            self._write_tus(tmp)
            binary = os.path.join(tmp, "two_tu")
            compile_proc = subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra",
                 "-I", REPO_ROOT,
                 os.path.join(tmp, "tu_a.cpp"), os.path.join(tmp, "tu_b.cpp"),
                 "-o", binary, "-ldl"],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(
                compile_proc.returncode, 0,
                "2-TU link failed:\n%s" % compile_proc.stderr[-3000:])
            run_proc = subprocess.run(
                [binary], capture_output=True, text=True, timeout=120)
            self.assertEqual(run_proc.returncode, 0,
                             "2-TU binary exited %d:\n%s"
                             % (run_proc.returncode, run_proc.stdout[-2000:]))
            self.assertIn("2TU-PASS", run_proc.stdout)


class _SimCrash(Exception):
    """Simulated kill -9 at a chosen line (NOT caught by lxgr_load)."""


class _FakeDriver:
    """Fake MEMD driver: load() mints a resident handle, unload() drops it.

    Missing-handle unload returns -ENOENT like a real double-dlclose, so
    retry-after-crash corpse behavior is visible instead of masked."""

    def __init__(self):
        self.resident = set()
        self.next_handle = 0x1000

    def load(self):
        handle = self.next_handle
        self.next_handle += 1
        self.resident.add(handle)
        return (0, handle, 0)

    def unload(self, handle):
        if handle in self.resident:
            self.resident.discard(handle)
            return 0
        return -errno.ENOENT


class _FakeSock:
    """Dummy for find_driver_family: cmd_* only call close() on it."""
    def close(self):
        pass


def _recorded_handles(state):
    out = set()
    handle = state.get("handle", 0)
    if isinstance(handle, int) and not isinstance(handle, bool) and handle:
        out.add(handle)
    for prev in lxgr_load.pending_handles(state):
        out.add(prev)
    return out


class HotswapCrashConsistencyTests(unittest.TestCase):
    """kill -9 at every line of hotswap: is state always recoverable?

    Method: seed {handle: OLD, prev_handles: [P1]} with a fake driver for
    whom {OLD, P1} are resident, then run a real cmd_hotswap with the
    driver/state calls intact except ONE crash injected per run. After
    each crash, every handle the (fake) driver still has resident must be
    on disk (current or prev_handles); anything else is an orphan the next
    hotswap/uninstall can never find.

    Result (pinned by test_crash_points_table): every crash point is
    recoverable EXCEPT post-load/pre-record, where the just-loaded handle
    is resident but unrecorded. That window is structural -- the handle
    only exists after the driver returns, so no pre-load record can name
    it (no handle-reservation ioctl exists) -- and is documented here, not
    hidden. Retry semantics after mid-loop crashes are pinned too: the
    survivor write happens after the loop, so a crash replays the full
    chain and already-unloaded handles come back as bounded -ENOENT
    corpses (MAX_PREV_HANDLES caps the chain), never silent leaks.

    Two windows outside cmd_hotswap's own loop are pinned separately:
    - kill -9 mid-UNINSTALL-loop (test_uninstall_midloop_crash_drains):
      the survivor write also happens after the loop, so the crash leaves
      the full pre-run record on disk and the retry replays the chain.
    - kill -9 between install's record write and the staged-file unlink
      (test_install_crash_between_record_and_unlink): the mapping is
      already recorded, so the leftover staged file is just garbage the
      next install overwrites via tmp+rename.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "stage")
        self.zip_path = os.path.join(self.tmp.name, "demo.zip")
        make_module_zip(self.zip_path)
        self.pid = 99
        self.old, self.p1 = 0x111, 0x222

    def _args(self, **over):
        import argparse

        base = dict(zip=self.zip_path, root=self.root, pid=self.pid,
                    abi="arm64-v8a", entry="lxgr_main", su=False,
                    ephemeral=False, unlink=False)
        base.update(over)
        return argparse.Namespace(**base)

    def _seed(self, record):
        os.makedirs(os.path.join(self.root, "lxgr.demo"), exist_ok=True)
        lxgr_load.write_state(self.root, "lxgr.demo", self.pid, record)

    def _patched(self, driver, crash_at=None):
        """mock helpers; crash_at is a zero-arg hook run at the crash line."""
        import unittest.mock as mock

        state = {"writes": 0, "unloads": 0}

        def fake_load(sock, pid, path, entry, su, ephemeral):
            return driver.load()

        def fake_unload(sock, pid, handle):
            state["unloads"] += 1
            if crash_at == "pre-first-unload" and state["unloads"] == 1:
                raise _SimCrash("kill -9 before first unload")
            result = driver.unload(handle)
            if crash_at == "mid-loop" and state["unloads"] == 1:
                raise _SimCrash("kill -9 mid unload loop")
            return result

        real_write = lxgr_load.write_state

        def fake_write(root, module_id, pid, record):
            state["writes"] += 1
            if crash_at == "pre-record" and state["writes"] == 1:
                raise _SimCrash("kill -9 post-load pre-record")
            if crash_at == "pre-survivor-write" and state["writes"] == 2:
                raise _SimCrash("kill -9 post-loop pre-survivor-write")
            return real_write(root, module_id, pid, record)

        return (mock.patch.object(lxgr_load, "ioctl_load", side_effect=fake_load),
                mock.patch.object(lxgr_load, "ioctl_unload", side_effect=fake_unload),
                mock.patch.object(lxgr_load, "write_state", side_effect=fake_write),
                mock.patch.object(lxgr_load, "find_driver_family",
                                return_value=_FakeSock()),
                state)

    def _run_hotswap_crash(self, driver, crash_at):
        loaders = self._patched(driver, crash_at)
        with loaders[0], loaders[1], loaders[2], loaders[3]:
            if crash_at == "during-stage":
                import unittest.mock as mock
                with mock.patch.object(
                        lxgr_load, "stage_module",
                        side_effect=_SimCrash("kill -9 during stage")):
                    with self.assertRaises(_SimCrash):
                        lxgr_load.cmd_hotswap(self._args())
                return
            with self.assertRaises(_SimCrash):
                lxgr_load.cmd_hotswap(self._args())

    def test_crash_points_table(self):
        # (crash point, expect_orphans) -- only pre-record orphans.
        for crash_at, expect_orphan in [
            ("during-stage", set()),
            ("pre-record", None),  # handled separately: exactly {NEW}
            ("pre-first-unload", set()),
            ("mid-loop", set()),
            ("pre-survivor-write", set()),
        ]:
            driver = _FakeDriver()
            driver.resident = {self.old, self.p1}
            self._seed({"id": "lxgr.demo", "version": "2",
                        "handle": self.old, "prev_handles": [self.p1]})
            if crash_at == "pre-record":
                loaders = self._patched(driver, crash_at)
                with loaders[0], loaders[1], loaders[2], loaders[3]:
                    with self.assertRaises(_SimCrash):
                        lxgr_load.cmd_hotswap(self._args())
                recorded = _recorded_handles(
                    lxgr_load.read_state(self.root, "lxgr.demo", self.pid))
                orphans = set(driver.resident) - recorded
                # THE window: exactly the just-loaded handle is orphaned.
                self.assertEqual(len(orphans), 1, crash_at)
                self.assertEqual(recorded, {self.old, self.p1}, crash_at)
                continue
            self._run_hotswap_crash(driver, crash_at)
            recorded = _recorded_handles(
                lxgr_load.read_state(self.root, "lxgr.demo", self.pid))
            orphans = set(driver.resident) - recorded
            self.assertEqual(orphans, expect_orphan,
                             "crash@%s orphans %s" % (crash_at, orphans))

    def test_retry_after_midloop_crash_drains(self):
        """Crash mid-loop, then a clean hotswap must not leak: the driver
        ends with exactly the newest handle, on record.

        Pinned wart: the handle the crashed run DID unload (OLD) is still
        in the on-disk chain (survivor write happens after the loop), so
        the retry's unload of OLD fails -ENOENT (double-dlclose) and OLD
        stays as a bounded corpse entry. rc is therefore -ENOENT, not 0,
        and prev_handles == [OLD]. Corpses never silently leak a resident
        library (driver holds only the newest), and the chain stays capped
        at MAX_PREV_HANDLES -- but nothing auto-drops them today."""
        import unittest.mock as mock

        driver = _FakeDriver()
        driver.resident = {self.old, self.p1}
        self._seed({"id": "lxgr.demo", "version": "2",
                    "handle": self.old, "prev_handles": [self.p1]})
        self._run_hotswap_crash(driver, "mid-loop")
        with mock.patch.object(lxgr_load, "ioctl_load",
                               side_effect=lambda *a: driver.load()), \
             mock.patch.object(lxgr_load, "ioctl_unload",
                               side_effect=lambda s, p, h: driver.unload(h)), \
             mock.patch.object(lxgr_load, "find_driver_family",
                               return_value=_FakeSock()):
            self.assertEqual(lxgr_load.cmd_hotswap(self._args()),
                             -errno.ENOENT)
        state = lxgr_load.read_state(self.root, "lxgr.demo", self.pid)
        # No leak: the only resident library is the recorded current one.
        self.assertEqual(driver.resident, {state["handle"]})
        # The double-unloaded entry is a bounded on-record corpse, not a leak.
        self.assertEqual(state["prev_handles"], [self.old])
        self.assertLessEqual(len(state["prev_handles"]),
                             lxgr_load.MAX_PREV_HANDLES)

    def test_uninstall_midloop_crash_drains(self):
        """kill -9 mid-UNINSTALL-loop: no test covered this window before.

        cmd_uninstall's survivor write also happens after the loop, so a
        crash leaves the full pre-run record on disk (nothing resident is
        ever unrecorded) and the retry replays the whole chain. The handle
        the crashed run DID unload (OLD) comes back as a bounded -ENOENT
        corpse on retry -- same double-dlclose semantics as the hotswap
        mid-loop crash.

        Pinned wart: unlike hotswap, uninstall mints no replacement
        handle, so after the retry the on-record current handle (OLD) is
        itself the corpse while nothing is resident. The next uninstall
        reports -ENOENT again for the same corpse instead of converging
        to 0 -- bounded (one entry, no leak: driver.resident is empty),
        but nothing auto-drops it today."""
        import argparse
        import unittest.mock as mock

        driver = _FakeDriver()
        driver.resident = {self.old, self.p1}
        self._seed({"id": "lxgr.demo", "version": "2",
                    "handle": self.old, "prev_handles": [self.p1]})
        calls = []

        def crashing_unload(sock, pid, handle):
            calls.append(handle)
            if len(calls) == 2:
                raise _SimCrash("kill -9 mid uninstall loop")
            return driver.unload(handle)

        with mock.patch.object(lxgr_load, "ioctl_unload",
                               side_effect=crashing_unload), \
             mock.patch.object(lxgr_load, "find_driver_family",
                               return_value=_FakeSock()):
            args = argparse.Namespace(id="lxgr.demo", root=self.root,
                                      pid=self.pid)
            with self.assertRaises(_SimCrash):
                lxgr_load.cmd_uninstall(args)
        # Crash left the pre-run record intact: OLD unloaded but still on
        # disk, P1 never attempted -- both accounted for, no orphan.
        recorded = _recorded_handles(
            lxgr_load.read_state(self.root, "lxgr.demo", self.pid))
        self.assertEqual(recorded, {self.old, self.p1})
        self.assertEqual(set(driver.resident) - recorded, set())
        # Clean retry replays the chain: OLD is already gone (-ENOENT
        # corpse), P1 unloads cleanly. Nothing resident, nothing leaked.
        with mock.patch.object(lxgr_load, "ioctl_unload",
                               side_effect=lambda s, p, h: driver.unload(h)), \
             mock.patch.object(lxgr_load, "find_driver_family",
                               return_value=_FakeSock()):
            args = argparse.Namespace(id="lxgr.demo", root=self.root,
                                      pid=self.pid)
            self.assertEqual(lxgr_load.cmd_uninstall(args), -errno.ENOENT)
        self.assertEqual(driver.resident, set())
        state = lxgr_load.read_state(self.root, "lxgr.demo", self.pid)
        self.assertEqual(state["handle"], self.old)  # corpse, not resident
        self.assertNotIn("prev_handles", state)

    def test_install_crash_between_record_and_unlink(self):
        """kill -9 after install's record write but before staged unlink.

        Uncovered window: the new handle is already on disk (write_state
        precedes unlink in cmd_install), so the crash orphans nothing --
        it only leaves a stale staged payload.so behind. The next install
        stages via tmp+rename (overwriting the leftover) and folds the
        recorded handle into prev_handles, so the leftover is garbage,
        not a leak, and the staged file converges to unlinked.
        """
        import unittest.mock as mock

        driver = _FakeDriver()
        with mock.patch.object(lxgr_load, "ioctl_load",
                               side_effect=lambda *a: driver.load()), \
             mock.patch.object(lxgr_load, "find_driver_family",
                               return_value=_FakeSock()), \
             mock.patch("os.unlink",
                        side_effect=_SimCrash("kill -9 pre-unlink")):
            with self.assertRaises(_SimCrash):
                lxgr_load.cmd_install(self._args(unlink=True))
        state = lxgr_load.read_state(self.root, "lxgr.demo", self.pid)
        new_handle = state["handle"]
        # Recorded before the crash: the resident handle is on disk.
        self.assertEqual(set(driver.resident), {new_handle})
        self.assertEqual(set(driver.resident) - _recorded_handles(state),
                         set())
        # The staged file survived the crash (unlink never ran).
        staged = lxgr_load.staging_path(self.root, "lxgr.demo")
        self.assertTrue(os.path.exists(staged))
        # Next install recovers: leftover staged file is overwritten via
        # tmp+rename, the recorded handle is retained pending unload.
        with mock.patch.object(lxgr_load, "ioctl_load",
                               side_effect=lambda *a: driver.load()), \
             mock.patch.object(lxgr_load, "find_driver_family",
                               return_value=_FakeSock()):
            self.assertEqual(lxgr_load.cmd_install(self._args(unlink=True)),
                             0)
        state = lxgr_load.read_state(self.root, "lxgr.demo", self.pid)
        self.assertEqual(state["prev_handles"], [new_handle])
        self.assertEqual(set(driver.resident) - _recorded_handles(state),
                         set())
        self.assertFalse(os.path.exists(staged))

    def test_kill_during_replace_keeps_old_record(self):
        """write_state = tmp + fsync + rename: killing the rename leaves
        the previous COMPLETE record (never truncated JSON, which
        read_state would misread as 'no install' and leak live handles)."""
        import unittest.mock as mock

        self._seed({"id": "lxgr.demo", "version": "2", "handle": self.old})
        with mock.patch("os.replace",
                        side_effect=_SimCrash("kill -9 during rename")):
            with self.assertRaises(_SimCrash):
                lxgr_load.write_state(self.root, "lxgr.demo", self.pid,
                                      {"id": "lxgr.demo", "version": "3",
                                       "handle": 0x999})
        state = lxgr_load.read_state(self.root, "lxgr.demo", self.pid)
        self.assertEqual(state["handle"], self.old)
        # A stray tmp never masquerades as state; the next write reuses
        # the same tmp path and converges.
        lxgr_load.write_state(self.root, "lxgr.demo", self.pid,
                              {"id": "lxgr.demo", "version": "3",
                               "handle": 0x999})
        self.assertEqual(
            lxgr_load.read_state(self.root, "lxgr.demo", self.pid)["handle"],
            0x999)


if __name__ == "__main__":
    unittest.main()
