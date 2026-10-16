import errno
import json
import os
import struct
import tempfile
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


if __name__ == "__main__":
    unittest.main()
