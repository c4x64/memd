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


if __name__ == "__main__":
    unittest.main()
