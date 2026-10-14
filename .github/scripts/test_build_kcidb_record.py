import os
import tempfile
import unittest

import build_kcidb_record


class ToolchainSelectionTests(unittest.TestCase):
    def write_config(self, contents):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
        with handle:
            handle.write(contents)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_selects_arm64_cross_compiler(self):
        path = self.write_config("CONFIG_64BIT=y\n")
        self.assertEqual(
            build_kcidb_record.select_toolchain(
                {"architecture": "arm64", "compiler": "gcc"}, path
            ),
            ("arm64", "aarch64-linux-gnu-", "gcc-aarch64-linux-gnu", False),
        )

    def test_selects_little_endian_64_bit_mips(self):
        path = self.write_config("CONFIG_64BIT=y\nCONFIG_CPU_LITTLE_ENDIAN=y\n")
        self.assertEqual(
            build_kcidb_record.select_toolchain(
                {"architecture": "mips", "compiler": "gcc"}, path
            ),
            ("mips", "mips64el-linux-gnuabi64-", "gcc-mips64el-linux-gnuabi64", False),
        )

    def test_selects_llvm_for_clang_builds(self):
        path = self.write_config("CONFIG_64BIT=y\n")
        self.assertEqual(
            build_kcidb_record.select_toolchain(
                {"architecture": "x86_64", "compiler": "clang 17"}, path
            ),
            ("x86", "", "clang", True),
        )


if __name__ == "__main__":
    unittest.main()
