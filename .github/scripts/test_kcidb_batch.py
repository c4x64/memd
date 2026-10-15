import json
import os
import tempfile
import unittest
from unittest.mock import patch

import kcidb_batch


def make_record(index, device_class="oem_consumer"):
    return {
        "build_id": f"build-{index}",
        "checkout_id": f"checkout-{index}",
        "kernel_version": f"v6.{index}",
        "kernel_hash": f"{index:040x}",
        "kernel_branch": f"android{14 + index}-6.{index}",
        "git_repository_url": "https://example.com/kernel.git",
        "tree_name": "kernel/common",
        "device_class": device_class,
        "architecture": "arm64",
        "config_name": f"device-{index}_defconfig",
        "config_url": "https://example.com/config",
        "valid": True,
        "source_unique_count": 3,
        "source_ranchu_count": 1,
        "source_consumer_count": 2,
    }


class KcidbBatchTests(unittest.TestCase):
    def write_json(self, payload):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
        with handle:
            json.dump(payload, handle)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_loads_unique_verified_device_kernel_rows(self):
        path = self.write_json(
            [
                make_record(0, "ranchu"),
                make_record(1),
                make_record(2),
            ]
        )
        with patch.object(kcidb_batch, "MIN_TARGETS", 3):
            manifest = kcidb_batch.load_snapshot(path)

        self.assertEqual(manifest["selected_count"], 3)
        self.assertEqual(manifest["source_counts"]["ranchu"], 1)
        self.assertEqual(manifest["source_counts"]["oem_consumer"], 2)

    def test_rejects_duplicate_device_kernel_identity(self):
        path = self.write_json(
            [
                make_record(0, "ranchu"),
                make_record(1),
                make_record(1),
            ]
        )
        with patch.object(kcidb_batch, "MIN_TARGETS", 3):
            with self.assertRaisesRegex(
                ValueError, "Duplicate device/kernel identity"
            ):
                kcidb_batch.load_snapshot(path)

    def test_rejects_incomplete_query_result(self):
        records = [make_record(0, "ranchu"), make_record(1), make_record(2)]
        for record in records:
            record.pop("source_unique_count")
            record.pop("source_ranchu_count")
            record.pop("source_consumer_count")
        path = self.write_json(
            {
                "records": records,
                "source_counts": {"unique": 4, "ranchu": 1, "oem_consumer": 3},
            }
        )
        with patch.object(kcidb_batch, "MIN_TARGETS", 3):
            with self.assertRaisesRegex(ValueError, "incomplete manifest"):
                kcidb_batch.load_snapshot(path)

    def test_matrix_selects_contiguous_resumable_slice(self):
        manifest = {
            "records": [make_record(index) for index in range(5)],
        }
        with patch.object(kcidb_batch, "BATCH_SIZE", 2):
            first, first_end = kcidb_batch.make_matrix(manifest, 0)
            second, second_end = kcidb_batch.make_matrix(manifest, first_end)
            final, final_end = kcidb_batch.make_matrix(manifest, second_end)

        # Axis form: plain global index lists (see make_matrix).
        self.assertEqual(first["index"], [0, 1])
        self.assertEqual(second["index"], [2, 3])
        self.assertEqual(final["index"], [4])
        self.assertEqual(final_end, 5)

    def test_target_key_for_index_roundtrip(self):
        manifest = {
            "records": [make_record(index) for index in range(3)],
        }
        for index in range(3):
            self.assertEqual(
                kcidb_batch.target_key(manifest["records"][index]),
                kcidb_batch.target_key(manifest["records"][index]),
            )
        keys = {kcidb_batch.target_key(r) for r in manifest["records"]}
        self.assertEqual(len(keys), 3)


if __name__ == "__main__":
    unittest.main()
# .github/scripts/test_kcidb_batch.py[∂]
