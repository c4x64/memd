import json
import os
import tempfile
import unittest
from unittest.mock import patch

import kcidb_batch
import kcidb_mirror


def make_node(index, **overrides):
    node = {
        "id": "node-%d" % index,
        "kind": "kbuild",
        "state": "done",
        "result": "pass",
        "parent": "checkout-%d" % index,
        "data": {
            "arch": "arm64",
            "defconfig": "gki_defconfig",
            "config_full": "gki_defconfig",
            "compiler": "clang-21",
            "kernel_revision": {
                "tree": "android",
                "url": "https://android.googlesource.com/kernel/common",
                "branch": "android14-6.1",
                "commit": "%040x" % index,
                "describe": "android14-6.1-%d" % index,
            },
        },
        "artifacts": {
            "_config": "https://files.kernelci.org/build-%d/.config" % index,
        },
    }
    node.update(overrides)
    return node


class MirrorMapTests(unittest.TestCase):
    def test_maps_full_node(self):
        record = kcidb_mirror.map_node(make_node(1))
        self.assertEqual(record["kernel_hash"], "%040x" % 1)
        self.assertEqual(
            record["git_repository_url"],
            "https://android.googlesource.com/kernel/common",
        )
        self.assertEqual(record["architecture"], "arm64")
        self.assertEqual(record["config_name"], "gki_defconfig")
        self.assertEqual(record["device_class"], "maestro")
        self.assertTrue(record["valid"])

    def test_rejects_bad_nodes(self):
        base = make_node(1)
        bad_kind = make_node(2, kind="checkout")
        bad_result = make_node(3, result="fail")
        no_config = make_node(4)
        del no_config["artifacts"]["_config"]
        short_hash = make_node(5)
        short_hash["data"]["kernel_revision"]["commit"] = "abc123"
        bad_url = make_node(6)
        bad_url["data"]["kernel_revision"]["url"] = "http://insecure.example/x.git"
        bad_arch = make_node(7)
        bad_arch["data"]["arch"] = "fake64"
        for node in (bad_kind, bad_result, no_config, short_hash, bad_url, bad_arch):
            self.assertIsNone(kcidb_mirror.map_node(node), node)

    def test_paginates_and_dedupes(self):
        pages = [
            {"items": [make_node(1), make_node(2)]},
            {"items": [make_node(2), make_node(3)]},
            {"items": []},
        ]
        calls = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(self.payload).encode()

        def fake_urlopen(request, timeout=None):
            calls.append(request.full_url)
            return FakeResponse(pages[min(len(calls) - 1, 2)])

        with patch.object(
            kcidb_mirror.urllib.request, "urlopen", side_effect=fake_urlopen
        ):
            with patch.object(kcidb_mirror, "MIN_TARGETS", 3):
                manifest = kcidb_mirror.collect_manifest(
                    "https://example.com", "android", 3, 2, 5, 10
                )
        self.assertEqual(manifest["selected_count"], 3)
        self.assertEqual(manifest["source"], "maestro-api")
        self.assertEqual(len(calls), 2)

    def test_short_mirror_fails(self):
        with patch.object(
            kcidb_mirror, "fetch_page", return_value=[make_node(1)]
        ):
            with patch.object(kcidb_mirror, "MIN_TARGETS", 3):
                with self.assertRaisesRegex(ValueError, "at least 3"):
                    kcidb_mirror.collect_manifest(
                        "https://example.com", "android", 3, 10, 5, 10
                    )


def make_record(index, device_class="maestro"):
    record = {
        "build_id": "build-%d" % index,
        "checkout_id": "checkout-%d" % index,
        "kernel_version": "v6.%d" % index,
        "kernel_hash": "%040x" % index,
        "kernel_branch": "android14-6.1",
        "git_repository_url": "https://example.com/kernel.git",
        "tree_name": "kernel/common",
        "device_class": device_class,
        "architecture": "arm64",
        "config_name": "device-%d_defconfig" % index,
        "config_url": "https://example.com/config",
        "valid": True,
    }
    return record


class MaestroBatchRuleTests(unittest.TestCase):
    def write_json(self, payload):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
        with handle:
            json.dump(payload, handle)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_all_maestro_manifest_passes(self):
        path = self.write_json(
            {
                "source": "maestro-api",
                "source_counts": {
                    "unique": 3,
                    "ranchu": 0,
                    "oem_consumer": 0,
                    "maestro": 3,
                },
                "records": [make_record(0), make_record(1), make_record(2)],
            }
        )
        with patch.object(kcidb_batch, "MIN_TARGETS", 3):
            manifest = kcidb_batch.load_snapshot(path)
        self.assertEqual(manifest["selected_count"], 3)
        self.assertEqual(manifest["source"], "maestro-api")
        self.assertEqual(manifest["source_counts"]["maestro"], 3)

    def test_mixed_classes_still_need_both(self):
        records = [make_record(0, "ranchu"), make_record(1, "maestro")]
        for record in records:
            record["source_unique_count"] = 2
            record["source_ranchu_count"] = 1
            record["source_consumer_count"] = 0
        path = self.write_json(records)
        with patch.object(kcidb_batch, "MIN_TARGETS", 2):
            with self.assertRaisesRegex(ValueError, "Ranchu and consumer"):
                kcidb_batch.load_snapshot(path)


if __name__ == "__main__":
    unittest.main()
