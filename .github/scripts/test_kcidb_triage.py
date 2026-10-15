import json
import os
import tempfile
import unittest

import kcidb_triage


def write(path, content):
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(content)


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        manifest = {
            "records": [
                {
                    "kernel_hash": "%040x" % i,
                    "architecture": "arm64" if i % 2 == 0 else "riscv",
                    "compiler": "clang-21",
                    "config_name": "cfg-%d" % i,
                    "tree_name": "android",
                    "kernel_branch": "android14-6.1",
                }
                for i in range(4)
            ]
        }
        self.manifest = os.path.join(self.tmp.name, "manifest.json")
        write(self.manifest, json.dumps(manifest))
        write(
            os.path.join(self.tmp.name, "worker-0.jsonl"),
            '{"index":0,"target_key":"aa","status":"pass"}\n'
            '{"index":1,"target_key":"bb","status":"fail"}\n',
        )
        write(
            os.path.join(self.tmp.name, "worker-1.jsonl"),
            '{"index":2,"target_key":"cc","status":"pass"}\n',
        )
        write(os.path.join(self.tmp.name, "1.log"), "foo\nerror: ld blew up\n")

    def test_aggregates_rows_and_failures(self):
        report = kcidb_triage.triage(self.manifest, self.tmp.name)
        self.assertEqual(report["total"], 4)
        self.assertEqual(report["passed"], 2)
        self.assertEqual(report["missing"], [3])
        self.assertEqual(len(report["failures"]), 2)
        by_index = {f["index"]: f for f in report["failures"]}
        self.assertEqual(by_index[1]["status"], "fail")
        self.assertIn("ld blew up", by_index[1]["log_hits"][0])
        self.assertEqual(by_index[3]["status"], "missing")


if __name__ == "__main__":
    unittest.main()
