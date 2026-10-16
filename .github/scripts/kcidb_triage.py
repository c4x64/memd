#!/usr/bin/env python3
"""Aggregate per-worker KernelCI batch results into a triage report.

Inputs: the batch manifest.json plus a directory holding worker-N.jsonl
rows (each ``{"index", "target_key", "status"}``) and optional per-target
``<index>.log`` files. Output: pass/fail totals, breakdowns by
architecture/compiler/tree, and the failing targets with the first
suspicious log lines. Pure stdlib; doubles as the local triage tool and
a future CI gate.
"""

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter

ERROR_RE = re.compile(
    r"(?i)\b(error|failed|fatal|undefined reference|not found|No such file)\b"
)


def load_results(results_dir):
    rows = {}
    for path in sorted(glob.glob(os.path.join(results_dir, "worker-*.jsonl"))):
        with open(path, encoding="utf-8", errors="replace") as stream:
            for lineno, line in enumerate(stream, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    rows[int(row["index"])] = row
                except (ValueError, KeyError, TypeError) as error:
                    raise ValueError(
                        "%s:%d: bad result row: %s" % (path, lineno, error)
                    )
    return rows


def first_errors(log_path, limit=4):
    if not os.path.isfile(log_path):
        return ["<no log>"]
    hits = []
    with open(log_path, encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if ERROR_RE.search(line):
                hits.append(line.strip()[:220])
                if len(hits) >= limit:
                    break
    return hits or ["<no error line matched>"]


def triage(manifest_path, results_dir):
    with open(manifest_path, encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest.get("records"), list):
        raise ValueError("manifest %s has no records list" % manifest_path)
    records = {i: r for i, r in enumerate(manifest["records"])}
    rows = load_results(results_dir)

    missing = sorted(set(records) - set(rows))
    by_arch = Counter()
    by_compiler = Counter()
    by_tree_branch = Counter()
    failures = []
    for index, record in records.items():
        row = rows.get(index)
        status = (row or {}).get("status", "missing")
        by_arch[(record["architecture"], status)] += 1
        by_compiler[(record.get("compiler", "?"), status)] += 1
        by_tree_branch[
            (record["tree_name"], record["kernel_branch"], status)
        ] += 1
        if status != "pass":
            failures.append(
                {
                    "index": index,
                    "status": status,
                    "arch": record["architecture"],
                    "compiler": record.get("compiler"),
                    "config": record["config_name"],
                    "branch": record["kernel_branch"],
                    "commit": record["kernel_hash"][:12],
                    "target_key": (row or {}).get("target_key", "?")[:16],
                    "log_hits": first_errors(
                        os.path.join(results_dir, "%d.log" % index)
                    ),
                }
            )
    return {
        "total": len(records),
        "reported": len(rows),
        "missing": missing,
        "passed": sum(1 for i in records if rows.get(i, {}).get("status") == "pass"),
        "by_arch": sorted(by_arch.items()),
        "by_compiler": sorted(by_compiler.items()),
        "by_tree_branch": sorted(by_tree_branch.items()),
        "failures": failures,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--json-out", required=False)
    args = parser.parse_args(argv)

    try:
        report = triage(args.manifest, args.results_dir)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("triage failed: %s" % error, file=sys.stderr)
        return 1
    total = report["total"]
    passed = report["passed"]
    print("targets: %d, reported: %d, passed: %d" % (total, report["reported"], passed))
    print("by arch/status:")
    for (arch, status), count in report["by_arch"]:
        print("  %-10s %-8s %d" % (arch, status, count))
    print("by compiler/status:")
    for (compiler, status), count in report["by_compiler"]:
        print("  %-12s %-8s %d" % (compiler, status, count))
    print("failures (%d):" % len(report["failures"]))
    for failure in report["failures"][:50]:
        print(
            "  [%d] %s %s %s %s %s (%s)"
            % (
                failure["index"],
                failure["status"],
                failure["arch"],
                failure["compiler"],
                failure["branch"],
                failure["config"][:40],
                failure["target_key"],
            )
        )
        for hit in failure["log_hits"][:2]:
            print("      | %s" % hit)
    if report["missing"]:
        print("missing rows for indices: %s" % report["missing"][:20])
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=1)
    return 0 if (passed == total and not report["missing"]) else 1


if __name__ == "__main__":
    sys.exit(main())
