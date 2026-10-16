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


def _record_text(record, field, index):
    """Required manifest string field; ValueError (not KeyError) if absent."""
    value = record.get(field) if isinstance(record, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "manifest record %d has no usable %r" % (index, field)
        )
    return value.strip()


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
                except ValueError as error:
                    raise ValueError(
                        "%s:%d: bad result row: %s" % (path, lineno, error)
                    )
                if not isinstance(row, dict) or "index" not in row:
                    raise ValueError(
                        "%s:%d: bad result row: not an indexed object"
                        % (path, lineno)
                    )
                index = row["index"]
                if isinstance(index, bool):
                    raise ValueError(
                        "%s:%d: bad result row: index is not an integer"
                        % (path, lineno)
                    )
                if isinstance(index, int):
                    pass
                elif (isinstance(index, str)
                        and index.strip().lstrip("-").isdigit()):
                    index = int(index.strip())
                else:
                    raise ValueError(
                        "%s:%d: bad result row: index %r is not an integer"
                        % (path, lineno, row["index"])
                    )
                rows[index] = row
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
        if not isinstance(record, dict):
            raise ValueError("manifest record %d is not an object" % index)
        architecture = _record_text(record, "architecture", index)
        tree_name = _record_text(record, "tree_name", index)
        branch = _record_text(record, "kernel_branch", index)
        config = _record_text(record, "config_name", index)
        commit = _record_text(record, "kernel_hash", index)
        row = rows.get(index)
        status = (row or {}).get("status", "missing")
        if not isinstance(status, str):
            raise ValueError(
                "result row %d has a non-string status %r" % (index, status)
            )
        compiler = record.get("compiler") or "?"
        target_key = str((row or {}).get("target_key", "?"))[:16]
        by_arch[(architecture, status)] += 1
        by_compiler[(compiler, status)] += 1
        by_tree_branch[(tree_name, branch, status)] += 1
        if status != "pass":
            failures.append(
                {
                    "index": index,
                    "status": status,
                    "arch": architecture,
                    "compiler": record.get("compiler"),
                    "config": config,
                    "branch": branch,
                    "commit": commit[:12],
                    "target_key": target_key,
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
    except (OSError, ValueError) as error:
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
