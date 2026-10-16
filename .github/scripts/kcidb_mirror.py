#!/usr/bin/env python3
"""Fetch verified KernelCI build records from the public Maestro mirror.

The Maestro REST API (https://api.kernelci.org) serves reads without
authentication, unlike the BigQuery dataset which needs a privileged
service account. This script pages ``/nodes`` for passing kbuild nodes
on a given tree (default: android) and maps them onto the manifest
record schema consumed by ``kcidb_batch.py``.

Each record carries everything the compile step needs: source commit,
repository URL, branch, architecture, full defconfig name, a direct
``.config`` artifact URL, and the compiler. ``device_class`` is the
constant ``"maestro"`` (provenance, not a device claim): batch
validation treats an all-maestro manifest as its own coverage class.
"""

import argparse
import http.client
import json
import os
import re
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import build_kcidb_record
    import kcidb_batch

    SUPPORTED_ARCHES = frozenset(build_kcidb_record.TOOLCHAINS)
    MIN_TARGETS = kcidb_batch.MIN_TARGETS
except ImportError:  # pragma: no cover - defensive; tests run in-dir
    SUPPORTED_ARCHES = frozenset(
        {
            "aarch64",
            "arm64",
            "arm",
            "x86_64",
            "i386",
            "riscv",
            "riscv64",
            "mips",
            "mips64",
            "powerpc",
            "powerpc64",
            "s390x",
            "sparc64",
        }
    )
    MIN_TARGETS = 10_001

DEVICE_CLASS = "maestro"
DEFAULT_API_BASE = "https://api.kernelci.org/latest"
DEFAULT_TREE = "android"


def require_https(url, field):
    if not isinstance(url, str):
        raise ValueError(f"{field} must be an HTTPS URL without credentials")
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError(f"{field} must be an HTTPS URL without credentials")
    return url


def map_node(node):
    """Map one Maestro node object onto a manifest record, or None."""
    if not isinstance(node, dict):
        return None
    if node.get("kind") != "kbuild":
        return None
    if node.get("state") != "done" or node.get("result") != "pass":
        return None
    data = node.get("data")
    if not isinstance(data, dict):
        return None
    revision = data.get("kernel_revision")
    if not isinstance(revision, dict):
        return None

    commit = revision.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        return None
    try:
        repo_url = require_https(revision.get("url"), "kernel_revision.url")
        branch = revision.get("branch")
        tree = revision.get("tree")
        if not branch or not str(branch).strip():
            return None
        if not tree or not str(tree).strip():
            return None
    except ValueError:
        # require_https only raises ValueError (non-string inputs are
        # rejected by isinstance, never by attribute access), so nothing
        # broader is caught here.
        return None

    architecture = str(data.get("arch") or "").strip().lower()
    if architecture not in SUPPORTED_ARCHES:
        return None
    config_name = data.get("config_full") or data.get("defconfig")
    if not config_name or not str(config_name).strip():
        return None
    artifacts = node.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    try:
        config_url = require_https(artifacts.get("_config"), "artifacts._config")
    except ValueError:
        # Same as above: artifacts is a checked dict, require_https only
        # raises ValueError.
        return None
    compiler = data.get("compiler")
    if not compiler or not str(compiler).strip():
        return None
    build_id = node.get("id")
    checkout_id = node.get("parent")
    if not build_id or not checkout_id:
        return None
    describe = revision.get("describe") or ""
    version = str(describe).strip() or "%s@%s" % (branch, commit[:12])

    return {
        "build_id": str(build_id),
        "checkout_id": str(checkout_id),
        "kernel_version": version,
        "kernel_hash": commit.lower(),
        "kernel_branch": str(branch).strip(),
        "git_repository_url": repo_url,
        "tree_name": str(tree).strip(),
        "device_class": DEVICE_CLASS,
        "architecture": architecture,
        "config_name": str(config_name).strip(),
        "config_url": config_url,
        "compiler": str(compiler).strip(),
        "valid": True,
    }


def fetch_page(api_base, tree, limit, offset, timeout):
    params = urllib.parse.urlencode(
        {
            "kind": "kbuild",
            "data.kernel_revision.tree": tree,
            "result": "pass",
            "state": "done",
            "limit": limit,
            "offset": offset,
        }
    )
    url = "%s/nodes?%s" % (api_base.rstrip("/"), params)
    request = urllib.request.Request(
        url, headers={"User-Agent": "rwbridge-kernelci-mirror/1", "Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("mirror returned an unexpected nodes payload")
    return payload["items"]


def collect_manifest(api_base, tree, want_unique, page_size, timeout, max_pages):
    records = []
    seen = set()
    offset = 0
    for _ in range(max_pages):
        items = fetch_page(api_base, tree, page_size, offset, timeout)
        if not items:
            break
        offset += len(items)
        for node in items:
            record = map_node(node)
            if record is None:
                continue
            identity = tuple(
                record[field] for field in (
                    "kernel_hash",
                    "git_repository_url",
                    "kernel_branch",
                    "tree_name",
                    "architecture",
                    "config_name",
                    "device_class",
                )
            )
            if identity in seen:
                continue
            seen.add(identity)
            records.append(record)
            if len(records) >= want_unique:
                break
        if len(records) >= want_unique or len(items) < page_size:
            break
    if len(records) < MIN_TARGETS:
        raise ValueError(
            "mirror yielded %d unique targets; at least %d are required"
            % (len(records), MIN_TARGETS)
        )
    count = len(records)
    return {
        "source": "maestro-api",
        "source_counts": {
            "unique": count,
            "ranchu": 0,
            "oem_consumer": 0,
            "maestro": count,
        },
        "selected_count": count,
        "records": records,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--tree", default=DEFAULT_TREE)
    parser.add_argument("--want", type=int, default=MIN_TARGETS + 999)
    parser.add_argument("--page-size", type=int, default=200)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)

    manifest = collect_manifest(
        args.api_base, args.tree, args.want, args.page_size, args.timeout, args.max_pages
    )
    with open(args.manifest, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, separators=(",", ":"))
        stream.write("\n")
    print(
        "mirror: %d unique compile targets from %s (tree %s)"
        % (manifest["selected_count"], args.api_base, args.tree)
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, http.client.HTTPException) as error:
        print("KernelCI mirror fetch failed: %s" % error, file=sys.stderr)
        sys.exit(1)
