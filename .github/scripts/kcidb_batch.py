#!/usr/bin/env python3
"""Validate a KCIDB build snapshot and prepare a resumable Actions batch."""

import argparse
import hashlib
import json
import os
import sys

MIN_TARGETS = 10_001
BATCH_SIZE = 256
IDENTITY_FIELDS = (
    "kernel_hash",
    "git_repository_url",
    "kernel_branch",
    "tree_name",
    "architecture",
    "config_name",
    "device_class",
)
REQUIRED_FIELDS = (
    "build_id",
    "checkout_id",
    "kernel_version",
    "kernel_hash",
    "kernel_branch",
    "git_repository_url",
    "tree_name",
    "device_class",
    "architecture",
    "config_name",
    "config_url",
)


def _required_text(record, field, row_number):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"row {row_number}: missing non-empty {field}")
    return value.strip()


def load_snapshot(path):
    with open(path, encoding="utf-8") as stream:
        payload = json.load(stream)

    if isinstance(payload, dict):
        records = payload.get("records")
        source_counts = payload.get("source_counts")
        if not isinstance(records, list) or not isinstance(source_counts, dict):
            raise ValueError("manifest must contain records and source_counts")
    elif isinstance(payload, list):
        records = payload
        source_counts = None
    else:
        raise ValueError("KCIDB query output must be a JSON array or manifest object")

    if not records:
        raise ValueError("KCIDB query returned no eligible builds")

    normalized = []
    identities = set()
    build_ids = set()
    metadata = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"row {index}: expected a JSON object")
        for field in REQUIRED_FIELDS:
            _required_text(record, field, index)
        if record["device_class"] not in {"ranchu", "oem_consumer"}:
            raise ValueError(
                f"row {index}: unsupported device_class {record['device_class']!r}"
            )
        valid = record.get("valid")
        if valid is not True and str(valid).lower() != "true":
            raise ValueError(f"row {index}: build {record['build_id']} is not valid")

        identity = tuple(record[field] for field in IDENTITY_FIELDS)
        if identity in identities:
            raise ValueError(f"duplicate device/kernel identity in row {index}")
        identities.add(identity)
        if record["build_id"] in build_ids:
            raise ValueError(f"duplicate build_id {record['build_id']!r}")
        build_ids.add(record["build_id"])

        count_fields = (
            "source_unique_count",
            "source_ranchu_count",
            "source_consumer_count",
        )
        if all(record.get(field) is not None for field in count_fields):
            metadata.add(
                (
                    int(record["source_unique_count"]),
                    int(record["source_ranchu_count"]),
                    int(record["source_consumer_count"]),
                )
            )

        normalized.append(record)

    if len(normalized) < MIN_TARGETS:
        raise ValueError(
            f"KCIDB returned {len(normalized)} unique targets; "
            f"at least {MIN_TARGETS} are required"
        )

    ranchu_count = sum(r["device_class"] == "ranchu" for r in normalized)
    consumer_count = sum(r["device_class"] == "oem_consumer" for r in normalized)
    if not ranchu_count or not consumer_count:
        raise ValueError(
            "KCIDB snapshot must contain both Ranchu and consumer builds"
        )

    if metadata:
        if len(metadata) != 1:
            raise ValueError("inconsistent source counts in KCIDB query result")
        total, ranchu_total, consumer_total = metadata.pop()
    elif source_counts is not None:
        total = int(source_counts["unique"])
        ranchu_total = int(source_counts["ranchu"])
        consumer_total = int(source_counts["oem_consumer"])
    else:
        total, ranchu_total, consumer_total = (
            len(normalized),
            ranchu_count,
            consumer_count,
        )

    if total != len(normalized):
        raise ValueError(
            f"snapshot contains {len(normalized)} targets but the query reports "
            f"{total}; refusing an incomplete manifest"
        )
    if ranchu_total < ranchu_count or consumer_total < consumer_count:
        raise ValueError("per-class source counts are smaller than the snapshot")

    return {
        "source": "kernelci-production.kernelci_production",
        "source_counts": {
            "unique": total,
            "ranchu": ranchu_total,
            "oem_consumer": consumer_total,
        },
        "selected_count": len(normalized),
        "records": normalized,
    }


def target_key(record):
    raw = "\0".join(str(record[field]) for field in IDENTITY_FIELDS)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def make_matrix(manifest, offset):
    records = manifest["records"]
    if offset < 0 or offset >= len(records):
        raise ValueError(
            f"batch offset {offset} is outside the manifest "
            f"(0..{len(records) - 1})"
        )

    end = min(offset + BATCH_SIZE, len(records))
    matrix = {
        "include": [
            {"index": index, "target_key": target_key(records[index])}
            for index in range(offset, end)
        ]
    }
    return matrix, end


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="KCIDB JSON or prior manifest")
    parser.add_argument("--manifest", required=True, help="output snapshot manifest")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--matrix-output", required=True)
    args = parser.parse_args()

    manifest = load_snapshot(args.input)
    with open(args.manifest, "w", encoding="utf-8") as stream:
        json.dump(manifest, stream, separators=(",", ":"))
        stream.write("\n")

    matrix, end = make_matrix(manifest, args.offset)
    with open(args.matrix_output, "w", encoding="utf-8") as stream:
        json.dump(matrix, stream, separators=(",", ":"))
        stream.write("\n")

    source = manifest["source_counts"]
    print(
        f"KCIDB: {manifest['selected_count']} unique compile targets "
        f"({source['ranchu']} Ranchu, {source['oem_consumer']} consumer "
        f"available); batch {args.offset}:{end}"
    )
    print(f"Next batch offset: {end}")
    with open(os.environ.get("GITHUB_OUTPUT", os.devnull), "a", encoding="utf-8") as out:
        out.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
        out.write(f"next_offset={end}\n")
        out.write(f"batch_end={end}\n")
        out.write(f"target_count={manifest['selected_count']}\n")
    with open(os.environ.get("GITHUB_STEP_SUMMARY", os.devnull), "a", encoding="utf-8") as summary:
        summary.write(
            f"KCIDB compile batch `{args.offset}:{end}` of "
            f"`{manifest['selected_count']}` unique targets.\n\n"
            f"Manifest source counts: `{source['unique']}` total, "
            f"`{source['ranchu']}` Ranchu, "
            f"`{source['oem_consumer']}` consumer.\n\n"
        )
        if end < manifest["selected_count"]:
            summary.write(
                f"To resume, dispatch this workflow with `manifest_run_id` set "
                f"to the current run ID and `batch_offset` set to `{end}`.\n"
            )
        else:
            summary.write("This batch includes every target in the manifest.\n")
    print(json.dumps(matrix, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"KCIDB batch preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
