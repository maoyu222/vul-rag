#!/usr/bin/env python3
"""Full offline audit of normalized cohorts across datasets and official splits."""
import _bootstrap  # noqa: F401
import argparse
import collections
import json
import sqlite3
from pathlib import Path

from src.io_utils import append_json, atomic_json, file_hash, fresh_directory, open_new_jsonl
from src.leakage_check import SimilarityAudit
from src.readers import records
from src.schemas import normalize_sample


def audit(paths, output, near_limit=5000):
    out = fresh_directory(output)
    db = sqlite3.connect(out / "audit_index.sqlite3")
    db.execute("PRAGMA temp_store=MEMORY")
    db.execute("CREATE TABLE samples(sid TEXT PRIMARY KEY,dataset TEXT,version TEXT,split TEXT,pair TEXT,variant TEXT,label INTEGER,hash TEXT,cve TEXT,fix TEXT)")
    count, labels, near = 0, collections.Counter(), SimilarityAudit(max_reports=near_limit)
    try:
        with open_new_jsonl(out / "near_duplicate_candidates.jsonl") as log:
            for path in paths:
                for _, value in records(path, "jsonl"):
                    sample = normalize_sample(value)
                    if value.get("sample_hash") and sample["sample_hash"] != value["sample_hash"]:
                        raise ValueError("sample fingerprint mismatch")
                    try:
                        db.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?,?)", (sample["sample_id"], sample["dataset"], str(sample.get("dataset_version", "")), sample["split"], sample["pair_id"], sample["variant"], sample["label"], sample["normalized_code_hash"], sample["cve_id"].upper(), sample["fix_commit"].lower()))
                    except sqlite3.IntegrityError:
                        raise ValueError("duplicate sample_id across audit inputs: audit ordinary/paired and official/strict views separately") from None
                    labels[f"{sample['dataset']}@{sample.get('dataset_version', '')}/{sample['split']}/label={sample['label']}"] += 1
                    count += 1
                    for candidate in near.add(sample):
                        append_json(log, candidate)
        db.commit()
        counts = collections.Counter()
        with open_new_jsonl(out / "violations.jsonl") as log:
            for column, rule in (("hash", "normalized_code"), ("cve", "cve"), ("fix", "fix_commit")):
                for value, n, datasets, splits, distinct_labels in db.execute(f"SELECT {column},COUNT(*),COUNT(DISTINCT dataset),COUNT(DISTINCT split),COUNT(DISTINCT label) FROM samples WHERE {column}!='' GROUP BY {column} HAVING COUNT(*)>1"):
                    cross_dataset, cross_split = datasets > 1, splits > 1
                    if rule == "normalized_code" or cross_dataset or cross_split:
                        rows = db.execute(f"SELECT sid,dataset,version,split,label FROM samples WHERE {column}=? ORDER BY sid", (value,)).fetchall()
                        append_json(log, {"rule": rule, "value": value, "samples": rows, "cross_dataset": cross_dataset,
                            "cross_split": cross_split, "label_conflict": distinct_labels > 1 if rule == "normalized_code" else None})
                        counts[rule + "_duplicate_groups"] += 1
                        counts[rule + "_cross_dataset_groups"] += cross_dataset
                        counts[rule + "_cross_split_groups"] += cross_split
            for dataset, version, pair, n, variants, splits in db.execute("SELECT dataset,version,pair,COUNT(*),COUNT(DISTINCT variant),COUNT(DISTINCT split) FROM samples WHERE pair IS NOT NULL GROUP BY dataset,version,pair"):
                counts["pair_groups"] += 1
                if n != 2 or variants != 2 or splits != 1:
                    counts["invalid_or_cross_split_pairs"] += 1
                    append_json(log, {"rule": "pair_integrity", "dataset": dataset, "version": version, "pair_id": pair, "members": n, "variants": variants, "splits": splits})
        result = {"sample_count": count, "labels": dict(labels), "audit_counts": dict(counts),
            "inputs": [{"path": str(p.resolve()), "sha256": file_hash(p)} for p in paths],
            "near_duplicate_audit": {"reported": near.reported, "comparisons": near.comparison_count,
                                     "max_indexed": near.max_indexed, "unindexed_samples": near.unindexed_samples,
                                     "skipped_bucket_entries": near.skipped_bucket_entries, "limit": near_limit},
            "note": "只报告，不删除、不改写官方划分。近重复为有界词法候选审计，不能宣称全量语义去重。"}
        atomic_json(out / "audit_report.json", result)
        return result
    finally:
        db.close()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--near-duplicate-limit", type=int, default=5000)
    args = p.parse_args(argv)
    if args.near_duplicate_limit < 0:
        p.error("near-duplicate-limit must be nonnegative")
    print(json.dumps(audit(args.input, args.output, args.near_duplicate_limit), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
