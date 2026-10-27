"""Read-only bounded schema survey; does not import HTTP clients or call a model."""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import collections
import itertools
import json
import sqlite3
import tempfile
from pathlib import Path

from src.io_utils import EXPERIMENT_ROOT, atomic_json, canonical
from src.normalization import code_hash
from src.readers import records

DATA_ROOT = Path("/home/PublicData/PHY-data/vul_detect/data")
FILES = {
    "PrimeVul_v0.1": ["primevul_test.jsonl", "primevul_test_paired.jsonl", "primevul_train.jsonl", "primevul_valid.jsonl"],
    "PrimeVul_original": ["primevul_test.jsonl", "primevul_test_paired.jsonl"],
    "megavul": ["megavul.json"], "bigvul": ["MSR_data_cleaned.csv"],
    "diversevul": ["diversevul_20230702.json"], "devign": ["dataset.json"],
    "reveal": ["vulnerables.json", "non-vulnerables.json"],
    "cleanvul": ["vulnerability_score_4.csv"], "reposvul": ["ReposVul_c.jsonl"],
}


def describe(value, depth=0):
    if isinstance(value, dict):
        return {k: describe(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return {"type": "list", "length": len(value), "first": describe(value[0], depth + 1) if value and depth < 5 else None}
    if isinstance(value, str):
        return {"type": "str", "length": len(value), "preview": value[:120]}
    return {"type": type(value).__name__, "value": value}


def full_counts(path, dataset):
    """Raw histograms are not inferred binary labels, especially for scores/file targets."""
    fields = {"PrimeVul_v0.1": ("target", "func"), "PrimeVul_original": ("target", "func"),
              "megavul": ("is_vul", "func"), "devign": ("target", "func"),
              "diversevul": ("target", "func"), "bigvul": ("vul", "func_before"),
              "cleanvul": ("vulnerability_score", "func_before"), "reposvul": ("target", None),
              "reveal": (None, "code")}
    label_field, code_field = fields[dataset]
    labels, counts = collections.Counter(), collections.Counter()
    with tempfile.TemporaryDirectory(prefix="schema_count_") as directory:
        db = sqlite3.connect(Path(directory) / "hashes.sqlite3")
        try:
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("CREATE TABLE hashes(hash TEXT PRIMARY KEY,n INTEGER)")
            for _, row in records(path):
                counts["records"] += 1
                labels[canonical(row.get(label_field)) if label_field else "file:" + path.name] += 1
                code = row.get("func_before") if dataset == "megavul" and row.get("is_vul") is True else row.get(code_field)
                if isinstance(code, str) and code.strip():
                    db.execute("INSERT INTO hashes VALUES(?,1) ON CONFLICT(hash) DO UPDATE SET n=n+1", (code_hash(code),))
                else:
                    counts["missing_code_under_inspection_profile"] += 1
            counts["normalized_duplicate_groups"] = db.execute("SELECT COUNT(*) FROM hashes WHERE n>1").fetchone()[0]
            counts["normalized_extra_duplicate_rows"] = db.execute("SELECT COALESCE(SUM(n-1),0) FROM hashes WHERE n>1").fetchone()[0]
        finally:
            db.close()
    return {"counts": dict(counts), "raw_label_field": label_field, "raw_label_histogram": dict(labels),
            "note": "原始字段频次，不等于已验证二分类标签；ReposVul不把完整文件当函数，CleanVul分数不转二分类。"}


def main(argv=None):
    p = argparse.ArgumentParser(description="只读检查真实数据文件的字段与小样本，不运行模型")
    p.add_argument("--data-root", type=Path, default=DATA_ROOT)
    p.add_argument("--sample-records", type=int, default=3)
    p.add_argument("--dataset", action="append", choices=list(FILES), help="inspect selected directories only; repeatable")
    p.add_argument("--full-counts", action="store_true", help="stream entire selected files for counts/raw labels/lexical duplicate hashes; can be slow")
    p.add_argument("--output", type=Path, default=EXPERIMENT_ROOT / "inspection/dataset_inventory.json")
    args = p.parse_args(argv)
    if not 1 <= args.sample_records <= 100:
        p.error("sample-records must be 1..100")
    result = {"root": str(args.data_root), "exists": args.data_root.is_dir(),
              "scope": "bounded schema inspection, not full sample counts or label-semantic proof", "files": []}
    for dataset, names in FILES.items():
        if args.dataset and dataset not in args.dataset:
            continue
        for name in names:
            path = args.data_root / dataset / name
            info = {"dataset": dataset, "path": str(path), "exists": path.is_file()}
            if path.is_file():
                before = path.stat()
                try:
                    examples = list(itertools.islice(records(path), args.sample_records))
                    info.update(bytes=before.st_size, format="csv" if name.endswith(".csv") else
                                "array_or_jsonl", inspected_records=len(examples),
                                schemas=[describe(row) for _, row in examples])
                    if args.full_counts:
                        info["full_scan"] = full_counts(path, dataset)
                except (ValueError, OSError) as error:
                    info["inspection_error"] = str(error)
                after = path.stat()
                info["size_mtime_unchanged"] = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
            result["files"].append(info)
    result["other_directories"] = {name: {"exists": (args.data_root / name).exists(),
        "adapter_status": "not_enabled: parquet needs separate reader" if name == "SecVulEval" else
        "not_enabled: generation/context tasks require an explicit function-label mapping"}
        for name in ("SecVulEval", "sven")}
    atomic_json(args.output, result)
    print(args.output)


if __name__ == "__main__":
    main()
