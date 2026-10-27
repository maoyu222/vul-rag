#!/usr/bin/env python3
"""Evaluate a frozen run offline, including every selected but incomplete sample."""
import _bootstrap  # noqa: F401
import argparse
import json
import sqlite3
import tempfile
from pathlib import Path

from src.checkpoint import read_ledger
from src.io_utils import atomic_json, canonical, file_hash, fingerprint, output_path, utc_now
from src.metrics import Suite
from src.prompts import Prompt
from src.readers import records
from src.schemas import normalize_sample


def evaluate_run(run, minimum_support=20):
    config = json.loads((run / "run_config.json").read_text(encoding="utf-8"))
    if config.get("protocol") != Prompt.protocol:
        raise ValueError("evaluation requires the current strict binary protocol; use a matching run directory")
    if fingerprint({k: v for k, v in config.items() if k not in {"created_at", "config_hash"}}) != config.get("config_hash"):
        raise ValueError("run_config.json fingerprint mismatch")
    if file_hash(run / "samples.jsonl") != config["samples_sha256"]:
        raise ValueError("frozen cohort checksum differs from run_config.json")
    with tempfile.TemporaryDirectory(prefix="metrics_") as directory:
        db = sqlite3.connect(Path(directory) / "index.sqlite3")
        try:
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("CREATE TABLE gold(sid TEXT PRIMARY KEY, shash TEXT, payload TEXT)")
            db.execute("CREATE TABLE pred(sid TEXT PRIMARY KEY, payload TEXT)")
            for _, source in records(run / "samples.jsonl", "jsonl"):
                sample = normalize_sample(source)
                if sample["sample_hash"] != source.get("sample_hash"):
                    raise ValueError("frozen sample fingerprint mismatch")
                db.execute("INSERT INTO gold VALUES(?,?,?)", (sample["sample_id"], sample["sample_hash"], canonical(sample)))
            for result in read_ledger(run / "results.jsonl"):
                gold = db.execute("SELECT shash,payload FROM gold WHERE sid=?", (result.get("sample_id"),)).fetchone()
                if not gold or result.get("config_hash") != config["config_hash"] or result.get("sample_hash") != gold[0]:
                    raise ValueError("prediction has unknown ID or wrong sample/config fingerprint")
                if result.get("true_label") != json.loads(gold[1])["label"]:
                    raise ValueError("saved prediction gold label differs from frozen sample")
                db.execute("INSERT OR REPLACE INTO pred VALUES(?,?)", (result["sample_id"], canonical(result)))
            suite = Suite(minimum_support)
            for gold_text, pred_text in db.execute("SELECT g.payload,p.payload FROM gold g LEFT JOIN pred p ON g.sid=p.sid ORDER BY g.sid"):
                sample = json.loads(gold_text)
                prediction = json.loads(pred_text) if pred_text else {"status": "not_completed", "predicted_label": None}
                # Metadata/gold come from the frozen cohort, never from generated text.
                row = {**prediction, **{key: sample.get(key) for key in ("sample_id", "dataset", "dataset_version", "split", "pair_id", "variant", "cwe_ids")}, "true_label": sample["label"]}
                suite.add(row)
            report = suite.report()
            starts, ends, usage, missing = set(), set(), {k: 0 for k in ("prompt_tokens", "completion_tokens", "total_tokens")}, 0
            latency_sum, finished = 0, 0
            for event in read_ledger(run / "requests.jsonl"):
                if event.get("config_hash") != config["config_hash"]:
                    raise ValueError("request journal configuration mismatch")
                if event["event"] == "started":
                    starts.add(event["attempt_id"])
                elif event["event"] == "finished":
                    if event["attempt_id"] in ends:
                        raise ValueError("duplicate finished attempt ID")
                    ends.add(event["attempt_id"])
                    finished += 1
                    latency_sum += event.get("latency_ms", 0)
                    u = event.get("usage", {})
                    missing += any(u.get(k) is None for k in usage)
                    for key in usage:
                        if u.get(key) is not None:
                            usage[key] += u[key]
            report.update(config_hash=config["config_hash"], samples_sha256=config["samples_sha256"], evaluated_at=utc_now(),
                requests={"started_attempts": len(starts), "finished_attempts": finished, "interrupted_attempts": len(starts - ends),
                    "attempts_with_incomplete_usage": missing, "observed_token_lower_bounds": usage,
                    "usage_complete": not missing and not starts - ends,
                    "total_tokens": usage["total_tokens"] if not missing and not starts - ends else None,
                    "mean_finished_request_latency_ms": latency_sum / finished if finished else None})
            if report["sample_count"] != config["sample_count"]:
                raise ValueError("cohort sample count differs from run manifest")
            return report
        finally:
            db.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="default RUN_DIR/metrics.json; never overwrites predictions")
    parser.add_argument("--minimum-support", type=int, default=20)
    args = parser.parse_args(argv)
    if args.minimum_support < 1:
        parser.error("minimum support must be positive")
    target = output_path(args.output or args.run_dir / "metrics.json")
    if target.resolve() in {p.resolve() for p in (args.run_dir / "results.jsonl", args.run_dir / "samples.jsonl", args.run_dir / "run_config.json", args.run_dir / "requests.jsonl")}:
        parser.error("metrics output must not overwrite run inputs or ledgers")
    report = evaluate_run(args.run_dir, args.minimum_support)
    atomic_json(target, report)
    print(json.dumps({"sample_count": report["sample_count"], "metrics": str(target)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
