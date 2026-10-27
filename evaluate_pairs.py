from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from vul_pipeline.detector import VulnerabilityDetector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate vulnerable/patched function pairs")
    parser.add_argument("--cases", type=Path, default=Path("data/paired_evaluation_cases.json"))
    parser.add_argument("--metadata", type=Path, default=Path("data/paired_evaluation_metadata.json"))
    parser.add_argument("--knowledge", type=Path, default=Path("artifacts/security_condition_knowledge.json"))
    parser.add_argument("--model-path", type=Path, default=Path.home() / "models/Qwen2.5-Coder-7B-Instruct")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/pair_evaluation"))
    parser.add_argument("--endpoint")
    parser.add_argument("--endpoint-model")
    parser.add_argument("--max-new-tokens", type=int, default=1024)
    parser.add_argument("--retrieve-k", type=int, default=10)
    parser.add_argument("--limit-pairs", type=int, default=0)
    parser.add_argument("--compare-code-only", action="store_true")
    return parser.parse_args()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def metric(numerator: int, denominator: int) -> dict:
    return {"numerator": numerator, "denominator": denominator, "value": numerator / denominator if denominator else None}


def binary_metrics(rows: list[dict]) -> dict:
    tp = sum(row["expected_label"] == "vulnerable" and row["predicted_label"] == "vulnerable" for row in rows)
    fp = sum(row["expected_label"] == "benign" and row["predicted_label"] == "vulnerable" for row in rows)
    fn = sum(row["expected_label"] == "vulnerable" and row["predicted_label"] != "vulnerable" for row in rows)
    tn = sum(row["expected_label"] == "benign" and row["predicted_label"] == "benign" for row in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": metric(sum(row["predicted_label"] == row["expected_label"] for row in rows), len(rows)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "unknown": sum(row["predicted_label"] == "unknown" for row in rows),
        "execution_errors": sum(row["predicted_label"] is None for row in rows),
    }


def validate_evaluation_inputs(cases: list[dict], metadata: list[dict]) -> None:
    if len(cases) != len(metadata):
        raise ValueError("pair evaluation cases and metadata counts differ")
    seen_sample_ids: set[str] = set()
    for index, (case, sample) in enumerate(zip(cases, metadata), start=1):
        if not isinstance(case, dict) or not isinstance(sample, dict):
            raise ValueError(f"pair {index}: case and metadata must both be JSON objects")
        sample_id = str(sample.get("sample_id", "")).strip()
        if not sample_id:
            raise ValueError(f"pair {index}: metadata contains an empty sample_id")
        if sample_id in seen_sample_ids:
            raise ValueError(f"duplicate pair evaluation sample_id: {sample_id}")
        seen_sample_ids.add(sample_id)
        case_cve = str(case.get("cve_id", "")).strip()
        metadata_cve = str(sample.get("cve_id", "")).strip()
        case_cwe = str(case.get("cwe_id", "")).strip()
        metadata_cwe = str(sample.get("cwe_id", "")).strip()
        if case_cve != metadata_cve or case_cwe != metadata_cwe:
            raise ValueError(
                f"{sample_id}: case/metadata mismatch at pair {index}: "
                f"case identifiers=({case_cve!r}, {case_cwe!r}), "
                f"metadata identifiers=({metadata_cve!r}, {metadata_cwe!r})"
            )
        function_name = str(sample.get("function_name", "")).strip()
        if not function_name:
            raise ValueError(f"{sample_id}: metadata contains an empty function_name")
        function_pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(function_name)}\s*\(")
        for code_key in ("code_before_change", "code_after_change"):
            code = case.get(code_key)
            if not isinstance(code, str) or not code.strip():
                raise ValueError(f"{sample_id}: missing {code_key}")
            if function_pattern.search(code) is None:
                raise ValueError(f"{sample_id}: {code_key} does not contain metadata function {function_name!r}; case/metadata ordering may be wrong")


def pair_results(rows: list[dict]) -> tuple[list[dict], dict]:
    by_sample: dict[str, dict[str, dict]] = {}
    for row in rows:
        sample_id = str(row.get("sample_id", "")).strip()
        variant = str(row.get("variant", "")).strip()
        if not sample_id:
            raise ValueError("pair result row has an empty sample_id")
        if variant not in {"vulnerable", "patched"}:
            raise ValueError(f"{sample_id}: unexpected pair variant {variant!r}")
        variants = by_sample.setdefault(sample_id, {})
        if variant in variants:
            raise ValueError(f"{sample_id}: duplicate {variant} result")
        variants[variant] = row
    pairs = []
    for sample_id, variants in by_sample.items():
        if set(variants) != {"vulnerable", "patched"}:
            raise ValueError(f"{sample_id}: pair evaluation requires both variants")
        vulnerable = variants["vulnerable"]
        patched = variants["patched"]
        pairs.append({
            "sample_id": sample_id,
            "vulnerable_prediction": vulnerable["predicted_label"],
            "patched_prediction": patched["predicted_label"],
            "exact_correct": vulnerable["predicted_label"] == "vulnerable" and patched["predicted_label"] == "benign",
        })
    return pairs, metric(sum(item["exact_correct"] for item in pairs), len(pairs))


def main() -> None:
    args = parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not isinstance(metadata, list):
        raise ValueError("pair evaluation cases and metadata must be JSON lists")
    if args.limit_pairs < 0:
        raise ValueError("limit_pairs must not be negative")
    if args.limit_pairs > 0:
        cases = cases[: args.limit_pairs]
        metadata = metadata[: args.limit_pairs]
    validate_evaluation_inputs(cases, metadata)

    detector = VulnerabilityDetector(
        args.knowledge, args.model_path, retrieve_k=args.retrieve_k,
        endpoint=args.endpoint, endpoint_model=args.endpoint_model,
        max_new_tokens=args.max_new_tokens,
    )
    write_json(args.output_dir / "runtime.json", detector.model.runtime_info())
    rows = []
    code_only_rows = []
    for case, sample in zip(cases, metadata):
        sample_id = str(sample["sample_id"]).strip()
        for variant, code_key, expected_label in (
            ("vulnerable", "code_before_change", "vulnerable"),
            ("patched", "code_after_change", "benign"),
        ):
            code = str(case[code_key])
            stage_dir = args.output_dir / sample_id / variant
            result = detector.detect(code, debug_dir=stage_dir, sample_metadata={
                "sample_id": sample_id,
                "variant": variant,
                "file_path": sample.get("file_path", ""),
                "function_name": sample.get("function_name", ""),
            })
            retrieval_path = stage_dir / "retrieval_results.json"
            retrieval = json.loads(retrieval_path.read_text(encoding="utf-8")) if retrieval_path.is_file() else {"results": []}
            rows.append({
                "sample_id": sample_id,
                "variant": variant,
                "expected_label": expected_label,
                "predicted_label": result.label,
                "status": result.status,
                "correct": result.label == expected_label,
                "retrieved_source_sample_ids": [item.get("source_sample_id", "") for item in retrieval.get("results", [])],
                "condition_results": result.condition_results,
                "explanation": result.explanation,
            })
            if args.compare_code_only:
                baseline = detector.detect_code_only(code)
                write_json(stage_dir / "code_only_generation.json", detector.model.last_generation)
                write_json(stage_dir / "code_only_result.json", baseline.to_dict())
                code_only_rows.append({
                    "sample_id": sample_id,
                    "variant": variant,
                    "expected_label": expected_label,
                    "predicted_label": baseline.label,
                })
            print(f"evaluated {sample_id} {variant}: expected={expected_label} predicted={result.label}", flush=True)

    pairs, pair_exact = pair_results(rows)
    summary = {
        "experiment": "security_condition_pair_evaluation",
        "knowledge_record_count": len(detector.knowledge.records),
        "sample_count": len(cases),
        "variant_count": len(rows),
        "retrieve_k": args.retrieve_k,
        "metrics": {"classification": binary_metrics(rows), "pair_exact_accuracy": pair_exact},
        "predicted_label_counts": dict(sorted(Counter(row["predicted_label"] or "execution_error" for row in rows).items())),
        "pair_results": pairs,
        "results": rows,
        "paired_test_note": (
            "The patched variant is the expected negative for the linked repaired vulnerability in this diagnostic pair test. "
            "This does not prove that the entire patched function is free of every possible vulnerability."
        ),
    }
    if args.compare_code_only:
        _, baseline_pair_exact = pair_results(code_only_rows)
        summary["code_only_metrics"] = {
            "classification": binary_metrics(code_only_rows),
            "pair_exact_accuracy": baseline_pair_exact,
        }
    write_json(args.output_dir / "summary.json", summary)
    write_json(args.output_dir / "predictions.json", rows)
    print(json.dumps(summary["metrics"], indent=2))


if __name__ == "__main__":
    main()
