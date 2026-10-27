"""Bounded repair-pair pilot: precheck -> smoke gate -> extraction -> review artifacts."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit

from build_vulnerability_knowledge import validate_source_samples
from vul_pipeline.deepseek import DeepSeekClient, DeepSeekConfig
from vul_pipeline.knowledge_base import SecurityConditionKnowledgeBase
from vul_pipeline.mechanism_baseline import extract_baseline, validate_baseline
from vul_pipeline.mechanism_evaluator import evaluate_pilot
from vul_pipeline.mechanism_extractor import ExtractionConfig, MechanismExtractor
from vul_pipeline.mechanism_io import log_name, read_json, write_json
from vul_pipeline.mechanism_sampler import select_samples, sampling_manifest
from vul_pipeline.mechanism_schema import KNOWLEDGE_SCHEMA
from vul_pipeline.mechanism_validator import validate_knowledge

ARTIFACT_NAMES = ("selected_samples.json", "sample_distribution.json", "selected_source.json",
    "mechanism_knowledge.json", "baseline_knowledge.json", "validation_results.json",
    "comparison_results.json", "manual_review.csv", "quality_report.md", "runtime.json", "knowledge_schema.json")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="六层漏洞机制知识小规模试验（最多40组，默认先3组冒烟）")
    parser.add_argument("--input", type=Path, default=Path("data/high_quality_repair_pairs.json"))
    parser.add_argument("--output-dir", "--output", type=Path, default=Path("artifacts/mechanism_pilot"))
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--selected-ids", type=Path, help="JSON ID列表，或本程序 selected_samples.json")
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--base-url", default="https://api.deepseek.com")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--max-tokens", type=int, default=6000)
    parser.add_argument("--max-input-chars", type=int, default=180000)
    parser.add_argument("--retries", type=int, default=1, help="每阶段额外重试0..2次")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-failed", action="store_true", help="续跑时显式重新尝试失败样本；每次仍有重试上限")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--precheck", action="store_true", help="验证数据、抽样和生成待审核报告；不调用API")
    mode.add_argument("--validate-only", action="store_true", help="只校验既有记录、重新生成报告；不调用API")
    parser.add_argument("--smoke-count", type=int, default=3, choices=(2, 3))
    parser.add_argument("--baseline", type=Path, default=Path("artifacts/security_condition_knowledge.json"))
    parser.add_argument("--build-baseline", action="store_true", help="为缺失的同集合基线调用原始五字段提取法")
    parser.add_argument("--input-price-per-million", type=float)
    parser.add_argument("--output-price-per-million", type=float)
    return parser.parse_args(argv)


def _load_records(path: Path, rows: list[dict]) -> list[dict]:
    records = read_json(path) if path.exists() else []
    if not isinstance(records, list):
        raise ValueError(f"{path}: expected a JSON list")
    ids = [r.get("source_sample_id") for r in records if isinstance(r, dict)]
    if len(ids) != len(records) or len(set(ids)) != len(ids):
        raise ValueError(f"{path}: invalid or duplicate record IDs")
    if set(ids) - {row["sample_id"] for row in rows}:
        raise ValueError(f"{path}: records outside selected cohort")
    return records


def _load_logs(directory: Path, rows: list[dict]) -> list[dict]:
    return [read_json(directory / log_name(row["sample_id"])) for row in rows
            if (directory / log_name(row["sample_id"])).exists()]


def run(args) -> dict:
    # Validate budgets before reading, writing or making any network call.
    if not 1 <= args.count <= 40 or not 0 <= args.retries <= 2:
        raise ValueError("count must be 1..40; retries must be 0..2")
    if not 0 < args.timeout <= 180 or not 1000 <= args.max_tokens <= 16000:
        raise ValueError("timeout must be (0,180]; max-tokens must be 1000..16000")
    for price in (args.input_price_per_million, args.output_price_per_million):
        if price is not None and (not 0 <= price < float("inf")):
            raise ValueError("token prices must be finite and nonnegative")
    url = urlsplit(args.base_url)
    if url.scheme not in {"http", "https"} or not url.netloc or url.username or url.password or url.query or url.fragment:
        raise ValueError("base-url must be an HTTP(S) endpoint without credentials, query or fragment")
    if args.retry_failed and not args.resume:
        raise ValueError("--retry-failed requires --resume")
    source_path, output = args.input.resolve(), args.output_dir.resolve()
    if any((output / name).resolve() == source_path for name in ARTIFACT_NAMES):
        raise ValueError("output would overwrite the input source")
    raw = source_path.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    source = read_json(source_path)
    rows = validate_source_samples(source)
    if args.selected_ids:
        ids = read_json(args.selected_ids)
        if isinstance(ids, dict):
            if ids.get("source_sha256", source_hash) != source_hash:
                raise ValueError("selected IDs refer to a different source hash")
            ids = ids.get("sample_ids")
        if not isinstance(ids, list) or not all(isinstance(sid, str) for sid in ids):
            raise ValueError("selected IDs must be a string list")
        if len(ids) != args.count or len(set(ids)) != len(ids):
            raise ValueError("selected ID count mismatch or duplicates")
        by_id = {r["sample_id"]: r for r in rows}
        if set(ids) - by_id.keys():
            raise ValueError("selected ID not present in source")
        selected = [by_id[sid] for sid in ids]
    else:
        selected = select_samples(rows, args.count, args.seed)
    selection = {"seed": args.seed, "source_sha256": source_hash,
                 "sample_ids": [row["sample_id"] for row in selected]}
    selection_path = output / "selected_samples.json"
    if selection_path.exists() and read_json(selection_path) != selection:
        raise ValueError("output directory belongs to another cohort/seed/source; choose a new directory")
    records_path = output / "mechanism_knowledge.json"
    log_dir = output / "extraction_logs"
    baseline_log_dir = output / "baseline_logs"
    records = _load_records(records_path, selected)
    logs = _load_logs(log_dir, selected)
    if not (args.resume or args.precheck or args.validate_only) and (records or logs):
        raise ValueError("existing extraction artifacts: use --resume or a new output directory")
    baseline = _load_records(output / "baseline_knowledge.json", selected)
    old_by_id = {r["source_sample_id"]: validate_baseline(r, next(row for row in selected if row["sample_id"] == r["source_sample_id"])) for r in baseline}
    if args.baseline.exists() and args.baseline.resolve() != (output / "baseline_knowledge.json").resolve():
        kb = SecurityConditionKnowledgeBase.load(args.baseline)
        cohort = {r["sample_id"]: r for r in selected}
        for record in kb.records:
            if record.source_sample_id in cohort:
                candidate = validate_baseline(record.to_dict(), cohort[record.source_sample_id])
                if record.source_sample_id in old_by_id and old_by_id[record.source_sample_id] != candidate:
                    raise ValueError("conflicting baseline records for the same sample")
                old_by_id[record.source_sample_id] = candidate
    manifest = sampling_manifest(source, rows, selected, args.seed, source_hash)
    if args.selected_ids:
        manifest["method"] = "使用显式固定 ID 集合；原始选择种子保存在 selected_samples.json。"
    write_json(selection_path, selection)
    write_json(output / "sample_distribution.json", manifest)
    write_json(output / "selected_source.json", {**source, "samples": selected})
    write_json(output / "knowledge_schema.json", KNOWLEDGE_SCHEMA)
    baseline = [old_by_id[r["sample_id"]] for r in selected if r["sample_id"] in old_by_id]
    write_json(output / "baseline_knowledge.json", baseline)
    key_available = bool(os.environ.get(args.api_key_env, "").strip())
    runtime = {"mode": "precheck" if args.precheck else "validate_only" if args.validate_only else "extract",
               "api_key_configured": key_available, "model_requested": args.model,
               "smoke_sample_count": min(args.smoke_count, len(selected)), "smoke_gate": "not_run",
               "max_new_calls_this_run": len(selected) * 2 * (args.retries + 1) if not (args.precheck or args.validate_only) and key_available else 0,
               "max_baseline_calls_this_run": (len(selected) - len(baseline)) * (args.retries + 1) if args.build_baseline and not (args.precheck or args.validate_only) and key_available else 0,
               "planned_new_calls_without_retry": 2 * (len(selected) - len(records)),
               "source_sha256_verified_unchanged": False,
               "blockers": []}

    def finish():
        if hashlib.sha256(source_path.read_bytes()).hexdigest() != source_hash:
            raise RuntimeError("source file changed during pilot")
        runtime["source_sha256_verified_unchanged"] = True
        current_logs = _load_logs(log_dir, selected)
        current_baseline_logs = _load_logs(baseline_log_dir, selected)
        write_json(records_path, records)
        write_json(output / "runtime.json", runtime)
        return evaluate_pilot(output, selected, records, baseline, current_logs, current_baseline_logs,
                              manifest, runtime, args.input_price_per_million, args.output_price_per_million)

    if args.precheck or args.validate_only:
        if not key_available:
            runtime["blockers"].append(f"{args.api_key_env} 未配置，真实 API 提取未执行")
        return finish()
    if not key_available:
        runtime["blockers"].append(f"{args.api_key_env} 未配置，真实 API 提取未执行")
        return finish()
    client = DeepSeekClient(DeepSeekConfig(model=args.model, base_url=args.base_url,
                           api_key_env=args.api_key_env, max_tokens=args.max_tokens, timeout=args.timeout))
    extractor = MechanismExtractor(client, ExtractionConfig(args.model, args.retries, args.max_input_chars))
    by_id = {r["source_sample_id"]: r for r in records}
    for row in selected:
        if row["sample_id"] in by_id:
            check = validate_knowledge(by_id[row["sample_id"]], row)
            if check["status"] == "invalid":
                raise ValueError(f"{row['sample_id']}: existing record no longer validates")
            log_path = log_dir / log_name(row["sample_id"])
            if not log_path.exists():
                raise ValueError("resume requires per-sample extraction log")
            saved = read_json(log_path)
            if saved.get("identity", {}).get("extractor") != extractor.identity:
                raise ValueError("resume model/config/prompt mismatch")
            if saved.get("record") != by_id[row["sample_id"]]:
                raise ValueError("resume aggregate record differs from its completed generation log")
    # Recover a completed per-sample checkpoint if interruption preceded aggregate save.
    for row in selected:
        path = log_dir / log_name(row["sample_id"])
        if row["sample_id"] not in by_id and path.exists():
            saved = read_json(path)
            if saved.get("status") == "completed" and saved.get("record"):
                record, _ = extractor.extract(row, saved, lambda value, p=path: write_json(p, value))
                if record:
                    by_id[row["sample_id"]] = record
    records = [by_id[r["sample_id"]] for r in selected if r["sample_id"] in by_id]
    write_json(records_path, records)

    def extract_one(row):
        nonlocal records
        sid = row["sample_id"]
        if sid in by_id:
            return True
        path = log_dir / log_name(sid)
        saved = read_json(path) if path.exists() else None
        if saved and saved.get("status") in {"failed", "invalid"} and not args.retry_failed:
            return False
        if saved and args.retry_failed and saved.get("status") == "invalid":
            # Retain old attempts for cost accounting, but request fresh outputs.
            for stage in saved.get("stages", {}).values():
                stage["status"] = "retry_requested"
        record, log = extractor.extract(row, saved, lambda value: write_json(path, value))
        if record:
            by_id[sid] = record
            records = [by_id[r["sample_id"]] for r in selected if r["sample_id"] in by_id]
            write_json(records_path, records)
        print(f"{sid}: {log['status']}", flush=True)
        return record is not None

    # A partial/failed smoke blocks the remaining cohort, including baseline API calls.
    smoke_results = [extract_one(row) for row in selected[:args.smoke_count]]
    if not all(smoke_results):
        runtime["smoke_gate"] = "failed"
        runtime["blockers"].append("冒烟样本未全部通过，未启动剩余集合提取")
        return finish()
    runtime["smoke_gate"] = "passed"
    for row in selected[args.smoke_count:]:
        extract_one(row)
    if args.build_baseline:
        for row in selected:
            sid = row["sample_id"]
            if sid in old_by_id:
                continue
            path = baseline_log_dir / log_name(sid)
            saved = read_json(path) if path.exists() else None
            if saved and saved.get("status") == "failed" and not args.retry_failed:
                continue
            if saved and saved.get("status") == "completed":
                record = validate_baseline(saved["record"], row)
            else:
                def save_baseline(value):
                    # Same redaction policy as the mechanism ledger.
                    write_json(path, extractor._redact(value))
                record, _ = extract_baseline(client, row, args.retries, saved, save_baseline)
            if record:
                old_by_id[sid] = record
                baseline = [old_by_id[r["sample_id"]] for r in selected if r["sample_id"] in old_by_id]
                write_json(output / "baseline_knowledge.json", baseline)
    records = [by_id[r["sample_id"]] for r in selected if r["sample_id"] in by_id]
    if len(records) != len(selected):
        runtime["blockers"].append(f"{len(selected) - len(records)} 个样本未生成有效知识；详见逐样本日志")
    if args.build_baseline and len(baseline) != len(selected):
        runtime["blockers"].append(f"{len(selected) - len(baseline)} 条基线仍缺失；详见 baseline_logs")
    return finish()


def main(argv=None):
    args = parse_args(argv)
    try:
        report = run(args)
    except (ValueError, RuntimeError, OSError) as error:
        raise SystemExit(str(error)) from error
    print(f"selected={report['selected_sample_count']} valid={report['valid_knowledge_count']} baseline={report['baseline_available_count']}")
    print(args.output_dir / "quality_report.md")
    if report["runtime"]["blockers"] and not (args.precheck or args.validate_only):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
