"""Observable quality proxies and review support. Never fabricates semantic scores."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path

from .mechanism_io import atomic_text, fingerprint, write_json
from .mechanism_schema import walk_claims
from .mechanism_validator import source_contains, validate_knowledge

COMPARISON_DIMENSIONS = ["dangerous_operation_correctness", "semantic_roles_correctness",
    "applicability_correctness", "trigger_precision", "safety_counterevidence_correctness",
    "source_evidence_correctness", "verifiability", "unsupported_assertions"]
REVIEW_FIELDS = [f"{method}_{key}" for method in ("old", "new") for key in COMPARISON_DIMENSIONS]
REVIEW_FIELDS += ["better_knowledge", "reviewer", "review_notes", "review_status"]


def ratio(numerator: int, denominator: int) -> dict:
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def summarize_cost(logs: list[dict], input_price: float | None = None,
                   output_price: float | None = None) -> dict:
    attempts = [a for log in logs for stage in log.get("stages", {}).values()
                for a in stage.get("attempts", [])]
    groups = {}
    known, unknown, estimated = 0, 0, 0.0
    for attempt in attempts:
        response = attempt.get("response") or {}
        usage = response.get("usage") or {}
        model = response.get("model") or "not_reported"
        group = groups.setdefault(model, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                                          "prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 0})
        group["calls"] += 1
        if all(type(usage.get(key)) is int and usage[key] >= 0 for key in ("prompt_tokens", "completion_tokens")):
            known += 1
            for key in ("prompt_tokens", "completion_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens"):
                if type(usage.get(key)) is int and usage[key] >= 0:
                    group[key] += usage[key]
            if input_price is not None and output_price is not None:
                estimated += (usage["prompt_tokens"] * input_price + usage["completion_tokens"] * output_price) / 1e6
        else:
            unknown += 1
    return {"attempted_calls": len(attempts), "usage_reported_calls": known,
            "usage_unknown_calls": unknown, "by_response_model": groups,
            "input_price_per_million_user_supplied": input_price,
            "output_price_per_million_user_supplied": output_price,
            "priced_known_usage_subtotal": round(estimated, 8) if input_price is not None and output_price is not None else None,
            "complete_cost_known": bool(attempts) and unknown == 0 and input_price is not None and output_price is not None,
            "note": "价格由用户提供；统一输入价不区分缓存折扣；无用量的超时/失败调用仍可能计费。已有基线未附日志时历史成本未知。"}


def old_observables(old: dict | None, row: dict) -> dict | None:
    if old is None:
        return None
    quotes = [(side, text) for side in ("before", "after") for text in old.get(side + "_evidence", [])]
    valid = sum(source_contains(row["code_" + side], text) for side, text in quotes)
    return {"operation_recorded": bool(old.get("operation")), "role_count": len(old.get("roles", {})),
            "trigger_text_recorded": bool(old.get("unsafe_when")),
            "safety_property_recorded": bool(old.get("security_condition")),
            "target_fact_requests": len(old.get("required_target_facts", [])),
            "quote_existence": ratio(valid, len(quotes)),
            "semantic_correctness": "not_reviewed"}


def new_observables(new: dict | None, validation: dict) -> dict | None:
    if new is None or validation["status"] == "invalid":
        return None
    triggers = new["trigger_conditions"]
    tasks = new["required_program_evidence"]
    guards = new["safety_counterevidence"]["safeguards"]
    claims = [c for _, c in walk_claims({k: new[k] for k in (
        "dangerous_operation", "applicability_conditions", "trigger_conditions", "safety_counterevidence")})]
    claims.extend(c for _, c in walk_claims(new["provenance_and_boundaries"]["boundaries"]))
    generic = {"missing bounds check", "missing boundary check", "missing appropriate checks", "缺少边界检查", "缺少适当检查"}
    generic_flags = [c["id"] for c in triggers
                     if c["behavior"]["description"].strip().lower().rstrip(".;。") in generic]
    return {"operation_recorded": new["dangerous_operation"]["semantics"]["status"] != "unknown",
            "role_count": len(new["dangerous_operation"]["roles"]),
            "linked_resolved_triggers": sum(c["behavior"]["status"] != "unknown" and bool(c["role_refs"])
                                             and bool(c["applicability_refs"]) for c in triggers),
            "formalized_triggers": sum(c["formalization"] != "none" for c in triggers),
            "generic_trigger_wording_flags": generic_flags,
            "explicit_type_range_premises": sum(c["category"] == "type_and_range" for c in new["applicability_conditions"]),
            "future_analysis_tasks": len(tasks),
            "function_local_tasks": sum(task["function_source_sufficient"] for task in tasks),
            "unknown_claims": sum(c["status"] == "unknown" for c in claims),
            "inferred_claims": sum(c["status"] == "inferred" for c in claims),
            "safeguard_origins": dict(Counter(c["origin"] for c in guards)),
            "diff_alignment": validation["diff_alignment"], "semantic_correctness": "not_reviewed",
            "specificity_note": "关系引用、前提和分析任务是可操作性代理，不是机制正确率；不按文本长度评分。"}


def review_csv(path: Path, rows: list[dict], new_by_id: dict, old_by_id: dict) -> dict:
    previous = {}
    if path.exists():
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for record in csv.DictReader(handle):
                if record["sample_id"] in previous:
                    raise ValueError("duplicate sample ID in manual_review.csv")
                previous[record["sample_id"]] = record
        if set(previous) - {row["sample_id"] for row in rows}:
            raise ValueError("manual review contains IDs outside selected samples; refusing to overwrite")
    fields = ["sample_id", "review_input_fingerprint", "cwe", "mechanism", "key_before_source", "key_after_source",
              "old_knowledge_summary", "new_knowledge_summary"] + REVIEW_FIELDS
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    reviewed, ratings = 0, []
    for row in rows:
        sid = row["sample_id"]
        new, old = new_by_id.get(sid), old_by_id.get(sid)
        summary = {key: new[key] for key in ("dangerous_operation", "applicability_conditions", "trigger_conditions",
                    "safety_counterevidence", "required_program_evidence")} if new else None
        record = {"sample_id": sid, "cwe": ",".join(row.get("cwe") or []) or "not_recorded",
                  "review_input_fingerprint": fingerprint([row, new, old]),
                  "mechanism": row["vulnerability_type"],
                  "key_before_source": "\n\n".join(x["source_text"] for x in row["review_annotations"]["locations"]["before"]),
                  "key_after_source": "\n\n".join(x["source_text"] for x in row["review_annotations"]["locations"]["after"]),
                  "old_knowledge_summary": json.dumps(old, ensure_ascii=False) if old else "missing",
                  "new_knowledge_summary": json.dumps(summary, ensure_ascii=False) if new else "not_extracted"}
        for field in REVIEW_FIELDS:
            record[field] = previous.get(sid, {}).get(field, "not_reviewed" if field == "review_status" else "")
        if (record["review_status"] == "reviewed" and previous[sid].get("review_input_fingerprint")
                != record["review_input_fingerprint"]):
            # Preserve annotations but do not reuse ratings for changed knowledge.
            record["review_status"] = "stale_needs_review"
        if record["review_status"] == "reviewed":
            reviewed += 1
            ratings.append({"sample_id": sid, **{field: record[field] for field in REVIEW_FIELDS}})
        writer.writerow(record)
    atomic_text(path, "\ufeff" + buffer.getvalue())
    return {"reviewed_count": reviewed, "ratings": ratings,
            "note": "仅 review_status=reviewed 的用户填写记录计入审核数；系统不产生人工分数。"}


def evaluate_pilot(output: Path, rows: list[dict], records: list[dict], baseline: list[dict],
                   logs: list[dict], baseline_logs: list[dict], manifest: dict,
                   runtime: dict, input_price=None, output_price=None) -> dict:
    new_by_id = {r["source_sample_id"]: r for r in records}
    old_by_id = {r["source_sample_id"]: r for r in baseline}
    logs_by_id = {r["source_sample_id"]: r for r in logs}
    validations, comparisons = [], []
    for row in rows:
        sid = row["sample_id"]
        new, old, log = new_by_id.get(sid), old_by_id.get(sid), logs_by_id.get(sid, {})
        if new is not None:
            v = validate_knowledge(new, row)
        elif log.get("validation"):
            v = log["validation"]
        else:
            v = {"source_sample_id": sid, "status": "extraction_failed" if log.get("status") == "failed" else "not_extracted",
                 "errors": [log["error"]] if log.get("error") else [], "warnings": [],
                 "source_evidence": [], "claim_status_counts": {}, "diff_alignment": "unknown"}
        validations.append(v)
        comparisons.append({"source_sample_id": sid, "baseline_available": old is not None,
            "new_available": new is not None and v["status"].startswith("valid_"),
            "old_observables": old_observables(old, row),
            "new_observables": new_observables(new, v),
            "semantic_comparison": {key: "not_reviewed" for key in COMPARISON_DIMENSIONS},
            "better": "not_reviewed"})
    review = review_csv(output / "manual_review.csv", rows, new_by_id, old_by_id)
    quotes = [e for v in validations for e in v["source_evidence"]]
    statuses = dict(Counter(v["status"] for v in validations))
    claims = Counter()
    for v in validations:
        claims.update(v["claim_status_counts"])
    valid_ids = [v["source_sample_id"] for v in validations if v["status"].startswith("valid_")]
    valid_records = [new_by_id[sid] for sid in valid_ids if sid in new_by_id]
    guard_origins = Counter(g["origin"] for r in valid_records for g in r["safety_counterevidence"]["safeguards"])
    task_types = Counter(t["evidence_type"] for r in valid_records for t in r["required_program_evidence"])
    specificity = {"operation_resolved_records": sum(c["new_observables"]["operation_recorded"] for c in comparisons if c["new_observables"]),
        "records_with_roles": sum(bool(r["dangerous_operation"]["roles"]) for r in valid_records),
        "linked_resolved_triggers": sum(c["new_observables"]["linked_resolved_triggers"] for c in comparisons if c["new_observables"]),
        "generic_trigger_wording_flags": sum(len(c["new_observables"]["generic_trigger_wording_flags"]) for c in comparisons if c["new_observables"]),
        "safeguard_origins": dict(guard_origins), "future_evidence_task_types": dict(task_types),
        "unsupported_assertion_count": None,
        "note": "不以输出长度或字段数评分；空泛措辞是待审标志；这些可观测代理不衡量语义准确性或模型幻觉总量。"}
    report = {"selected_sample_count": len(rows), "validation_status_counts": statuses,
              "source_audit": manifest.get("selected_source_audit"),
              "valid_knowledge_count": len(valid_ids), "serialized_record_count": len(records),
              "model_extraction_completed_count": sum(log.get("status") in {"completed", "invalid"} for log in logs),
              "source_quote_existence": ratio(sum(e["valid"] for e in quotes), len(quotes)),
              "claim_status_counts": dict(claims),
              "diff_changed_quote_count": sum(v["diff_alignment"] == "changed_patch_quote_present" for v in validations),
              "validation_warning_count": sum(len(v["warnings"]) for v in validations),
              "specificity_and_verifiability_observables": specificity,
              "baseline_available_count": len(old_by_id),
              "paired_available_count": sum(r["baseline_available"] and r["new_available"] for r in comparisons),
              "manual_review": review,
              "new_cost": summarize_cost(logs, input_price, output_price),
              "baseline_cost": summarize_cost(baseline_logs, input_price, output_price),
              "baseline_missing_additional_calls_without_retry": len(rows) - len(old_by_id),
              "runtime": runtime, "comparisons": comparisons,
              "interpretation": "自动指标仅衡量结构、引用存在性及可操作性代理；新旧字段数量不计分；所有语义准确率和无依据断言总量均待人工审核。"}
    write_json(output / "validation_results.json", validations)
    write_json(output / "comparison_results.json", report)
    text = ["# 漏洞机制知识提取试验报告", "",
        "## 1. 实验目标", "验证安全反证、适用前提和程序证据需求的六层知识表示；不改变漏洞检测决策逻辑。", "",
        "## 2. 数据来源与抽样", f"原始样本数：{manifest['source_count']}；本次固定选择：{len(rows)}；种子：{manifest['seed']}。",
        manifest["method"], manifest["limitations"],
        f"原始数据 SHA-256：`{manifest['source_sha256']}`。完整 ID 见 selected_samples.json。", "",
        "原始样本完整性检查（与新知识引用检查分别统计）：", "```json",
        json.dumps({"population": manifest.get("population_source_audit"), "selected": manifest.get("selected_source_audit")}, ensure_ascii=False, indent=2), "```", "",
        "## 3. 样本分布", "```json", json.dumps(manifest["selected"], ensure_ascii=False, indent=2), "```", "",
        "## 4. 旧五字段基线", f"同集合已有基线：{len(old_by_id)}/{len(rows)}；新旧同时可用：{report['paired_available_count']}。",
        "基线由原构建器的五字段提示词产生或从原知识库按 ID 读取，绝不从新知识转换。缺失项不判错；语义比较保持未审核。",
        f"补齐缺失基线至少需 {report['baseline_missing_additional_calls_without_retry']} 次调用（不含重试）；历史成本无日志时未知。", "",
        "## 5. 新表示与方法", "dangerous_operation、applicability_conditions、trigger_conditions、safety_counterevidence、required_program_evidence、provenance_and_boundaries。",
        "两阶段 JSON 调用；源码/审核说明是数据而非指令。程序复制原始 keep_reason、完整源码、审核标注及来源；逐次调用持久化日志，逐样本原子保存。", "",
        "## 6. 实际提取情况", f"有效知识：{len(valid_ids)}；状态计数：`{json.dumps(statuses, ensure_ascii=False)}`。",
        f"运行状态：`{json.dumps(runtime, ensure_ascii=False)}`。",
        "只有实际返回且通过校验的记录计入有效知识；预检查不会产生占位知识。", "",
        "## 7. 源码引用校验", f"引用存在性：`{json.dumps(report['source_quote_existence'])}`。",
        "按 before/after 检查连续原文（只归一化换行）；引用存在不证明语义、控制支配、可达性或别名关系成立。", "",
        "## 8. 未知与失败", f"声明状态：`{json.dumps(dict(claims))}`。校验警告数：{report['validation_warning_count']}。"]
    failures = [v for v in validations if v["status"] in {"invalid", "extraction_failed"}]
    for v in failures[:5]:
        text.append(f"- `{v['source_sample_id']}`：{'; '.join(v['errors'])}")
    text.extend(["", "## 9. 修复前后对照", f"实际补丁引用与变更行重叠的记录：{report['diff_changed_quote_count']}；其余未知。",
        "此指标只验证差分位置关联；安全性质是否充分仍需人工或后续程序分析。修复不代表整个函数无漏洞。", "",
        "## 10. 安全反证检查", "验证防护关联触发 ID 与证据任务、候选防护前提和推导状态；具体实现被声称为必要防护时告警。",
        "没有执行类型推断、数据流、别名、生命周期、路径或同步分析，未输出已证明等价的防护。", "",
        "机制明确性、反证与可验证性的自动可观测量：", "```json",
        json.dumps(specificity, ensure_ascii=False, indent=2), "```", "",
        "## 11. 公平比较与成本", report["interpretation"],
        "```json", json.dumps({"new": report["new_cost"], "baseline": report["baseline_cost"]}, ensure_ascii=False, indent=2), "```", "",
        "## 12. 代表性有效案例"])
    if valid_ids:
        for sid in valid_ids[:2]:
            row, knowledge = next(r for r in rows if r["sample_id"] == sid), new_by_id[sid]
            text.extend([f"### {sid}", "该记录通过自动结构与引用检查；尚未确认语义正确。",
                knowledge["dangerous_operation"]["semantics"]["description"],
                "修复前：", "```c", row["review_annotations"]["locations"]["before"][0]["source_text"], "```",
                "修复后：", "```c", row["review_annotations"]["locations"]["after"][0]["source_text"], "```"])
    else:
        text.append("暂无实际有效提取记录，不能给出成功案例。")
    text.extend(["", "## 13. 代表性失败或未执行案例"])
    if failures:
        v = failures[0]
        row = next(r for r in rows if r["sample_id"] == v["source_sample_id"])
        text.extend([f"样本 `{v['source_sample_id']}`：{'；'.join(v['errors'])}",
                     "```c", row["review_annotations"]["locations"]["before"][0]["source_text"], "```"])
    else:
        text.append("没有记录实际提取失败；未执行样本不冒充模型失败案例。")
        if not valid_ids:
            row = rows[0]
            text.extend([f"待提取样本 `{row['sample_id']}` 的原始审核证据（未形成新知识）：",
                         "```c", row["review_annotations"]["locations"]["before"][0]["source_text"], "```"])
    text.extend(["", "## 14. 人工审核", f"已标记人工审核：{review['reviewed_count']}；详见 manual_review.csv。",
        "人工评分由用户填写，系统保留既有评分；未审核时不能声称准确率提升，也不能以模型判断冒充人工审核。", "",
        "## 15. 局限与下一步", "抽样优先多样性，不能推断总体准确率；缺失外部类型、宏、契约或调用上下文时保留未知。",
        "先完成真实 API 冒烟测试，再提取固定集合、生成独立旧基线并逐条人工审核；未来可按证据任务接入程序分析。",
        "复现步骤见 docs/MECHANISM_PILOT_GUIDE.md；所有数字来自本次 artifact，不包含模拟测试结果。", ""])
    atomic_text(output / "quality_report.md", "\n".join(text))
    return report
