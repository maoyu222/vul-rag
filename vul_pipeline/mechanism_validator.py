"""Source grounding and conservative consistency checks, not a static analyzer."""
from __future__ import annotations

import re
from collections import Counter
from difflib import SequenceMatcher

from .mechanism_io import fingerprint
from .mechanism_schema import KNOWLEDGE_SCHEMA, validate_shape, walk_claims


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def source_contains(source: str, fragment: str) -> bool:
    source, fragment = normalize_newlines(source), normalize_newlines(fragment)
    if not fragment.strip():
        return False
    if re.fullmatch(r"[A-Za-z_]\w*", fragment):
        return re.search(r"(?<!\w)" + re.escape(fragment) + r"(?!\w)", source) is not None
    return fragment in source


def quote_touches_change(row: dict, evidence: dict) -> bool:
    side = evidence["version"]
    source = normalize_newlines(row["code_" + side])
    fragment = normalize_newlines(evidence["source_text"])
    intervals = []
    start = source.find(fragment)
    while start >= 0:
        intervals.append((start, start + len(fragment)))
        start = source.find(fragment, start + 1)
    a, b = normalize_newlines(row["code_before"]), normalize_newlines(row["code_after"])
    # autojunk=False avoids dropping repeated punctuation in C/C++ functions.
    for tag, i, j, k, l in SequenceMatcher(None, a.splitlines(True), b.splitlines(True), autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        lines, lo, hi = (a.splitlines(True), i, j) if side == "before" else (b.splitlines(True), k, l)
        if lo == hi:
            continue
        left, right = sum(map(len, lines[:lo])), sum(map(len, lines[:hi]))
        if any(x < right and y > left for x, y in intervals):
            return True
    return False


def validate_knowledge(value: dict, row: dict) -> dict:
    errors, warnings = [], []
    result = {"source_sample_id": row["sample_id"], "status": "invalid",
              "errors": errors, "warnings": warnings, "source_evidence": [],
              "claim_status_counts": {}, "diff_alignment": "unknown",
              "semantic_correctness": "not_reviewed", "safety_correctness": "not_reviewed"}
    try:
        validate_shape(value, KNOWLEDGE_SCHEMA)
    except ValueError as error:
        errors.append(str(error))
        return result
    p = value["provenance_and_boundaries"]
    expected = {"source_sample_id": row["sample_id"], "source_fingerprint": fingerprint(row),
                "source_project": row.get("project") or "", "dataset": row.get("dataset") or "",
                "cve": row.get("cve") or "", "cwe": row.get("cwe") or [],
                "fix_commit": row.get("fix_commit") or "", "file_path": row.get("file_path") or "",
                "function_name": row.get("function_name") or "", "keep_reason": row["keep_reason"],
                "code_before": row["code_before"], "code_after": row["code_after"],
                "review_annotations": row["review_annotations"], "pair_provenance": row.get("pair_provenance") or {}}
    for key, expected_value in expected.items():
        if p[key] != expected_value:
            errors.append(f"provenance mismatch: {key}")
    if value["source_sample_id"] != row["sample_id"]:
        errors.append("source_sample_id mismatch")
    if value["mechanism_type"] != row["vulnerability_type"]:
        errors.append("mechanism_type mismatch")

    def index(items, label):
        ids = [item["id"] for item in items]
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate {label} id")
        return {item["id"]: item for item in items}

    evidence = index(value["evidence"], "evidence")
    roles = index(value["dangerous_operation"]["roles"], "role")
    apps = index(value["applicability_conditions"], "applicability")
    triggers = index(value["trigger_conditions"], "trigger")
    tasks = index(value["required_program_evidence"], "evidence task")
    index(value["safety_counterevidence"]["safeguards"], "safeguard")

    def refs(items, table, label):
        if len(items) != len(set(items)):
            errors.append(f"duplicate reference: {label}")
        for item in items:
            if item not in table:
                errors.append(f"dangling {label} reference: {item}")

    for key, item in evidence.items():
        source = normalize_newlines(row["code_" + item["version"]])
        fragment = normalize_newlines(item["source_text"])
        valid = source_contains(source, fragment)
        position = source.find(fragment) if valid else -1
        result["source_evidence"].append({"id": key, "version": item["version"], "valid": valid,
            "start_line": source[:position].count("\n") + 1 if valid else None,
            "end_line": source[:position + len(fragment)].count("\n") + 1 if valid else None})
        if not valid:
            errors.append(f"evidence {key} not present in code_{item['version']}")
        if item["origin"] == "review_location":
            snippets = [normalize_newlines(x["source_text"]) for x in row["review_annotations"]["locations"][item["version"]]]
            if fragment not in snippets:
                errors.append(f"evidence {key} falsely attributed to review_location")
    if {item["version"] for item in evidence.values()} != {"before", "after"}:
        errors.append("evidence must cover both versions")

    # Only inspect the knowledge claims, never interpret untrusted code/annotations.
    claims = list(walk_claims({key: value[key] for key in (
        "dangerous_operation", "applicability_conditions", "trigger_conditions", "safety_counterevidence")}))
    claims += list(walk_claims(p["boundaries"], "$.boundaries"))
    result["claim_status_counts"] = dict(Counter(claim["status"] for _, claim in claims))
    for path, claim in claims:
        refs(claim["evidence_refs"], evidence, "source evidence")
        if claim["status"] == "confirmed":
            if claim["origin"] != "source_code" or not claim["evidence_refs"]:
                errors.append(f"{path}: confirmed requires source_code evidence")
            if claim["depends_on_external_context"]:
                errors.append(f"{path}: external dependency cannot be confirmed from this pair")
        if claim["status"] == "inferred" and not claim["rationale"].strip():
            errors.append(f"{path}: inferred requires derivation rationale")
        if claim["status"] == "unknown":
            if not claim["unknown_reason"].strip() or not claim["additional_information"]:
                errors.append(f"{path}: unknown requires reason and missing information")
        elif claim["unknown_reason"].strip():
            errors.append(f"{path}: known claim has unknown_reason")
        if claim["depends_on_external_context"] and not claim["additional_information"]:
            errors.append(f"{path}: external context requires information request")
        if claim["origin"] == "derivation" and claim["status"] == "confirmed":
            errors.append(f"{path}: derivation is not a source fact")

    for role in roles.values():
        for binding in role["bindings"]:
            refs(binding["evidence_refs"], evidence, "binding evidence")
            if not binding["evidence_refs"]:
                errors.append(f"role {role['id']}: binding requires evidence")
            if not source_contains(row["code_" + binding["version"]], binding["expression"]):
                errors.append(f"role {role['id']}: expression not present in binding version")
            for ref in binding["evidence_refs"]:
                if ref in evidence and (evidence[ref]["version"] != binding["version"] or
                    not source_contains(evidence[ref]["source_text"], binding["expression"])):
                    errors.append(f"role {role['id']}: binding evidence does not contain expression in same version")
        if role["claim"]["status"] == "confirmed" and not role["bindings"]:
            errors.append(f"role {role['id']}: confirmed role has no bindings")

    for trigger in triggers.values():
        refs(trigger["role_refs"], roles, "trigger role")
        refs(trigger["applicability_refs"], apps, "trigger applicability")
        if trigger["formalization"] != "none" and not (trigger["expression"] or "").strip():
            errors.append(f"trigger {trigger['id']}: formalization requires expression")
        if trigger["formalization"] == "none" and trigger["expression"] is not None:
            errors.append(f"trigger {trigger['id']}: unformalized expression must be null")
        if trigger["formalization"] == "formal" and trigger["relation_kind"] == "numeric":
            related = [apps[ref] for ref in trigger["applicability_refs"] if ref in apps]
            if not any(x["category"] == "type_and_range" for x in related):
                errors.append(f"trigger {trigger['id']}: numeric formalization lacks type/range premise")
        if trigger["behavior"]["status"] != "unknown" and not trigger["role_refs"]:
            errors.append(f"trigger {trigger['id']}: resolved trigger has no semantic roles")
    for task in tasks.values():
        refs(task["role_refs"], roles, "task role")
        refs(task["trigger_refs"], triggers, "task trigger")
        if not task["role_refs"] and not task["trigger_refs"]:
            errors.append(f"task {task['id']}: no role or trigger connection")

    changed_patch = False
    for guard in value["safety_counterevidence"]["safeguards"]:
        refs(guard["trigger_refs"], triggers, "safeguard trigger")
        refs(guard["required_evidence_refs"], tasks, "safeguard evidence task")
        if not guard["trigger_refs"] or not guard["required_evidence_refs"]:
            errors.append(f"safeguard {guard['id']}: requires trigger and verification tasks")
        claim = guard["claim"]
        if guard["origin"] == "actual_patch":
            after = [evidence[ref] for ref in claim["evidence_refs"]
                     if ref in evidence and evidence[ref]["version"] == "after"]
            if claim["status"] != "unknown" and not after:
                errors.append(f"safeguard {guard['id']}: actual patch requires after evidence")
            changed_patch |= any(quote_touches_change(row, item) for item in after)
        else:
            if not guard["prerequisites"]:
                errors.append(f"safeguard {guard['id']}: candidate lacks prerequisites")
            expected_status = "inferred" if guard["origin"] == "derived_candidate" else "unknown"
            if claim["status"] != expected_status:
                errors.append(f"safeguard {guard['id']}: candidate/unverified cannot be historical fact")
            if guard["origin"] == "derived_candidate" and claim["origin"] != "derivation":
                errors.append(f"safeguard {guard['id']}: candidate requires derivation origin")
        if claim["condition_kind"] == "necessary":
            warnings.append(f"safeguard {guard['id']}: necessity of a concrete implementation requires manual review")
    for guard in value["safety_counterevidence"]["insufficient_guards"]:
        refs(guard["trigger_refs"], triggers, "insufficient guard trigger")

    # Deliberately narrow contradiction check: identical proposition cannot be
    # both a sufficient trigger and the sufficient safety property in this scope.
    safety = value["safety_counterevidence"]["security_property"]
    normalized = lambda s: " ".join(s.lower().split()).rstrip(".;")
    for trigger in triggers.values():
        if (trigger["behavior"]["status"] != "unknown" and safety["status"] != "unknown"
                and normalized(trigger["behavior"]["description"]) == normalized(safety["description"])):
            errors.append("identical trigger and safety proposition; contradictory scopes require revision")
    result["diff_alignment"] = "changed_patch_quote_present" if changed_patch else "unknown"
    if not changed_patch:
        warnings.append("no actual_patch quote overlaps changed lines; semantic diff relevance remains unknown")
    if not roles:
        warnings.append("semantic roles unresolved")
    result["condition_consistency_scope"] = "引用关系、状态约束及相同触发/安全命题检查；未执行 SMT、路径或类型分析"
    if not errors:
        partial = bool(result["claim_status_counts"].get("unknown") or not roles
                       or not value["safety_counterevidence"]["safeguards"])
        result["status"] = "valid_partial_unknown" if partial else "valid_complete"
    return result
