"""Synthetic fixtures used only for tests, never written as pilot observations."""
from copy import deepcopy

from vul_pipeline.mechanism_extractor import assemble_record


def claim(description, status="inferred", refs=None, external=False, kind="descriptive"):
    return {"description": description, "status": status,
            "origin": "source_code" if status == "confirmed" else "external_context" if status == "unknown" else "derivation",
            "condition_kind": kind, "evidence_refs": refs or [], "assumptions": [],
            "rationale": "derived from the copy and its size argument" if status == "inferred" else "",
            "unknown_reason": "caller capacity contract is unavailable" if status == "unknown" else "",
            "depends_on_external_context": external,
            "additional_information": ["caller allocation extent"] if external or status == "unknown" else []}


def row(sid="fixture_copy"):
    signature = "void copy(char *dst, const char *src, size_t n, size_t cap)"
    return {"sample_id": sid, "dataset": "synthetic_test_only", "project": "test/project", "cve": "", "cwe": ["CWE-787"],
        "fix_commit": "fixture_commit", "vulnerability_type": "bounds_write",
        "code_before": signature + " {\n  memcpy(dst, src, n);\n}\n",
        "code_after": signature + " {\n  if (n > cap) return;\n  memcpy(dst, src, n);\n}\n",
        "unsafe_behavior": "copy may exceed writable capacity", "security_change": "reject length exceeding capacity",
        "keep_reason": "Local copy extent only; actual capacity is a caller contract.  ",
        "review_annotations": {"repair_pattern": "length_or_capacity_check", "locations": {
            "before": [{"source_text": "  memcpy(dst, src, n);"}],
            "after": [{"source_text": "  if (n > cap) return;"}]}}, "pair_provenance": {}}


def source(rows=None):
    return {"schema_version": 2, "rag_knowledge_text_generated": False,
            "heldout_exclusion": {"final_overlap_counts": {"CVE": 0, "fix_commit": 0, "project": 0}},
            "samples": rows or [row()]}


def stages():
    roles = [{"id": key, "meaning": meaning,
              "bindings": [{"version": "before", "expression": expression,
                            "evidence_refs": [evidence]}],
              "claim": claim(meaning, "inferred", [evidence])}
             for key, meaning, expression, evidence in (
                 ("destination", "writable destination", "dst", "review_before_0"),
                 ("length", "copy extent", "n", "review_before_0"),
                 ("capacity", "claimed capacity, actual extent unverified", "cap", "signature"))]
    one = {"dangerous_operation": {"category": "buffer_write",
        "semantics": claim("copies bytes into destination", "confirmed", ["review_before_0"]), "roles": roles},
        "applicability_conditions": [
            {"id": "a_type", "category": "type_and_range", "claim": claim("length and claimed capacity have size_t type", "confirmed", ["signature"])},
            {"id": "a_capacity", "category": "function_contract", "claim": claim("claimed capacity is no greater than writable object extent", "unknown", external=True)}],
        "trigger_conditions": [{"id": "t_copy", "behavior": claim("copy length exceeds writable capacity", kind="sufficient"),
             "relation_kind": "numeric", "role_refs": ["length", "capacity"], "applicability_refs": ["a_type", "a_capacity"],
             "formalization": "partial", "expression": "length > capacity"}],
        "evidence": [{"id": "signature", "version": "before", "source_text": "void copy(char *dst, const char *src, size_t n, size_t cap)", "origin": "model_quote"}]}
    two = {"safety_counterevidence": {
        "security_property": claim("copy length does not exceed actual writable capacity", kind="sufficient"),
        "safeguards": [{"id": "g_patch", "mechanism": "reject oversized copy", "origin": "actual_patch",
            "claim": claim("returns when n is greater than cap", "confirmed", ["review_after_0"]),
            "trigger_refs": ["t_copy"], "prerequisites": [claim("cap reflects true object extent", "unknown", external=True)],
            "required_evidence_refs": ["task_capacity", "task_path"]},
            {"id": "g_candidate", "mechanism": "grow destination before copy", "origin": "derived_candidate",
             "claim": claim("successful sufficient allocation can meet the copy extent", kind="candidate"),
             "trigger_refs": ["t_copy"], "prerequisites": [claim("allocation succeeds and aliases are updated", "unknown", external=True)],
             "required_evidence_refs": ["task_capacity"]}],
        "insufficient_guards": [{"mechanism": "nonnull destination alone", "reason": claim("nonnull does not bound writable extent"), "trigger_refs": ["t_copy"]}]},
        "required_program_evidence": [
            {"id": "task_capacity", "evidence_type": "function_contract", "role_refs": ["capacity"], "trigger_refs": ["t_copy"],
             "question": "does cap bound the destination object?", "suggested_analysis": "inspect caller allocation and contract",
             "function_source_sufficient": False, "missing_evidence_action": "keep_unknown"},
            {"id": "task_path", "evidence_type": "control_flow", "role_refs": ["length"], "trigger_refs": ["t_copy"],
             "question": "does rejection dominate the copy?", "suggested_analysis": "build intraprocedural CFG and check dominance",
             "function_source_sufficient": True, "missing_evidence_action": "keep_unknown"}],
        "boundaries": {"assumptions": [claim("capacity contract requires caller evidence", "unknown", external=True)],
                       "not_applicable": ["operation does not write a finite destination"],
                       "undecidable": ["caller allocation extent unavailable"]}, "evidence": []}
    return deepcopy(one), deepcopy(two)


def record(sample=None):
    one, two = stages()
    return assemble_record(sample or row(), one, two, "test-model")
