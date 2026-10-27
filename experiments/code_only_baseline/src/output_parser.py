"""Strict local parsing: malformed/truncated answers never become negatives."""
import json
import re

OUTPUT_SCHEMA = {"type": "object", "additionalProperties": False,
    "required": ["label", "vulnerability_type", "evidence", "reason"],
    "properties": {"label": {"type": "string", "enum": ["vulnerable", "benign"]},
                   "vulnerability_type": {"type": "string"}, "evidence": {"type": "array", "items": {"type": "string"}},
                   "reason": {"type": "string"}}}


def failure(kind, detail=""):
    return {"status": "error", "predicted_label": None, "error_type": kind, "error_detail": detail,
            "vulnerability_type": "", "evidence": [], "reason": ""}


def parse_output(raw, code, finish_reason=None):
    if finish_reason == "length":
        return failure("truncated_output", "finish_reason=length; not converted to a binary prediction")
    if finish_reason not in {None, "stop"}:
        return failure("unexpected_finish_reason", str(finish_reason))
    if not isinstance(raw, str) or not raw.strip():
        return failure("empty_response")
    content = raw.strip()
    fence = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", content, flags=re.S | re.I)
    if fence:
        content = fence.group(1).strip()
    try:
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate JSON key: " + key)
                value[key] = item
            return value
        value = json.loads(content, object_pairs_hook=unique_object,
                           parse_constant=lambda x: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    except (ValueError, TypeError):
        return failure("invalid_json")
    if not isinstance(value, dict) or set(value) != set(OUTPUT_SCHEMA["required"]):
        return failure("invalid_fields", "expected exactly label/vulnerability_type/evidence/reason")
    if not isinstance(value["label"], str) or value["label"] not in {"vulnerable", "benign"}:
        return failure("invalid_label")
    if not isinstance(value["reason"], str) or not value["reason"].strip() or not isinstance(value["vulnerability_type"], str):
        return failure("invalid_field_type", "reason must be a nonempty string; vulnerability_type must be a string")
    evidence = value["evidence"]
    if not isinstance(evidence, list) or any(not isinstance(e, str) or not e.strip() for e in evidence):
        return failure("invalid_evidence_type")
    # Existence check only: this cannot validate semantic sufficiency of an argument.
    normalized = code.replace("\r\n", "\n")
    missing = [e for e in evidence if e.replace("\r\n", "\n") not in normalized]
    if missing:
        return failure("evidence_not_in_source", "one or more evidence strings are not literal source excerpts")
    return {"status": "success",
            "predicted_label": {"vulnerable": 1, "benign": 0}[value["label"]],
            "vulnerability_type": value["vulnerability_type"], "evidence": evidence, "reason": value["reason"],
            "evidence_check": "literal_excerpts_exist" if evidence else "no_excerpts_provided",
            "error_type": None, "error_detail": ""}
