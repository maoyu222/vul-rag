from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


def _string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a JSON list")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} items must be strings")
        text = item.strip()
        if text:
            result.append(text)
    return result


def _string_dict(value: Any, field_name: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError(f"{field_name} keys and values must be strings")
        key_text = key.strip()
        item_text = item.strip()
        if key_text and item_text:
            result[key_text] = item_text
    return result


@dataclass
class SecurityConditionKnowledge:
    """One reviewed historical repair expressed as a reusable security condition."""

    source_sample_id: str
    source_project: str
    source_fix_commit: str
    cve_id: str
    cwe_ids: list[str]
    vulnerability_type: str
    repair_pattern: str

    operation: str
    roles: dict[str, str]
    unsafe_when: str
    security_condition: str
    required_target_facts: list[str]
    assumptions: list[str]
    before_evidence: list[str]
    after_evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SecurityConditionKnowledge":
        if not isinstance(value, dict):
            raise ValueError("knowledge record must be a JSON object")

        required_text = (
            "source_sample_id",
            "vulnerability_type",
            "repair_pattern",
            "operation",
            "unsafe_when",
            "security_condition",
        )
        normalized = {key: str(value.get(key, "")).strip() for key in required_text}
        missing = [key for key, item in normalized.items() if not item]
        if missing:
            raise ValueError(f"knowledge record missing required fields: {missing}")

        roles = _string_dict(value.get("roles", {}), "roles")
        if not roles:
            raise ValueError("knowledge record requires at least one role")

        required_target_facts = _string_list(
            value.get("required_target_facts", []), "required_target_facts"
        )
        if not required_target_facts:
            raise ValueError("knowledge record requires required_target_facts")

        before_evidence = _string_list(value.get("before_evidence", []), "before_evidence")
        after_evidence = _string_list(value.get("after_evidence", []), "after_evidence")
        if not before_evidence or not after_evidence:
            raise ValueError("knowledge record requires reviewed before and after evidence")

        return cls(
            source_sample_id=normalized["source_sample_id"],
            source_project=str(value.get("source_project", "")).strip(),
            source_fix_commit=str(value.get("source_fix_commit", "")).strip(),
            cve_id=str(value.get("cve_id", "")).strip(),
            cwe_ids=_string_list(value.get("cwe_ids", []), "cwe_ids"),
            vulnerability_type=normalized["vulnerability_type"],
            repair_pattern=normalized["repair_pattern"],
            operation=normalized["operation"],
            roles=roles,
            unsafe_when=normalized["unsafe_when"],
            security_condition=normalized["security_condition"],
            required_target_facts=required_target_facts,
            assumptions=_string_list(value.get("assumptions", []), "assumptions"),
            before_evidence=before_evidence,
            after_evidence=after_evidence,
        )


@dataclass
class DetectionResult:
    label: str | None
    explanation: str
    retrieved_cves: list[str]
    condition_results: list[dict[str, Any]]
    status: str = "completed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
