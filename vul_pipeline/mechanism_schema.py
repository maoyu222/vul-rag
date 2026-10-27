"""Versioned six-layer representation and dependency-free structural validation.

The exported schema uses a deliberately small JSON Schema subset. Every object
is closed and every property required; uncertainty is represented by Claim,
never by deleting keys. Semantic/evidence checks live in mechanism_validator.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Any

SCHEMA_VERSION = "1.0"
EVIDENCE_TYPES = ("source_location", "variable_definition", "def_use_relation", "data_flow",
                  "control_flow", "path_condition", "type_and_range", "alias_relation",
                  "object_lifetime", "function_contract", "synchronization")


def string(*choices: str, empty: bool = False) -> dict:
    result = {"type": "string", "minLength": 0 if empty else 1}
    if choices:
        result["enum"] = list(choices)
    return result


def array(item: dict, minimum: int = 0) -> dict:
    return {"type": "array", "items": item, "minItems": minimum}


def obj(**properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties),
            "additionalProperties": False}


TEXTS = array(string())
BOOL = {"type": "boolean"}
CLAIM = obj(
    description=string(), status=string("confirmed", "inferred", "unknown"),
    origin=string("source_code", "review_annotation", "derivation", "external_context"),
    condition_kind=string("necessary", "sufficient", "candidate", "descriptive"),
    evidence_refs=TEXTS, assumptions=TEXTS, rationale=string(empty=True),
    unknown_reason=string(empty=True), depends_on_external_context=BOOL,
    additional_information=TEXTS,
)
EVIDENCE = obj(id=string(), version=string("before", "after"), source_text=string(),
               origin=string("review_location", "model_quote"))
ROLE = obj(id=string(), meaning=string(), bindings=array(obj(
    version=string("before", "after"), expression=string(), evidence_refs=TEXTS)), claim=CLAIM)
OPERATION = obj(category=string(), semantics=CLAIM, roles=array(ROLE))
APPLICABILITY = array(obj(id=string(), category=string(
    "operation", "type_and_range", "object_state", "execution_path", "function_contract"),
    claim=CLAIM), 1)
TRIGGERS = array(obj(id=string(), behavior=CLAIM, relation_kind=string(
    "numeric", "state", "path", "alias", "temporal", "structured_natural_language"),
    role_refs=TEXTS, applicability_refs=TEXTS,
    formalization=string("none", "partial", "formal"),
    expression={"type": ["string", "null"]}), 1)
SAFEGUARD = obj(id=string(), mechanism=string(),
                origin=string("actual_patch", "derived_candidate", "unverified"),
                claim=CLAIM, trigger_refs=TEXTS, prerequisites=array(CLAIM),
                required_evidence_refs=TEXTS)
SAFETY = obj(security_property=CLAIM, safeguards=array(SAFEGUARD),
             insufficient_guards=array(obj(mechanism=string(), reason=CLAIM, trigger_refs=TEXTS)))
REQUIREMENTS = array(obj(id=string(), evidence_type=string(*EVIDENCE_TYPES), role_refs=TEXTS,
    trigger_refs=TEXTS, question=string(), suggested_analysis=string(),
    function_source_sufficient=BOOL, missing_evidence_action=string("keep_unknown")), 1)
BOUNDARIES = obj(assumptions=array(CLAIM), not_applicable=TEXTS, undecidable=TEXTS)

STAGE_ONE_SCHEMA = obj(dangerous_operation=OPERATION, applicability_conditions=APPLICABILITY,
                       trigger_conditions=TRIGGERS, evidence=array(EVIDENCE))
STAGE_TWO_SCHEMA = obj(safety_counterevidence=SAFETY, required_program_evidence=REQUIREMENTS,
                       boundaries=BOUNDARIES, evidence=array(EVIDENCE))
PROVENANCE = obj(
    source_sample_id=string(), source_fingerprint=string(), source_project=string(empty=True),
    dataset=string(empty=True), cve=string(empty=True), cwe=TEXTS, fix_commit=string(empty=True),
    file_path=string(empty=True), function_name=string(empty=True),
    keep_reason=string(), review_scope=string(),
    code_before=string(), code_after=string(),
    review_annotations={"type": "object"}, pair_provenance={"type": "object"},
    boundaries=BOUNDARIES, validation_status=string("not_semantically_reviewed"),
)
KNOWLEDGE_SCHEMA = obj(
    schema_version=string(SCHEMA_VERSION), knowledge_id=string(), source_sample_id=string(),
    mechanism_type=string(), extraction_model=string(),
    extraction_status=string("completed"),
    validation_status=string("pending", "valid_complete", "valid_partial_unknown", "invalid"),
    dangerous_operation=OPERATION, applicability_conditions=APPLICABILITY,
    trigger_conditions=TRIGGERS, safety_counterevidence=SAFETY,
    required_program_evidence=REQUIREMENTS, provenance_and_boundaries=PROVENANCE,
    evidence=array(EVIDENCE, 2),
)
KNOWLEDGE_SCHEMA["$schema"] = "https://json-schema.org/draft/2020-12/schema"


def validate_shape(value: Any, schema: dict, path: str = "$") -> None:
    """Validate precisely the subset used above, rejecting bool as integer, etc."""
    expected = schema["type"]
    types = expected if isinstance(expected, list) else [expected]
    matches = {"object": isinstance(value, dict), "array": isinstance(value, list),
               "string": isinstance(value, str), "boolean": type(value) is bool,
               "null": value is None}
    if not any(matches.get(item, False) for item in types):
        raise ValueError(f"{path}: expected {expected}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: invalid enum value {value!r}")
    if isinstance(value, str) and len(value.strip()) < schema.get("minLength", 0):
        raise ValueError(f"{path}: empty string")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ValueError(f"{path}: too few items")
        for i, item in enumerate(value):
            validate_shape(item, schema["items"], f"{path}[{i}]")
    if isinstance(value, dict) and "properties" in schema:
        props = schema["properties"]
        missing = set(schema["required"]) - value.keys()
        extra = value.keys() - props.keys()
        if missing or (extra and schema.get("additionalProperties") is False):
            raise ValueError(f"{path}: missing={sorted(missing)}, unexpected={sorted(extra)}")
        for key, item in value.items():
            if key in props:
                validate_shape(item, props[key], f"{path}.{key}")


@dataclass
class VulnerabilityMechanismKnowledge:
    schema_version: str
    knowledge_id: str
    source_sample_id: str
    mechanism_type: str
    extraction_model: str
    extraction_status: str
    validation_status: str
    dangerous_operation: dict[str, Any]
    applicability_conditions: list[dict[str, Any]]
    trigger_conditions: list[dict[str, Any]]
    safety_counterevidence: dict[str, Any]
    required_program_evidence: list[dict[str, Any]]
    provenance_and_boundaries: dict[str, Any]
    evidence: list[dict[str, Any]]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "VulnerabilityMechanismKnowledge":
        validate_shape(value, KNOWLEDGE_SCHEMA)
        return cls(**deepcopy(value))


def walk_claims(value: Any, path: str = "$"):
    if isinstance(value, dict):
        if {"status", "origin", "condition_kind", "description"} <= value.keys():
            yield path, value
        for key, item in value.items():
            yield from walk_claims(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_claims(item, f"{path}[{index}]")
