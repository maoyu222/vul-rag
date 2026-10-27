"""Normalized experiment samples; metadata never enters prompt construction."""
from __future__ import annotations

from .io_utils import fingerprint
from .normalization import code_hash, cwes, language, text

SAMPLE_SCHEMA_VERSION = "code_only_sample_v1"


def binary_label(value) -> int:
    if type(value) is int and value in (0, 1):
        return value
    if isinstance(value, str) and value.strip() in {"0", "1"}:
        return int(value.strip())
    raise ValueError("label must be integer 0/1 (or an explicitly mapped string); bool is not a label")


def normalize_sample(value: dict) -> dict:
    if not isinstance(value, dict):
        raise ValueError("sample must be an object")
    sid = text(value.get("sample_id"))
    if not sid or not text(value.get("dataset")) or not text(value.get("split")):
        raise ValueError("sample_id, dataset and split are required")
    code = value.get("code")
    if not isinstance(code, str) or not text(code):
        raise ValueError("empty or non-string code")
    lang, basis = language(value.get("language", ""))
    label = binary_label(value.get("label"))
    result = {**value, "schema_version": SAMPLE_SCHEMA_VERSION, "sample_id": sid,
              "dataset": text(value["dataset"]), "split": text(value["split"]),
              "pair_id": value.get("pair_id") or None, "variant": value.get("variant") or None,
              "project": text(value.get("project")), "cve_id": text(value.get("cve_id")),
              "cwe_ids": cwes(value.get("cwe_ids", [])), "fix_commit": text(value.get("fix_commit")),
              "file_path": text(value.get("file_path")), "function_name": text(value.get("function_name")),
              "language": lang, "language_basis": value.get("language_basis") or basis,
              "code": code, "label": label, "normalized_code_hash": code_hash(code)}
    if bool(result["pair_id"]) != bool(result["variant"]):
        raise ValueError("pair_id and variant must be supplied together")
    if result["variant"] not in {None, "before", "after"}:
        raise ValueError("variant must be before/after/null")
    if result["variant"] and label != (1 if result["variant"] == "before" else 0):
        raise ValueError("paired labels must be before=1, after=0 for the linked vulnerability")
    result["sample_hash"] = fingerprint({k: v for k, v in result.items() if k != "sample_hash"})
    return result
