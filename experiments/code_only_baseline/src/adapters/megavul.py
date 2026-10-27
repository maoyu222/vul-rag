"""Observed MegaVul flat function records: is_vul, func_before, func."""
from __future__ import annotations

from pathlib import Path

from ..normalization import cwes, language, text
from ..readers import records
from .base import Adaptation, rejection


class MegaVulAdapter:
    def __init__(self, options):
        self.options = options
        if options.mode not in {"ordinary", "paired"}:
            raise ValueError("MegaVul mode must be ordinary/paired")

    def iter_batches(self, path: Path):
        for index, row in records(path, "array"):
            try:
                if type(row.get("is_vul")) is not bool:
                    raise ValueError("MegaVul is_vul must be a real JSON boolean")
                for key in ("func", "repo_name", "commit_hash", "file_path", "func_name"):
                    if key not in row:
                        raise ValueError(f"MegaVul missing observed field {key}")
                lang, basis = language(row.get("language", ""), text(row["file_path"]), "")
                base = {"dataset": "MegaVul", "dataset_version": self.options.version,
                        "split": "unassigned", "pair_id": None, "variant": None,
                        "project": text(row["repo_name"]), "cve_id": text(row.get("cve_id")),
                        "cwe_ids": cwes(row.get("cwe_ids")), "fix_commit": text(row["commit_hash"]),
                        "raw_cwe_annotations": row.get("cwe_ids"),
                        "file_path": text(row["file_path"]), "function_name": text(row["func_name"]),
                        "language": lang, "language_basis": basis, "source_file": str(path),
                        "source_row_index": index, "source_record_id": str(index),
                        "legacy_source_ids": [f"megavul_{index:06}"], "label_scope": "dataset_annotation"}
                if self.options.mode == "paired":
                    if not row["is_vul"]:
                        yield Adaptation(rejected=[rejection(path, [index], "not_a_vulnerable_repair_pair: ordinary negative excluded from paired view")])
                        continue
                    pair_id = f"MegaVul:{self.options.version}:pair:{index}"
                    before = {**base, "sample_id": f"MegaVul:{self.options.version}:{index}:before", "code": row.get("func_before"), "label": 1,
                              "pair_id": pair_id, "variant": "before", "label_scope": "linked_repair", "pairing_method": "native_function_record"}
                    after = {**base, "sample_id": f"MegaVul:{self.options.version}:{index}:after", "code": row["func"], "label": 0,
                             "pair_id": pair_id, "variant": "after", "label_scope": "linked_repair", "pairing_method": "native_function_record"}
                    if not all(isinstance(s["code"], str) and s["code"].strip() for s in (before, after)):
                        raise ValueError("repair pair requires two nonempty function strings")
                    yield Adaptation(samples=[before, after])
                else:
                    code = row.get("func_before") if row["is_vul"] else row["func"]
                    yield Adaptation(samples=[{**base, "sample_id": f"MegaVul:{self.options.version}:{index}:function",
                                              "code": code, "label": int(row["is_vul"])}])
            except (ValueError, TypeError) as error:
                yield Adaptation(rejected=[rejection(path, [index], str(error))])
