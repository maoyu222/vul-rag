"""Explicit field contracts for other verified datasets; no automatic label guessing."""
from __future__ import annotations

from pathlib import Path

from ..normalization import cwes, function_name, language, text
from ..readers import records
from ..schemas import binary_label
from .base import Adaptation, rejection


def lookup(row, path, default=None):
    value = row
    for name in path.split("."):
        if not isinstance(value, dict) or name not in value:
            return default
        value = value[name]
    return value


class MappedAdapter:
    def __init__(self, options, mapping):
        self.options, self.mapping = options, mapping
        if not isinstance(mapping, dict) or mapping.get("verified_by_user") is not True:
            raise ValueError("mapped adapter requires explicit verified_by_user=true field contract")
        self.fields = mapping["fields"]
        if "code" not in self.fields or ("label" not in self.fields and "label_constant" not in mapping):
            raise ValueError("mapping requires code and label/label_constant")
        if options.mode != "ordinary":
            raise ValueError("generic mapping never infers pairs; use a verified native pair adapter")
        if not isinstance(mapping.get("label_map"), dict) or not mapping["label_map"]:
            raise ValueError("mapping requires a nonempty explicit label_map")
        for value in mapping["label_map"].values():
            binary_label(value)

    def iter_batches(self, path: Path):
        for index, row in records(path, self.mapping.get("format", self.options.format)):
            try:
                values = {key: lookup(row, source) for key, source in self.fields.items()}
                raw_label = self.mapping.get("label_constant", values.get("label"))
                key = str(raw_label)
                if key not in self.mapping["label_map"]:
                    raise ValueError(f"unmapped label {raw_label!r}")
                code = values.get("code")
                lang, basis = language(values.get("language"), text(values.get("file_path")), self.mapping.get("dataset_language", ""))
                native_id = text(values.get("source_record_id")) or str(index)
                sample = {"sample_id": f"{self.options.dataset}:{self.options.version}:{self.options.split}:{native_id}",
                    "dataset": self.options.dataset, "dataset_version": self.options.version, "split": self.options.split,
                    "pair_id": None, "variant": None, "source_record_id": native_id,
                    "source_file": str(path), "source_row_index": index, "legacy_source_ids": [],
                    "code": code, "label": self.mapping["label_map"][key], "language": lang, "language_basis": basis,
                    "project": text(values.get("project")), "cve_id": text(values.get("cve_id")),
                    "cwe_ids": cwes(values.get("cwe_ids")), "fix_commit": text(values.get("fix_commit")),
                    "raw_cwe_annotations": values.get("cwe_ids"),
                    "file_path": text(values.get("file_path")), "function_name": text(values.get("function_name")) or function_name(code or ""),
                    "label_scope": "dataset_annotation"}
                yield Adaptation(samples=[sample])
            except (ValueError, TypeError) as error:
                yield Adaptation(rejected=[rejection(path, [index], str(error))])
