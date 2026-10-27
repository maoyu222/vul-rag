"""Official PrimeVul JSONL profiles. Pair adjacency is always context-checked."""
from __future__ import annotations

from pathlib import Path

from ..io_utils import fingerprint
from ..normalization import cwes, function_name, language, text
from ..readers import records
from ..schemas import binary_label
from .base import Adaptation, rejection


class PrimeVulAdapter:
    def __init__(self, options):
        self.options = options
        if options.version not in {"v0.1", "original"}:
            raise ValueError("PrimeVul requires version v0.1/original; do not mix releases")
        if options.split not in {"train", "valid", "test"}:
            raise ValueError("PrimeVul preserves official train/valid/test splits")

    def sample(self, row, index, path):
        for key in ("idx", "func", "target", "project", "commit_id"):
            if key not in row:
                raise ValueError(f"PrimeVul missing observed field {key}")
        if not isinstance(row["func"], str) or not row["func"].strip():
            raise ValueError("empty code")
        if isinstance(row["idx"], bool) or not text(row["idx"]):
            raise ValueError("PrimeVul source idx must be present and nonboolean")
        file_path = text(row.get("file_name"))
        lang, basis = language(row.get("language", ""), file_path, "C/C++")
        return {"sample_id": f"PrimeVul:{self.options.version}:{self.options.split}:{row['idx']}",
                "dataset": "PrimeVul", "dataset_version": self.options.version,
                "split": self.options.split, "pair_id": None, "variant": None,
                "project": text(row["project"]), "project_url": text(row.get("project_url")),
                "cve_id": text(row.get("cve")), "cwe_ids": cwes(row.get("cwe")),
                "raw_cwe_annotations": row.get("cwe"),
                "fix_commit": text(row["commit_id"]), "file_path": file_path,
                "function_name": function_name(row["func"]), "language": lang, "language_basis": basis,
                "code": row["func"], "label": binary_label(row["target"]),
                "label_scope": "dataset_annotation", "source_file": str(path), "source_row_index": index,
                "source_record_id": str(row["idx"]), "legacy_source_ids": [f"primevul_{self.options.split}_{index:06}"],
                "legacy_id_basis": "source-row convention used by existing curated pairs; compare with code/CVE/commit too"}

    def iter_batches(self, path: Path):
        expected = f"primevul_{self.options.split}{'_paired' if self.options.mode == 'paired' else ''}.jsonl"
        if path.name != expected:
            raise ValueError(f"official split/file mismatch: expected {expected}, got {path.name}")
        stream = iter(records(path, "jsonl"))
        if self.options.mode == "ordinary":
            for index, row in stream:
                try:
                    yield Adaptation(samples=[self.sample(row, index, path)])
                except (ValueError, TypeError) as error:
                    yield Adaptation(rejected=[rejection(path, [index], str(error))])
            return
        if self.options.mode != "paired" or not path.name.endswith("_paired.jsonl"):
            raise ValueError("paired mode requires an official *_paired.jsonl file")
        while True:
            first = next(stream, None)
            if first is None:
                return
            second = next(stream, None)
            if second is None:
                yield Adaptation(rejected=[rejection(path, [first[0]], "unpaired trailing record")])
                return
            (i, left), (j, right) = first, second
            try:
                a, b = self.sample(left, i, path), self.sample(right, j, path)
                if {a["label"], b["label"]} != {0, 1}:
                    raise ValueError("adjacent official pair does not have labels {0,1}")
                if not a["project"] or not a["fix_commit"] or any(
                        text(left.get(k)) and text(right.get(k)) and text(left.get(k)) != text(right.get(k))
                        for k in ("project", "commit_id", "file_name", "big_vul_idx", "cve")):
                    raise ValueError("adjacent pair source context mismatch; no pair inferred")
                if not a["function_name"] or a["function_name"] != b["function_name"]:
                    raise ValueError("pair function identity is missing/ambiguous; requires explicit manual pair manifest")
                pair = "PrimeVul:" + self.options.version + ":" + self.options.split + ":pair:" + fingerprint([a["sample_id"], b["sample_id"]])[:20]
                for sample in (a, b):
                    sample.update(pair_id=pair, variant="before" if sample["label"] else "after",
                                  label_scope="linked_repair", pairing_method="official_adjacency_context_and_function_checked")
                yield Adaptation(samples=[a, b])
            except (ValueError, TypeError) as error:
                yield Adaptation(rejected=[rejection(path, [i, j], str(error))])
