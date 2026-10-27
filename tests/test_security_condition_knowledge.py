from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from build_vulnerability_knowledge import (
    _build_record,
    _evidence,
    _knowledge_source_input,
    _validate_resume_record,
    validate_source_samples,
)
from vul_pipeline.knowledge_base import SecurityConditionKnowledgeBase
from vul_pipeline.schemas import SecurityConditionKnowledge


def record(sample_id: str, operation: str, condition: str) -> SecurityConditionKnowledge:
    return SecurityConditionKnowledge(
        source_sample_id=sample_id,
        source_project="p",
        source_fix_commit="c",
        cve_id="",
        cwe_ids=[],
        vulnerability_type="bounds_write",
        repair_pattern="length_or_capacity_check",
        operation=operation,
        roles={"extent": "number of bytes", "capacity": "destination capacity"},
        unsafe_when="extent exceeds capacity",
        security_condition=condition,
        required_target_facts=[
            "target has the same copy extent and destination capacity roles"
        ],
        assumptions=["retain only the local copy-length relation"],
        before_evidence=["copy(dst, src, n);"],
        after_evidence=["if (n <= cap) copy(dst, src, n);"],
    )


def source_row(sample_id: str = "x") -> dict:
    return {
        "sample_id": sample_id,
        "project": "p",
        "fix_commit": "c",
        "cve": "",
        "cwe": [],
        "vulnerability_type": "bounds_write",
        "unsafe_behavior": "copy length can exceed destination capacity",
        "security_change": "copy length is constrained by destination capacity",
        "keep_reason": "retain only the local copy-length relation",
        "code_before": "copy(dst, src, n);\n",
        "code_after": "if (n <= cap) copy(dst, src, n);\n",
        "review_annotations": {
            "repair_pattern": "length_or_capacity_check",
            "locations": {
                "before": [{"source_text": "copy(dst, src, n);"}],
                "after": [{"source_text": "if (n <= cap) copy(dst, src, n);"}],
            },
        },
    }


def source_file(*rows: dict) -> dict:
    return {
        "schema_version": 2,
        "rag_knowledge_text_generated": False,
        "heldout_exclusion": {
            "final_overlap_counts": {"CVE": 0, "fix_commit": 0, "project": 0}
        },
        "samples": list(rows),
    }


class SecurityConditionKnowledgeTest(unittest.TestCase):
    def test_curated_source_uses_every_sample_without_second_filter(self):
        rows = [source_row("a"), source_row("b")]
        result = validate_source_samples(source_file(*rows))
        self.assertEqual([row["sample_id"] for row in result], ["a", "b"])

    def test_source_schema_version_is_required(self):
        value = source_file(source_row())
        value["schema_version"] = 1
        with self.assertRaisesRegex(ValueError, "schema_version"):
            validate_source_samples(value)

    def test_pre_generated_rag_text_is_rejected(self):
        value = source_file(source_row())
        value["rag_knowledge_text_generated"] = True
        with self.assertRaisesRegex(ValueError, "pre-generated RAG text"):
            validate_source_samples(value)

    def test_heldout_overlap_must_remain_zero(self):
        value = source_file(source_row())
        value["heldout_exclusion"]["final_overlap_counts"]["project"] = 1
        with self.assertRaisesRegex(ValueError, "overlaps held-out"):
            validate_source_samples(value)

    def test_duplicate_sample_ids_are_rejected(self):
        value = source_file(source_row("same"), source_row("same"))
        with self.assertRaisesRegex(ValueError, "sample_id values must be unique"):
            validate_source_samples(value)

    def test_reviewed_evidence_must_exist_in_stored_source(self):
        row = source_row()
        self.assertEqual(_evidence(row, "before"), ["copy(dst, src, n);"])
        row["review_annotations"]["locations"]["before"][0]["source_text"] = "other();"
        with self.assertRaisesRegex(ValueError, "not present"):
            _evidence(row, "before")

    def test_locations_are_required_without_legacy_line_fallback(self):
        row = source_row()
        row["review_annotations"]["locations"]["before"] = []
        row["review_annotations"]["unsafe_line"] = "copy(dst, src, n);"
        with self.assertRaisesRegex(ValueError, "locations are empty"):
            _evidence(row, "before")

    def test_model_input_uses_compact_curated_fields(self):
        payload = _knowledge_source_input(source_row())
        self.assertEqual(
            set(payload),
            {
                "vulnerability_type",
                "repair_pattern",
                "unsafe_behavior",
                "security_change",
                "scope_and_assumptions",
                "before_evidence",
                "after_evidence",
            },
        )
        self.assertNotIn("function_diff", payload)
        self.assertNotIn("code_before", payload)
        self.assertNotIn("code_after", payload)

    def test_keep_reason_is_copied_without_model_rewriting(self):
        row = source_row()
        generated = {
            "operation": "memory copy",
            "roles": {"extent": "number of bytes", "capacity": "destination capacity"},
            "unsafe_when": "extent exceeds capacity",
            "security_condition": "extent must not exceed destination capacity",
            "required_target_facts": ["target has a copy extent and destination capacity"],
            "assumptions": ["model-generated text must be ignored"],
        }
        built = _build_record(row, generated)
        self.assertEqual(built.assumptions, [row["keep_reason"]])

    def test_resume_rejects_changed_source_input(self):
        row = source_row()
        saved_record = record("x", "memory copy", "extent <= capacity")
        with TemporaryDirectory() as directory:
            debug_dir = Path(directory)
            (debug_dir / "x.json").write_text(
                json.dumps({"source_input": _knowledge_source_input(row)}),
                encoding="utf-8",
            )
            _validate_resume_record(row, saved_record, debug_dir)
            row["security_change"] = "different reviewed description"
            with self.assertRaisesRegex(ValueError, "source record changed"):
                _validate_resume_record(row, saved_record, debug_dir)

    def test_schema_requires_required_target_facts(self):
        value = record("x", "memory copy", "extent <= capacity").to_dict()
        value["required_target_facts"] = []
        with self.assertRaisesRegex(ValueError, "required_target_facts"):
            SecurityConditionKnowledge.from_dict(value)

    def test_knowledge_base_rejects_duplicate_source_ids(self):
        item = record("same", "memory copy", "extent <= capacity")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            SecurityConditionKnowledgeBase([item, item])

    def test_bm25_retrieves_by_operation_and_value_relation(self):
        copy = record(
            "copy",
            "memory copy",
            "copy extent must not exceed destination capacity",
        )
        index = SecurityConditionKnowledge(
            source_sample_id="index",
            source_project="p",
            source_fix_commit="c",
            cve_id="",
            cwe_ids=[],
            vulnerability_type="bounds_read",
            repair_pattern="bounds_check",
            operation="array indexing",
            roles={"index": "selected element index", "capacity": "element count"},
            unsafe_when="index reaches or exceeds element count",
            security_condition="index must be below element count",
            required_target_facts=[
                "target indexes an array using a bounded element count"
            ],
            assumptions=["retain only the local index relation"],
            before_evidence=["x = a[i];"],
            after_evidence=["if (i < n) x = a[i];"],
        )
        kb = SecurityConditionKnowledgeBase([copy, index])
        results = kb.search(
            "memory copy length destination capacity bytes",
            retrieve_k=2,
        )
        self.assertEqual(results[0][1].source_sample_id, "copy")


if __name__ == "__main__":
    unittest.main()
