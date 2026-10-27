import csv
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mechanism_fixtures import record, row
from vul_pipeline.mechanism_evaluator import evaluate_pilot, new_observables, review_csv, summarize_cost
from vul_pipeline.mechanism_io import read_json
from vul_pipeline.mechanism_validator import validate_knowledge


class EvaluatorTests(unittest.TestCase):
    def manifest(self):
        return {"source_count": 1, "seed": 42, "method": "synthetic test selection", "limitations": "test only",
                "source_sha256": "test-hash", "selected": {"mechanism": {"bounds_write": 1}}}

    def test_missing_baseline_and_no_api_do_not_invent_quality(self):
        with TemporaryDirectory() as temp:
            out = Path(temp)
            report = evaluate_pilot(out, [row()], [], [], [], [], self.manifest(), {"blockers": ["key missing"]})
            self.assertEqual(report["valid_knowledge_count"], 0)
            self.assertEqual(report["baseline_available_count"], 0)
            self.assertIsNone(report["source_quote_existence"]["value"])
            self.assertEqual(report["manual_review"]["reviewed_count"], 0)
            self.assertEqual(report["comparisons"][0]["semantic_comparison"]["trigger_precision"], "not_reviewed")
            self.assertIn("暂无实际有效提取记录", (out / "quality_report.md").read_text())

    def test_source_existence_is_separate_from_semantics(self):
        with TemporaryDirectory() as temp:
            report = evaluate_pilot(Path(temp), [row()], [record()], [], [], [], self.manifest(), {})
            self.assertEqual(report["source_quote_existence"]["value"], 1.0)
            self.assertEqual(report["valid_knowledge_count"], 1)
            self.assertEqual(report["comparisons"][0]["semantic_comparison"]["source_evidence_correctness"], "not_reviewed")

    def test_existing_human_review_preserved(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "review.csv"
            review_csv(path, [row()], {row()["sample_id"]: record()}, {})
            with path.open(encoding="utf-8-sig", newline="") as handle:
                entries = list(csv.DictReader(handle))
            entries[0].update(review_status="reviewed", reviewer="human tester", review_notes="checked manually",
                              new_trigger_precision="correct", better_knowledge="not_decided")
            with path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(entries[0]))
                writer.writeheader()
                writer.writerows(entries)
            result = review_csv(path, [row()], {row()["sample_id"]: record()}, {})
            self.assertEqual(result["reviewed_count"], 1)
            self.assertEqual(result["ratings"][0]["new_trigger_precision"], "correct")
            self.assertIn("checked manually", path.read_text())

    def test_cost_includes_failed_and_unknown_calls(self):
        logs = [{"stages": {"first": {"attempts": [
            {"status": "failed", "response": {"model": "m", "usage": {"prompt_tokens": 100, "completion_tokens": 20}}},
            {"status": "failed", "response": {}},
            {"status": "completed", "response": {"model": "m", "usage": {"prompt_tokens": 50, "completion_tokens": 10}}}]}}}]
        cost = summarize_cost(logs, 1, 2)
        self.assertEqual(cost["attempted_calls"], 3)
        self.assertEqual(cost["usage_unknown_calls"], 1)
        self.assertEqual(cost["priced_known_usage_subtotal"], 0.00021)
        self.assertFalse(cost["complete_cost_known"])

    def test_changed_knowledge_marks_review_stale_without_deleting_ratings(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "review.csv"
            original = record()
            review_csv(path, [row()], {row()["sample_id"]: original}, {})
            with path.open(encoding="utf-8-sig", newline="") as handle:
                entries = list(csv.DictReader(handle))
            entries[0].update(review_status="reviewed", review_notes="preserve this", new_trigger_precision="correct")
            with path.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(entries[0]))
                writer.writeheader()
                writer.writerows(entries)
            original["dangerous_operation"]["category"] = "revised_category"
            result = review_csv(path, [row()], {row()["sample_id"]: original}, {})
            self.assertEqual(result["reviewed_count"], 0)
            self.assertIn("stale_needs_review", path.read_text())
            self.assertIn("preserve this", path.read_text())

    def test_generic_trigger_gets_advisory_not_high_precision_score(self):
        value = record()
        value["trigger_conditions"][0]["behavior"]["description"] = "缺少边界检查"
        observable = new_observables(value, validate_knowledge(value, row()))
        self.assertEqual(observable["generic_trigger_wording_flags"], ["t_copy"])
        self.assertEqual(observable["semantic_correctness"], "not_reviewed")

    def test_invalid_extraction_is_counted_and_not_a_success_example(self):
        bad = record()
        bad["evidence"][0]["source_text"] = "invented"
        with TemporaryDirectory() as temp:
            report = evaluate_pilot(Path(temp), [row()], [], [], [{"source_sample_id": row()["sample_id"],
                "status": "invalid", "validation": __import__("vul_pipeline.mechanism_validator", fromlist=["validate_knowledge"]).validate_knowledge(bad, row())}],
                [], self.manifest(), {})
            self.assertEqual(report["validation_status_counts"], {"invalid": 1})
            self.assertEqual(report["valid_knowledge_count"], 0)
            self.assertIn("not present", (Path(temp) / "quality_report.md").read_text())
