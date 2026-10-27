import unittest

from mechanism_fixtures import claim, record, row
from vul_pipeline.mechanism_validator import source_contains, validate_knowledge


class ValidatorTests(unittest.TestCase):
    def check(self, value):
        return validate_knowledge(value, row())

    def test_partial_unknown_is_valid_not_model_error(self):
        result = self.check(record())
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["status"], "valid_partial_unknown")
        self.assertEqual(result["diff_alignment"], "changed_patch_quote_present")
        self.assertEqual(result["semantic_correctness"], "not_reviewed")

    def test_fabricated_or_wrong_version_quote_fails(self):
        for change in ("source_text", "version"):
            value = record()
            quote = next(q for q in value["evidence"] if q["id"] == "review_after_0")
            quote[change] = "absent_quote();" if change == "source_text" else "before"
            self.assertEqual(self.check(value)["status"], "invalid")

    def test_keep_reason_verbatim(self):
        value = record()
        self.assertTrue(value["provenance_and_boundaries"]["keep_reason"].endswith("  "))
        value["provenance_and_boundaries"]["keep_reason"] = "model paraphrase"
        self.assertIn("provenance mismatch: keep_reason", self.check(value)["errors"])

    def test_confirmed_external_context_rejected(self):
        value = record()
        value["applicability_conditions"][1]["claim"].update(status="confirmed")
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_unknown_requires_missing_information(self):
        value = record()
        value["applicability_conditions"][1]["claim"]["additional_information"] = []
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_candidate_cannot_masquerade_as_patch_fact(self):
        value = record()
        value["safety_counterevidence"]["safeguards"][1]["claim"] = claim("candidate is confirmed", "confirmed", ["review_after_0"])
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_candidate_requires_prerequisites(self):
        value = record()
        value["safety_counterevidence"]["safeguards"][1]["prerequisites"] = []
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_actual_patch_requires_after_evidence(self):
        value = record()
        value["safety_counterevidence"]["safeguards"][0]["claim"]["evidence_refs"] = ["review_before_0"]
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_duplicate_and_dangling_references(self):
        value = record()
        value["evidence"].append(value["evidence"][0].copy())
        self.assertEqual(self.check(value)["status"], "invalid")
        value = record()
        value["trigger_conditions"][0]["role_refs"] = ["invented"]
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_binding_cannot_use_wrong_quote(self):
        value = record()
        value["dangerous_operation"]["roles"][2]["bindings"][0]["evidence_refs"] = ["review_before_0"]
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_numeric_formalization_requires_type_premise(self):
        value = record()
        value["trigger_conditions"][0].update(formalization="formal", applicability_refs=["a_capacity"])
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_identical_trigger_and_safety_detected(self):
        value = record()
        value["safety_counterevidence"]["security_property"] = value["trigger_conditions"][0]["behavior"].copy()
        self.assertEqual(self.check(value)["status"], "invalid")

    def test_source_matching_is_exact_except_newlines(self):
        self.assertTrue(source_contains("x\r\ny", "x\ny"))
        self.assertFalse(source_contains("length", "len"))
        self.assertFalse(source_contains("a  + b", "a + b"))
        self.assertFalse(source_contains("anything", ""))
