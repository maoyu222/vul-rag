from __future__ import annotations

import json
import unittest

from vul_pipeline.qwen import (
    QwenCoder,
    label_from_checks,
    source_has_fragment,
    validate_condition_checks,
    validate_condition_matches,
    validate_target_code_facts,
)
from vul_pipeline.schemas import SecurityConditionKnowledge


def knowledge(sample_id: str, cve_id: str) -> SecurityConditionKnowledge:
    return SecurityConditionKnowledge(
        source_sample_id=sample_id,
        source_project="p",
        source_fix_commit="c",
        cve_id=cve_id,
        cwe_ids=[],
        vulnerability_type="bounds_write",
        repair_pattern="length_check",
        operation="memory copy",
        roles={"extent": "number of bytes"},
        unsafe_when="extent exceeds capacity",
        security_condition="extent must not exceed capacity",
        required_target_facts=["target has a copy extent"],
        assumptions=["local relation only"],
        before_evidence=["copy(dst, src, n);"],
        after_evidence=["if (n <= cap) copy(dst, src, n);"],
    )


class _StubQwen(QwenCoder):
    def __init__(self, response: dict):
        self.response = response

    def _generate(self, system: str, user: str) -> str:
        return json.dumps(self.response)


class DetectionLogicTest(unittest.TestCase):
    def test_source_fragment_identifier_uses_token_boundary(self):
        source = "size_t length = packet_len; copy(dst, src, length);"
        self.assertTrue(source_has_fragment(source, "length"))
        self.assertFalse(source_has_fragment(source, "len"))

    def test_target_code_facts_require_source_evidence(self):
        source = "copy(dst, src, n);"
        value = {"operations": [{"fact": "copies n bytes", "evidence": source}], "value_relations": [], "checks": [], "state_changes": []}
        self.assertEqual(validate_target_code_facts(value, source)["operations"][0]["fact"], "copies n bytes")
        value["operations"][0]["evidence"] = "copy(other, src, n);"
        with self.assertRaisesRegex(ValueError, "copied from target source"):
            validate_target_code_facts(value, source)

    def test_applicable_condition_requires_all_roles(self):
        source = "if (n > cap) return -1; copy(dst, src, n);"
        roles = {1: {"extent", "capacity", "destination"}}
        decision = {"decisions": [{
            "rank": 1, "status": "applicable", "target_operation": "copy(dst, src, n);",
            "role_mapping": {"extent": "n", "capacity": "cap", "destination": "dst"},
            "reason": "same copy operation",
        }]}
        self.assertEqual(validate_condition_matches(decision, roles, source)[0]["status"], "applicable")
        decision["decisions"][0]["role_mapping"].pop("capacity")
        with self.assertRaisesRegex(ValueError, "every historical role"):
            validate_condition_matches(decision, roles, source)

    def test_role_mapping_values_must_exist_in_source(self):
        value = {"decisions": [{
            "rank": 1, "status": "applicable", "target_operation": "copy(dst, src, n);",
            "role_mapping": {"extent": "missing_n"}, "reason": "same operation",
        }]}
        with self.assertRaisesRegex(ValueError, "present in source"):
            validate_condition_matches(value, {1: {"extent"}}, "copy(dst, src, n);")

    def test_non_applicable_condition_cannot_bind_values(self):
        value = {"decisions": [{
            "rank": 1, "status": "not_applicable", "target_operation": "",
            "role_mapping": {"extent": "n"}, "reason": "different operation",
        }]}
        with self.assertRaisesRegex(ValueError, "cannot bind"):
            validate_condition_matches(value, {1: {"extent"}}, "copy(dst, src, n);")

    def test_resolved_condition_requires_source_evidence(self):
        value = {"condition_checks": [{"rank": 1, "status": "satisfied", "evidence": [], "reason": "guard bounds n"}]}
        with self.assertRaisesRegex(ValueError, "requires source evidence"):
            validate_condition_checks(value, {1}, "if (n > cap) return -1;")

    def test_condition_evidence_must_exist_in_source(self):
        value = {"condition_checks": [{
            "rank": 1, "status": "violated", "evidence": ["copy(other, src, n);"], "reason": "unbounded",
        }]}
        with self.assertRaisesRegex(ValueError, "copied from target source"):
            validate_condition_checks(value, {1}, "copy(dst, src, n);")

    def test_program_computes_final_label(self):
        self.assertEqual(label_from_checks([{"status": "violated"}]), "vulnerable")
        self.assertEqual(label_from_checks([{"status": "satisfied"}]), "benign")
        self.assertEqual(label_from_checks([{"status": "satisfied"}], has_uncertain_match=True), "unknown")

    def test_final_result_keeps_all_matches(self):
        candidates = [(2.0, knowledge("a", "CVE-1")), (1.0, knowledge("b", "CVE-2"))]
        matches = [
            {"rank": 1, "status": "applicable", "target_operation": "copy(dst, src, n);", "role_mapping": {"extent": "n"}, "reason": "same operation"},
            {"rank": 2, "status": "uncertain", "target_operation": "", "role_mapping": {}, "reason": "cannot establish role"},
        ]
        model = _StubQwen({"condition_checks": [{
            "rank": 1, "status": "satisfied", "evidence": ["if (n <= cap) copy(dst, src, n);"], "reason": "guarded",
        }]})
        result = model.check_security_conditions("if (n <= cap) copy(dst, src, n);", candidates, matches)
        self.assertEqual(result.label, "unknown")
        self.assertEqual(len(result.condition_results), 2)
        self.assertEqual(result.condition_results[0]["source_sample_id"], "a")
        self.assertIsNone(result.condition_results[1]["check"])


if __name__ == "__main__":
    unittest.main()
