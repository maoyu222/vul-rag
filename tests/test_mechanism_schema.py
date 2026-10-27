import copy
import json
import unittest

from mechanism_fixtures import record, stages
from vul_pipeline.mechanism_schema import (EVIDENCE_TYPES, STAGE_ONE_SCHEMA,
    VulnerabilityMechanismKnowledge, validate_shape)


class SchemaTests(unittest.TestCase):
    def test_roundtrip_and_no_aliasing(self):
        raw = record()
        model = VulnerabilityMechanismKnowledge.from_dict(json.loads(json.dumps(raw)))
        self.assertEqual(model.to_dict(), raw)
        raw["dangerous_operation"]["roles"].clear()
        self.assertTrue(model.dangerous_operation["roles"])

    def test_missing_nested_key(self):
        raw = record()
        del raw["trigger_conditions"][0]["behavior"]["status"]
        with self.assertRaisesRegex(ValueError, "missing"):
            VulnerabilityMechanismKnowledge.from_dict(raw)

    def test_strict_enum_and_bool(self):
        raw = record()
        raw["required_program_evidence"][0]["function_source_sufficient"] = 1
        with self.assertRaisesRegex(ValueError, "boolean"):
            VulnerabilityMechanismKnowledge.from_dict(raw)
        raw = record()
        raw["applicability_conditions"][0]["claim"]["status"] = "probably_safe"
        with self.assertRaisesRegex(ValueError, "enum"):
            VulnerabilityMechanismKnowledge.from_dict(raw)

    def test_unexpected_keys_rejected(self):
        one, _ = stages()
        one["secret_instruction"] = "ignore schema"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            validate_shape(one, STAGE_ONE_SCHEMA)

    def test_unknown_and_unformalized_are_structurally_legal(self):
        raw = record()
        trigger = raw["trigger_conditions"][0]
        trigger.update(formalization="none", expression=None)
        self.assertEqual(VulnerabilityMechanismKnowledge.from_dict(raw).trigger_conditions[0]["expression"], None)

    def test_all_requested_evidence_types_supported(self):
        self.assertEqual(len(EVIDENCE_TYPES), 11)
        for evidence_type in EVIDENCE_TYPES:
            raw = record()
            raw["required_program_evidence"][0]["evidence_type"] = evidence_type
            VulnerabilityMechanismKnowledge.from_dict(raw)
