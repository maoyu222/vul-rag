from __future__ import annotations

import unittest

from vul_pipeline.detector import VulnerabilityDetector
from vul_pipeline.schemas import DetectionResult


class _Knowledge:
    def __init__(self, candidates):
        self.candidates = candidates

    def search(self, query, retrieve_k):
        return self.candidates[:retrieve_k]


class _Model:
    def __init__(self):
        self.last_generation = {}
        self.checked_candidate_count = 0
        self.checked_match_count = 0

    def extract_target_code_facts(self, code):
        return {"operations": [{"fact": "copy bytes", "evidence": "copy(dst, src, n);"}], "value_relations": [], "checks": [], "state_changes": []}

    def retrieval_query(self, facts):
        return "copy bytes"

    def match_security_conditions(self, code, candidates):
        return [
            {"rank": rank, "status": "applicable", "target_operation": "copy(dst, src, n);", "role_mapping": {"extent": "n"}, "reason": "same operation"}
            for rank in range(1, len(candidates) + 1)
        ]

    def check_security_conditions(self, code, candidates, matches):
        self.checked_candidate_count = len(candidates)
        self.checked_match_count = len([item for item in matches if item["status"] == "applicable"])
        return DetectionResult(label="unknown", explanation="test", retrieved_cves=[], condition_results=[])


class DetectorFlowTest(unittest.TestCase):
    def test_all_applicable_retrieved_conditions_reach_final_check(self):
        detector = VulnerabilityDetector.__new__(VulnerabilityDetector)
        detector.retrieve_k = 4
        detector.knowledge = _Knowledge([(1.0, object()) for _ in range(4)])
        detector.model = _Model()
        result = detector.detect("copy(dst, src, n);")
        self.assertEqual(result.status, "completed")
        self.assertEqual(detector.model.checked_candidate_count, 4)
        self.assertEqual(detector.model.checked_match_count, 4)


if __name__ == "__main__":
    unittest.main()
