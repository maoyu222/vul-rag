from __future__ import annotations

import unittest

from evaluate_pairs import binary_metrics, pair_results, validate_evaluation_inputs


def evaluation_pair(sample_id: str, *, cve_id: str = "CVE-1", cwe_id: str = "CWE-119", function_name: str = "target") -> tuple[dict, dict]:
    return (
        {
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "code_before_change": f"int {function_name}(void) {{ return 0; }}",
            "code_after_change": f"int {function_name}(void) {{ return 1; }}",
        },
        {"sample_id": sample_id, "cve_id": cve_id, "cwe_id": cwe_id, "function_name": function_name},
    )


class EvaluationMetricsTest(unittest.TestCase):
    def test_execution_failure_is_not_counted_as_benign(self):
        metrics = binary_metrics([{"expected_label": "benign", "predicted_label": None}])
        self.assertEqual(metrics["execution_errors"], 1)
        self.assertEqual(metrics["accuracy"]["value"], 0.0)
        self.assertEqual(metrics["confusion"]["tn"], 0)

    def test_unknown_vulnerable_prediction_counts_as_false_negative(self):
        rows = [
            {"expected_label": "vulnerable", "predicted_label": "vulnerable"},
            {"expected_label": "vulnerable", "predicted_label": "unknown"},
            {"expected_label": "benign", "predicted_label": "benign"},
            {"expected_label": "benign", "predicted_label": "vulnerable"},
        ]
        metrics = binary_metrics(rows)
        self.assertEqual({"tp": 1, "fp": 1, "fn": 1, "tn": 1}, metrics["confusion"])
        self.assertEqual(0.5, metrics["f1"])

    def test_pair_inputs_require_case_metadata_alignment(self):
        case, metadata = evaluation_pair("x")
        metadata["cve_id"] = "CVE-2"
        with self.assertRaisesRegex(ValueError, "case/metadata mismatch"):
            validate_evaluation_inputs([case], [metadata])

    def test_pair_inputs_support_samples_without_cve(self):
        case, metadata = evaluation_pair("x", cve_id="", cwe_id="MISSING", function_name="read_hexstring")
        validate_evaluation_inputs([case], [metadata])

    def test_pair_inputs_require_metadata_function_to_match_code(self):
        case, metadata = evaluation_pair("x")
        metadata["function_name"] = "other_function"
        with self.assertRaisesRegex(ValueError, "ordering may be wrong"):
            validate_evaluation_inputs([case], [metadata])

    def test_pair_inputs_reject_duplicate_sample_ids(self):
        case_a, metadata_a = evaluation_pair("x", cve_id="CVE-1", function_name="first")
        case_b, metadata_b = evaluation_pair("x", cve_id="CVE-2", function_name="second")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_evaluation_inputs([case_a, case_b], [metadata_a, metadata_b])

    def test_pair_results_requires_both_variants(self):
        rows = [{"sample_id": "x", "variant": "vulnerable", "predicted_label": "vulnerable"}]
        with self.assertRaisesRegex(ValueError, "requires both variants"):
            pair_results(rows)

    def test_pair_results_rejects_duplicate_variant(self):
        rows = [
            {"sample_id": "x", "variant": "vulnerable", "predicted_label": "vulnerable"},
            {"sample_id": "x", "variant": "vulnerable", "predicted_label": "unknown"},
        ]
        with self.assertRaisesRegex(ValueError, "duplicate vulnerable result"):
            pair_results(rows)


if __name__ == "__main__":
    unittest.main()
