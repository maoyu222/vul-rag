import contextlib
import csv
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mechanism_fixtures import row, source, stages
from test_mechanism_extractor import FakeClient
from run_mechanism_pilot import parse_args, run
from vul_pipeline.mechanism_io import read_json, write_json
from vul_pipeline.mechanism_io import log_name
from vul_pipeline.mechanism_extractor import MechanismExtractor, ExtractionConfig
from vul_pipeline.mechanism_baseline import extract_baseline
from vul_pipeline.mechanism_sampler import select_samples


class PilotTests(unittest.TestCase):
    def setup_args(self, directory, *extra):
        root = Path(directory)
        rows = [row(f"synthetic_{i}") for i in range(45)]
        write_json(root / "source.json", source(rows))
        return parse_args(["--input", str(root / "source.json"), "--output-dir", str(root / "out"),
                           "--model", "test-model", *extra])

    def test_offline_precheck_is_reproducible_and_source_unchanged(self):
        with TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True), patch("run_mechanism_pilot.DeepSeekClient") as client:
            args = self.setup_args(temp, "--precheck")
            before = args.input.read_bytes()
            one = run(args)
            selected = read_json(args.output_dir / "selected_samples.json")
            two = run(args)
            self.assertEqual(one, two)
            self.assertEqual(selected, read_json(args.output_dir / "selected_samples.json"))
            self.assertEqual(args.input.read_bytes(), before)
            self.assertEqual(len(selected["sample_ids"]), 40)
            self.assertFalse(client.called)
            self.assertEqual(read_json(args.output_dir / "mechanism_knowledge.json"), [])

    def test_forty_mock_extractions_plus_independent_original_baseline(self):
        one, two = stages()
        baseline = {"operation": "copy bytes", "roles": {"length": "extent", "capacity": "writable bound"},
            "unsafe_when": "length exceeds capacity", "security_condition": "length <= capacity",
            "required_target_facts": ["copy and destination extent"]}
        client = FakeClient([one, two] * 40 + [baseline] * 40)
        with TemporaryDirectory() as temp, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test"}), patch("run_mechanism_pilot.DeepSeekClient", return_value=client), contextlib.redirect_stdout(io.StringIO()):
            args = self.setup_args(temp, "--build-baseline")
            report = run(args)
            self.assertEqual(report["valid_knowledge_count"], 40)
            self.assertEqual(report["baseline_available_count"], 40)
            self.assertEqual(report["paired_available_count"], 40)
            self.assertEqual(report["new_cost"]["attempted_calls"], 80)
            self.assertEqual(report["baseline_cost"]["attempted_calls"], 40)
            self.assertEqual(report["runtime"]["smoke_gate"], "passed")
            self.assertEqual(report["manual_review"]["reviewed_count"], 0)
            args.resume = True
            again = run(args)
            self.assertEqual(len(client.calls), 120)
            self.assertEqual(again["valid_knowledge_count"], 40)

    def test_smoke_failure_stops_remaining_cohort_and_baseline(self):
        client = FakeClient([TimeoutError("test timeout")] * 6)
        with TemporaryDirectory() as temp, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test"}), patch("run_mechanism_pilot.DeepSeekClient", return_value=client), contextlib.redirect_stdout(io.StringIO()):
            report = run(self.setup_args(temp, "--build-baseline"))
            self.assertEqual(report["runtime"]["smoke_gate"], "failed")
            self.assertEqual(len(client.calls), 6)
            self.assertEqual(report["validation_status_counts"], {"extraction_failed": 3, "not_extracted": 37})
            self.assertEqual(report["baseline_cost"]["attempted_calls"], 0)

    def test_failure_after_smoke_does_not_discard_other_samples(self):
        one, two = stages()
        client = FakeClient([one, two] * 3 + [TimeoutError()] * 2 + [one, two])
        with TemporaryDirectory() as temp, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test"}), patch("run_mechanism_pilot.DeepSeekClient", return_value=client), contextlib.redirect_stdout(io.StringIO()):
            report = run(self.setup_args(temp, "--count", "5"))
            self.assertEqual(report["valid_knowledge_count"], 4)
            self.assertEqual(report["validation_status_counts"]["extraction_failed"], 1)
            self.assertEqual(report["runtime"]["smoke_gate"], "passed")
            self.assertTrue(report["runtime"]["blockers"])

    def test_resume_recovers_completed_checkpoint_before_aggregate_write(self):
        one, two = stages()
        client = FakeClient([one, two] * 3)
        with TemporaryDirectory() as temp, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test"}), patch("run_mechanism_pilot.DeepSeekClient", return_value=client), contextlib.redirect_stdout(io.StringIO()):
            args = self.setup_args(temp, "--count", "3", "--resume")
            selected = select_samples(read_json(args.input)["samples"], 3, 42)
            path = args.output_dir / "extraction_logs" / log_name(selected[0]["sample_id"])
            extractor = MechanismExtractor(client, ExtractionConfig("test-model", 1))
            saved, _ = extractor.extract(selected[0], None, lambda value: write_json(path, value))
            self.assertIsNotNone(saved)
            self.assertFalse((args.output_dir / "mechanism_knowledge.json").exists())
            result = run(args)
            self.assertEqual(result["valid_knowledge_count"], 3)
            self.assertEqual(len(client.calls), 6)

    def test_baseline_invalid_json_usage_and_retry_are_preserved(self):
        generated = {"operation": "copy", "roles": {"length": "extent"}, "unsafe_when": "length exceeds extent",
                     "security_condition": "length within capacity", "required_target_facts": ["capacity"]}
        client = FakeClient(["not JSON", generated])
        snapshots = []
        record, ledger = extract_baseline(client, row(), 1, None, lambda value: snapshots.append(value))
        self.assertIsNotNone(record)
        attempts = ledger["stages"]["baseline"]["attempts"]
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0]["status"], "invalid_output")
        self.assertEqual(attempts[0]["response"]["usage"]["prompt_tokens"], 100)

    def test_recovered_record_survives_other_smoke_failures(self):
        one, two = stages()
        client = FakeClient([one, two] + [TimeoutError()] * 4)
        with TemporaryDirectory() as temp, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test"}), patch("run_mechanism_pilot.DeepSeekClient", return_value=client), contextlib.redirect_stdout(io.StringIO()):
            args = self.setup_args(temp, "--count", "3", "--resume")
            selected = select_samples(read_json(args.input)["samples"], 3, 42)
            path = args.output_dir / "extraction_logs" / log_name(selected[0]["sample_id"])
            extractor = MechanismExtractor(client, ExtractionConfig("test-model", 1))
            extractor.extract(selected[0], None, lambda value: write_json(path, value))
            result = run(args)
            self.assertEqual(result["runtime"]["smoke_gate"], "failed")
            self.assertEqual(result["valid_knowledge_count"], 1)
            self.assertEqual(len(read_json(args.output_dir / "mechanism_knowledge.json")), 1)

    def test_input_source_cannot_be_overwritten_by_artifact_path(self):
        with TemporaryDirectory() as temp:
            args = self.setup_args(temp, "--precheck")
            protected = args.output_dir / "mechanism_knowledge.json"
            write_json(protected, source())
            args.input = protected
            before = protected.read_bytes()
            with self.assertRaisesRegex(ValueError, "overwrite"):
                run(args)
            self.assertEqual(protected.read_bytes(), before)

    def test_validate_only_reports_corrupt_stored_source_quote(self):
        from mechanism_fixtures import record
        with TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            args = self.setup_args(temp, "--precheck")
            run(args)
            sid = read_json(args.output_dir / "selected_samples.json")["sample_ids"][0]
            sample = next(r for r in read_json(args.input)["samples"] if r["sample_id"] == sid)
            corrupt = record(sample)
            corrupt["evidence"][0]["source_text"] = "not in original source"
            write_json(args.output_dir / "mechanism_knowledge.json", [corrupt])
            args.precheck, args.validate_only = False, True
            result = run(args)
            self.assertEqual(result["validation_status_counts"]["invalid"], 1)
            self.assertEqual(result["valid_knowledge_count"], 0)

    def test_no_key_records_blocker_without_calling_api(self):
        with TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True), patch("run_mechanism_pilot.DeepSeekClient") as client:
            report = run(self.setup_args(temp))
            self.assertTrue(report["runtime"]["blockers"])
            self.assertEqual(report["valid_knowledge_count"], 0)
            self.assertFalse(client.called)

    def test_validate_only_never_calls_api_even_with_key(self):
        with TemporaryDirectory() as temp, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test"}), patch("run_mechanism_pilot.DeepSeekClient") as client:
            report = run(self.setup_args(temp, "--validate-only"))
            self.assertFalse(client.called)
            self.assertEqual(report["runtime"]["mode"], "validate_only")

    def test_budgets_and_credential_urls_rejected_before_client(self):
        with TemporaryDirectory() as temp, patch("run_mechanism_pilot.DeepSeekClient") as client:
            for options in (("--count", "1279"), ("--retries", "9"),
                            ("--base-url", "https://secret@example.com"), ("--timeout", "nan")):
                with self.assertRaises(ValueError):
                    run(self.setup_args(temp, *options))
            self.assertFalse(client.called)

    def test_changed_cohort_cannot_overwrite_previous_artifacts(self):
        with TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            args = self.setup_args(temp, "--precheck")
            run(args)
            original = (args.output_dir / "selected_samples.json").read_bytes()
            args.seed = 15
            with self.assertRaisesRegex(ValueError, "another cohort"):
                run(args)
            self.assertEqual(original, (args.output_dir / "selected_samples.json").read_bytes())
