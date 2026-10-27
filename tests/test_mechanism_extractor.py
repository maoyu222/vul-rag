import io
import json
import os
import unittest
from copy import deepcopy
from unittest.mock import patch

from mechanism_fixtures import row, stages
from vul_pipeline.deepseek import DeepSeekClient, DeepSeekConfig
from vul_pipeline.mechanism_evaluator import summarize_cost
from vul_pipeline.mechanism_extractor import ExtractionConfig, MechanismExtractor, json_object


class FakeClient:
    api_key = "secret-test-value"

    def __init__(self, outputs):
        self.outputs = iter(outputs)
        self.calls = []
        self.last_response = {}

    def runtime_info(self):
        return {"model": "test-model", "base_url": "https://example.invalid", "max_tokens": 6000, "timeout": 90}

    def generate_with_metadata(self, system, user):
        self.calls.append((system, user))
        value = next(self.outputs)
        if isinstance(value, Exception):
            raise value
        result = {"content": value if isinstance(value, str) else json.dumps(value),
                  "usage": {"prompt_tokens": 100, "completion_tokens": 200},
                  "model": "test-model", "request_id": "test-request", "finish_reason": "stop"}
        self.last_response = result
        return result


class ExtractorTests(unittest.TestCase):
    def run_extraction(self, outputs, retries=1, checkpoint=None, sample=None):
        client = FakeClient(outputs)
        extractor = MechanismExtractor(client, ExtractionConfig("test-model", retries))
        saved = []
        record, log = extractor.extract(sample or row(), checkpoint, lambda v: saved.append(deepcopy(v)))
        return client, record, log, saved

    def test_two_stages_preserve_source_and_usage(self):
        client, record, log, saved = self.run_extraction(stages())
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(record["provenance_and_boundaries"]["keep_reason"], row()["keep_reason"])
        self.assertEqual(log["status"], "completed")
        self.assertEqual(saved[0]["stages"]["mechanism"]["attempts"][0]["status"], "started")
        self.assertEqual(summarize_cost([log])["attempted_calls"], 2)
        self.assertIn("UNTRUSTED", client.calls[0][0])

    def test_json_failure_retried_and_all_usage_accounted(self):
        one, two = stages()
        client, result, log, _ = self.run_extraction(["not json", one, two])
        self.assertIsNotNone(result)
        self.assertEqual(len(client.calls), 3)
        self.assertEqual(summarize_cost([log])["usage_reported_calls"], 3)

    def test_failure_retry_bound_and_no_fake_record(self):
        client, result, log, _ = self.run_extraction([TimeoutError("timeout")] * 3, retries=2)
        self.assertIsNone(result)
        self.assertEqual(len(client.calls), 3)
        self.assertEqual(log["status"], "failed")
        self.assertEqual(summarize_cost([log])["usage_unknown_calls"], 3)

    def test_permanent_http_errors_not_retried(self):
        error = RuntimeError("HTTP 401")
        error.http_status = 401
        client, result, log, _ = self.run_extraction([error])
        self.assertIsNone(result)
        self.assertEqual(len(client.calls), 1)

    def test_resume_reuses_successful_first_stage(self):
        one, two = stages()
        _, record, log, _ = self.run_extraction([one, TimeoutError()], retries=0)
        self.assertIsNone(record)
        client, record, log, _ = self.run_extraction([two], retries=0, checkpoint=log)
        self.assertEqual(len(client.calls), 1)
        self.assertIsNotNone(record)
        self.assertEqual(summarize_cost([log])["attempted_calls"], 3)

    def test_resume_rejects_source_or_config_change(self):
        _, _, log, _ = self.run_extraction(stages())
        sample = row()
        sample["keep_reason"] += " changed"
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.run_extraction([], checkpoint=log, sample=sample)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.run_extraction([], retries=2, checkpoint=log)

    def test_hallucinated_evidence_retained_as_invalid_not_exported(self):
        one, two = stages()
        one["evidence"][0]["source_text"] = "fabricated();"
        _, record, log, _ = self.run_extraction([one, two])
        self.assertIsNone(record)
        self.assertEqual(log["status"], "invalid")
        self.assertTrue(log["validation"]["errors"])
        self.assertIn("record", log)

    def test_input_budget_fails_before_network(self):
        client = FakeClient([])
        extractor = MechanismExtractor(client, ExtractionConfig("test-model", 0, 1000))
        record, log = extractor.extract(row(), None, lambda value: None)
        self.assertIsNone(record)
        self.assertIn("input exceeds", log["error"])
        self.assertEqual(client.calls, [])

    def test_secret_is_redacted_in_failure_ledger(self):
        _, _, _, saved = self.run_extraction([RuntimeError("echo secret-test-value")] * 2)
        self.assertNotIn("secret-test-value", json.dumps(saved))

    def test_json_object_rejects_array_and_accepts_fence(self):
        self.assertEqual(json_object('```json\n{"x": 1}\n```'), {"x": 1})
        with self.assertRaises(ValueError):
            json_object("[]")


class TransportTests(unittest.TestCase):
    def client(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "private-token"}):
            return DeepSeekClient(DeepSeekConfig(model="configurable-model", timeout=7))

    def test_old_generate_interface_and_metadata(self):
        response = {"choices": [{"message": {"content": '{"ok":true}'}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 4, "completion_tokens": 3}, "id": "r"}
        client = self.client()
        with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(response).encode())) as transport:
            self.assertEqual(client.generate("system", "untrusted data"), '{"ok":true}')
            self.assertEqual(transport.call_args.kwargs["timeout"], 7)
            self.assertEqual(client.last_response["usage"]["prompt_tokens"], 4)
            payload = json.loads(transport.call_args.args[0].data)
            self.assertEqual(payload["model"], "configurable-model")
            self.assertEqual(payload["response_format"], {"type": "json_object"})

    def test_truncation_keeps_usage(self):
        response = {"choices": [{"message": {"content": '{"cut":'}, "finish_reason": "length"}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 20}}
        client = self.client()
        with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(response).encode())):
            with self.assertRaisesRegex(RuntimeError, "cut off"):
                client.generate("system", "data")
        self.assertEqual(client.last_response["usage"]["completion_tokens"], 20)

    def test_error_bodies_cannot_leak_key(self):
        import urllib.error
        client = self.client()
        error = urllib.error.HTTPError("https://example.invalid", 401, "bad", {}, io.BytesIO(b"private-token"))
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                client.generate("s", "u")
        self.assertNotIn("private-token", str(caught.exception))
