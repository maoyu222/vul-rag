"""Written for manual execution; test IO is confined to the experiment runtime."""
import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _bootstrap  # noqa: E402,F401
import httpx  # noqa: E402

from src.adapters import AdapterOptions, get_adapter
from src.checkpoint import RunStore, read_ledger
from src.io_utils import EXPERIMENT_ROOT, append_json, file_hash, output_path
from src.leakage_check import KnowledgeIndex, SimilarityAudit, UnionFind, deterministic_split
from src.metrics import calculate
from src.normalization import code_hash
from src.output_parser import OUTPUT_SCHEMA, parse_output
from src.preparation import prepare
from src.prompts import Prompt
from src.schemas import binary_label, normalize_sample
from src.vllm_client import Settings, VLLMClient
from evaluate import evaluate_run


def sample(sid="s1", label=1, **kwargs):
    return normalize_sample({"sample_id": sid, "dataset": "SyntheticOnly", "dataset_version": "fixture-v1",
        "split": "test", "code": "int f(void) { return 1; }", "language": "C", "label": label, **kwargs})


def answer(label="vulnerable", **kwargs):
    return json.dumps({"label": label, "vulnerability_type": "", "evidence": ["return 1;"], "reason": "synthetic mocked answer", **kwargs})


class Files(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="baseline_tests_")
        self.root = Path(self.temporary.name)
        self.assertTrue(self.root.is_relative_to(EXPERIMENT_ROOT))

    def tearDown(self):
        self.temporary.cleanup()

    def jsonl(self, name, rows):
        path = self.root / name
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                append_json(handle, row)
        return path

    def knowledge(self, rows=()):
        path = self.root / "synthetic_knowledge.json"
        path.write_text(json.dumps({"schema_version": 2, "samples": list(rows)}), encoding="utf-8")
        return path

    def test_normalization_preserves_literal_content(self):
        self.assertEqual(code_hash("int f(){ /* comment */return 1;}"), code_hash("int f() {return 1; }"))
        self.assertNotEqual(code_hash('puts("a b");'), code_hash('puts("ab");'))
        self.assertNotEqual(code_hash('puts("// text");'), code_hash('puts("");'))
        self.assertNotEqual(code_hash('auto x=R"tag(a b)tag";'), code_hash('auto x=R"tag(ab)tag";'))

    def test_invalid_samples_and_labels(self):
        for bad in (-1, 2, True, None, "vul", 0.0):
            with self.subTest(label=bad), self.assertRaises(ValueError):
                binary_label(bad)
        for changes in ({"code": " "}, {"code": []}, {"language": "Python"}, {"label": 8}, {"pair_id": "p"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                sample(**changes)
        self.assertEqual(binary_label("1"), 1)
        with self.assertRaises(ValueError):
            output_path(Path("/home/PublicData/PHY-data/vul_detect/data/forbidden.json"))

    def test_primevul_checked_official_pair(self):
        path = self.jsonl("primevul_test_paired.jsonl", [
            {"idx": 1, "project": "p", "commit_id": "c", "file_name": "f.c", "func": "int f(){return 1;}", "target": 1, "cwe": ["CWE-120"]},
            {"idx": 2, "project": "p", "commit_id": "c", "file_name": "None", "func": "int f(){return 0;}", "target": 0}])
        adapter = get_adapter("primevul", AdapterOptions("PrimeVul", "v0.1", mode="paired"))
        batches = list(adapter.iter_batches(path))
        self.assertEqual(len(batches[0].samples), 2)
        a, b = batches[0].samples
        self.assertEqual(a["pair_id"], b["pair_id"])
        self.assertEqual([a["variant"], b["variant"]], ["before", "after"])
        bad = json.loads(path.read_text().splitlines()[1]); bad["commit_id"] = "other"
        path = self.jsonl("primevul_test_paired.jsonl", [json.loads(path.read_text().splitlines()[0]), bad])
        self.assertTrue(list(adapter.iter_batches(path))[0].rejected)
        with self.assertRaises(ValueError):
            list(adapter.iter_batches(self.jsonl("primevul_train_paired.jsonl", [])))

    def mega_rows(self):
        return [{"is_vul": True, "func_before": "int f(){return 1;}", "func": "int f(){return 0;}",
            "repo_name": "p", "commit_hash": "c", "file_path": "f.c", "func_name": "f", "cve_id": "CVE-TEST-1", "cwe_ids": ["CWE-120"]},
            {"is_vul": False, "func": "int g(){return 2;}", "repo_name": "q", "commit_hash": "d", "file_path": "g.cpp", "func_name": "g"}]

    def test_megavul_native_labels_and_pairs(self):
        path = self.root / "mega.json"
        path.write_text(json.dumps(self.mega_rows()), encoding="utf-8")
        ordinary = list(get_adapter("megavul", AdapterOptions("MegaVul", "fixture")).iter_batches(path))
        self.assertEqual([b.samples[0]["label"] for b in ordinary], [1, 0])
        self.assertIn("return 1", ordinary[0].samples[0]["code"])
        paired = list(get_adapter("megavul", AdapterOptions("MegaVul", "fixture", mode="paired")).iter_batches(path))
        self.assertEqual([s["label"] for s in paired[0].samples], [1, 0])
        self.assertTrue(paired[1].rejected)
        rows = self.mega_rows(); rows[0]["is_vul"] = 1
        path.write_text(json.dumps(rows))
        self.assertTrue(list(get_adapter("megavul", AdapterOptions("MegaVul", "fixture")).iter_batches(path))[0].rejected)

    def test_explicit_mapping(self):
        mapping = {"verified_by_user": True, "format": "jsonl", "dataset_language": "C/C++",
            "fields": {"code": "func", "label": "target", "project": "project"}, "label_map": {"1": 1, "0": 0}}
        path = self.jsonl("mapped.jsonl", [{"func": "int f(){}", "target": 1, "project": "p"}, {"func": "int x(){}", "target": "maybe"}])
        batches = list(get_adapter("mapped", AdapterOptions("Explicit", "fixture"), mapping).iter_batches(path))
        self.assertEqual(batches[0].samples[0]["label"], 1)
        self.assertTrue(batches[1].rejected)
        with self.assertRaises(ValueError):
            get_adapter("mapped", AdapterOptions("Explicit", "fixture"), {**mapping, "verified_by_user": False})

    def test_knowledge_overlap_and_provenance_bound_alias(self):
        row = {"sample_id": "legacy", "project": "p", "cve": "CVE-1", "fix_commit": "ABC",
               "code_before": "int f(){return 1;}", "code_after": "int f(){return 0;}",
               "pair_provenance": {"source_path": "PrimeVul_original/primevul_test.jsonl"}}
        index = KnowledgeIndex(self.knowledge([row]))
        source = sample(code="int f(){return 1;}", project="p", cve_id="CVE-1", fix_commit="abc", legacy_source_ids=["legacy"],
                        source_file="/data/PrimeVul_original/primevul_test.jsonl")
        self.assertEqual(set(index.overlaps(source)), {"sample_id", "cve", "fix_commit", "project", "code_hash"})
        source["source_file"] = "/data/PrimeVul_v0.1/primevul_test.jsonl"
        self.assertNotIn("sample_id", index.overlaps(source))
        self.assertEqual(set(index.overlaps(source, ["cve"])), {"cve"})

    def test_preparation_dedup_isolation_pair_closure_and_read_only(self):
        source = self.root / "mega.json"
        source.write_text(json.dumps(self.mega_rows()), encoding="utf-8")
        before = file_hash(source)
        knowledge = self.knowledge([{"sample_id": "k", "project": "", "cve": "CVE-TEST-1", "fix_commit": "", "code_before": "", "code_after": ""}])
        out = self.root / "prepared"
        result = prepare(AdapterOptions("MegaVul", "fixture", mode="paired"), [source], out, knowledge,
                         ratios=(0, 0, 1), isolation_rules=["cve"], near_duplicate_limit=10)
        self.assertEqual(result["statistics"]["counts"]["official_test"], 2)
        self.assertEqual(result["statistics"]["counts"]["strict_excluded"], 2)
        self.assertEqual(file_hash(source), before)
        self.assertEqual((out / "strict/test.jsonl").read_text(), "")
        with self.assertRaises(ValueError):
            prepare(AdapterOptions("MegaVul", "fixture"), [source], out, knowledge)
        # Exact duplicates are reported, not silently removed from the official view.
        rows = self.mega_rows(); rows.append(dict(rows[1]))
        source.write_text(json.dumps(rows))
        result = prepare(AdapterOptions("MegaVul", "fixture"), [source], self.root / "duplicates", knowledge,
                         ratios=(0, 0, 1), isolation_rules=[], deduplicate="within-split")
        self.assertEqual(result["statistics"]["exact_duplicate_groups"], 1)
        self.assertEqual(result["statistics"]["counts"]["same_split_duplicates_removed"], 1)

    def test_stable_group_components(self):
        dsu = UnionFind()
        dsu.union("z", "y"); dsu.union("y", "x"); dsu.union("x", "a")
        self.assertEqual(dsu.find("z"), "a")
        self.assertEqual(deterministic_split(dsu.find("z"), 42), deterministic_split("a", 42))

    def test_prompt_has_only_code_as_dynamic_content(self):
        prompt = Prompt()
        self.assertEqual(prompt.version, "code_only")
        self.assertEqual({p.name for p in (EXPERIMENT_ROOT / "prompts").glob("*.txt")}, {"system.txt", "user.txt"})
        messages = prompt.messages("int f(){ return 1; }")
        self.assertEqual(len(messages), 2)
        self.assertNotIn("unknown", json.dumps(messages))
        self.assertEqual(OUTPUT_SCHEMA["properties"]["label"]["enum"], ["vulnerable", "benign"])
        for forbidden in ("CVE-SECRET", "CWE-SECRET", "true_label", "pair_id"):
            self.assertNotIn(forbidden, json.dumps(messages))
        with self.assertRaises(TypeError):
            prompt.messages(sample(cve_id="CVE-SECRET"))

    def test_parser_binary_labels_and_fences(self):
        code = sample()["code"]
        self.assertEqual(parse_output(answer(), code)["predicted_label"], 1)
        self.assertEqual(parse_output("```json\n" + answer("benign") + "\n```", code)["predicted_label"], 0)
        cases = [("{", "invalid_json"), (answer("safe"), "invalid_label"), ("{}", "invalid_fields"),
                 (answer("unknown"), "invalid_label"), (answer("uncertain"), "invalid_label"),
                 (answer(evidence=["nonexistent excerpt"]), "evidence_not_in_source"),
                 (answer(evidence=1), "invalid_evidence_type"), (answer(reason=""), "invalid_field_type")]
        for raw, kind in cases:
            self.assertEqual(parse_output(raw, code)["error_type"], kind)
            self.assertEqual(parse_output(raw, code)["status"], "error")
            self.assertIsNone(parse_output(raw, code)["predicted_label"])
        self.assertEqual(parse_output(answer(), code, "length")["error_type"], "truncated_output")

    def test_checkpoint_resume_and_offline_evaluation(self):
        first, second = sample("one"), sample("two", 0)
        source = self.jsonl("input.jsonl", [first, second])
        settings, prompt, out = Settings("http://unused.invalid/v1", "mock"), Prompt(), self.root / "run"
        with RunStore(out, [source], settings, prompt) as store:
            result = {**first, "true_label": 1, "predicted_label": 1, "status": "success", "config_hash": store.config_hash}
            store.save(result)
        with RunStore(out, [source], settings, prompt, resume=True) as store:
            self.assertEqual([s["sample_id"] for s in store.pending()], ["two"])
            store.save({**second, "true_label": 0, "predicted_label": 0, "status": "success", "config_hash": store.config_hash})
        with RunStore(out, [source], settings, prompt, resume=True) as store:
            self.assertEqual(list(store.pending(retry_failed=True)), [])
        report = evaluate_run(out)
        stats = report["cohorts"]["ordinary_functions"]["overall"]["all"]
        self.assertNotIn("unknown_rate", stats)
        self.assertNotIn("unknown", stats["counts"])
        self.assertEqual(stats["binary_coverage"], 1)
        self.assertEqual(stats["all_samples"]["accuracy"], 1)
        with self.assertRaises(ValueError):
            RunStore(out, [source], Settings("http://unused.invalid/v1", "other"), prompt, resume=True)
        source.write_text(source.read_text() + "\n")
        with self.assertRaises(ValueError):
            RunStore(out, [source], settings, prompt, resume=True)

    def test_error_retry_and_incomplete_pair_refusal(self):
        source = self.jsonl("input.jsonl", [sample()]); out = self.root / "retry"
        settings, prompt = Settings("http://unused.invalid/v1", "mock"), Prompt()
        with RunStore(out, [source], settings, prompt) as store:
            row = next(store.pending())
            store.save({**row, "true_label": 1, "predicted_label": None, "status": "error", "config_hash": store.config_hash})
            self.assertEqual(list(store.pending()), [])
            self.assertEqual(len(list(store.pending(True))), 1)
        pair = self.jsonl("pair.jsonl", [sample(pair_id="p", variant="before")])
        with self.assertRaises(ValueError):
            RunStore(self.root / "invalid_pair", [pair], settings, prompt)

    def test_checkpoint_and_metrics_reject_third_prediction_status(self):
        row = sample()
        source = self.jsonl("binary.jsonl", [row])
        settings = Settings("http://unused.invalid/v1", "mock")
        with RunStore(self.root / "binary", [source], settings, Prompt()) as store:
            self.assertEqual(store.config["protocol"], Prompt.protocol)
            with self.assertRaises(ValueError):
                store.save({**row, "true_label": 1, "status": "unknown", "predicted_label": None,
                            "config_hash": store.config_hash})
        with self.assertRaises(ValueError):
            calculate([{"dataset": "D", "true_label": 1, "predicted_label": None, "status": "unknown"}])

    def test_finished_journal_answer_is_recovered_before_another_post(self):
        source = self.jsonl("input.jsonl", [sample()]); out = self.root / "journal_recovery"
        settings, prompt = Settings("http://unused.invalid/v1", "mock"), Prompt()
        with RunStore(out, [source], settings, prompt) as store:
            row = next(store.pending())
            event = {"sample_id": row["sample_id"], "sample_hash": row["sample_hash"], "attempt_id": "synthetic-attempt", "attempt_number": 1}
            store.log_attempt({**event, "event": "started"})
            store.log_attempt({**event, "event": "finished", "status": "success", "raw_response": answer(), "finish_reason": "stop", "latency_ms": 1, "usage": {}})
        with RunStore(out, [source], settings, prompt, resume=True) as store:
            self.assertEqual(list(store.pending(True)), [])
            saved = list(read_ledger(out / "results.jsonl"))
            self.assertTrue(saved[0]["recovered_from_journal"])

    def test_tail_recovery_does_not_hide_middle_corruption(self):
        path = self.root / "ledger.jsonl"
        path.write_bytes(b'{"a":1}\n{"broken"')
        self.assertEqual(list(read_ledger(path, repair_tail=True)), [{"a": 1}])
        self.assertTrue(list(self.root.glob("recovery_*.json")))
        path.write_bytes(b'{"a":1}')
        self.assertEqual(list(read_ledger(path, repair_tail=True)), [{"a": 1}])
        path.write_bytes(b'{"broken"\n{"a":1}\n')
        with self.assertRaises(ValueError):
            list(read_ledger(path, repair_tail=True))

    def test_metrics_confusion_and_pair_denominators(self):
        rows = [{"dataset": "D", "true_label": gold, "predicted_label": pred, "status": "success"}
                for gold, pred in [(1, 1), (0, 1), (0, 0), (1, 0)]]
        complete = calculate(rows)["cohorts"]["ordinary_functions"]["overall"]["all"]
        self.assertEqual(complete["binary_coverage"], 1)
        self.assertEqual(complete["all_samples"]["accuracy"], .5)
        self.assertEqual(complete["all_samples"]["f1_with_positive_failures_as_misses"], .5)
        self.assertEqual(complete["all_samples"]["mcc"], 0)
        rows.append({"dataset": "D", "true_label": 1, "predicted_label": None, "status": "error"})
        stats = calculate(rows)["cohorts"]["ordinary_functions"]["overall"]["all"]
        self.assertEqual(stats["conditional_binary_only"]["f1"], .5)
        self.assertEqual(stats["all_samples"]["accuracy"], .4)
        self.assertEqual(stats["all_samples"]["f1_with_positive_failures_as_misses"], .4)
        self.assertEqual(stats["counts"]["error"], 1)
        self.assertIsNone(stats["all_samples"]["mcc"])
        pairs = [{"dataset": "D", "pair_id": pair, "variant": variant, "true_label": gold,
                  "predicted_label": pred, "status": status} for pair, variant, gold, pred, status in
                 [("a", "before", 1, 1, "success"), ("a", "after", 0, 0, "success"),
                  ("b", "before", 1, 1, "success"), ("b", "after", 0, None, "error")]]
        result = calculate(pairs)["pairs"]["overall"]["all"]
        self.assertEqual(result["rates_over_all_pair_groups"]["exact_correct"], .5)
        self.assertEqual(result["counts"]["unresolved"], 1)


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_schema_constrains_binary_and_third_label_response_is_error(self):
        calls = []
        def handler(request):
            payload = json.loads(request.content)
            calls.append(payload)
            self.assertEqual(payload["guided_json"]["properties"]["label"]["enum"], ["vulnerable", "benign"])
            return httpx.Response(200, json={"choices": [{"message": {"content": answer("unknown")}, "finish_reason": "stop"}]})
        settings = Settings("http://unused.invalid/v1", "mock", json_mode="guided_json")
        async with VLLMClient(settings, Prompt(), transport=httpx.MockTransport(handler)) as client:
            result = await client.predict(sample(), lambda event: None)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_type"], "invalid_label")
        self.assertIsNone(result["predicted_label"])
        self.assertEqual(len(calls), 1)

    async def test_timeout_then_success_has_bounded_retry_and_usage_uncertainty(self):
        calls, logs, delays = [], [], []
        def handler(request):
            calls.append(request)
            payload = json.loads(request.content)
            self.assertEqual(len(payload["messages"]), 2)
            self.assertNotIn("true_label", payload)
            if len(calls) == 1:
                raise httpx.ReadTimeout("mock", request=request)
            return httpx.Response(200, json={"choices": [{"message": {"content": answer()}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
        async def sleep(delay):
            delays.append(delay)
        settings = Settings("http://unused.invalid/v1", "mock", max_retries=1)
        async with VLLMClient(settings, Prompt(), transport=httpx.MockTransport(handler), sleep=sleep) as client:
            result = await client.predict(sample(), logs.append)
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(logs), 4)
        self.assertEqual(delays, [1])
        self.assertIsNone(result["total_tokens"])
        self.assertEqual(result["observed_token_lower_bounds"]["total_tokens"], 15)

    async def test_terminal_http_and_long_input_never_turn_benign(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(400, text="context length exceeded")
        async with VLLMClient(Settings("http://unused.invalid/v1", "mock", max_retries=2), Prompt(), transport=httpx.MockTransport(handler)) as client:
            result = await client.predict(sample(), lambda e: None)
        self.assertEqual(result["status"], "error")
        self.assertEqual(len(calls), 1)
        async with VLLMClient(Settings("http://unused.invalid/v1", "mock", max_code_chars=1), Prompt(), transport=httpx.MockTransport(handler)) as client:
            result = await client.predict(sample(), lambda e: None)
        self.assertEqual(result["error_type"], "input_too_long")
        self.assertEqual(len(calls), 1)

    async def test_concurrency_limit_and_retry_cap(self):
        active, maximum, calls = 0, 0, 0
        async def handler(request):
            nonlocal active, maximum, calls
            active += 1; calls += 1; maximum = max(maximum, active)
            await asyncio.sleep(0)
            active -= 1
            return httpx.Response(503)
        async def no_wait(_):
            return None
        settings = Settings("http://unused.invalid/v1", "mock", concurrency=2, max_retries=1)
        async with VLLMClient(settings, Prompt(), transport=httpx.MockTransport(handler), sleep=no_wait) as client:
            results = await asyncio.gather(*(client.predict(sample(str(i)), lambda e: None) for i in range(5)))
        self.assertLessEqual(maximum, 2)
        self.assertEqual(calls, 10)
        self.assertTrue(all(row["status"] == "error" for row in results))


if __name__ == "__main__":
    unittest.main()
