from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .schemas import DetectionResult, SecurityConditionKnowledge


@dataclass(frozen=True)
class QwenConfig:
    model_path: Path = Path.home() / "models/Qwen2.5-Coder-7B-Instruct"
    max_new_tokens: int = 1024
    temperature: float = 0.0
    endpoint: str | None = None
    endpoint_model: str | None = None


def _json_object(text: str) -> dict:
    text = text.strip()
    if text.startswith("```json") and text.endswith("```"):
        text = text[7:-3].strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("model must return exactly one JSON object") from error
    if not isinstance(value, dict):
        raise ValueError("model response must be a JSON object")
    return value


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def source_has_fragment(source: str, fragment: str) -> bool:
    fragment = _norm(fragment)
    if not fragment:
        return False
    source = _norm(source)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", fragment):
        return re.search(rf"(?<!\w){re.escape(fragment)}(?!\w)", source) is not None
    return fragment in source


def _strings(value, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} items must be strings")
        if item.strip():
            result.append(item.strip())
    return result


def validate_target_code_facts(value: dict, source: str) -> dict[str, list[dict]]:
    result = {}
    for key in ("operations", "value_relations", "checks", "state_changes"):
        items = value.get(key, [])
        if not isinstance(items, list):
            raise ValueError(f"target code facts {key} must be a list")
        result[key] = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"target code facts {key} items must be objects")
            fact = str(item.get("fact", "")).strip()
            evidence = str(item.get("evidence", "")).strip()
            if not fact or not evidence:
                raise ValueError(f"target code facts {key} require fact and evidence")
            if not source_has_fragment(source, evidence):
                raise ValueError(f"target code facts {key} evidence must be copied from target source")
            result[key].append({"fact": fact, "evidence": evidence})
    return result


def validate_condition_matches(value: dict, roles_by_rank: dict[int, set[str]], source: str) -> list[dict]:
    decisions = value.get("decisions")
    if not isinstance(decisions, list):
        raise ValueError("condition matching response requires a decisions list")
    expected = set(roles_by_rank)
    seen = set()
    result = []
    for item in decisions:
        if not isinstance(item, dict):
            raise ValueError("condition matching decisions must be objects")
        rank = item.get("rank")
        if type(rank) is not int or rank not in expected or rank in seen:
            raise ValueError("condition matching decision has invalid or duplicate rank")
        seen.add(rank)
        status = str(item.get("status", "")).strip()
        if status not in {"applicable", "not_applicable", "uncertain"}:
            raise ValueError("invalid condition matching status")
        reason = str(item.get("reason", "")).strip()
        if not reason:
            raise ValueError("condition matching decision requires a reason")
        operation = str(item.get("target_operation", "")).strip()
        raw_mapping = item.get("role_mapping", {})
        if not isinstance(raw_mapping, dict):
            raise ValueError("role_mapping must be an object")
        mapping = {
            str(role).strip(): str(expression).strip()
            for role, expression in raw_mapping.items()
            if str(role).strip() and str(expression).strip()
        }
        if status == "applicable":
            if not operation or not source_has_fragment(source, operation):
                raise ValueError("applicable condition must quote a target operation present in source")
            required = roles_by_rank[rank]
            if set(mapping) != required:
                raise ValueError("applicable condition must map every historical role exactly once")
            if any(not source_has_fragment(source, expression) for expression in mapping.values()):
                raise ValueError("role_mapping values must be target expressions present in source")
        elif operation or mapping:
            raise ValueError("not_applicable or uncertain conditions cannot bind a target operation")
        result.append({
            "rank": rank,
            "status": status,
            "target_operation": operation,
            "role_mapping": mapping,
            "reason": reason,
        })
    if seen != expected:
        raise ValueError("condition matching response must cover every candidate exactly once")
    return sorted(result, key=lambda item: item["rank"])


def validate_condition_checks(value: dict, applicable_ranks: set[int], source: str) -> list[dict]:
    checks = value.get("condition_checks")
    if not isinstance(checks, list):
        raise ValueError("condition_checks must be a list")
    seen = set()
    result = []
    for item in checks:
        if not isinstance(item, dict):
            raise ValueError("condition check must be an object")
        rank = item.get("rank")
        if type(rank) is not int or rank not in applicable_ranks or rank in seen:
            raise ValueError("condition check has invalid or duplicate rank")
        seen.add(rank)
        status = str(item.get("status", "")).strip()
        if status not in {"violated", "satisfied", "unknown"}:
            raise ValueError("condition status must be violated, satisfied, or unknown")
        reason = str(item.get("reason", "")).strip()
        if not reason:
            raise ValueError("condition check requires a reason")
        evidence = _strings(item.get("evidence", []), "evidence")
        if any(not source_has_fragment(source, fragment) for fragment in evidence):
            raise ValueError("condition evidence must be copied from target source")
        if status in {"violated", "satisfied"} and not evidence:
            raise ValueError(f"{status} condition requires source evidence")
        result.append({"rank": rank, "status": status, "evidence": evidence, "reason": reason})
    if seen != applicable_ranks:
        raise ValueError("condition_checks must cover every applicable condition")
    return result


def label_from_checks(checks: list[dict], *, has_uncertain_match: bool = False) -> str:
    if any(item["status"] == "violated" for item in checks):
        return "vulnerable"
    if has_uncertain_match:
        return "unknown"
    if checks and all(item["status"] == "satisfied" for item in checks):
        return "benign"
    return "unknown"


class QwenCoder:
    def __init__(self, config: QwenConfig):
        if config.max_new_tokens <= 0:
            raise ValueError("max_new_tokens must be positive")
        self.config = config
        self.last_generation: dict = {}
        if config.endpoint:
            with urllib.request.urlopen(config.endpoint.rstrip("/") + "/models", timeout=30) as response:
                value = json.load(response)
            data = value.get("data") if isinstance(value, dict) else None
            if not isinstance(data, list):
                raise ValueError("model endpoint /models response must contain a data list")
            ids = [str(item.get("id", "")).strip() for item in data if isinstance(item, dict) and str(item.get("id", "")).strip()]
            if config.endpoint_model:
                if config.endpoint_model not in ids:
                    raise ValueError(f"endpoint model {config.endpoint_model!r} is not exposed by the server")
                self.endpoint_model = config.endpoint_model
            elif len(ids) == 1:
                self.endpoint_model = ids[0]
            elif not ids:
                raise ValueError("model endpoint did not report any model IDs")
            else:
                raise ValueError("model endpoint exposes multiple models; specify endpoint_model explicitly")
            return

        if not config.model_path.exists():
            raise FileNotFoundError(f"Qwen model not found at {config.model_path}")
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_path, local_files_only=True, trust_remote_code=True)
        dtype = torch.bfloat16 if torch.cuda.is_available() else torch.float32
        self.model = AutoModelForCausalLM.from_pretrained(
            config.model_path, local_files_only=True, trust_remote_code=True,
            dtype=dtype, device_map="auto", low_cpu_mem_usage=True,
        )
        self.model.eval()

    def runtime_info(self) -> dict:
        if self.config.endpoint:
            return {"endpoint": self.config.endpoint, "model": self.endpoint_model, "max_new_tokens": self.config.max_new_tokens}
        parameter = next(self.model.parameters())
        return {"cuda_available": self.torch.cuda.is_available(), "model_input_device": str(parameter.device), "model_dtype": str(parameter.dtype)}

    def _generate(self, system: str, user: str) -> str:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        self.last_generation = {"messages": messages}
        if self.config.endpoint:
            payload = {
                "model": self.endpoint_model,
                "messages": messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_new_tokens,
                "chat_template_kwargs": {"enable_thinking": False},
                "stream": False,
                "response_format": {"type": "json_object"},
            }
            request = urllib.request.Request(
                self.config.endpoint.rstrip("/") + "/chat/completions",
                data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=900) as response:
                    value = json.load(response)
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")
                self.last_generation["error"] = detail
                raise ValueError(f"Model API HTTP {error.code}: {detail}") from error
            choice = value["choices"][0]
            content = choice["message"].get("content") or ""
            self.last_generation.update(response=content, usage=value.get("usage", {}))
            if choice.get("finish_reason") == "length":
                raise ValueError("model output was cut off by the token limit")
            return content

        prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer(prompt, return_tensors="pt")
        input_tokens = inputs["input_ids"].shape[1]
        context_limit = self.model.config.max_position_embeddings
        if input_tokens + self.config.max_new_tokens > context_limit:
            raise ValueError(f"model context limit exceeded: {input_tokens} input tokens + {self.config.max_new_tokens} output tokens > {context_limit}")
        device = next(self.model.parameters()).device
        inputs = {key: value.to(device) for key, value in inputs.items()}
        kwargs = {"max_new_tokens": self.config.max_new_tokens, "do_sample": self.config.temperature > 0}
        if self.config.temperature > 0:
            kwargs["temperature"] = self.config.temperature
        with self.torch.inference_mode():
            output = self.model.generate(**inputs, **kwargs)
        generated = output[0, input_tokens:]
        content = self.tokenizer.decode(generated, skip_special_tokens=True)
        self.last_generation.update(response=content, input_tokens=input_tokens, output_tokens=len(generated))
        if len(generated) >= self.config.max_new_tokens:
            raise ValueError("model output reached the token limit and may be incomplete")
        return content

    def extract_target_code_facts(self, code: str) -> dict:
        value = _json_object(self._generate(
            "List only facts directly visible in one C/C++ function. Do not decide vulnerability. Every fact must quote source text. Return JSON only.",
            'Return {"operations":[{"fact":"...","evidence":"..."}],"value_relations":[],"checks":[],"state_changes":[]}. Use empty lists when absent. Evidence must be copied from TARGET SOURCE.\n\nTARGET SOURCE:\n' + code,
        ))
        return validate_target_code_facts(value, code)

    @staticmethod
    def retrieval_query(facts: dict) -> str:
        return "\n".join(
            str(item["fact"])
            for key in ("operations", "value_relations", "checks", "state_changes")
            for item in facts.get(key, [])
            if str(item["fact"]).strip()
        )

    def match_security_conditions(self, code: str, candidates: list[tuple[float, SecurityConditionKnowledge]]) -> list[dict]:
        historical = []
        roles_by_rank = {}
        for rank, (_, record) in enumerate(candidates, start=1):
            historical.append({
                "rank": rank, "operation": record.operation, "roles": record.roles,
                "unsafe_when": record.unsafe_when, "security_condition": record.security_condition,
                "required_target_facts": record.required_target_facts, "assumptions": record.assumptions,
            })
            roles_by_rank[rank] = set(record.roles)
        value = _json_object(self._generate(
            "For each historical condition, decide whether the same operation and every historical role can be identified in the target. Similar API names alone are insufficient. Do not decide vulnerability. Return JSON only.",
            'Return {"decisions":[{"rank":1,"status":"applicable|not_applicable|uncertain","target_operation":"exact target excerpt or empty","role_mapping":{"historical_role":"exact target expression"},"reason":"..."}]}. Applicable requires every historical role; other statuses must leave operation empty and mapping {}.\n\nHISTORICAL CONDITIONS:\n'
            + json.dumps(historical, ensure_ascii=False) + "\n\nTARGET SOURCE:\n" + code,
        ))
        return validate_condition_matches(value, roles_by_rank, code)

    def check_security_conditions(self, code: str, candidates: list[tuple[float, SecurityConditionKnowledge]], matches: list[dict]) -> DetectionResult:
        by_rank = {rank: record for rank, (_, record) in enumerate(candidates, start=1)}
        applicable = [item for item in matches if item["status"] == "applicable"]
        checks = []
        if applicable:
            conditions = [{
                "rank": item["rank"],
                "unsafe_when": by_rank[item["rank"]].unsafe_when,
                "security_condition": by_rank[item["rank"]].security_condition,
                "assumptions": by_rank[item["rank"]].assumptions,
                "target_operation": item["target_operation"],
                "role_mapping": item["role_mapping"],
            } for item in applicable]
            value = _json_object(self._generate(
                "Check each security condition using only visible target-source facts. Mark satisfied only when visibly enforced, violated only when the unsafe relation is visibly allowed, otherwise unknown. Return JSON only.",
                'Return {"condition_checks":[{"rank":1,"status":"violated|satisfied|unknown","evidence":["exact target excerpt"],"reason":"..."}]}. Violated/satisfied require source evidence.\n\nCONDITIONS:\n'
                + json.dumps(conditions, ensure_ascii=False) + "\n\nTARGET SOURCE:\n" + code,
            ))
            checks = validate_condition_checks(value, {item["rank"] for item in applicable}, code)

        uncertain = any(item["status"] == "uncertain" for item in matches)
        label = label_from_checks(checks, has_uncertain_match=uncertain)
        if not applicable:
            explanation = "At least one retrieved condition has uncertain applicability, so the function cannot be classified from visible source alone." if uncertain else "No retrieved security condition was shown to apply to this function."
        elif label == "vulnerable":
            explanation = "At least one applicable security condition is violated."
        elif uncertain:
            explanation = "No applicable condition is violated, but at least one retrieved condition has uncertain applicability."
        elif any(item["status"] == "unknown" for item in checks):
            explanation = "No applicable condition is violated, but at least one applicable security condition cannot be resolved from visible source alone."
        else:
            explanation = "All applicable security conditions are satisfied, and no retrieved condition has uncertain applicability."

        checks_by_rank = {item["rank"]: item for item in checks}
        condition_results = []
        for match in matches:
            rank = match["rank"]
            record = by_rank[rank]
            check = checks_by_rank.get(rank)
            condition_results.append({
                "rank": rank,
                "source_sample_id": record.source_sample_id,
                "cve_id": record.cve_id,
                "operation": record.operation,
                "security_condition": record.security_condition,
                "match": {key: value for key, value in match.items() if key != "rank"},
                "check": {key: value for key, value in check.items() if key != "rank"} if check else None,
            })
        return DetectionResult(
            label=label,
            explanation=explanation,
            retrieved_cves=list(dict.fromkeys(record.cve_id for _, record in candidates if record.cve_id)),
            condition_results=condition_results,
        )

    def code_only_verdict(self, code: str) -> DetectionResult:
        value = _json_object(self._generate(
            "Review one C/C++ function for a source-level vulnerability using only visible code. Do not invent external contracts. Return JSON only.",
            'Return {"label":"vulnerable|benign|unknown","reason":"concise source-based explanation"}.\n\nTARGET SOURCE:\n' + code,
        ))
        label = str(value.get("label", "")).strip().lower()
        reason = str(value.get("reason", "")).strip()
        if label not in {"vulnerable", "benign", "unknown"} or not reason:
            raise ValueError("invalid code-only verdict")
        return DetectionResult(label=label, explanation=reason, retrieved_cves=[], condition_results=[])
