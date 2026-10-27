"""Bounded async OpenAI-compatible HTTP client; never starts a model server."""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

import httpx

from .io_utils import utc_now
from .output_parser import OUTPUT_SCHEMA, failure, parse_output

RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}
TOKEN_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")


@dataclass(frozen=True)
class Settings:
    base_url: str
    model: str
    concurrency: int = 4
    timeout: float = 120
    max_retries: int = 2
    temperature: float = 0
    max_tokens: int = 1024
    seed: int = 42
    max_code_chars: int = 30000
    json_mode: str = "json_object"

    def validate(self):
        url = urlsplit(self.base_url)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("base URL must be http(s), without credentials/query/fragment; include the API prefix such as /v1")
        if not self.model.strip() or not 1 <= self.concurrency <= 128 or not 0 < self.timeout <= 3600:
            raise ValueError("invalid model, concurrency (1..128), or timeout (0..3600]")
        if not 0 <= self.max_retries <= 5 or self.max_tokens < 1 or self.max_code_chars < 1:
            raise ValueError("max_retries must be 0..5; max_tokens and max_code_chars must be positive")
        if not 0 <= self.temperature <= 2 or self.json_mode not in {"none", "json_object", "guided_json"}:
            raise ValueError("invalid temperature or JSON mode")
        return self

    def public_dict(self):
        return asdict(self)


def extract_usage(data):
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    return {key: usage.get(key) if type(usage.get(key)) is int and usage[key] >= 0 else None for key in TOKEN_FIELDS}


class VLLMClient:
    def __init__(self, settings: Settings, prompt, api_key="", transport=None, sleep=asyncio.sleep):
        self.settings, self.prompt, self.sleep = settings.validate(), prompt, sleep
        self.api_key = api_key
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        headers = {"Authorization": "Bearer " + api_key} if api_key else {}
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(settings.timeout), headers=headers, trust_env=False,
            limits=httpx.Limits(max_connections=settings.concurrency, max_keepalive_connections=settings.concurrency),
            transport=transport, follow_redirects=False)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.http.aclose()

    def redact(self, value):
        # Avoid writing an authentication secret even if a proxy echoes it back.
        if isinstance(value, str):
            return value.replace(self.api_key, "[REDACTED]") if self.api_key else value
        if isinstance(value, dict):
            return {k: self.redact(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        return value

    async def check_model(self):
        response = await self.http.get(self.settings.base_url.rstrip("/") + "/models")
        response.raise_for_status()
        data = response.json()
        names = [item.get("id") for item in data.get("data", []) if isinstance(item, dict)]
        if self.settings.model not in names:
            raise ValueError(f"configured model is not advertised by /models; advertised IDs: {names}")
        return {"checked_at": utc_now(), "model_ids": names}

    async def predict(self, sample, log_attempt):
        start = time.perf_counter()
        if len(sample["code"]) > self.settings.max_code_chars:
            return {**failure("input_too_long", "fixed character limit exceeded; source not truncated"),
                "raw_response": "", **{k: None for k in TOKEN_FIELDS}, "latency_ms": 0, "attempt_count": 0}
        payload = {"model": self.settings.model, "messages": self.prompt.messages(sample["code"]),
                   "temperature": self.settings.temperature, "max_tokens": self.settings.max_tokens,
                   "seed": self.settings.seed, "stream": False}
        if self.settings.json_mode == "json_object":
            payload["response_format"] = {"type": "json_object"}
        elif self.settings.json_mode == "guided_json":
            payload["guided_json"] = OUTPUT_SCHEMA
        sums = {k: 0 for k in TOKEN_FIELDS}
        missing = {k: False for k in TOKEN_FIELDS}
        last = failure("request_not_completed")
        raw = ""
        attempts = 0
        for number in range(self.settings.max_retries + 1):
            attempt_id = uuid.uuid4().hex
            event = {"sample_id": sample["sample_id"], "sample_hash": sample["sample_hash"],
                     "attempt_id": attempt_id, "attempt_number": number + 1}
            retryable = False
            usage = {k: None for k in TOKEN_FIELDS}
            response_code, finish, raw = None, None, ""
            async with self.semaphore:
                # Persist intent before POST: interruption can leave server-side work indeterminate.
                log_attempt({**event, "event": "started", "timestamp": utc_now()})
                tick = time.perf_counter()
                attempts += 1
                try:
                    response = await self.http.post(self.settings.base_url.rstrip("/") + "/chat/completions", json=payload)
                    response_code = response.status_code
                    raw = response.text
                    if response.is_error or response.is_redirect:
                        retryable = response.status_code in RETRY_STATUS
                        last = failure("http_error", f"HTTP {response.status_code}; see attempt log for body")
                    else:
                        try:
                            data = response.json()
                            usage = extract_usage(data)
                            choice = data["choices"][0]
                            finish = choice.get("finish_reason")
                            raw = choice["message"]["content"]
                            last = parse_output(raw, sample["code"], finish)
                        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
                            last = failure("invalid_api_response", "not an OpenAI-compatible chat completion")
                except httpx.TimeoutException:
                    retryable = True
                    last = failure("timeout", "request timed out; server-side completion is unknown")
                except httpx.TransportError as error:
                    retryable = True
                    last = failure("transport_error", type(error).__name__)
                duration = round((time.perf_counter() - tick) * 1000, 3)
                for key in TOKEN_FIELDS:
                    if usage[key] is None:
                        missing[key] = True
                    else:
                        sums[key] += usage[key]
                log_attempt(self.redact({**event, "event": "finished", "timestamp": utc_now(),
                    "http_status": response_code, "status": last["status"], "error_type": last.get("error_type"),
                    "finish_reason": finish, "raw_response": raw, "usage": usage, "latency_ms": duration,
                    "retryable": retryable}))
            if not retryable or number == self.settings.max_retries:
                break
            await self.sleep(min(2 ** number, 16))
        return self.redact({**last, "raw_response": raw, "finish_reason": finish,
            "attempt_id": attempt_id,
            **{key: None if missing[key] else sums[key] for key in TOKEN_FIELDS},
            "observed_token_lower_bounds": sums, "usage_incomplete": any(missing.values()),
            "attempt_count": attempts, "latency_ms": round((time.perf_counter() - start) * 1000, 3)})
