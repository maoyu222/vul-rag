from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class DeepSeekConfig:
    model: str = "deepseek-v4-pro"
    base_url: str = "https://api.deepseek.com"
    api_key_env: str = "sk-02f6e931289b46f0ac68427227eefc6d"
    max_tokens: int = 1600
    thinking: bool = False
    timeout: float = 180.0


class DeepSeekClient:
    """Small DeepSeek API client used only when building the knowledge base."""

    def __init__(self, config: DeepSeekConfig):
        self.config = config
        self.api_key = os.environ.get(config.api_key_env, "").strip()
        if not self.api_key:
            raise RuntimeError(
                f"{config.api_key_env} is not set; it is required to build the knowledge base"
            )

    def runtime_info(self) -> dict:
        return {
            "model": self.config.model,
            "base_url": self.config.base_url,
            "thinking": self.config.thinking,
            "max_tokens": self.config.max_tokens,
            "timeout": self.config.timeout,
        }

    def generate(self, system: str, user: str) -> str:
        return self.generate_with_metadata(system, user)["content"]

    def generate_with_metadata(self, system: str, user: str) -> dict:
        """Backward-compatible transport with usage retained even on truncation."""
        self.last_response = {}
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "max_tokens": self.config.max_tokens,
            "thinking": {
                "type": "enabled" if self.config.thinking else "disabled"
            },
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            self.config.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                value = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            # Server error bodies may echo credentials; never place them in logs.
            failure = RuntimeError(f"DeepSeek API HTTP {error.code}")
            failure.http_status = error.code
            raise failure from error
        except urllib.error.URLError as error:
            raise RuntimeError("DeepSeek API network request failed") from error
        except (TimeoutError, OSError) as error:
            raise RuntimeError("DeepSeek API request timed out or transport failed") from error

        try:
            choice = value["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise RuntimeError(
                "DeepSeek API response did not contain choices[0].message.content"
            ) from error

        self.last_response = {
            "content": content, "usage": value.get("usage", {}),
            "request_id": value.get("id"), "model": value.get("model", self.config.model),
            "finish_reason": choice.get("finish_reason"),
        }
        if choice.get("finish_reason") == "length":
            raise RuntimeError("DeepSeek output was cut off by the token limit")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("DeepSeek API returned empty content")
        self.last_response["content"] = content.strip()
        return self.last_response
