#!/usr/bin/env python3
"""Explicitly invoke an existing remote vLLM service on a frozen code-only cohort."""
import _bootstrap  # noqa: F401
import argparse
import asyncio
import json
import os
from pathlib import Path

from src.io_utils import EXPERIMENT_ROOT
from src.runner import execute
from src.vllm_client import Settings


def main(argv=None, retry_default=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=EXPERIMENT_ROOT / "config.json")
    parser.add_argument("--input", type=Path, action="append", required=True, help="normalized JSONL; repeatable, do not mix ordinary/paired records")
    parser.add_argument("--output", type=Path, required=True, help="new run directory, or exact prior directory with --resume")
    parser.add_argument("--base-url", help="OpenAI API prefix, e.g. http://HOST:PORT/v1; also VLLM_BASE_URL")
    parser.add_argument("--model")
    parser.add_argument("--api-key", help="prefer VLLM_API_KEY to avoid shell-history exposure; never persisted")
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--max-retries", type=int)
    parser.add_argument("--temperature", type=float)
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--max-code-chars", type=int, help="longer functions become error/input_too_long, without truncation or POST")
    parser.add_argument("--json-mode", choices=["none", "json_object", "guided_json"])
    parser.add_argument("--dataset", action="append", default=[], help="exact normalized dataset name")
    parser.add_argument("--split", action="append", choices=["train", "valid", "test", "unspecified"], help="default: test only")
    parser.add_argument("--limit", type=int, help="deterministic sample cap; keep whole pairs; part of resume identity")
    parser.add_argument("--resume", action="store_true", default=retry_default)
    parser.add_argument("--retry-failed", action="store_true", default=retry_default)
    parser.add_argument("--skip-model-check", action="store_true", help="explicitly skip GET /models for services without that endpoint")
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if set(config) - set(Settings.__dataclass_fields__):
        parser.error("unknown key in config.json")
    config["base_url"] = args.base_url or os.environ.get("VLLM_BASE_URL") or config.get("base_url")
    for key in Settings.__dataclass_fields__:
        if getattr(args, key, None) is not None:
            config[key] = getattr(args, key)
    if not config.get("base_url"):
        parser.error("provide the verified --base-url or VLLM_BASE_URL; no service address is assumed")
    if args.retry_failed and not args.resume:
        parser.error("--retry-failed requires --resume")
    settings = Settings(**config).validate()
    result = asyncio.run(execute(args.input, args.output, settings, args.api_key or os.environ.get("VLLM_API_KEY", ""),
        resume=args.resume, retry_failed=args.retry_failed, limit=args.limit, datasets=args.dataset,
        splits=args.split or ["test"], skip_model_check=args.skip_model_check))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
