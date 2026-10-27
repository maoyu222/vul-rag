from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .knowledge_base import SecurityConditionKnowledgeBase
from .qwen import QwenCoder, QwenConfig
from .schemas import DetectionResult


class VulnerabilityDetector:
    """Detect vulnerabilities by checking reviewed historical security conditions."""

    def __init__(
        self,
        knowledge_path: Path,
        model_path: Path,
        *,
        retrieve_k: int = 10,
        endpoint: str | None = None,
        endpoint_model: str | None = None,
        max_new_tokens: int = 1024,
    ):
        if retrieve_k <= 0:
            raise ValueError("retrieve_k must be positive")
        self.knowledge = SecurityConditionKnowledgeBase.load(knowledge_path)
        self.model = QwenCoder(
            QwenConfig(
                model_path=model_path,
                endpoint=endpoint,
                endpoint_model=endpoint_model,
                max_new_tokens=max_new_tokens,
            )
        )
        self.retrieve_k = retrieve_k

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _error(message: str) -> DetectionResult:
        return DetectionResult(
            label=None,
            status="error",
            explanation=message,
            retrieved_cves=[],
            condition_results=[],
        )

    @staticmethod
    def _retrieval_rows(candidates) -> list[dict]:
        rows = []
        for rank, (score, record) in enumerate(candidates, start=1):
            rows.append(
                {
                    "rank": rank,
                    "score": score,
                    "source_sample_id": record.source_sample_id,
                    "cve_id": record.cve_id,
                    "vulnerability_type": record.vulnerability_type,
                    "repair_pattern": record.repair_pattern,
                    "operation": record.operation,
                    "roles": record.roles,
                    "unsafe_when": record.unsafe_when,
                    "security_condition": record.security_condition,
                    "required_target_facts": record.required_target_facts,
                    "assumptions": record.assumptions,
                }
            )
        return rows

    def detect(
        self,
        code: str,
        debug_dir: Path | None = None,
        sample_metadata: dict[str, Any] | None = None,
    ) -> DetectionResult:
        if debug_dir is not None:
            self._write_json(debug_dir / "metadata.json", sample_metadata or {})

        try:
            target_code_facts = self.model.extract_target_code_facts(code)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            result = self._error(f"Target code fact extraction failed: {error}")
            if debug_dir is not None:
                self._write_json(debug_dir / "target_code_facts_generation.json", self.model.last_generation)
                self._write_json(debug_dir / "result.json", result.to_dict())
            return result

        if debug_dir is not None:
            self._write_json(debug_dir / "target_code_facts_generation.json", self.model.last_generation)

        query = self.model.retrieval_query(target_code_facts)
        candidates = self.knowledge.search(query, retrieve_k=self.retrieve_k)
        if debug_dir is not None:
            self._write_json(
                debug_dir / "retrieval_results.json",
                {
                    "target_code_facts": target_code_facts,
                    "query_text": query,
                    "retrieve_k": self.retrieve_k,
                    "results": self._retrieval_rows(candidates),
                },
            )

        if not candidates:
            result = DetectionResult(
                label="unknown",
                explanation="No related historical security condition was retrieved.",
                retrieved_cves=[],
                condition_results=[],
            )
            if debug_dir is not None:
                self._write_json(debug_dir / "result.json", result.to_dict())
            return result

        try:
            matches = self.model.match_security_conditions(code, candidates)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            result = self._error(f"Security-condition matching failed: {error}")
            if debug_dir is not None:
                self._write_json(debug_dir / "condition_match_generation.json", self.model.last_generation)
                self._write_json(debug_dir / "result.json", result.to_dict())
            return result

        if debug_dir is not None:
            self._write_json(debug_dir / "condition_match_generation.json", self.model.last_generation)
            self._write_json(debug_dir / "condition_matches.json", {"decisions": matches})

        try:
            result = self.model.check_security_conditions(code, candidates, matches)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            result = self._error(f"Security-condition checking failed: {error}")

        if debug_dir is not None:
            self._write_json(debug_dir / "condition_check_generation.json", self.model.last_generation)
            self._write_json(debug_dir / "result.json", result.to_dict())
        return result

    def detect_code_only(self, code: str) -> DetectionResult:
        try:
            return self.model.code_only_verdict(code)
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            return self._error(f"Code-only review failed: {error}")
