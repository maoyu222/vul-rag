from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

from .schemas import SecurityConditionKnowledge


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.I)


def _tokens(text: str) -> list[str]:
    return [token.lower() for token in _TOKEN_RE.findall(text)]


class SecurityConditionKnowledgeBase:
    """BM25 retrieval over reviewed operation/condition knowledge."""

    def __init__(self, records: list[SecurityConditionKnowledge]):
        sample_ids = [record.source_sample_id for record in records]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("knowledge base contains duplicate source_sample_id values")

        self.records = records
        self.documents = [_tokens(self._document(record)) for record in records]
        self.doc_freq: Counter[str] = Counter()
        for document in self.documents:
            self.doc_freq.update(set(document))
        self.avg_len = (
            sum(len(document) for document in self.documents) / len(self.documents)
            if self.documents
            else 0.0
        )

    @staticmethod
    def _document(record: SecurityConditionKnowledge) -> str:
        roles = " ".join(f"{name} {description}" for name, description in record.roles.items())
        return "\n".join(
            [
                record.operation,
                roles,
                record.unsafe_when,
                record.security_condition,
                " ".join(record.required_target_facts),
            ]
        )

    @classmethod
    def load(cls, path: Path) -> "SecurityConditionKnowledgeBase":
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, list):
            raise ValueError("knowledge base must be a JSON list")
        return cls([SecurityConditionKnowledge.from_dict(item) for item in value])

    @staticmethod
    def save(path: Path, records: list[SecurityConditionKnowledge]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps([record.to_dict() for record in records], indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )

    def search(
        self, query: str, retrieve_k: int = 10
    ) -> list[tuple[float, SecurityConditionKnowledge]]:
        if retrieve_k <= 0:
            raise ValueError("retrieve_k must be positive")
        if not self.records:
            return []

        query_terms = list(dict.fromkeys(_tokens(query)))
        if not query_terms:
            return []

        k1 = 1.5
        b = 0.75
        total_docs = len(self.documents)
        scored: list[tuple[float, SecurityConditionKnowledge]] = []

        for document, record in zip(self.documents, self.records):
            counts = Counter(document)
            score = 0.0
            for term in query_terms:
                df = self.doc_freq.get(term, 0)
                tf = counts.get(term, 0)
                if not df or not tf:
                    continue
                idf = math.log(1.0 + (total_docs - df + 0.5) / (df + 0.5))
                norm = tf + k1 * (
                    1.0 - b + b * len(document) / max(self.avg_len, 1.0)
                )
                score += idf * (tf * (k1 + 1.0)) / norm
            if score > 0.0:
                scored.append((score, record))

        scored.sort(key=lambda item: item[0], reverse=True)
        return scored[:retrieve_k]
