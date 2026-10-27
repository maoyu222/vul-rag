from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AdapterOptions:
    dataset: str
    version: str
    split: str = "test"
    mode: str = "ordinary"
    format: str = "auto"


@dataclass
class Adaptation:
    samples: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)


def rejection(path: Path, indices, reason: str, pair=None) -> dict:
    return {"source_file": str(path), "source_row_indices": list(indices),
            "pair_id": pair, "reason": reason}
