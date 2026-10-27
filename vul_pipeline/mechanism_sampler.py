"""Seeded mechanism strata with greedy coverage within strata; not population inference."""
from __future__ import annotations

import random
from collections import Counter, defaultdict

MAX_PILOT_SAMPLES = 40
SAMPLER_VERSION = "mechanism_coverage_v1"


def labels(row: dict) -> dict[str, list[str]]:
    return {"mechanism": [row.get("vulnerability_type") or "not_recorded"],
            "repair_pattern": [row.get("review_annotations", {}).get("repair_pattern") or "not_recorded"],
            "cwe": row.get("cwe") or ["not_recorded"],
            "project": [row.get("project") or "not_recorded"],
            "dataset": [row.get("dataset") or "not_recorded"]}


def distribution(rows: list[dict]) -> dict:
    result = {key: Counter() for key in labels({})}
    for row in rows:
        for key, values in labels(row).items():
            result[key].update(values)
    return {key: dict(sorted(count.items())) for key, count in result.items()}


def select_samples(rows: list[dict], count: int = 40, seed: int = 42) -> list[dict]:
    if not 1 <= count <= min(MAX_PILOT_SAMPLES, len(rows)):
        raise ValueError("pilot count must be 1..40 and no larger than the source")
    ids = [row["sample_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate sample IDs")
    rng = random.Random(seed)
    # Sorting first makes results independent of input order and Python hash seed.
    ordered = sorted(rows, key=lambda row: row["sample_id"])
    rng.shuffle(ordered)
    priority = {row["sample_id"]: i for i, row in enumerate(ordered)}
    strata = defaultdict(list)
    for row in ordered:
        strata[labels(row)["mechanism"][0]].append(row)
    selected, selected_ids = [], set()
    seen = {key: Counter() for key in labels({})}

    def choose(pool):
        def score(row):
            tags = labels(row)
            # Primary mechanism coverage is controlled by strata below. Real
            # recorded labels alone earn novelty credit; missing data does not.
            novelty = sum(weight * sum(v != "not_recorded" and not seen[key][v] for v in tags[key])
                          for key, weight in (("repair_pattern", 4), ("cwe", 3),
                                              ("project", 2), ("dataset", 1)))
            return novelty, -priority[row["sample_id"]]
        row = max(pool, key=score)
        selected.append(row)
        selected_ids.add(row["sample_id"])
        for key, values in labels(row).items():
            seen[key].update(values)

    # Cover each available mechanism once, rare strata first if the budget is small.
    for mechanism in sorted(strata, key=lambda k: (len(strata[k]), k))[:count]:
        choose(strata[mechanism])
    while len(selected) < count:
        available = [key for key, pool in strata.items()
                     if any(row["sample_id"] not in selected_ids for row in pool)]
        # Allocate additional slots proportionally to sqrt(stratum size), so large
        # classes are represented without consuming the whole pilot budget.
        mechanism = max(sorted(available), key=lambda k: len(strata[k]) ** 0.5 / (seen["mechanism"][k] + 1))
        choose([row for row in strata[mechanism] if row["sample_id"] not in selected_ids])
    return selected


def sampling_manifest(source: dict, rows: list[dict], selected: list[dict], seed: int, source_hash: str) -> dict:
    def source_audit(items):
        return {"sample_count": len(items), "unique_project_labels": len({r.get("project") for r in items if r.get("project")}),
                "missing_metadata_counts": {key: sum(not r.get(key) for r in items)
                                            for key in ("dataset", "project", "cve", "cwe", "fix_commit")},
                "reviewed_quote_counts": {side: sum(len(r["review_annotations"]["locations"][side]) for r in items)
                                          for side in ("before", "after")},
                "source_integrity_passed": True,
                "note": "审核引用均已由原始 validate_source_samples 检查存在性；项目按原始标签计数，不推断标签真实性。"}
    return {"sampler_version": SAMPLER_VERSION, "seed": seed, "sample_count": len(selected),
            "source_count": len(rows), "source_sha256": source_hash,
            "method": "机制分层；每层至少一例（预算允许时）；余量按 sqrt(层大小)/(已选数+1) 分配；层内优先覆盖修复模式、CWE、项目、数据集，种子打破并列。",
            "limitations": "多样性导向的诊断抽样，非总体准确率估计；CWE 为多标签计数；未记录值不推测。",
            "source_integrity": {key: source[key] for key in ("schema_version", "rag_knowledge_text_generated", "heldout_exclusion")},
            "population": distribution(rows), "selected": distribution(selected),
            "population_source_audit": source_audit(rows), "selected_source_audit": source_audit(selected),
            "selected_sample_ids": [row["sample_id"] for row in selected]}
