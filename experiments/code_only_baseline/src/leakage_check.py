"""Knowledge-source isolation and bounded near-duplicate candidate auditing."""
from __future__ import annotations

import collections
import hashlib
import heapq
import json
import re

from .io_utils import file_hash
from .normalization import code_hash, project_key, text, tokens

RULES = ("sample_id", "cve", "fix_commit", "project", "code_hash")


class KnowledgeIndex:
    def __init__(self, path, aliases=None):
        self.path, self.aliases = path, aliases or {}
        self.sha256 = file_hash(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != 2 or not isinstance(data.get("samples"), list):
            raise ValueError("knowledge-source isolation expects the original curated schema-2 file")
        self.values = {key: set() for key in RULES}
        self.legacy_paths = {}
        self.sample_count = len(data["samples"])
        for row in data["samples"]:
            source_path = text(row.get("pair_provenance", {}).get("source_path"))
            if source_path:
                self.legacy_paths[text(row.get("sample_id"))] = source_path
            for rule, value in (("sample_id", text(row.get("sample_id"))), ("cve", text(row.get("cve")).upper()),
                                ("fix_commit", text(row.get("fix_commit")).lower()),
                                ("project", project_key(row.get("project", ""), self.aliases))):
                if value:
                    self.values[rule].add(value)
            for side in ("before", "after"):
                if isinstance(row.get("code_" + side), str) and row["code_" + side].strip():
                    self.values["code_hash"].add(code_hash(row["code_" + side]))

    def overlaps(self, sample, rules=RULES, legacy_ids=True):
        aliases = [sid for sid in sample.get("legacy_source_ids", [])
                   if self.legacy_paths.get(sid) and str(sample.get("source_file", "")).endswith("/" + self.legacy_paths[sid])]
        candidates = {"sample_id": [sample["sample_id"]] + (aliases if legacy_ids else []),
            "cve": [text(sample.get("cve_id")).upper()], "fix_commit": [text(sample.get("fix_commit")).lower()],
            "project": [project_key(sample.get("project", ""), self.aliases)],
            "code_hash": [sample["normalized_code_hash"]]}
        return {rule: [value for value in candidates[rule] if value and value in self.values[rule]]
                for rule in rules if any(value and value in self.values[rule] for value in candidates[rule])}


class UnionFind:
    def __init__(self):
        self.parent, self.size = {}, {}

    def find(self, key):
        if key not in self.parent:
            self.parent[key], self.size[key] = key, 1
        root = key
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[key] != key:
            parent = self.parent[key]
            self.parent[key] = root
            key = parent
        return root

    def union(self, left, right):
        left, right = self.find(left), self.find(right)
        if left == right:
            return
        # Stable component representative, independent of insertion order.
        lo, hi = sorted((left, right))
        self.parent[hi] = lo
        self.size[lo] += self.size[hi]


def group_keys(sample, group_by="project", aliases=None):
    keys = ["code:" + sample["normalized_code_hash"]]
    if sample.get("pair_id"):
        keys.append("pair:" + sample["pair_id"])
    commit = text(sample.get("fix_commit")).lower()
    project = project_key(sample.get("project", ""), aliases)
    if commit:
        keys.append("commit:" + commit)
    if group_by == "project" and project:
        keys.append("project:" + project)
    if not project and not commit:
        keys.append("missing_group:" + sample["sample_id"])
    return keys


def deterministic_split(component: str, seed: int, ratios=(0.8, 0.1, 0.1)) -> str:
    value = int(hashlib.sha256(f"{seed}:{component}".encode()).hexdigest()[:16], 16) / 2 ** 64
    return "train" if value < ratios[0] else "valid" if value < ratios[0] + ratios[1] else "test"


class SimilarityAudit:
    """Bottom-k token-shingle sketches: candidates only, bounded and reported."""
    def __init__(self, threshold=0.8, sketch_size=32, max_reports=5000, bucket_limit=100, max_indexed=20000):
        self.threshold, self.sketch_size = threshold, sketch_size
        self.max_reports, self.bucket_limit = max_reports, bucket_limit
        self.buckets = collections.defaultdict(list)
        self.sketches, self.code_hashes = {}, {}
        self.reported = 0
        self.skipped_bucket_entries = 0
        self.comparison_count = 0
        self.max_indexed, self.unindexed_samples = max_indexed, 0

    def add(self, sample):
        if self.max_reports == 0:
            self.unindexed_samples += 1
            return []
        seq = tokens(sample["code"])
        if len(seq) < 5:
            return []
        hashes = {int.from_bytes(hashlib.blake2b("\x1f".join(seq[i:i + 5]).encode(), digest_size=8).digest(), "big")
                  for i in range(len(seq) - 4)}
        sketch = set(heapq.nsmallest(self.sketch_size, hashes))
        candidates = set()
        for value in sorted(sketch)[:4]:
            candidates.update(self.buckets[value])
        result = []
        for sid in sorted(candidates):
            if self.code_hashes[sid] == sample["normalized_code_hash"]:
                continue
            self.comparison_count += 1
            other = self.sketches[sid]
            score = len(sketch & other) / len(sketch | other)
            if score >= self.threshold and self.reported < self.max_reports:
                result.append({"left_sample_id": sid, "right_sample_id": sample["sample_id"],
                               "sketch_jaccard": score, "status": "candidate_not_semantic_duplicate"})
                self.reported += 1
        if len(self.sketches) >= self.max_indexed:
            self.unindexed_samples += 1
            return result
        self.sketches[sample["sample_id"]] = sketch
        self.code_hashes[sample["sample_id"]] = sample["normalized_code_hash"]
        for value in sorted(sketch)[:4]:
            if len(self.buckets[value]) < self.bucket_limit:
                self.buckets[value].append(sample["sample_id"])
            else:
                self.skipped_bucket_entries += 1
        return result
