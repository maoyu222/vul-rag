"""Offline normalization, stable group splits, isolation and frozen test manifests."""
from __future__ import annotations

import collections
import contextlib
import json
import sqlite3
from pathlib import Path

from .adapters import AdapterOptions, get_adapter
from .io_utils import append_json, atomic_json, canonical, file_hash, fingerprint, fresh_directory, open_new_jsonl, utc_now
from .leakage_check import KnowledgeIndex, RULES, SimilarityAudit, UnionFind, deterministic_split, group_keys
from .normalization import NORMALIZATION_VERSION, project_key
from .readers import records
from .schemas import normalize_sample


def prepare(options: AdapterOptions, paths: list[Path], output: Path, knowledge_source: Path,
            seed=42, group_by="project", ratios=(0.8, 0.1, 0.1), isolation_rules=RULES,
            aliases=None, mapping=None, legacy_ids=True, deduplicate="keep", near_duplicate_limit=5000,
            reference_paths=()):
    if group_by not in {"project", "commit"} or deduplicate not in {"keep", "within-split"}:
        raise ValueError("invalid group_by/deduplicate")
    if len(ratios) != 3 or any(x < 0 for x in ratios) or abs(sum(ratios) - 1) > 1e-8:
        raise ValueError("split ratios must be nonnegative train/valid/test values summing to one")
    if not set(isolation_rules) <= set(RULES):
        raise ValueError("unknown isolation rule")
    if near_duplicate_limit < 0:
        raise ValueError("near_duplicate_limit must be nonnegative")
    if options.dataset == "MegaVul" and group_by == "project" and ratios[2] <= 0:
        raise ValueError("MegaVul test split must have positive probability")
    for path in paths:
        if not path.is_file():
            raise ValueError(f"missing input {path}")
        if path.resolve() == knowledge_source.resolve():
            raise ValueError("the 1,279 knowledge-source pairs are not an evaluation dataset")
    inputs = [{"path": str(path.resolve()), "sha256": file_hash(path), "bytes": path.stat().st_size,
               "mtime_ns": path.stat().st_mtime_ns} for path in paths]
    knowledge = KnowledgeIndex(knowledge_source, aliases)
    out = fresh_directory(output)
    config = {"adapter": options.__dict__, "seed": seed, "group_by": group_by, "split_ratios": ratios,
        "isolation_rules": list(isolation_rules), "legacy_id_aliases": legacy_ids, "project_aliases": aliases or {},
        "deduplicate": deduplicate, "normalization_version": NORMALIZATION_VERSION, "mapping": mapping,
        "knowledge_source_sha256": knowledge.sha256, "knowledge_source_count": knowledge.sample_count,
        "reference_files": [{"path": str(p.resolve()), "sha256": file_hash(p)} for p in reference_paths]}
    manifest = {"status": "building", "created_at": utc_now(), "config": config, "input_files": inputs}
    manifest["preparation_hash"] = fingerprint([config, inputs])
    atomic_json(out / "preparation_manifest.json", manifest)
    connection = sqlite3.connect(out / "normalized_cache.sqlite3")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.execute("CREATE TABLE samples(sid TEXT PRIMARY KEY, codehash TEXT, label INTEGER, split TEXT, pairkey TEXT, payload TEXT)")
    totals, rejected_reasons = collections.Counter(), collections.Counter()
    dsu = UnionFind()
    key_owner = {}
    similarity = SimilarityAudit(max_reports=near_duplicate_limit)
    adapter = get_adapter(options.dataset.lower() if options.dataset.lower() in {"primevul", "megavul"} else "mapped", options, mapping)
    try:
        with contextlib.ExitStack() as stack:
            rejected = stack.enter_context(open_new_jsonl(out / "rejected.jsonl"))
            near = stack.enter_context(open_new_jsonl(out / "near_duplicate_candidates.jsonl"))
            for path in paths:
                for batch in adapter.iter_batches(path):
                    totals["raw_batches"] += 1
                    if batch.rejected:
                        for item in batch.rejected:
                            totals["raw_source_records"] += len(item["source_row_indices"])
                            rejected_reasons[item["reason"]] += len(item["source_row_indices"])
                            append_json(rejected, item)
                        continue
                    totals["raw_source_records"] += len({s.get("source_row_index") for s in batch.samples})
                    try:
                        samples = [normalize_sample(s) for s in batch.samples]
                        for sample in samples:
                            if connection.execute("SELECT 1 FROM samples WHERE sid=?", (sample["sample_id"],)).fetchone():
                                raise ValueError("duplicate sample_id in source inputs")
                        if len({s["sample_id"] for s in samples}) != len(samples):
                            raise ValueError("duplicate sample_id in one adaptation batch")
                        with connection:
                            for sample in samples:
                                connection.execute("INSERT INTO samples VALUES(?,?,?,?,?,?)", (
                                    sample["sample_id"], sample["normalized_code_hash"], sample["label"],
                                    sample["split"], sample.get("pair_id"), canonical(sample)))
                        for sample in samples:
                            sid = sample["sample_id"]
                            dsu.find(sid)
                            for key in group_keys(sample, group_by, aliases):
                                if key in key_owner:
                                    dsu.union(sid, key_owner[key])
                                else:
                                    key_owner[key] = sid
                            for item in similarity.add(sample):
                                append_json(near, item)
                            totals["normalized_samples"] += 1
                            totals["missing_project"] += not bool(sample["project"])
                            totals["missing_fix_commit"] += not bool(sample["fix_commit"])
                            totals["missing_cve"] += not bool(sample["cve_id"])
                    except (ValueError, TypeError) as error:
                        rejected_reasons[str(error)] += len(batch.samples)
                        append_json(rejected, {"source_file": str(path), "source_row_indices": [s.get("source_row_index") for s in batch.samples],
                                               "reason": str(error), "scope": "entire_pair_rejected_when_paired"})
            connection.execute("CREATE INDEX by_code ON samples(codehash)")
            connection.execute("CREATE INDEX by_pair ON samples(pairkey)")
            connection.commit()
            duplicate_groups, conflict_ids = 0, set()
            duplicate_log = stack.enter_context(open_new_jsonl(out / "exact_duplicates.jsonl"))
            for codehash, count, labels in connection.execute("SELECT codehash,COUNT(*),COUNT(DISTINCT label) FROM samples GROUP BY codehash HAVING COUNT(*)>1"):
                group = [r[0] for r in connection.execute("SELECT sid FROM samples WHERE codehash=? ORDER BY sid", (codehash,))]
                duplicate_groups += 1
                append_json(duplicate_log, {"code_hash": codehash, "sample_ids": group, "label_conflict": labels > 1})
                if labels > 1:
                    conflict_ids.update(group)
            # A conflict in one variant rejects the entire pair in both views.
            conflict_pairs = {row[0] for sid in conflict_ids for row in connection.execute("SELECT pairkey FROM samples WHERE sid=? AND pairkey IS NOT NULL", (sid,))}
            overlap_by_sid, overlap_pairs = {}, collections.defaultdict(set)
            split_by_sid, components = {}, collections.defaultdict(set)
            source_overlap = collections.Counter()
            cross_data_values = {key: collections.defaultdict(set) for key in ("cve", "fix_commit", "code_hash")}
            for sid, split, pair, payload in connection.execute("SELECT sid,split,pairkey,payload FROM samples ORDER BY sid"):
                sample = json.loads(payload)
                root = dsu.find(sid)
                assigned = deterministic_split(root, seed, ratios) if options.dataset.lower() == "megavul" else split
                split_by_sid[sid] = assigned
                components[root].add(assigned)
                matches = knowledge.overlaps(sample, isolation_rules, legacy_ids)
                if matches:
                    overlap_by_sid[sid] = matches
                    source_overlap.update(matches.keys())
                    if pair:
                        overlap_pairs[pair].update(matches)
                for key, value in (("cve", sample["cve_id"]), ("fix_commit", sample["fix_commit"]), ("code_hash", sample["normalized_code_hash"])):
                    if value:
                        cross_data_values[key][value.lower()].add(sample["dataset"])
            reference_audit = stack.enter_context(open_new_jsonl(out / "reference_overlap.jsonl"))
            reference_counts = collections.Counter()
            for reference in reference_paths:
                for _, sample in records(reference, "jsonl"):
                    sample = normalize_sample(sample)
                    for key, value in (("cve", sample["cve_id"]), ("fix_commit", sample["fix_commit"]), ("code_hash", sample["normalized_code_hash"])):
                        if value:
                            previous = cross_data_values[key].get(value.lower(), set())
                            if previous:
                                reference_counts[key] += 1
                                append_json(reference_audit, {"rule": key, "value": value, "reference_sample_id": sample["sample_id"],
                                                             "reference_dataset": sample["dataset"], "current_datasets": sorted(previous),
                                                             "cross_dataset": any(d != sample["dataset"] for d in previous)})
                                previous.add(sample["dataset"])
            writers = {}
            def writer(track, split):
                key = (track, split)
                if key not in writers:
                    if split not in {"train", "valid", "test", "unspecified"}:
                        raise ValueError(f"unsafe or unknown split name: {split}")
                    writers[key] = stack.enter_context(open_new_jsonl(out / track / (split + ".jsonl")))
                return writers[key]
            for track in ("official", "strict"):
                for split_name in ("train", "valid", "test", "unspecified"):
                    writer(track, split_name)
            exclusions = stack.enter_context(open_new_jsonl(out / "knowledge_overlap.jsonl"))
            frozen = stack.enter_context(open_new_jsonl(out / "sample_manifest.jsonl"))
            seen_hashes = set()
            effective_rules = collections.Counter()
            for sid, codehash, label, split, pair, payload in connection.execute("SELECT sid,codehash,label,split,pairkey,payload FROM samples ORDER BY sid"):
                sample = json.loads(payload)
                assigned = split_by_sid[sid]
                if deduplicate == "within-split" and not pair:
                    if (assigned, codehash) in seen_hashes:
                        totals["same_split_duplicates_removed"] += 1
                        append_json(rejected, {"sample_id": sid, "reason": "duplicate_code_within_split"})
                        continue
                    seen_hashes.add((assigned, codehash))
                sample["split"] = assigned
                sample["split_method"] = "connected_project_commit_pair_code_components" if options.dataset.lower() == "megavul" else "official_preserved_or_explicit_user_mapping"
                sample = normalize_sample({k: v for k, v in sample.items() if k != "sample_hash"})
                append_json(writer("official", assigned), sample)
                totals["official_" + assigned] += 1
                totals[f"official_{assigned}_label_{label}"] += 1
                matches = dict(overlap_by_sid.get(sid, {}))
                active_rules = set(matches)
                if sid in conflict_ids or pair in conflict_pairs:
                    matches["label_conflict"] = ["normalized_code_has_conflicting_labels_or_pair_closure"]
                    totals["strict_label_conflict_excluded"] += 1
                if pair in overlap_pairs:
                    matches["pair_closure"] = sorted(overlap_pairs[pair])
                    active_rules.update(overlap_pairs[pair])
                effective_rules.update(active_rules)
                if matches:
                    append_json(exclusions, {"sample_id": sid, "pair_id": pair, "matches": matches})
                    totals["strict_excluded"] += 1
                else:
                    append_json(writer("strict", assigned), sample)
                    totals["strict_" + assigned] += 1
                    totals[f"strict_{assigned}_label_{label}"] += 1
                append_json(frozen, {"sample_id": sid, "dataset": sample["dataset"], "dataset_version": sample["dataset_version"],
                    "split": assigned, "pair_id": pair, "variant": sample["variant"], "label": label,
                    "sample_hash": sample["sample_hash"], "normalized_code_hash": codehash, "strict_included": not bool(matches)})
        cross_split_components = sum(len(splits) > 1 for splits in components.values())
        report = {"counts": dict(totals), "rejected_reasons": dict(rejected_reasons),
                  "knowledge_overlap_per_rule_nonexclusive": dict(source_overlap), "exact_duplicate_groups": duplicate_groups,
                  "strict_knowledge_exclusions_per_rule_including_pair_closure_nonexclusive": dict(effective_rules),
                  "cross_split_components": cross_split_components,
                  "reference_overlap_counts_nonexclusive": dict(reference_counts),
                  "label_conflict_policy": "官方视图保留合法原始标签并报告冲突；严格视图排除冲突及对应完整配对。",
                  "official_split_note": "PrimeVul官方划分不改写；若发现跨划分重叠只报告。MegaVul为本实验固定的连接分量划分，不是官方测试集。",
                  "cross_dataset_shared_identifiers": {key: sum(len(ds) > 1 for ds in values.values()) for key, values in cross_data_values.items()},
                  "near_duplicate_audit": {"reported": similarity.reported, "comparisons": similarity.comparison_count,
                    "max_indexed": similarity.max_indexed, "unindexed_samples": similarity.unindexed_samples,
                    "skipped_bucket_entries": similarity.skipped_bucket_entries, "limit": near_duplicate_limit,
                    "note": "有界词法候选审计，不保证召回全部近重复；未自动按相似度删除。"}}
        for info in inputs:
            stat = Path(info["path"]).stat()
            if (stat.st_size, stat.st_mtime_ns) != (info["bytes"], info["mtime_ns"]):
                raise ValueError("a source file changed externally during conversion")
        manifest.update(status="complete", finished_at=utc_now(), statistics=report,
                        outputs={str(path.relative_to(out)): file_hash(path) for path in out.rglob("*.jsonl")})
        atomic_json(out / "preparation_manifest.json", manifest)
        atomic_json(out / "data_quality_report.json", report)
        return manifest
    except BaseException as error:
        manifest.update(status="failed", failure_type=type(error).__name__, finished_at=utc_now())
        atomic_json(out / "preparation_manifest.json", manifest)
        raise
    finally:
        connection.close()
