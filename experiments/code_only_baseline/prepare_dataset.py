#!/usr/bin/env python3
"""Convert read-only source data; never use curated knowledge pairs as test data."""
import _bootstrap  # noqa: F401
import argparse
import json
from pathlib import Path

from src.adapters import AdapterOptions
from src.io_utils import EXPERIMENT_ROOT, PROJECT_ROOT
from src.leakage_check import RULES
from src.preparation import prepare


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, help="PrimeVul / MegaVul / a user-mapped dataset name")
    parser.add_argument("--version", required=True, help="PrimeVul: v0.1/original; others: an explicit snapshot identifier")
    parser.add_argument("--data-root", type=Path, default=Path("/home/PublicData/PHY-data/vul_detect/data"))
    parser.add_argument("--input", type=Path, action="append", help="explicit source path, repeatable for mapped datasets")
    parser.add_argument("--output", type=Path, required=True, help="a NEW directory inside this experiment module")
    parser.add_argument("--split", choices=["train", "valid", "test", "unspecified"], default="test")
    parser.add_argument("--mode", choices=["ordinary", "paired"], default="ordinary")
    parser.add_argument("--format", choices=["auto", "json", "jsonl", "csv"], default="auto")
    parser.add_argument("--mapping", type=Path, help="explicit verified JSON mapping, required for non-native datasets")
    parser.add_argument("--knowledge-source", type=Path, default=PROJECT_ROOT / "data/high_quality_repair_pairs.json")
    parser.add_argument("--isolation-rules", default=",".join(RULES), help="comma-separated rules; 'none' disables knowledge exclusion explicitly")
    parser.add_argument("--project-aliases", type=Path, help="JSON object of explicitly verified project aliases")
    parser.add_argument("--disable-legacy-id-aliases", action="store_true")
    parser.add_argument("--reference", type=Path, action="append", default=[], help="normalized JSONL from other datasets/splits; audit only")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--group-by", choices=["project", "commit"], default="project")
    parser.add_argument("--ratios", type=float, nargs=3, default=[0.8, 0.1, 0.1], metavar=("TRAIN", "VALID", "TEST"))
    parser.add_argument("--deduplicate", choices=["keep", "within-split"], default="keep")
    parser.add_argument("--near-duplicate-limit", type=int, default=5000)
    args = parser.parse_args(argv)
    dataset = {"primevul": "PrimeVul", "megavul": "MegaVul"}.get(args.dataset.lower(), args.dataset)
    paths = args.input
    if not paths:
        if dataset == "PrimeVul" and args.version in {"v0.1", "original"}:
            folder = "PrimeVul_v0.1" if args.version == "v0.1" else "PrimeVul_original"
            paths = [args.data_root / folder / f"primevul_{args.split}{'_paired' if args.mode == 'paired' else ''}.jsonl"]
        elif dataset == "MegaVul":
            paths = [args.data_root / "megavul/megavul.json"]
        else:
            parser.error("this adapter requires --input; no source path is guessed")
    mapping = json.loads(args.mapping.read_text(encoding="utf-8")) if args.mapping else None
    aliases = json.loads(args.project_aliases.read_text(encoding="utf-8")) if args.project_aliases else {}
    rules = () if args.isolation_rules == "none" else tuple(x.strip() for x in args.isolation_rules.split(","))
    options = AdapterOptions(dataset, args.version, args.split, args.mode, args.format)
    result = prepare(options, paths, args.output, args.knowledge_source, seed=args.seed, group_by=args.group_by,
                     ratios=tuple(args.ratios), isolation_rules=rules, aliases=aliases, mapping=mapping,
                     legacy_ids=not args.disable_legacy_id_aliases, deduplicate=args.deduplicate,
                     near_duplicate_limit=args.near_duplicate_limit, reference_paths=args.reference)
    print(json.dumps(result["statistics"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
