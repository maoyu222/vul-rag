"""Strict binary metrics with explicit execution-failure denominators."""
from __future__ import annotations

import collections
import math


def ratio(n, d):
    return n / d if d else None


def zero_ratio(n, d):
    return n / d if d else 0.0


def binary_metrics(tp, fp, tn, fn):
    n = tp + fp + tn + fn
    f1_positive = zero_ratio(2 * tp, 2 * tp + fp + fn)
    f1_negative = zero_ratio(2 * tn, 2 * tn + fp + fn)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {"n": n, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "accuracy": ratio(tp + tn, n), "precision": zero_ratio(tp, tp + fp),
        "recall": zero_ratio(tp, tp + fn), "f1": f1_positive, "macro_f1": (f1_positive + f1_negative) / 2,
        "mcc": (tp * tn - fp * fn) / denominator if denominator else 0.0,
        "balanced_accuracy": (tp / (tp + fn) + tn / (tn + fp)) / 2 if tp + fn and tn + fp else None,
        "fpr": ratio(fp, tn + fp), "fnr": ratio(fn, tp + fn)}


class Classification:
    def __init__(self):
        self.counts = collections.Counter()
        self.matrix = {0: collections.Counter(), 1: collections.Counter()}

    def add(self, row):
        gold = row["true_label"]
        status = row.get("status", "not_completed")
        pred = row.get("predicted_label")
        if type(gold) is not int or gold not in (0, 1):
            raise ValueError("metrics require gold integer 0/1")
        if status not in {"success", "error", "not_completed"}:
            raise ValueError("unrecognized result status")
        if status == "success" and (type(pred) is not int or pred not in (0, 1)):
            raise ValueError("success must have binary prediction")
        if status != "success" and pred is not None:
            raise ValueError("failed or incomplete requests must have null prediction")
        outcome = str(pred) if status == "success" else status
        self.matrix[gold][outcome] += 1
        self.counts[status] += 1
        self.counts["total"] += 1

    def report(self):
        m, c = self.matrix, self.counts
        tp, fp, tn, fn = m[1]["1"], m[0]["1"], m[0]["0"], m[1]["0"]
        positives, negatives = sum(m[1].values()), sum(m[0].values())
        rejected_pos = positives - tp - fn
        rejected_neg = negatives - tn - fp
        all_f1_pos = zero_ratio(2 * tp, 2 * tp + fp + fn + rejected_pos)
        all_f1_neg = zero_ratio(2 * tn, 2 * tn + fp + fn + rejected_neg)
        return {"support": {"all": c["total"], "positive": positives, "negative": negatives},
            "counts": {key: c[key] for key in ("success", "error", "not_completed")},
            "error_rate": ratio(c["error"], c["total"]),
            "binary_coverage": ratio(c["success"], c["total"]),
            "all_samples": {"accuracy": ratio(tp + tn, c["total"]), "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                "positive_failures_or_incomplete": rejected_pos, "negative_failures_or_incomplete": rejected_neg,
                "precision": zero_ratio(tp, tp + fp), "recall": ratio(tp, positives),
                "f1_with_positive_failures_as_misses": all_f1_pos,
                "macro_f1_with_class_failures_as_misses": (all_f1_pos + all_f1_neg) / 2,
                "balanced_accuracy": (tp / positives + tn / negatives) / 2 if positives and negatives else None,
                "fpr": ratio(fp, negatives), "fnr": ratio(fn, positives),
                "positive_miss_or_failure_rate": ratio(fn + rejected_pos, positives),
                "negative_error_or_failure_rate": ratio(fp + rejected_neg, negatives),
                "mcc": binary_metrics(tp, fp, tn, fn)["mcc"] if not rejected_pos + rejected_neg else None},
            "conditional_binary_only": binary_metrics(tp, fp, tn, fn),
            "extended_confusion_matrix": {str(g): {key: m[g][key] for key in ("0", "1", "error", "not_completed")} for g in (0, 1)}}


def pair_report(groups):
    c = collections.Counter()
    for members in groups.values():
        c["total_pair_groups"] += 1
        by_side = {r.get("variant"): r for r in members}
        valid = len(members) == 2 and set(by_side) == {"before", "after"} and by_side["before"]["true_label"] == 1 and by_side["after"]["true_label"] == 0
        if not valid:
            c["invalid_or_incomplete_pairs"] += 1
            continue
        c["valid_pairs"] += 1
        before, after = by_side["before"], by_side["after"]
        a = before.get("predicted_label") if before.get("status") == "success" else None
        b = after.get("predicted_label") if after.get("status") == "success" else None
        c["before_correct"] += a == 1
        c["after_correct"] += b == 0
        c["exact_correct"] += a == 1 and b == 0
        c["reasonable_change"] += a == 1 and b == 0
        c["both_vulnerable"] += a == 1 and b == 1
        c["both_benign"] += a == 0 and b == 0
        c["reversed_change"] += a == 0 and b == 1
        c["unresolved"] += a is None or b is None
    total = c["total_pair_groups"]
    names = ("total_pair_groups", "valid_pairs", "invalid_or_incomplete_pairs", "before_correct", "after_correct", "exact_correct", "reasonable_change", "both_vulnerable", "both_benign", "reversed_change", "unresolved")
    return {"counts": {name: c[name] for name in names},
        "rates_over_all_pair_groups": {name: ratio(c[name], total) for name in names[3:]},
        "note": "分母包含执行错误、未完成和不完整配对；after=0 仅表示数据集关联的目标漏洞已修复。"}


class Suite:
    def __init__(self, minimum_support=20):
        self.minimum_support = minimum_support
        self.stats = collections.defaultdict(Classification)
        self.pairs = collections.defaultdict(list)
        self.n = 0

    def add(self, row):
        self.n += 1
        cohort = "paired_functions" if row.get("pair_id") else "ordinary_functions"
        dataset = row["dataset"] + "@" + str(row.get("dataset_version", "unspecified"))
        keys = [(cohort, "overall", "all"), (cohort, "dataset", dataset)]
        keys += [(cohort, "split", row.get("split") or "unspecified"),
                 (cohort, "dataset_split", dataset + "/" + (row.get("split") or "unspecified"))]
        cwes = row.get("cwe_ids") or ["CWE-UNKNOWN"]
        keys += [(cohort, "cwe", cwe) for cwe in cwes]
        keys += [(cohort, "dataset_cwe", dataset + "/" + cwe) for cwe in cwes]
        for key in keys:
            self.stats[key].add(row)
        if row.get("pair_id"):
            self.pairs[(dataset, row["pair_id"])].append({key: row.get(key) for key in
                ("variant", "true_label", "predicted_label", "status", "cwe_ids")})

    def report(self):
        result = {"schema": "code_only_metrics", "sample_count": self.n,
            "definitions": {"labels": "only vulnerable=1 and benign=0; error/not_completed are operational states, not prediction classes",
                "all_samples": "execution failures and incomplete requests count as incorrect for accuracy; class recall/F1 includes them as misses",
                "mcc": "MCC is binary-only; all-sample MCC is null when execution failures or incomplete requests exist",
                "fpr_fnr": "FP / all negatives and FN / all positives; execution failure rates are shown separately",
                "zero_division": "conditional precision/recall/F1/MCC use 0 when undefined; empty accuracy/rates use null",
                "cwe": "multi-label categories overlap; missing CWE has its own bucket; never sum categories as independent samples",
                "roc_auc": "not computed: no reliable continuous score"}, "cohorts": {}}
        for (cohort, dimension, name), statistic in sorted(self.stats.items()):
            block = statistic.report()
            block["small_support"] = block["support"]["all"] < self.minimum_support
            result["cohorts"].setdefault(cohort, {}).setdefault(dimension, {})[name] = block
        pair_dimensions = collections.defaultdict(dict)
        for (dataset, pair), members in self.pairs.items():
            key = (dataset, pair)
            pair_dimensions[("overall", "all")][key] = members
            pair_dimensions[("dataset", dataset)][key] = members
            cwes = {cwe for row in members for cwe in row.get("cwe_ids") or []} or {"CWE-UNKNOWN"}
            for cwe in cwes:
                pair_dimensions[("cwe", cwe)][key] = members
                pair_dimensions[("dataset_cwe", dataset + "/" + cwe)][key] = members
        result["pairs"] = {}
        for (dimension, name), groups in sorted(pair_dimensions.items()):
            report = pair_report(groups)
            report["small_support"] = len(groups) < self.minimum_support
            result["pairs"].setdefault(dimension, {})[name] = report
        return result


def calculate(rows, minimum_support=20):
    suite = Suite(minimum_support)
    for row in rows:
        suite.add(row)
    return suite.report()
