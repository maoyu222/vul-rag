import random
import unittest

from mechanism_fixtures import row
from vul_pipeline.mechanism_sampler import distribution, select_samples


class SamplerTests(unittest.TestCase):
    def population(self):
        rows = [row(f"id_{i:03}") for i in range(90)]
        for i, sample in enumerate(rows):
            sample["vulnerability_type"] = f"mechanism_{i % 25}"
            sample["project"] = f"project_{i % 13}"
        return rows

    def test_deterministic_independent_of_source_order(self):
        rows = self.population()
        first = [r["sample_id"] for r in select_samples(rows)]
        random.Random(7).shuffle(rows)
        self.assertEqual(first, [r["sample_id"] for r in select_samples(rows)])
        self.assertNotEqual(first, [r["sample_id"] for r in select_samples(rows, seed=9)])

    def test_mechanism_coverage_without_duplicates(self):
        selected = select_samples(self.population())
        self.assertEqual(len(selected), 40)
        self.assertEqual(len({r["sample_id"] for r in selected}), 40)
        self.assertEqual(len({r["vulnerability_type"] for r in selected}), 25)

    def test_hard_limit_and_duplicate_ids(self):
        for count in (0, -1, 41, 1279):
            with self.assertRaises(ValueError):
                select_samples(self.population(), count)
        with self.assertRaises(ValueError):
            select_samples([row(), row()], 2)

    def test_missing_labels_are_not_guessed(self):
        sample = row()
        sample.update(dataset="", cwe=[], project="")
        counts = distribution([sample])
        self.assertEqual(counts["cwe"], {"not_recorded": 1})
        self.assertEqual(counts["dataset"], {"not_recorded": 1})

    def test_small_budget_covers_rare_mechanisms_first(self):
        rows = [row(str(i)) for i in range(10)]
        rows[0]["vulnerability_type"] = "rare"
        self.assertIn("rare", {r["vulnerability_type"] for r in select_samples(rows, 2)})
