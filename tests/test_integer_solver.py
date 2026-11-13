"""整数求解器与真实支持枚举的单元测试。"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.integer_solver import (  # noqa: E402
    BudgetExhausted,
    FeasibilityCache,
    Infeasible,
    Row,
    feasible,
    integer_support,
    maximize,
    minimize,
    normalize_row,
    real_feasible,
    witness,
)


class SolverTests(unittest.TestCase):
    def test_basic_feasibility_and_witness(self):
        rows = [Row((1, 1), 10, "eq")]
        bounds = [(0, 10), (0, 10)]
        self.assertTrue(feasible(rows, bounds))
        assignment = witness(rows, bounds)
        self.assertEqual(assignment[0] + assignment[1], 10)

    def test_integer_infeasible_but_real_feasible_parity(self):
        # 2x - y = 0 与 x + y = 10 => 3x = 10，实数有解、整数无解。
        rows = [Row((2, -1), 0, "eq"), Row((1, 1), 10, "eq")]
        bounds = [(0, 10), (0, 10)]
        self.assertFalse(feasible(rows, bounds))
        self.assertTrue(real_feasible(rows, bounds))

    def test_gcd_normalization_detects_infeasible_equation(self):
        with self.assertRaises(Infeasible):
            normalize_row((2, 2), 7, "eq")
        row = normalize_row((2, 2), 8, "eq")
        self.assertEqual((row.coeffs, row.rhs), ((1, 1), 4))

    def test_minimize_maximize_bounds(self):
        rows = [Row((1, 1), 10, "eq")]
        bounds = [(0, 10), (0, 10)]
        cache = FeasibilityCache()
        self.assertEqual(minimize([1, 0], rows, bounds, cache=cache), 0)
        self.assertEqual(maximize([1, 0], rows, bounds, cache=cache), 10)

    def test_support_has_parity_hole_not_interval(self):
        # x + 2z = 6，x,z ∈ [0,6]：x 只能取偶数 {0,2,4,6}，区间长度 7 但支持只有 4。
        rows = [Row((1, 2), 6, "eq")]
        bounds = [(0, 6), (0, 6)]
        support = integer_support(0, rows, bounds, cache=FeasibilityCache())
        values = [entry["value"] for entry in support]
        self.assertEqual(values, [0, 2, 4, 6])
        for entry in support:
            assignment = entry["witness"]
            self.assertEqual(assignment[0] + 2 * assignment[1], 6)
            self.assertEqual(assignment[0], entry["value"])

    def test_support_with_internal_hole(self):
        # x + 3z = 9，x,z ∈ [0,9]：x ∈ {0,3,6,9}，洞在内部。
        rows = [Row((1, 3), 9, "eq")]
        bounds = [(0, 9), (0, 9)]
        support = integer_support(0, rows, bounds)
        self.assertEqual([e["value"] for e in support], [0, 3, 6, 9])

    def test_cache_reuses_answers(self):
        rows = [Row((1, 1), 10, "eq")]
        bounds = [(0, 10), (0, 10)]
        cache = FeasibilityCache()
        feasible(rows, bounds, cache=cache)
        hits_before = cache.stats.cache_hits
        feasible(rows, bounds, cache=cache)
        self.assertEqual(cache.stats.cache_hits, hits_before + 1)

    def test_budget_exhaustion_raises_and_poisons_no_cache(self):
        # 无解系统配合极小预算，触发预算耗尽且缓存不记录错误结论。
        rows = [Row((1, 1, 1), 1, "eq"), Row((1, -1, 0), 0, "eq")]
        bounds = [(0, 50), (0, 50), (0, 50)]
        cache = FeasibilityCache()
        with self.assertRaises(BudgetExhausted):
            feasible(rows, bounds, cache=cache, budget=1)
        self.assertEqual(cache.answers, {})

    def test_inequality_gcd_uses_directed_rounding(self):
        # 2x - 2y >= 5 约分后必须是 x - y >= 3（ceil），不能放松成 >= 2。
        rows = [Row((1, 0), 4, "le"), Row((2, -2), 5, "ge"), Row((1, 0), -3, "ge")]
        bounds = [(0, 4), (0, 6)]
        support = integer_support(0, rows, bounds)
        self.assertEqual([e["value"] for e in support], [3, 4])

    def test_inequality_propagation(self):
        rows = [Row((1, 1), 5, "le"), Row((1, 0), 2, "ge")]
        bounds = [(0, 10), (0, 10)]
        self.assertTrue(feasible(rows, bounds))
        self.assertEqual(minimize([1, 0], rows, bounds), 2)

    def test_witness_cap_truncation_marker(self):
        rows = [Row((1, 1), 100, "eq")]
        bounds = [(0, 100), (0, 100)]
        support = integer_support(0, rows, bounds, witness_cap=5)
        self.assertTrue(support[-1]["truncated"])
        self.assertEqual(len(support), 6)  # 5 条见证 + 1 条截断标记


if __name__ == "__main__":
    unittest.main()
