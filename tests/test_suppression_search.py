"""互补抑制搜索测试：精确最优、无可保护方案、预算耗尽、跨表拼接。"""

import itertools
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.audit_engine import AuditContext, Cell, ProtectionRequirement, Query, audit_primary  # noqa: E402
from src.integer_solver import FeasibilityCache  # noqa: E402
from src.suppression_search import search_complementary_suppression  # noqa: E402


def make_context(cells, base, candidates, requirements, extra=None):
    order = [c[0] for c in cells]
    return AuditContext(
        order=order,
        cells=[Cell(k, lo, hi, truth, primary) for k, lo, hi, truth, primary in cells],
        requirements={k: ProtectionRequirement(k_, ld, ud) for k, k_, ld, ud in requirements},
        base_queries=[Query(k, tuple(a), ans) for k, a, ans in base],
        candidates=[Query(k, tuple(a), ans, cost) for k, a, ans, cost in candidates],
        extra_released=[Query(k, tuple(a), ans, origin="other-table", hideable=False) for k, a, ans in (extra or [])],
        cache=FeasibilityCache(),
    )


def brute_force_optimal(ctx):
    keys = [q.key for q in ctx.candidates]
    costs = {q.key: q.suppression_cost for q in ctx.candidates}
    best = None
    for r in range(len(keys) + 1):
        for suppressed in itertools.combinations(keys, r):
            public = frozenset(keys) - frozenset(suppressed)
            rows = ctx.adversary_rows(public)
            ok = True
            for cell in ctx.cells:
                if cell.primary and not audit_primary(cell.key, rows, ctx).get("protected", False):
                    ok = False
                    break
            if ok:
                cost = sum(costs[k] for k in suppressed)
                if best is None or cost < best[0]:
                    best = (cost, frozenset(suppressed))
    return best


class SearchTests(unittest.TestCase):
    def _medium_context(self):
        # x+y=10；候选 y（直接泄露）、两个带洞线性组合与冗余查询。
        return make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [
                ("y", [0, 1], 8, 1),
                ("double", [2, 2], 20, 3),
                ("mix", [1, 2], 18, 2),
            ],
            [("x", 3, 1, 1)],
        )

    def test_matches_brute_force(self):
        ctx = self._medium_context()
        result = search_complementary_suppression(ctx, node_budget=10_000)
        self.assertEqual(result.status, "optimal")
        best = brute_force_optimal(ctx)
        self.assertIsNotNone(best)
        self.assertEqual(result.cost, best[0])
        self.assertEqual(frozenset(result.suppressed), best[1])

    def test_main_fixture_story_cheapest_suppression(self):
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("y", [0, 1], 8, 1), ("double", [2, 2], 20, 3)],
            [("x", 3, 1, 1)],
        )
        result = search_complementary_suppression(ctx, node_budget=10_000)
        self.assertEqual(result.status, "optimal")
        self.assertEqual(result.suppressed, ["y"])
        self.assertEqual(result.cost, 1)
        self.assertEqual(result.lower_bound, 1)

    def test_no_protection_scheme_when_prior_pins_primary(self):
        # published_prior 直接固定 x，任何候选隐藏都无法挽回。
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10), ("x-pin", [1, 0], 2)],
            [("y", [0, 1], 8, 1)],
            [("x", 3, 1, 1)],
        )
        result = search_complementary_suppression(ctx, node_budget=10_000)
        self.assertEqual(result.status, "no_protection_scheme")
        self.assertIsNone(result.cost)

    def _large_context(self, n_candidates=10):
        # 大量候选撑大搜索树，使小预算只能探索部分树。
        templates = [
            ("y", [0, 1], 8, 1),
            ("double", [2, 2], 20, 3),
            ("mix", [1, 2], 18, 2),
            ("shift", [1, 1], 10, 4),
            ("twice-x", [2, 0], 4, 5),
            ("triple-y", [0, 3], 24, 6),
        ]
        candidates = list(templates)
        for i in range(n_candidates - len(templates)):
            candidates.append((f"extra-{i}", [1, 1], 10, 7 + i))
        return make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            candidates,
            [("x", 3, 1, 1)],
        )

    def test_budget_exhaustion_without_any_witness_is_incomplete(self):
        ctx = self._large_context()
        result = search_complementary_suppression(ctx, node_budget=3)
        self.assertEqual(result.status, "analysis_incomplete")
        self.assertIsNone(result.cost)
        self.assertIsNotNone(result.lower_bound)

    def test_budget_exhaustion_returns_feasible_and_valid_lower_bound(self):
        ctx = self._large_context()
        full = search_complementary_suppression(ctx, node_budget=100_000)
        self.assertEqual(full.status, "optimal")
        optimal_cost = full.cost
        # 中等预算：找到至少一个可行方案后耗尽，交付可行方案与合法下界。
        result = search_complementary_suppression(ctx, node_budget=400)
        self.assertEqual(result.status, "feasible_with_lower_bound")
        self.assertIsNotNone(result.suppressed)
        self.assertGreaterEqual(result.cost, result.lower_bound)
        self.assertLessEqual(result.lower_bound, optimal_cost)
        self.assertIn("不得称为最优", result.note)
        # 报告的方案本身必须真的满足保护要求。
        public = frozenset(q.key for q in ctx.candidates) - frozenset(result.suppressed)
        for cell in ctx.cells:
            if cell.primary:
                self.assertTrue(audit_primary(cell.key, ctx.adversary_rows(public), ctx)["protected"])

    def test_cross_table_join_defeats_single_table_safety(self):
        # 单表只有 x+y=10（安全）；第二张表已发布 x-y=-6，联合后 x 唯一为 2。
        single = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [],
            [("x", 3, 1, 1)],
        )
        alone = audit_primary("x", single.adversary_rows(frozenset()), single)
        self.assertTrue(alone["protected"])
        joined = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("y", [0, 1], 8, 1)],
            [("x", 3, 1, 1)],
            extra=[("diff", [1, -1], -6)],
        )
        exposed = audit_primary("x", joined.adversary_rows(frozenset({"y"})), joined)
        self.assertEqual(exposed["integer_support_values"], [2])
        self.assertFalse(exposed["protected"])
        # 跨表查询不可隐藏：即使隐藏全部本地候选，联合知识仍固定 x。
        result = search_complementary_suppression(joined, node_budget=10_000)
        self.assertEqual(result.status, "no_protection_scheme")
        for query in joined.extra_released:
            self.assertFalse(query.hideable)


    def test_random_search_matches_brute_force(self):
        rng = random.Random(777)
        for trial in range(80):
            n = rng.randint(2, 3)
            cells = []
            for j in range(n):
                upper = rng.randint(4, 8)
                truth = rng.randint(0, upper)
                cells.append((f"c{j}", 0, upper, truth, j == 0))
            base = [("sum", [1] * n, sum(c[3] for c in cells))]
            candidates = []
            for j in range(rng.randint(1, 4)):
                coeffs = [rng.randint(0, 2) for _ in range(n)]
                if all(a == 0 for a in coeffs):
                    coeffs[0] = 1
                answer = sum(a * c[3] for a, c in zip(coeffs, cells))
                candidates.append((f"q{j}", coeffs, answer, rng.randint(1, 5)))
            req = [("c0", rng.randint(2, 4), rng.randint(0, 2), rng.randint(0, 2))]
            ctx = make_context(cells, base, candidates, req)
            result = search_complementary_suppression(ctx, node_budget=10_000)
            oracle = brute_force_optimal(ctx)
            if oracle is None:
                self.assertEqual(result.status, "no_protection_scheme")
            else:
                self.assertEqual(result.status, "optimal")
                self.assertEqual(result.cost, oracle[0])
                self.assertEqual(frozenset(result.suppressed), oracle[1])

    def test_contradictory_candidate_must_be_hidden_to_restore_feasibility(self):
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("bad", [2, -1], 0, 1), ("y", [0, 1], 8, 1)],
            [("x", 3, 1, 1)],
        )
        result = search_complementary_suppression(ctx, node_budget=10_000)
        self.assertEqual(result.status, "optimal")
        self.assertIn("bad", result.suppressed)
        self.assertIn("y", result.suppressed)


if __name__ == "__main__":
    unittest.main()
