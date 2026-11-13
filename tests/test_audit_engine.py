"""可行域泄露审计的单元测试：支持计数、保护距离、矛盾、冗余、真值边界。"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.audit_engine import (  # noqa: E402
    AuditContext,
    Cell,
    ProtectionRequirement,
    Query,
    audit_primary,
    consistency_report,
    redundancy_report,
)
from src.integer_solver import FeasibilityCache  # noqa: E402


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


class AuditEngineTests(unittest.TestCase):
    def test_full_release_exposes_unique_primary(self):
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("y", [0, 1], 8, 1)],
            [("x", 3, 1, 1)],
        )
        report = audit_primary("x", ctx.adversary_rows(frozenset({"y"})), ctx)
        self.assertEqual(report["integer_support_values"], [2])
        self.assertEqual(report["feasible_value_count"], 1)
        self.assertFalse(report["protected"])
        self.assertFalse(report["truth_used_as_adversary_constraint"])

    def test_suppression_restores_full_support(self):
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("y", [0, 1], 8, 1)],
            [("x", 3, 1, 1)],
        )
        report = audit_primary("x", ctx.adversary_rows(frozenset()), ctx)
        self.assertEqual(report["integer_support_values"], list(range(11)))
        self.assertTrue(report["interval_equals_support"])
        self.assertTrue(report["protected"])
        self.assertEqual(report["lower_protection"]["endpoint_slack"], 2)
        self.assertEqual(report["upper_protection"]["endpoint_slack"], 8)

    def test_hole_support_count_not_interval(self):
        # x + 2z = 6，x 真值 2：区间 0..6 长度 7，真实支持只有偶数 4 个。
        ctx = make_context(
            [("x", 0, 6, 2, True), ("z", 0, 6, 2, False)],
            [("eq", [1, 2], 6)],
            [],
            [("x", 5, 1, 1)],
        )
        report = audit_primary("x", ctx.adversary_rows(frozenset()), ctx)
        self.assertEqual(report["integer_support_values"], [0, 2, 4, 6])
        self.assertEqual(report["interval_length_naive"], 7)
        self.assertFalse(report["interval_equals_support"])
        self.assertFalse(report["passes_k"])  # 4 < 5，区间冒充 k 会误判通过

    def test_protection_distances_checked_against_truth_separately(self):
        # x + y = 10，真值 x=9：下侧 slack=9 足够，上侧 slack=1 不足（要求 2）。
        ctx = make_context(
            [("x", 0, 10, 9, True), ("y", 0, 10, 1, False)],
            [("total", [1, 1], 10)],
            [],
            [("x", 3, 2, 2)],
        )
        report = audit_primary("x", ctx.adversary_rows(frozenset()), ctx)
        self.assertTrue(report["lower_protection"]["passes"])
        self.assertFalse(report["upper_protection"]["passes"])
        self.assertFalse(report["protected"])

    def test_contradictory_candidate_flagged_integer_vs_real(self):
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("bad", [2, -1], 0, 1)],
            [("x", 3, 1, 1)],
        )
        report = consistency_report(ctx)
        bad = next(c for c in report["candidates"] if c["key"] == "bad")
        self.assertTrue(bad["contradiction"])
        self.assertFalse(bad["integer_feasible"])
        self.assertTrue(bad["real_feasible"])
        self.assertTrue(bad["must_suppress"])

    def test_redundant_query_detected(self):
        ctx = make_context(
            [("x", 0, 10, 2, True), ("y", 0, 10, 8, False)],
            [("total", [1, 1], 10)],
            [("y", [0, 1], 8, 1), ("double", [2, 2], 20, 3)],
            [("x", 3, 1, 1)],
        )
        report = {entry["key"]: entry for entry in redundancy_report(ctx)}
        self.assertTrue(report["double"]["redundant"])
        self.assertFalse(report["y"]["redundant"])

    def test_truth_consistency_detects_bad_fixture(self):
        ctx = make_context(
            [("x", 0, 10, 5, True), ("y", 0, 10, 5, False)],
            [("total", [1, 1], 10)],
            [],
            [("x", 3, 1, 1)],
        )
        check = ctx.check_truth_consistency()
        self.assertTrue(check["consistent"])
        # 真值不满足某查询时应被指出，但这只说明 fixture 非法，不进对手模型。
        ctx.cells[0] = Cell("x", 0, 10, 9, True)
        bad = make_context(
            [("x", 0, 10, 9, True), ("y", 0, 10, 1, False)],
            [("total", [1, 1], 9)],  # 答案与真值不符
            [],
            [("x", 3, 1, 1)],
        )
        self.assertFalse(bad.check_truth_consistency()["consistent"])


if __name__ == "__main__":
    unittest.main()
