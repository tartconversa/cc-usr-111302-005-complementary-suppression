"""端到端测试：CLI 装配、主 fixture 叙述、跨表联合发布、输出边界声明。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.release_audit import DISCLAIMER, build_context, run_audit  # noqa: E402
from src.suppression_reader import load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class EndToEndTests(unittest.TestCase):
    def test_main_fixture_full_report_contract(self):
        report = run_audit(
            ROOT / "fixtures/cells.json",
            ROOT / "fixtures/queries.json",
            ROOT / "fixtures/suppression.json",
        )
        # 矛盾诊断：2x-y=0 与 x+y=10 整数无解、实数有解。
        diag = report["diagnostic_cases"][0]
        self.assertTrue(diag["flagged_contradiction"])
        self.assertFalse(diag["integer_feasible"])
        self.assertTrue(diag["real_feasible"])
        # 冗余：double-total 不新增信息。
        redundancy = {entry["key"]: entry for entry in report["redundancy"]}
        self.assertTrue(redundancy["double-total"]["redundant"])
        # 全公开时主格唯一确定，搜索得到成本 1 的精确最优。
        self.assertEqual(report["full_release_primary_audit"][0]["integer_support_values"], [2])
        search = report["suppression_search"]
        self.assertEqual(search["status"], "optimal")
        self.assertEqual(search["suppressed_queries"], ["y"])
        self.assertEqual(search["suppression_cost"], 1)
        # 方案后主格支持恢复为 0..10，端点见证齐全。
        plan_audit = search["plan_primary_audit"][0]
        self.assertEqual(plan_audit["integer_support_values"], list(range(11)))
        self.assertEqual(plan_audit["support_witnesses"][0]["value"], 0)
        self.assertEqual(plan_audit["support_witnesses"][-1]["value"], 10)
        # 边界与免责声明。
        self.assertTrue(report["boundary"]["truth_is_feasibility_witness_only"])
        self.assertTrue(report["boundary"]["truth_consistency_check"]["consistent"])
        self.assertIn("不是差分隐私", report["disclaimer"])
        self.assertEqual(report["disclaimer"], DISCLAIMER)

    def test_cross_table_join_marks_no_protection_scheme(self):
        report = run_audit(
            ROOT / "fixtures/cells.json",
            ROOT / "fixtures/queries.json",
            ROOT / "fixtures/suppression_cross_table.json",
            [ROOT / "fixtures/queries_neighbor_table.json"],
        )
        origins = {entry["key"]: entry["origin"] for entry in report["adversary_knowledge"]["cross_table_released_queries"]}
        self.assertEqual(origins["difference-x-minus-y"], "queries_neighbor_table.json")
        search = report["suppression_search"]
        self.assertEqual(search["status"], "no_protection_scheme")
        exposed = report["full_release_primary_audit"][0]
        self.assertEqual(exposed["integer_support_values"], [2])

    def test_cli_writes_output_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable, "-m", "src.release_audit",
                    str(ROOT / "fixtures/cells.json"),
                    str(ROOT / "fixtures/queries.json"),
                    str(ROOT / "fixtures/suppression.json"),
                    "--output", str(out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["status"], "optimal")
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["suppression_search"]["suppressed_queries"], ["y"])

    def test_inline_extra_release_in_config(self):
        suppression_doc = load(ROOT / "fixtures/suppression.json")
        suppression_doc["adversary_extra_releases"] = [
            {"key": "inline-diff", "coefficients": [1, -1], "answer": -6}
        ]
        cells_doc = load(ROOT / "fixtures/cells.json")
        queries_doc = load(ROOT / "fixtures/queries.json")
        ctx = build_context(cells_doc, queries_doc, suppression_doc)
        self.assertEqual(ctx.extra_released[0].key, "inline-diff")
        self.assertFalse(ctx.extra_released[0].hideable)

    def test_reports_are_json_serializable(self):
        report = run_audit(
            ROOT / "fixtures/cells.json",
            ROOT / "fixtures/queries.json",
            ROOT / "fixtures/suppression.json",
            [ROOT / "fixtures/queries_neighbor_table.json"],
        )
        json.dumps(report, ensure_ascii=False)


if __name__ == "__main__":
    unittest.main()
