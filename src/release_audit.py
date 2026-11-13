"""审计器装配层与命令行入口。

把 fixtures 的三份 JSON（以及可选的跨表已发布查询）装配成 AuditContext，
产出结构化 JSON 报告。报告区分：

* 公开规则（容量界、已发布查询系数与答案）——对手可见；
* 隐藏真值（true_value、保护距离判定）——仅本地验证，不进入对手约束。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # 支持 python -I 直接运行脚本（隔离模式不读 PYTHONPATH）
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import suppression_reader  # noqa: E402
from src.audit_engine import (  # noqa: E402
    AuditContext,
    Cell,
    ProtectionRequirement,
    Query,
    consistency_report,
    redundancy_report,
)
from src.integer_solver import FeasibilityCache  # noqa: E402
from src.suppression_search import search_complementary_suppression  # noqa: E402

SCHEMA_VERSION = "1.0"

DISCLAIMER = (
    "本工具是基于已声明公开规则的精确整数审计，不是差分隐私机制；"
    "不提供差分隐私保证，不抵抗未知外部信息（其他发布、背景知识、联动攻击），"
    "true_value 仅用于本地保护验证，从未作为对手可见约束参与求解。"
)


def _build_query(raw: dict, origin: str, hideable: bool) -> Query:
    return Query(
        key=str(raw["key"]),
        coefficients=tuple(int(c) for c in raw["coefficients"]),
        answer=int(raw["answer"]),
        suppression_cost=(int(raw["suppression_cost"]) if "suppression_cost" in raw else None),
        origin=origin,
        hideable=hideable,
    )


def build_context(cells_doc: dict, queries_doc: dict, suppression_doc: dict,
                  extra_docs: list[tuple[str, dict]] | None = None) -> AuditContext:
    order = list(cells_doc["order"])
    if [c["key"] for c in cells_doc["cells"]] != order:
        raise ValueError("cells 顺序必须与 order 一致")
    cells = [
        Cell(
            key=item["key"],
            lower=int(item["lower"]),
            upper=int(item["upper"]),
            true_value=int(item["true_value"]),
            primary=bool(item["primary"]),
        )
        for item in cells_doc["cells"]
    ]
    n = len(order)
    for cell in cells:
        if cell.lower < 0 or cell.upper < cell.lower or not cell.lower <= cell.true_value <= cell.upper:
            raise ValueError(f"格 {cell.key} 的容量界或真值非法")

    def check_vector(q: dict) -> None:
        if len(q["coefficients"]) != n:
            raise ValueError(f"查询 {q.get('key')} 系数长度与格数不一致")

    base_queries = []
    for raw in queries_doc.get("published_prior", []):
        check_vector(raw)
        base_queries.append(_build_query(raw, origin="published_prior", hideable=False))
    candidates = []
    for raw in queries_doc.get("candidates", []):
        check_vector(raw)
        if "suppression_cost" not in raw:
            raise ValueError(f"候选查询 {raw['key']} 缺少 suppression_cost")
        candidates.append(_build_query(raw, origin="local", hideable=True))

    extra_released = []
    for source_name, doc in extra_docs or []:
        for raw in doc.get("published_prior", []) + doc.get("candidates", []):
            check_vector(raw)
            # 跨表发布已经发生，对手知识不可撤销，全部不可隐藏。
            extra_released.append(_build_query(raw, origin=source_name, hideable=False))
    for raw in suppression_doc.get("adversary_extra_releases", []):
        check_vector(raw)
        extra_released.append(_build_query(raw, origin="inline_config", hideable=False))

    requirements = {
        key: ProtectionRequirement(
            minimum_feasible_integer_values=int(spec["minimum_feasible_integer_values"]),
            lower_distance=int(spec["lower_distance"]),
            upper_distance=int(spec["upper_distance"]),
        )
        for key, spec in suppression_doc["primary_protection"].items()
    }
    missing = [key for key in requirements if key not in order]
    if missing:
        raise ValueError(f"保护要求引用了不存在的格: {missing}")

    return AuditContext(
        order=order,
        cells=cells,
        requirements=requirements,
        base_queries=base_queries,
        candidates=candidates,
        extra_released=extra_released,
        witness_cap=int(suppression_doc.get("witness_cap", 50)),
        cache=FeasibilityCache(),
        solver_budget=suppression_doc.get("solver_budget"),
    )


def diagnostic_cases(queries_doc: dict, ctx: AuditContext) -> list[dict]:
    """处理 queries.json 中无 key 的诊断用例（如 inconsistent_case）。"""
    findings = []
    base_rows = [q.row() for q in ctx.base_queries] + [q.row() for q in ctx.extra_released]
    for name, raw in queries_doc.items():
        if name in ("published_prior", "candidates"):
            continue
        from src.integer_solver import Row, real_feasible
        from src.integer_solver import feasible as int_feasible
        row = Row(tuple(int(c) for c in raw["coefficients"]), int(raw["answer"]), "eq")
        rows = base_rows + [row]
        integer_ok = int_feasible(rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
        real_ok = real_feasible(rows, ctx.bounds)
        findings.append({
            "case": name,
            "coefficients": list(row.coeffs),
            "answer": row.rhs,
            "integer_feasible": integer_ok,
            "real_feasible": real_ok,
            "flagged_contradiction": not integer_ok,
            "interpretation": (
                "实数松弛有解但整数域无解：候选答案与已公开关系矛盾，必须标记"
                if real_ok and not integer_ok else None
            ),
        })
    return findings


def run_audit(cells_path: Path, queries_path: Path, suppression_path: Path,
              extra_release_paths: list[Path] | None = None) -> dict:
    cells_doc = suppression_reader.load(cells_path)
    queries_doc = suppression_reader.load(queries_path)
    suppression_doc = suppression_reader.load(suppression_path)
    extra_docs = []
    for path in extra_release_paths or []:
        extra_docs.append((path.name, suppression_reader.load(path)))

    ctx = build_context(cells_doc, queries_doc, suppression_doc, extra_docs)
    truth_check = ctx.check_truth_consistency()
    consistency = consistency_report(ctx)
    redundancy = redundancy_report(ctx)

    node_budget = int(suppression_doc.get("search_node_budget", 10_000))
    search = search_complementary_suppression(ctx, node_budget=node_budget)

    # 对推荐方案与"全部候选公开"分别做主格审计，保留端点与支持见证。
    plan_public = frozenset(q.key for q in ctx.candidates) - frozenset(search.suppressed)
    plan_primary_audits = search.primary_audits
    full_primary_audits = []
    for cell in ctx.cells:
        if cell.primary:
            from src.audit_engine import audit_primary
            full_primary_audits.append(
                audit_primary(cell.key, ctx.adversary_rows(frozenset(q.key for q in ctx.candidates)), ctx)
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "inputs": {
            "cells": str(cells_path),
            "queries": str(queries_path),
            "suppression": str(suppression_path),
            "extra_release_tables": [str(p) for p in (extra_release_paths or [])],
        },
        "boundary": {
            "adversary_visible": [
                "每个格的公开容量上下界与非负整数性质",
                "published_prior、跨表已发布查询及仍公开候选的系数与答案",
            ],
            "local_only": ["true_value", "保护距离要求与判定", "被隐藏候选的存在与否按方案决定"],
            "truth_is_feasibility_witness_only": True,
            "truth_consistency_check": truth_check,
        },
        "adversary_knowledge": {
            "base_published_queries": [q.key for q in ctx.base_queries],
            "cross_table_released_queries": [
                {"key": q.key, "origin": q.origin} for q in ctx.extra_released
            ],
            "candidate_queries": [
                {"key": q.key, "cost": q.suppression_cost, "hideable": q.hideable} for q in ctx.candidates
            ],
        },
        "consistency": consistency,
        "diagnostic_cases": diagnostic_cases(queries_doc, ctx),
        "redundancy": redundancy,
        "full_release_primary_audit": full_primary_audits,
        "suppression_search": {
            "node_budget": node_budget,
            "status": search.status,
            "suppressed_queries": search.suppressed,
            "suppression_cost": search.cost,
            "lower_bound": search.lower_bound,
            "nodes_used": search.nodes_used,
            "note": search.note,
            "plan_primary_audit": plan_primary_audits,
        },
        "disclaimer": DISCLAIMER,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="表格发布可行域泄露审计与互补抑制搜索")
    parser.add_argument("cells", type=Path)
    parser.add_argument("queries", type=Path)
    parser.add_argument("suppression", type=Path)
    parser.add_argument("--extra-release", type=Path, action="append", default=[],
                        help="跨表发布文件，可重复传入；其查询联合加入对手知识且不可隐藏")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    report = run_audit(args.cells, args.queries, args.suppression, args.extra_release)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
        summary = {
            "status": report["suppression_search"]["status"],
            "suppressed": report["suppression_search"]["suppressed_queries"],
            "cost": report["suppression_search"]["suppression_cost"],
            "lower_bound": report["suppression_search"]["lower_bound"],
            "output": str(args.output),
        }
        print(json.dumps(summary, ensure_ascii=False))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
