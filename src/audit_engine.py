"""表格发布的可行域泄露审计。

对手模型（明确边界）：
* 对手知道每个底层格的公开容量上下界与非负整数性质；
* 对手知道所有已发布线性查询的系数与真实答案（含跨表联合发布）；
* 主抑制格从不直接发布，其 true_value 仅用于本地验证保护距离，
  绝不作为对手可见约束加入可行域；
* 本工具不提供差分隐私保证，也不抵抗未知外部信息带来的再识别。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import integer_solver as ilp
from .integer_solver import BudgetExhausted, FeasibilityCache, Infeasible, Row, real_feasible


@dataclass(frozen=True)
class Cell:
    key: str
    lower: int
    upper: int
    true_value: int
    primary: bool


@dataclass(frozen=True)
class Query:
    key: str
    coefficients: tuple[int, ...]
    answer: int
    suppression_cost: int | None = None
    origin: str = "local"          # local / 跨表来源标识
    hideable: bool = True          # published_prior 与跨表已发布查询不可隐藏

    def row(self) -> Row:
        return Row(self.coefficients, self.answer, "eq")


@dataclass
class ProtectionRequirement:
    minimum_feasible_integer_values: int
    lower_distance: int
    upper_distance: int


@dataclass
class AuditContext:
    order: list[str]
    cells: list[Cell]
    requirements: dict[str, ProtectionRequirement]
    base_queries: list[Query]                  # 本地不可隐藏的已发布查询
    candidates: list[Query]                    # 可额外隐藏的候选查询
    extra_released: list[Query] = field(default_factory=list)  # 跨表联合知识
    witness_cap: int = 50
    cache: FeasibilityCache = field(default_factory=FeasibilityCache)
    solver_budget: int | None = None

    @property
    def bounds(self) -> list[tuple[int, int]]:
        return [(c.lower, c.upper) for c in self.cells]

    @property
    def index(self) -> dict[str, int]:
        return {key: i for i, key in enumerate(self.order)}

    def adversary_rows(self, public_candidates: frozenset[str]) -> list[Row]:
        """构造对手可见的全部等式：基础查询 + 跨表查询 + 仍公开的候选。"""
        rows = [q.row() for q in self.base_queries]
        rows += [q.row() for q in self.extra_released]
        rows += [q.row() for q in self.candidates if q.key in public_candidates]
        return rows

    def truth_assignment(self) -> tuple[int, ...]:
        return tuple(c.true_value for c in self.cells)

    def check_truth_consistency(self) -> dict:
        """真实表只是可行见证：验证它满足全部查询与容量界。"""
        assignment = self.truth_assignment()
        violations = []
        for cell, value in zip(self.cells, assignment):
            if not cell.lower <= value <= cell.upper:
                violations.append({"cell": cell.key, "reason": "true_value 超出公开容量界"})
        for query in self.base_queries + self.extra_released + self.candidates:
            got = sum(c * v for c, v in zip(query.coefficients, assignment))
            if got != query.answer:
                violations.append({"query": query.key, "expected": query.answer, "computed": got})
        return {"consistent": not violations, "violations": violations}


def system_feasible(rows: list[Row], ctx: AuditContext) -> tuple[bool, bool | None]:
    """返回 (整数可行性, 实数可行性)。实数判定仅在整数无解时用于诊断。"""
    try:
        integer_ok = ilp.feasible(rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
    except BudgetExhausted:
        raise
    if integer_ok:
        return True, True
    try:
        real_ok = real_feasible(rows, ctx.bounds)
    except BudgetExhausted:
        real_ok = None
    return False, real_ok


def audit_primary(cell_key: str, rows: list[Row], ctx: AuditContext) -> dict:
    """对单个主抑制格做可行域泄露审计。"""
    req = ctx.requirements[cell_key]
    variable = ctx.index[cell_key]
    truth = ctx.cells[variable].true_value
    result: dict = {
        "cell": cell_key,
        "true_value": truth,
        "truth_used_as_adversary_constraint": False,  # 边界声明：真值不进对手模型
    }
    try:
        support = ilp.integer_support(
            variable, rows, ctx.bounds, cache=ctx.cache,
            budget=ctx.solver_budget, witness_cap=ctx.witness_cap,
        )
    except BudgetExhausted as exc:
        result["status"] = "analysis_incomplete"
        result["reason"] = str(exc)
        return result
    truncated = support and support[-1].get("truncated", False)
    if truncated:
        note = support.pop()
        result["support_truncated"] = True
        result["support_retained"] = note["retained"]
    else:
        result["support_truncated"] = False
    values = [entry["value"] for entry in support]
    result["integer_support_values"] = values
    result["feasible_value_count"] = len(values)
    result["support_witnesses"] = [
        {"value": entry["value"], "assignment": entry["witness"]} for entry in support
    ]
    if values:
        result["min_feasible"] = values[0]
        result["max_feasible"] = values[-1]
        result["interval_length_naive"] = values[-1] - values[0] + 1
        result["interval_equals_support"] = (values[-1] - values[0] + 1) == len(values)
    # 保护要求一：可行整数值个数（真实支持，而非区间长度）。
    result["requirement_k"] = req.minimum_feasible_integer_values
    result["passes_k"] = len(values) >= req.minimum_feasible_integer_values
    # 保护要求二/三：相对真实格值的上下侧保护距离（端点口径）。
    below = [v for v in values if v < truth]
    above = [v for v in values if v > truth]
    nearest_below = max(below) if below else None
    nearest_above = min(above) if above else None
    lower_slack = truth - values[0] if values else None
    upper_slack = values[-1] - truth if values else None
    result["lower_protection"] = {
        "required_distance": req.lower_distance,
        "endpoint_slack": lower_slack,
        "nearest_feasible_below_truth": nearest_below,
        "nearest_below_slack": (truth - nearest_below) if nearest_below is not None else None,
        "passes": lower_slack is not None and lower_slack >= req.lower_distance,
    }
    result["upper_protection"] = {
        "required_distance": req.upper_distance,
        "endpoint_slack": upper_slack,
        "nearest_feasible_above_truth": nearest_above,
        "nearest_above_slack": (nearest_above - truth) if nearest_above is not None else None,
        "passes": upper_slack is not None and upper_slack >= req.upper_distance,
    }
    result["protected"] = (
        result["passes_k"] and result["lower_protection"]["passes"] and result["upper_protection"]["passes"]
    )
    return result


def consistency_report(ctx: AuditContext) -> dict:
    """检查已发布查询集合的候选答案是否自洽（整数域为准）。"""
    report: dict = {}
    base_rows = [q.row() for q in ctx.base_queries] + [q.row() for q in ctx.extra_released]
    try:
        base_ok, base_real = system_feasible(base_rows, ctx)
    except BudgetExhausted as exc:
        return {"status": "analysis_incomplete", "reason": str(exc)}
    report["base_published_system"] = {
        "integer_feasible": base_ok,
        "real_feasible": base_real,
        "note": "实数可行但整数无解即典型奇偶型矛盾" if base_real and not base_ok else None,
    }
    candidate_status = []
    for query in ctx.candidates:
        try:
            ok, real_ok = system_feasible(base_rows + [query.row()], ctx)
        except BudgetExhausted as exc:
            candidate_status.append({"key": query.key, "status": "analysis_incomplete", "reason": str(exc)})
            continue
        candidate_status.append({
            "key": query.key,
            "integer_feasible": ok,
            "real_feasible": real_ok,
            "contradiction": not ok,
            "must_suppress": not ok,  # 矛盾候选答案一旦公开即暴露无解，必须隐藏
        })
    report["candidates"] = candidate_status
    full_rows = ctx.adversary_rows(frozenset(q.key for q in ctx.candidates))
    try:
        full_ok, full_real = system_feasible(full_rows, ctx)
    except BudgetExhausted as exc:
        report["full_release_system"] = {"status": "analysis_incomplete", "reason": str(exc)}
    else:
        report["full_release_system"] = {"integer_feasible": full_ok, "real_feasible": full_real}
    return report


def redundancy_report(ctx: AuditContext) -> list[dict]:
    """逐候选查询检测冗余：移除它不改变整数可行域则为冗余。

    判定方式：在"基础+跨表+其余候选全部公开"的系统上，比较加入该查询
    前后的整数可行性与各主格 min/max；完全相同则该查询不携带新增信息
    （例如 2x+2y=20 相对 x+y=10）。冗余查询仍可被隐藏，只是隐藏它不
    带来保护增益，报告用于解释成本去向。
    """
    findings = []
    public_all = frozenset(q.key for q in ctx.candidates)
    baseline_rows = ctx.adversary_rows(public_all)
    for query in ctx.candidates:
        reduced_rows = ctx.adversary_rows(public_all - {query.key})
        entry: dict = {"key": query.key, "suppression_cost": query.suppression_cost}
        try:
            baseline_feasible = ilp.feasible(baseline_rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
            reduced_feasible = ilp.feasible(reduced_rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
            same = baseline_feasible == reduced_feasible
            detail = {"feasibility_unchanged": baseline_feasible == reduced_feasible, "projection_unchanged": {}}
            if same and baseline_feasible:
                for cell in ctx.cells:
                    if not cell.primary:
                        continue
                    unit = [0] * len(ctx.cells)
                    unit[ctx.index[cell.key]] = 1
                    b_min = ilp.minimize(unit, baseline_rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
                    b_max = ilp.maximize(unit, baseline_rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
                    r_min = ilp.minimize(unit, reduced_rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
                    r_max = ilp.maximize(unit, reduced_rows, ctx.bounds, cache=ctx.cache, budget=ctx.solver_budget)
                    detail["projection_unchanged"][cell.key] = (b_min, b_max) == (r_min, r_max)
                    same = same and (b_min, b_max) == (r_min, r_max)
            entry["redundant"] = same
            entry["detail"] = detail
        except BudgetExhausted as exc:
            entry["redundant"] = None
            entry["status"] = "analysis_incomplete"
            entry["reason"] = str(exc)
        findings.append(entry)
    return findings
