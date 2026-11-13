"""最小损失互补抑制搜索（小规模精确，大规模给可行方案与合法下界）。

动作空间只允许"额外隐藏候选查询"：不修改任何答案、不添加噪声、
不隐藏 published_prior 与跨表已发布查询。搜索目标是在所有主抑制格
保护要求同时满足的前提下，最小化被隐藏候选的 suppression_cost 之和。
"""

from __future__ import annotations

from dataclasses import dataclass

from .audit_engine import AuditContext, audit_primary
from .integer_solver import BudgetExhausted


@dataclass
class SearchResult:
    status: str                       # optimal | feasible_with_lower_bound | no_protection_scheme | analysis_incomplete
    suppressed: list[str]
    cost: int | None
    lower_bound: int | None
    nodes_used: int
    budget: int
    primary_audits: list[dict]
    note: str | None = None


def _protected(public: frozenset[str], ctx: AuditContext) -> tuple[bool, list[dict]]:
    rows = ctx.adversary_rows(public)
    audits = []
    for cell in ctx.cells:
        if cell.primary:
            report = audit_primary(cell.key, rows, ctx)
            audits.append(report)
            if report.get("status") == "analysis_incomplete" or not report.get("protected", False):
                return False, audits
    return True, audits


def search_complementary_suppression(ctx: AuditContext, node_budget: int) -> SearchResult:
    """分支定界枚举候选查询的 隐藏/保留 决策。"""
    # 成本升序，让低成本抑制先被探索，尽早拿到紧的上界。
    ordered = sorted(
        ctx.candidates,
        key=lambda q: (q.suppression_cost if q.suppression_cost is not None else 0, q.key),
    )
    all_keys = [q.key for q in ordered]
    cost_of = {q.key: (q.suppression_cost if q.suppression_cost is not None else 0) for q in ordered}
    full_public = frozenset(all_keys)

    nodes = 0
    incumbent: list[str] | None = None
    incumbent_cost: int | None = None
    incumbent_audits: list[dict] = []
    timed_out = False
    timeout_reason: str | None = None
    frontier_floor: int | None = None   # 开放栈节点的最小已花成本（合法下界原料）

    def remember_floor(spent: int) -> None:
        nonlocal frontier_floor
        if stack:
            spent = min(spent, *(entry[2] for entry in stack))
        frontier_floor = spent if frontier_floor is None else min(frontier_floor, spent)

    # 栈元素：(候选下标, 当前公开集合, 当前已花成本)。
    stack: list[tuple[int, frozenset[str], int]] = [(0, full_public, 0)]
    while stack:
        index, public, spent = stack.pop()
        nodes += 1
        if nodes > node_budget:
            timed_out = True
            timeout_reason = f"搜索节点超过预算 {node_budget}"
            # 任何未发现的完整方案都扩展自开放栈中的节点；其已花成本
            # 是该子树内任意方案成本的合法下界。
            remember_floor(spent)
            break
        if incumbent_cost is not None and spent >= incumbent_cost:
            continue  # 界剪枝：继续隐藏只会更贵
        if index == len(ordered):
            try:
                ok, audits = _protected(public, ctx)
            except BudgetExhausted as exc:
                timed_out = True
                timeout_reason = str(exc)
                remember_floor(spent)
                break
            if ok:
                incumbent = [k for k in all_keys if k not in public]
                incumbent_cost = spent
                incumbent_audits = audits
            continue
        key = ordered[index].key
        # 先探索隐藏分支（栈 LIFO，压栈顺序相反）：尽快拿到可行上界，
        # 保留分支随后探索并以界剪枝改进成本。
        stack.append((index + 1, public, spent))
        stack.append((index + 1, public - {key}, spent + cost_of[key]))

    if incumbent is None:
        if timed_out:
            # 开放前沿仍在，但没有任何可行见证：不能声称方案存在。
            return SearchResult(
                status="analysis_incomplete", suppressed=[], cost=None,
                lower_bound=frontier_floor, nodes_used=nodes, budget=node_budget,
                primary_audits=[], note=timeout_reason,
            )
        return SearchResult(
            status="no_protection_scheme", suppressed=[], cost=None, lower_bound=None,
            nodes_used=nodes, budget=node_budget, primary_audits=[],
            note="枚举全部隐藏组合后仍无满足所有主格保护要求的方案",
        )

    if not timed_out:
        return SearchResult(
            status="optimal", suppressed=incumbent, cost=incumbent_cost,
            lower_bound=incumbent_cost, nodes_used=nodes, budget=node_budget,
            primary_audits=incumbent_audits,
        )

    # 任何未发现的完整方案都扩展自开放栈中的某个节点，其成本 >= 该节点
    # 已花成本；故 min(incumbent 成本, 前沿最小已花成本) 是合法下界，
    # 但只有完整枚举才能证明最优，结果必须标注为非最优。
    lower_bound = min(incumbent_cost, frontier_floor if frontier_floor is not None else incumbent_cost)
    return SearchResult(
        status="feasible_with_lower_bound", suppressed=incumbent, cost=incumbent_cost,
        lower_bound=lower_bound, nodes_used=nodes, budget=node_budget,
        primary_audits=incumbent_audits,
        note=timeout_reason + "；未证明最优，启发式结果不得称为最优",
    )
