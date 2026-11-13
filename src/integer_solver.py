"""有限域整数线性约束的精确求解器（纯标准库）。

只处理整数系数线性等式/不等式与整数有限域变量，采用：

* 队列化边界传播（约束按系数方向收紧变量下界/上界）；
* 最小域（MRV）变量、二分域分支的回溯搜索；
* 规范化约束缓存，跨审计场景复用整数可行性结论。

这不是松弛求解器：判定的是整数可行域，因此天然识别奇偶约束与
"实数可行但整数无解" 的候选答案矛盾。所有系数与右端项必须为整数。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from fractions import Fraction


class Infeasible(Exception):
    """当前约束系统在整数域上无解。"""


class BudgetExhausted(Exception):
    """搜索节点预算耗尽，无法给出精确结论。"""


@dataclass(frozen=True)
class Row:
    """规范化线性行：sense 为 "eq" / "le" / "ge"。"""

    coeffs: tuple[int, ...]
    rhs: int
    sense: str

    def canonical(self) -> tuple:
        return (self.sense, self.coeffs, self.rhs)


@dataclass
class SolveStats:
    nodes: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    budget: int | None = None


@dataclass
class FeasibilityCache:
    """以规范化约束系统为键的整数可行性缓存。"""

    answers: dict[tuple, bool] = field(default_factory=dict)
    stats: SolveStats = field(default_factory=SolveStats)

    @staticmethod
    def key(rows: list[Row], bounds: tuple[tuple[int, int], ...]) -> tuple:
        normalized = tuple(sorted(r.canonical() for r in rows))
        return (bounds, normalized)


def _gcd_nonzero(values: list[int]) -> int:
    result = 0
    for value in values:
        if value != 0:
            result = math.gcd(result, abs(value))
    return result


def normalize_row(coeffs, rhs: int, sense: str) -> Row | None:
    """按 gcd 约分并剔除恒真/恒假行；返回 None 表示恒真。"""
    if sense not in ("eq", "le", "ge"):
        raise ValueError(f"未知约束方向: {sense}")
    coeffs = tuple(int(c) for c in coeffs)
    rhs = int(rhs)
    nonzero = [(i, c) for i, c in enumerate(coeffs) if c != 0]
    if not nonzero:
        if (sense == "eq" and rhs != 0) or (sense == "le" and rhs < 0) or (sense == "ge" and rhs > 0):
            raise Infeasible("不含变量的约束恒假")
        return None
    g = _gcd_nonzero([c for _, c in nonzero])
    if sense == "eq":
        if rhs % g != 0:
            # gcd(a) 不整除 rhs：整数域无解（实数域可能有解）。
            raise Infeasible("等式 gcd 不整除右端项，整数域无解")
        g = math.gcd(g, abs(rhs)) if rhs != 0 else g
        reduced = tuple(c // g for c in coeffs)
        return Row(reduced, rhs // g, "eq")
    reduced = tuple(c // g for c in coeffs)
    # 整数约分必须保持约束方向：le 用 floor，ge 用 ceil，错向会放松/收紧整数可行域。
    reduced_rhs = math.floor(rhs / g) if sense == "le" else _ceil_div(rhs, g)
    return Row(reduced, reduced_rhs, sense)


def _ceil_div(a: int, b: int) -> int:
    """b 非零时 ceil(a / b)，对负分母同样成立。"""
    return -((-a) // b)


def propagate(rows: list[Row], lower: list[int], upper: list[int]) -> None:
    """就地收紧变量边界直至不动点；矛盾时抛 Infeasible。"""
    queue = list(range(len(rows)))
    queued = [True] * len(rows)
    while queue:
        row_idx = queue.pop()
        queued[row_idx] = False
        row = rows[row_idx]
        coeffs, rhs, sense = row.coeffs, row.rhs, row.sense
        # 固定变量代入，保持行不可变。
        terms = [(i, c) for i, c in enumerate(coeffs) if c != 0]
        constant = 0
        free: list[tuple[int, int]] = []
        for i, c in terms:
            if lower[i] == upper[i]:
                constant += c * lower[i]
            else:
                free.append((i, c))
        target = rhs - constant
        if not free:
            if (sense == "eq" and target != 0) or (sense == "le" and target < 0) or (sense == "ge" and target > 0):
                raise Infeasible("边界传播发现矛盾约束")
            continue
        for i, c in free:
            others = [(j, d) for j, d in free if j != i]
            if sense == "eq":
                min_others = sum(d * lower[j] if d > 0 else d * upper[j] for j, d in others)
                max_others = sum(d * upper[j] if d > 0 else d * lower[j] for j, d in others)
                new_lower = _ceil_div(target - max_others, c)
                new_upper = (target - min_others) // c
                if c < 0:
                    new_lower, new_upper = (
                        _ceil_div(target - min_others, c),
                        (target - max_others) // c,
                    )
            elif sense == "le":
                # c*x <= target - 其他项极值
                extreme = sum(d * lower[j] if d > 0 else d * upper[j] for j, d in others)
                bound = (target - extreme) // c
                if c > 0:
                    new_lower, new_upper = lower[i], bound
                else:
                    new_lower, new_upper = bound, upper[i]
            else:  # ge
                extreme = sum(d * upper[j] if d > 0 else d * lower[j] for j, d in others)
                bound = _ceil_div(target - extreme, c)
                if c > 0:
                    new_lower, new_upper = bound, upper[i]
                else:
                    new_lower, new_upper = lower[i], bound
            changed = False
            if new_lower > lower[i]:
                lower[i] = new_lower
                changed = True
            if new_upper < upper[i]:
                upper[i] = new_upper
                changed = True
            if lower[i] > upper[i]:
                raise Infeasible(f"变量 {i} 边界为空")
            if changed:
                for k, other in enumerate(rows):
                    if other.coeffs[i] != 0 and not queued[k]:
                        queue.append(k)
                        queued[k] = True


def feasible(
    rows: list[Row],
    bounds: list[tuple[int, int]],
    cache: FeasibilityCache | None = None,
    stats: SolveStats | None = None,
    budget: int | None = None,
) -> bool:
    """整数可行性判定；cache 与 stats 可省略（此时不缓存）。"""
    active_stats = cache.stats if cache is not None else (stats if stats is not None else SolveStats())
    canonical_rows: list[Row] = []
    for row in rows:
        normalized = normalize_row(row.coeffs, row.rhs, row.sense)
        if normalized is not None:
            canonical_rows.append(normalized)
    bound_tuple = tuple(bounds)
    if cache is not None:
        key = FeasibilityCache.key(canonical_rows, bound_tuple)
        if key in cache.answers:
            active_stats.cache_hits += 1
            return cache.answers[key]
        active_stats.cache_misses += 1
    try:
        result = _search(canonical_rows, [b[0] for b in bounds], [b[1] for b in bounds], active_stats, budget)
    except BudgetExhausted:
        if cache is not None:
            cache.answers.pop(FeasibilityCache.key(canonical_rows, bound_tuple), None)
        raise
    if cache is not None:
        cache.answers[FeasibilityCache.key(canonical_rows, bound_tuple)] = result
    return result


def _search(rows: list[Row], lower: list[int], upper: list[int], stats: SolveStats, budget: int | None) -> bool:
    stack: list[tuple[list[Row], list[int], list[int]]] = [(rows, lower, upper)]
    while stack:
        current_rows, lo, hi = stack.pop()
        stats.nodes += 1
        if budget is not None and stats.nodes > budget:
            raise BudgetExhausted(f"求解节点超过预算 {budget}")
        work_lo, work_hi = list(lo), list(hi)
        try:
            propagate(current_rows, work_lo, work_hi)
        except Infeasible:
            continue
        if all(work_lo[i] == work_hi[i] for i in range(len(work_lo))):
            lower[:], upper[:] = work_lo, work_hi
            return True
        # MRV：选择域最小的未固定变量。
        pivot = min(
            (i for i in range(len(work_lo)) if work_lo[i] < work_hi[i]),
            key=lambda i: work_hi[i] - work_lo[i],
        )
        mid = (work_lo[pivot] + work_hi[pivot]) // 2
        # 先探下半区（栈 LIFO，先压上半区）。
        up_lo, up_hi = list(work_lo), list(work_hi)
        up_lo[pivot] = mid + 1
        stack.append((current_rows, up_lo, up_hi))
        down_lo, down_hi = list(work_lo), list(work_hi)
        down_hi[pivot] = mid
        stack.append((current_rows, down_lo, down_hi))
    return False


def witness(
    rows: list[Row],
    bounds: list[tuple[int, int]],
    cache: FeasibilityCache | None = None,
    budget: int | None = None,
) -> tuple[int, ...] | None:
    """返回一个整数可行赋值；无解返回 None。"""
    stats = cache.stats if cache is not None else SolveStats()
    lo = [b[0] for b in bounds]
    hi = [b[1] for b in bounds]
    if feasible(rows, bounds, cache=cache, stats=stats, budget=budget):
        # feasible 命中缓存时不会回填赋值，独立再求一次见证（缓存加速）。
        if not all(lo[i] == hi[i] for i in range(len(lo))):
            normalized = [r for r in (normalize_row(x.coeffs, x.rhs, x.sense) for x in rows) if r is not None]
            _search(normalized, lo, hi, stats, budget)
        return tuple(lo)
    return None


def minimize(
    objective: list[int],
    rows: list[Row],
    bounds: list[tuple[int, int]],
    cache: FeasibilityCache | None = None,
    budget: int | None = None,
) -> int:
    """整数最小化；不可行抛 Infeasible，预算耗尽抛 BudgetExhausted。"""
    objective = list(objective)
    lo = min(sum(c * (bounds[i][0] if c > 0 else bounds[i][1]) for i, c in enumerate(objective) if c), 0)
    hi = max(sum(c * (bounds[i][1] if c > 0 else bounds[i][0]) for i, c in enumerate(objective) if c), 0)
    if not feasible(rows, bounds, cache=cache, budget=budget):
        raise Infeasible("最小化目标时系统不可行")
    # 二分最小可行目标值。
    while lo < hi:
        mid = (lo + hi) // 2
        tightened = rows + [Row(tuple(objective), mid, "le")]
        if feasible(tightened, bounds, cache=cache, budget=budget):
            hi = mid
        else:
            lo = mid + 1
    return lo


def maximize(
    objective: list[int],
    rows: list[Row],
    bounds: list[tuple[int, int]],
    cache: FeasibilityCache | None = None,
    budget: int | None = None,
) -> int:
    return -minimize([-c for c in objective], rows, bounds, cache=cache, budget=budget)


def integer_support(
    variable: int,
    rows: list[Row],
    bounds: list[tuple[int, int]],
    cache: FeasibilityCache | None = None,
    budget: int | None = None,
    witness_cap: int = 50,
) -> list[dict]:
    """枚举主格在整数可行域内真实可取的每个值及见证。

    逐值最小化枚举：每次加入 v_prev+1 <= x 的约束再求最小可行值，
    因此奇偶约束或内部洞会被如实跳过，绝不以 max-min+1 冒充支持大小。
    """
    unit = [0] * len(bounds)
    unit[variable] = 1
    support: list[dict] = []
    current_rows = list(rows)
    truncated = False
    while True:
        try:
            value = minimize(unit, current_rows, bounds, cache=cache, budget=budget)
        except Infeasible:
            break
        assignment = witness(current_rows + [Row(tuple(unit), value, "eq")], bounds, cache=cache, budget=budget)
        support.append({"value": value, "witness": list(assignment) if assignment is not None else None})
        if len(support) >= witness_cap:
            truncated = True
            break
        current_rows = current_rows + [Row(tuple(unit), value + 1, "ge")]
    return support if not truncated else _attach_truncation(support)


def _attach_truncation(support: list[dict]) -> list[dict]:
    support.append({"truncated": True, "retained": len(support)})
    return support


# ---------------------------------------------------------------------------
# 实数松弛可行性（Fourier-Motzkin），仅用于诊断 "整数无解但实数有解"。
# ---------------------------------------------------------------------------

def real_feasible(
    rows: list[Row],
    bounds: list[tuple[int, int]],
    elimination_budget: int = 20_000,
) -> bool:
    """Fourier-Motzkin 消元判断连续（实数）可行性。"""
    halfspaces: list[list[Fraction]] = []

    def add(coeffs, rhs: int) -> None:
        halfspaces.append([Fraction(c) for c in coeffs] + [Fraction(rhs)])

    for i, (lo, hi) in enumerate(bounds):
        unit = [0] * len(bounds)
        unit[i] = 1
        add(unit, hi)
        add([-c for c in unit], -lo)
    for row in rows:
        if row.sense == "eq":
            add(row.coeffs, row.rhs)
            add([-c for c in row.coeffs], -row.rhs)
        elif row.sense == "le":
            add(row.coeffs, row.rhs)
        else:
            add([-c for c in row.coeffs], -row.rhs)

    n = len(bounds)
    for pivot in range(n):
        positives = [h for h in halfspaces if h[pivot] > 0]
        negatives = [h for h in halfspaces if h[pivot] < 0]
        zeros = [h for h in halfspaces if h[pivot] == 0]
        if len(positives) * len(negatives) > elimination_budget:
            raise BudgetExhausted("Fourier-Motzkin 消元行数超预算")
        generated: list[list[Fraction]] = []
        for hi_row in positives:
            for lo_row in negatives:
                a, b = hi_row[pivot], -lo_row[pivot]
                combined = [b * hi_row[j] + a * lo_row[j] for j in range(len(hi_row))]
                generated.append(combined)
        halfspaces = zeros + generated
    return all(h[-1] >= 0 for h in halfspaces)
