"""随机对拍：小有限域上以穷举为基准校验整数求解器的全部结论。"""

import itertools
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.integer_solver import (  # noqa: E402
    FeasibilityCache,
    Infeasible,
    Row,
    feasible,
    integer_support,
    maximize,
    minimize,
    real_feasible,
)


def exhaustive(rows, bounds):
    assignments = []
    for point in itertools.product(*(range(lo, hi + 1) for lo, hi in bounds)):
        ok = True
        for row in rows:
            value = sum(c * x for c, x in zip(row.coeffs, point))
            if row.sense == "eq" and value != row.rhs:
                ok = False
            elif row.sense == "le" and value > row.rhs:
                ok = False
            elif row.sense == "ge" and value < row.rhs:
                ok = False
        if ok:
            assignments.append(point)
    return assignments


class BruteForceOracleTests(unittest.TestCase):
    def test_random_systems_against_exhaustion(self):
        rng = random.Random(20261113)
        for trial in range(600):
            n = rng.randint(1, 3)
            bounds = [(0, rng.randint(2, 6)) for _ in range(n)]
            rows = []
            for _ in range(rng.randint(0, 3)):
                coeffs = tuple(rng.randint(-2, 2) for _ in range(n))
                if all(c == 0 for c in coeffs):
                    continue
                sense = rng.choice(["eq", "eq", "le", "ge"])
                rhs = rng.randint(-3, sum(b[1] for b in bounds) + 2)
                rows.append(Row(coeffs, rhs, sense))
            oracle = exhaustive(rows, bounds)
            cache = FeasibilityCache()
            try:
                solver_says_feasible = feasible(rows, bounds, cache=cache)
            except Infeasible:
                solver_says_feasible = False
            self.assertEqual(solver_says_feasible, bool(oracle), f"trial {trial}: {rows}")
            if not oracle:
                # 实数可行只可能在整数可行时必然成立；整数无解时实数结论单独核验不抛错。
                real_feasible(rows, bounds)
                continue
            for variable in range(n):
                oracle_values = sorted({point[variable] for point in oracle})
                support = integer_support(variable, rows, bounds, cache=cache)
                self.assertEqual(
                    [e["value"] for e in support], oracle_values,
                    f"trial {trial} variable {variable}: {rows}",
                )
                # 每条见证必须真实满足全部约束。
                for entry in support:
                    self.assertIn(tuple(entry["witness"]), [tuple(p) for p in oracle])
                unit = [0] * n
                unit[variable] = 1
                self.assertEqual(minimize(unit, rows, bounds, cache=cache), oracle_values[0])
                self.assertEqual(maximize(unit, rows, bounds, cache=cache), oracle_values[-1])


if __name__ == "__main__":
    unittest.main()
