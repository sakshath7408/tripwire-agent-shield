"""Speed budgets that mean the same on a quiet laptop and a busy one.

A budget is written for a quiet machine. When a check runs over it, the same small pure-Python workload is timed
right then: if the machine is N times slower than quiet (other agents' tests, a benchmark, a video encode), the budget
grows N times. A real regression (a regex that takes 68 s, a parser that hangs) is still far over any scaled budget.
When the machine is so busy that no timing is fair (over MAX_SLOWDOWN), the check is skipped and says why.
"""

from __future__ import annotations

import re
import time

import pytest

QUIET_PROBE_S = 0.008  # the probe below on a quiet Apple-silicon laptop
MAX_SLOWDOWN = 8.0


def _probe() -> float:
    t = time.perf_counter()
    x = 0
    for i in range(300_000):
        x += i * i
    re.findall(r"\w+@\w+", "ab@cd " * 20_000)
    return time.perf_counter() - t


def slowdown() -> float:
    """How many times slower than a quiet machine this one runs right now (at least 1)."""
    return max(1.0, min(_probe() for _ in range(3)) / QUIET_PROBE_S)


def check_fast(elapsed: float, budget: float, what: str = "") -> None:
    """Fail when `elapsed` (seconds, or any unit shared with `budget`) is over the budget scaled to current load."""
    if elapsed <= budget:
        return
    f = slowdown()
    if elapsed <= budget * f:
        return
    if f >= MAX_SLOWDOWN:
        pytest.skip(f"machine {f:.0f}x slower than quiet; {what or 'timing'} {elapsed:.3g} vs budget {budget:.3g} not judged")
    raise AssertionError(f"{what or 'took'} {elapsed:.3g}, budget {budget:.3g} (x{f:.1f} for current load)")
