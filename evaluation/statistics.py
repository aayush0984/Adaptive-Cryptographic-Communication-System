"""Descriptive statistics utilities for benchmark result arrays."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


@dataclass
class Stats:
    """Container for descriptive statistics over a sample."""

    count: int
    mean: float
    median: float
    std_dev: float
    minimum: float
    maximum: float
    p95: float
    """95th-percentile value."""

    def to_dict(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "mean": self.mean,
            "median": self.median,
            "std_dev": self.std_dev,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "p95": self.p95,
        }


def compute_stats(values: Sequence[float]) -> Stats:
    """Compute descriptive statistics for a list of numeric values.

    Args:
        values: A non-empty sequence of floats (e.g., timing measurements).

    Returns:
        A :class:`Stats` dataclass instance.

    Raises:
        ValueError: If ``values`` is empty.
    """
    if not values:
        raise ValueError("Cannot compute statistics on an empty sequence")

    n = len(values)
    sorted_vals = sorted(values)
    mean = sum(sorted_vals) / n

    # Median
    mid = n // 2
    if n % 2 == 1:
        median = sorted_vals[mid]
    else:
        median = (sorted_vals[mid - 1] + sorted_vals[mid]) / 2

    # Population std dev (sample std dev when n > 1)
    variance = sum((x - mean) ** 2 for x in sorted_vals) / (n - 1 if n > 1 else 1)
    std_dev = math.sqrt(variance)

    # 95th percentile (nearest-rank method)
    p95_idx = max(0, math.ceil(0.95 * n) - 1)
    p95 = sorted_vals[p95_idx]

    return Stats(
        count=n,
        mean=round(mean, 6),
        median=round(median, 6),
        std_dev=round(std_dev, 6),
        minimum=round(sorted_vals[0], 6),
        maximum=round(sorted_vals[-1], 6),
        p95=round(p95, 6),
    )
