"""Memory monitoring utilities using tracemalloc and psutil."""

from __future__ import annotations

import os
import tracemalloc
from dataclasses import dataclass

import psutil


@dataclass
class MemorySnapshot:
    """Peak and current memory usage captured during a benchmark."""

    tracemalloc_peak_kb: float
    """Peak heap allocation tracked by tracemalloc during the measured block, in KB."""

    process_rss_kb: float
    """Process Resident Set Size (physical RAM) at snapshot time, in KB."""


def start_memory_tracking() -> None:
    """Start (or restart) tracemalloc allocation tracking."""
    if tracemalloc.is_tracing():
        tracemalloc.stop()
    tracemalloc.start()


def stop_memory_tracking() -> MemorySnapshot:
    """Stop tracemalloc and return a MemorySnapshot.

    Must be called after :func:`start_memory_tracking`. Calling without a
    prior ``start`` will return zeros rather than raising an error.
    """
    if tracemalloc.is_tracing():
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    else:
        peak = 0

    proc = psutil.Process(os.getpid())
    rss_bytes = proc.memory_info().rss

    return MemorySnapshot(
        tracemalloc_peak_kb=round(peak / 1024, 3),
        process_rss_kb=round(rss_bytes / 1024, 3),
    )


def get_current_rss_kb() -> float:
    """Return the current process RSS in KB (no tracemalloc required)."""
    proc = psutil.Process(os.getpid())
    return round(proc.memory_info().rss / 1024, 3)
