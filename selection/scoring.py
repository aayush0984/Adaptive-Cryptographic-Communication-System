"""Scoring utilities for adaptive crypto profile selection.

The scoring model follows the formula from the phase‑07 plan::

    score = wt * time + wm * memory + wc * communication + we * energy_proxy

All components are *normalized* across the candidate set (min‑max scaling).
A lower score indicates a cheaper profile.
"""

from __future__ import annotations

from typing import List, Dict, Tuple

# ---------------------------------------------------------------------------
# Helper normalization
# ---------------------------------------------------------------------------

def _min_max(values: List[float]) -> Tuple[float, float]:
    """Return (min, max) of *values* handling the empty list case.
    """
    if not values:
        return 0.0, 0.0
    return min(values), max(values)


def _normalize(value: float, min_val: float, max_val: float) -> float:
    """Normalise *value* to the 0‑1 range.

    If ``max_val == min_val`` the function returns ``0.0`` to avoid division
    by zero – in that situation all candidates are identical for the metric.
    """
    if max_val == min_val:
        return 0.0
    return (value - min_val) / (max_val - min_val)

# ---------------------------------------------------------------------------
# Core scoring logic
# ---------------------------------------------------------------------------

def score_candidates(
    candidates: List[Dict[str, any]],
    weights: Dict[str, float] | None = None,
) -> List[Tuple[Dict[str, any], float]]:
    """Return a list of *(candidate, score)* tuples sorted by ascending score.

    ``candidates`` is a list of benchmark documents (as stored in the
    ``benchmarks`` collection).  The function extracts the four cost dimensions
    used by the plan:

    * **time** – ``timings_ms.total`` (ms)
    * **memory** – ``peak_memory_kb`` (KB)
    * **communication** – ``application_bytes`` (bytes)
    * **energy_proxy** – optional ``energy_proxy`` field; defaults to ``0``

    ``weights`` may contain the keys ``wt``, ``wm``, ``wc`` and ``we``.  If omitted
    the function uses an equal split (``0.25`` each).
    """
    if weights is None:
        weights = {"wt": 0.25, "wm": 0.25, "wc": 0.25, "we": 0.25}
    # Extract raw metric lists
    times = [c["timings_ms"]["total"] for c in candidates]
    memories = [c.get("peak_memory_kb", 0.0) for c in candidates]
    comms = [c.get("application_bytes", 0) for c in candidates]
    energies = [c.get("energy_proxy", 0.0) for c in candidates]

    t_min, t_max = _min_max(times)
    m_min, m_max = _min_max(memories)
    c_min, c_max = _min_max(comms)
    e_min, e_max = _min_max(energies)

    scored: List[Tuple[Dict[str, any], float]] = []
    for doc in candidates:
        norm_time = _normalize(doc["timings_ms"]["total"], t_min, t_max)
        norm_mem = _normalize(doc.get("peak_memory_kb", 0.0), m_min, m_max)
        norm_comm = _normalize(doc.get("application_bytes", 0), c_min, c_max)
        norm_energy = _normalize(doc.get("energy_proxy", 0.0), e_min, e_max)
        score = (
            weights.get("wt", 0) * norm_time
            + weights.get("wm", 0) * norm_mem
            + weights.get("wc", 0) * norm_comm
            + weights.get("we", 0) * norm_energy
        )
        scored.append((doc, score))

    # Deterministic tie‑breaking: sort by score then by profile_id then by message size
    scored.sort(
        key=lambda pair: (
            pair[1],
            pair[0].get("profile_id", ""),
            pair[0].get("message_size_bytes", 0),
        )
    )
    return scored


def best_profile_for_message(
    benchmarks: List[Dict[str, any]],
    weights: Dict[str, float] | None = None,
) -> Tuple[Dict[str, any] | None, float | None]:
    """Convenience helper that returns the *single* best benchmark document.

    Returns ``(doc, score)`` where ``doc`` is the chosen benchmark entry (or ``None``
    if ``benchmarks`` is empty) and ``score`` is its computed score.
    """
    if not benchmarks:
        return None, None
    scored = score_candidates(benchmarks, weights)
    return scored[0]
