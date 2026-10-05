"""Scoring utilities and dynamic weight derivation for adaptive crypto profile selection.

Selection Architecture - Stage 2:
---------------------------------
After Stage 1 hard constraint filtering, profiles are ranked across four dimensions:
    - Time (predicted total end-to-end latency)
    - Memory (predicted peak memory)
    - Communication (application-layer bytes)
    - Energy proxy (energy consumption proxy based on endpoint work)

Instead of static equal weights (0.25 each), weights are dynamically derived from:
    1. Time Pressure (P_time): Strictest latency limit between Device A & B.
    2. Memory Pressure (P_memory): Lowest available RAM between Device A & B.
    3. Communication Pressure (P_comm): Message payload size relative to effective packet limits.
    4. Energy Pressure (P_energy): Endpoint power sources ('battery' vs 'mains').
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from models.device import Device

# ---------------------------------------------------------------------------
# Constants & Reference Ranges for Continuous Pressure Calculations
# ---------------------------------------------------------------------------

# Latency reference range in ms (IoT networks: strict real-time ~ 50ms, relaxed ~ 2000ms)
REF_LATENCY_MIN_MS = 50.0
REF_LATENCY_MAX_MS = 2000.0

# Memory reference range in KB (tiny microcontroller ~ 32KB, large SBC ~ 2097152KB / 2GB)
REF_MEMORY_MIN_KB = 32.0
REF_MEMORY_MAX_KB = 524288.0  # 512MB threshold for memory abundance

# Communication reference range in bytes
# (Small telemetry packet ~ 16B; large IoT frame/packet ceiling ~ 1500B MTU / 65536B)
REF_MESSAGE_MIN_BYTES = 16
DEFAULT_PACKET_LIMIT_BYTES = 1500

# Power source pressure constants (battery devices prioritize energy efficiency)
POWER_SOURCE_PRESSURE = {
    "mains": 0.20,
    "battery": 0.80,
}
# Both endpoints on battery create higher combined energy urgency
BOTH_BATTERY_PRESSURE = 0.95

# Safe fallback pressure baseline to avoid zero-total edge cases
MIN_PRESSURE_FLOOR = 0.05


# ---------------------------------------------------------------------------
# Dynamic Weight Derivation
# ---------------------------------------------------------------------------

def calculate_time_pressure(device_a: Device, device_b: Device) -> float:
    """Calculate time constraint pressure (0.05 to 1.0) based on latency limits.

    Smaller allowed latency -> higher time pressure.
    Continuous logarithmic scaling between REF_LATENCY_MIN_MS and REF_LATENCY_MAX_MS.
    """
    lat_a = getattr(device_a, "latency_requirement_ms", None) or REF_LATENCY_MAX_MS
    lat_b = getattr(device_b, "latency_requirement_ms", None) or REF_LATENCY_MAX_MS
    min_latency = max(1.0, min(lat_a, lat_b))

    if min_latency <= REF_LATENCY_MIN_MS:
        return 1.0
    if min_latency >= REF_LATENCY_MAX_MS:
        return MIN_PRESSURE_FLOOR

    # Inverted logarithmic interpolation: smaller latency -> higher pressure
    # log(2000) - log(min_latency) / (log(2000) - log(50))
    scale = (math.log(REF_LATENCY_MAX_MS) - math.log(min_latency)) / (
        math.log(REF_LATENCY_MAX_MS) - math.log(REF_LATENCY_MIN_MS)
    )
    pressure = MIN_PRESSURE_FLOOR + scale * (1.0 - MIN_PRESSURE_FLOOR)
    return round(float(min(1.0, max(MIN_PRESSURE_FLOOR, pressure))), 4)


def calculate_memory_pressure(device_a: Device, device_b: Device) -> float:
    """Calculate memory constraint pressure (0.05 to 1.0) based on available RAM.

    Smaller available RAM -> higher memory pressure.
    Continuous logarithmic scaling between REF_MEMORY_MIN_KB and REF_MEMORY_MAX_KB.
    """
    mem_a = getattr(device_a, "available_memory_kb", None) or REF_MEMORY_MAX_KB
    mem_b = getattr(device_b, "available_memory_kb", None) or REF_MEMORY_MAX_KB
    min_mem = max(1.0, min(mem_a, mem_b))

    if min_mem <= REF_MEMORY_MIN_KB:
        return 1.0
    if min_mem >= REF_MEMORY_MAX_KB:
        return MIN_PRESSURE_FLOOR

    scale = (math.log(REF_MEMORY_MAX_KB) - math.log(min_mem)) / (
        math.log(REF_MEMORY_MAX_KB) - math.log(REF_MEMORY_MIN_KB)
    )
    pressure = MIN_PRESSURE_FLOOR + scale * (1.0 - MIN_PRESSURE_FLOOR)
    return round(float(min(1.0, max(MIN_PRESSURE_FLOOR, pressure))), 4)


def calculate_communication_pressure(
    device_a: Device,
    device_b: Device,
    message_size_bytes: int,
) -> float:
    """Calculate communication pressure (0.05 to 1.0) from message size and packet capacity.

    A message approaching or exceeding effective packet capacity creates high pressure.
    Small messages relative to network capacity create low pressure.
    """
    limit_a = getattr(device_a, "maximum_packet_size_bytes", None) or DEFAULT_PACKET_LIMIT_BYTES
    limit_b = getattr(device_b, "maximum_packet_size_bytes", None) or DEFAULT_PACKET_LIMIT_BYTES
    effective_limit = max(64, min(limit_a, limit_b))

    msg_size = max(0, message_size_bytes)
    ratio = msg_size / float(effective_limit)

    if ratio <= 0.05:
        # Small telemetry packet relative to capacity
        return MIN_PRESSURE_FLOOR
    if ratio >= 1.0:
        # Message saturates or exceeds single frame capacity
        return 1.0

    # Smooth linear scaling between ratio 0.05 and 1.0
    pressure = MIN_PRESSURE_FLOOR + (ratio - 0.05) / 0.95 * (1.0 - MIN_PRESSURE_FLOOR)
    return round(float(min(1.0, max(MIN_PRESSURE_FLOOR, pressure))), 4)


def calculate_energy_pressure(device_a: Device, device_b: Device) -> float:
    """Calculate energy pressure (0.20 to 0.95) based strictly on device power_source.

    Does NOT inspect or assume battery percentage.
    - mains + mains     -> 0.20
    - battery + mains   -> 0.80
    - battery + battery -> 0.95
    """
    pwr_a = str(getattr(device_a, "power_source", "mains")).lower()
    pwr_b = str(getattr(device_b, "power_source", "mains")).lower()

    if pwr_a == "battery" and pwr_b == "battery":
        return BOTH_BATTERY_PRESSURE
    if pwr_a == "battery" or pwr_b == "battery":
        return max(
            POWER_SOURCE_PRESSURE.get(pwr_a, POWER_SOURCE_PRESSURE["mains"]),
            POWER_SOURCE_PRESSURE.get(pwr_b, POWER_SOURCE_PRESSURE["mains"]),
        )
    return POWER_SOURCE_PRESSURE.get("mains", 0.20)


def derive_dynamic_weights(
    device_a: Device,
    device_b: Device,
    message_size_bytes: int,
) -> Tuple[Dict[str, float], Dict[str, float]]:
    """Derive normalized weights from endpoint constraints and user message size.

    Returns:
        (weights, pressures)
        where weights = {'wt': float, 'wm': float, 'wc': float, 'we': float} summing to 1.0
        and pressures = {'p_time': float, 'p_memory': float, 'p_communication': float, 'p_energy': float}
    """
    p_time = calculate_time_pressure(device_a, device_b)
    p_mem = calculate_memory_pressure(device_a, device_b)
    p_comm = calculate_communication_pressure(device_a, device_b, message_size_bytes)
    p_energy = calculate_energy_pressure(device_a, device_b)

    pressures = {
        "p_time": p_time,
        "p_memory": p_mem,
        "p_communication": p_comm,
        "p_energy": p_energy,
    }

    total = p_time + p_mem + p_comm + p_energy
    if total <= 0:
        # Safe fallback: equal distribution
        weights = {"wt": 0.25, "wm": 0.25, "wc": 0.25, "we": 0.25}
    else:
        weights = {
            "wt": round(p_time / total, 4),
            "wm": round(p_mem / total, 4),
            "wc": round(p_comm / total, 4),
            "we": round(p_energy / total, 4),
        }
        # Guarantee exact 1.0 sum after rounding
        diff = round(1.0 - sum(weights.values()), 4)
        if diff != 0:
            weights["wt"] = round(weights["wt"] + diff, 4)

    return weights, pressures


def validate_custom_weights(weights: Dict[str, float]) -> Dict[str, float]:
    """Validate and normalize user-provided custom weights.

    Accepts keys ('wt', 'wm', 'wc', 'we') or long names ('time', 'memory', 'communication', 'energy').
    Returns canonical dict {'wt': ..., 'wm': ..., 'wc': ..., 'we': ...} summing to 1.0.
    """
    key_mapping = {
        "wt": "wt", "time": "wt",
        "wm": "wm", "memory": "wm",
        "wc": "wc", "communication": "wc",
        "we": "we", "energy": "we",
    }
    normalized_input: Dict[str, float] = {}
    for k, v in weights.items():
        k_lower = str(k).lower()
        if k_lower in key_mapping:
            if not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"Weight '{k}' must be a non-negative number, got {v}")
            normalized_input[key_mapping[k_lower]] = float(v)

    missing = {"wt", "wm", "wc", "we"} - set(normalized_input.keys())
    if missing:
        raise ValueError(f"Custom weights missing required keys: {sorted(missing)}")

    total = sum(normalized_input.values())
    if total <= 0:
        raise ValueError("Sum of custom weights must be greater than zero")

    return {k: round(v / total, 4) for k, v in normalized_input.items()}


# ---------------------------------------------------------------------------
# Metric Normalization
# ---------------------------------------------------------------------------

def _normalize(value: float, min_val: float, max_val: float) -> float:
    """Normalize value to the 0-1 range. Returns 0.0 if range is degenerate."""
    if max_val <= min_val:
        return 0.0
    clamped = max(min_val, min(max_val, value))
    return (clamped - min_val) / (max_val - min_val)


# ---------------------------------------------------------------------------
# Core Scoring
# ---------------------------------------------------------------------------

def score_candidates(
    candidates: List[Dict[str, Any]],
    weights: Optional[Dict[str, float]] = None,
    reference_bounds: Optional[Dict[str, Tuple[float, float]]] = None,
) -> List[Tuple[Dict[str, Any], float, Dict[str, float]]]:
    """Return a list of (candidate, score, normalized_metrics) tuples sorted ascending.

    Args:
        candidates: List of candidate benchmark documents.
        weights: Dictionary of weights (keys: 'wt', 'wm', 'wc', 'we').
        reference_bounds: Optional global/reference (min, max) bounds for stable normalization
            across candidate sets. Keys: 'time', 'memory', 'communication', 'energy'.
            If omitted, standard min-max normalization across the current candidate set is used.

    Returns:
        List of (doc, score, normalized_dict) sorted by ascending score with deterministic tie-breaking.
    """
    if not candidates:
        return []

    if weights is None:
        weights = {"wt": 0.25, "wm": 0.25, "wc": 0.25, "we": 0.25}

    times = [c["timings_ms"]["total"] for c in candidates]
    memories = [c.get("peak_memory_kb", 0.0) for c in candidates]
    comms = [c.get("application_bytes", 0) for c in candidates]
    # Energy proxy defaults to timing * 0.001 if not explicitly present
    energies = [c.get("energy_proxy", c["timings_ms"]["total"] * 0.001) for c in candidates]

    if reference_bounds:
        t_min, t_max = reference_bounds.get("time", (min(times), max(times)))
        m_min, m_max = reference_bounds.get("memory", (min(memories), max(memories)))
        c_min, c_max = reference_bounds.get("communication", (min(comms), max(comms)))
        e_min, e_max = reference_bounds.get("energy", (min(energies), max(energies)))
    else:
        # Fall back to local min-max scaling across current feasible set
        t_min, t_max = min(times), max(times)
        m_min, m_max = min(memories), max(memories)
        c_min, c_max = min(comms), max(comms)
        e_min, e_max = min(energies), max(energies)

    scored: List[Tuple[Dict[str, Any], float, Dict[str, float]]] = []
    for doc in candidates:
        raw_t = doc["timings_ms"]["total"]
        raw_m = doc.get("peak_memory_kb", 0.0)
        raw_c = doc.get("application_bytes", 0)
        raw_e = doc.get("energy_proxy", raw_t * 0.001)

        norm_time = _normalize(raw_t, t_min, t_max)
        norm_mem = _normalize(raw_m, m_min, m_max)
        norm_comm = _normalize(raw_c, c_min, c_max)
        norm_energy = _normalize(raw_e, e_min, e_max)

        score = (
            weights.get("wt", 0.25) * norm_time
            + weights.get("wm", 0.25) * norm_mem
            + weights.get("wc", 0.25) * norm_comm
            + weights.get("we", 0.25) * norm_energy
        )

        norm_dict = {
            "norm_time": round(norm_time, 4),
            "norm_memory": round(norm_mem, 4),
            "norm_communication": round(norm_comm, 4),
            "norm_energy": round(norm_energy, 4),
        }
        scored.append((doc, round(score, 6), norm_dict))

    # Deterministic tie-breaking: score -> application_bytes -> profile_id
    scored.sort(
        key=lambda item: (
            item[1],
            item[0].get("application_bytes", 0),
            item[0].get("profile_id", ""),
        )
    )
    return scored


def best_profile_for_message(
    benchmarks: List[Dict[str, Any]],
    weights: Optional[Dict[str, float]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[float]]:
    """Convenience helper returning the single best benchmark document and score."""
    if not benchmarks:
        return None, None
    scored = score_candidates(benchmarks, weights)
    return scored[0][0], scored[0][1]

