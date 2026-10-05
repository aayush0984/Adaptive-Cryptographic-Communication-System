# selection/compatibility.py
"""Compatibility checks for adaptive crypto profile selection.

This module provides functions to determine whether a given crypto
profile is applicable to a pair of devices for a specific message size.
The checks are deliberately lightweight – they verify the required
capabilities, security level, and that a benchmark measurement exists.
"""

from __future__ import annotations

from typing import List, Tuple

from models.crypto_profile import CryptoProfile
from models.device import Device
from repositories.benchmark_repository import BenchmarkRepository


def _has_required_algorithm(device: Device, family: str) -> bool:
    """Return ``True`` if the device lists ``family`` in its ``supported_algorithms``.

    The ``supported_algorithms`` field is a list of strings such as ``"RSA"``
    or ``"ECC"`` that the device can handle.  The check is case‑insensitive.
    """
    return any(alg.upper() == family.upper() for alg in getattr(device, "supported_algorithms", []))


def _security_sufficient(device: Device, required: str) -> bool:
    """Check that the device's security requirement meets or exceeds ``required``.

    Both ``required`` and the device's ``security_requirement`` are strings
    ``"standard"`` or ``"high"``.  ``"high"`` satisfies ``"standard"`` but
    not vice‑versa.
    """
    order = {"standard": 0, "high": 1}
    return order.get(device.security_requirement, -1) >= order.get(required, -1)


def _has_memory_for_profile(device: Device, profile: CryptoProfile) -> bool:
    """Simple memory sanity check.

    The profile does not currently specify a memory budget, so we only
    verify that the device reports a positive ``available_memory_kb``.
    """
    mem = getattr(device, "available_memory_kb", None)
    return isinstance(mem, (int, float)) and mem > 0


def _find_best_benchmark(
    repo: BenchmarkRepository,
    device_id: str,
    profile_id: str,
    message_size: int,
) -> Tuple[dict | None, List[str]]:
    """Return the most suitable benchmark document for the given parameters.

    Preference order:
    1. ``measurement_source == "physical-device"``
    2. Any other source (e.g. ``"local-computer"``)
    The function also returns a list of *rejection reasons* if no
    benchmark is found.
    """
    candidates = repo.find_runs(
        device_id=device_id,
        profile_id=profile_id,
        message_size_bytes=message_size,
        measurement_source=None,
        success_only=True,
    )
    if not candidates:
        return None, ["no benchmark data"]

    # Prefer physical-device measurements
    phys = [c for c in candidates if c.get("measurement_source") == "physical-device"]
    best = phys or candidates
    # Choose the one with the lowest total timing
    best_doc = min(best, key=lambda d: d["timings_ms"]["total"])
    return best_doc, []


def check_profile_compatibility(
    sender: Device,
    receiver: Device,
    profile: CryptoProfile,
    message_size: int,
    benchmark_repo: BenchmarkRepository,
) -> Tuple[bool, List[str]]:
    """Determine whether *profile* can be used between *sender* and *receiver*.

    Returns a tuple ``(compatible, reasons)`` where ``compatible`` is a
    boolean and ``reasons`` is a list of strings explaining any failures.
    """
    reasons: List[str] = []
    family = profile.key_establishment["family"]

    # Capability checks
    if not _has_required_algorithm(sender, family):
        reasons.append(f"sender lacks {family} support")
    if not _has_required_algorithm(receiver, family):
        reasons.append(f"receiver lacks {family} support")

    # Security requirement
    required_sec = profile.security_requirement  # type: ignore[attr-defined]
    if not _security_sufficient(sender, required_sec):
        reasons.append("sender security insufficient")
    if not _security_sufficient(receiver, required_sec):
        reasons.append("receiver security insufficient")

    # Memory sanity (optional, but kept for completeness)
    if not _has_memory_for_profile(sender, profile):
        reasons.append("sender memory not reported")
    if not _has_memory_for_profile(receiver, profile):
        reasons.append("receiver memory not reported")

    # Benchmark availability
    bench, bench_reasons = _find_best_benchmark(
        benchmark_repo, sender.device_id, profile.profile_id, message_size
    )
    if bench is None:
        reasons.extend(bench_reasons)
    else:
        # Attach the chosen benchmark to the result for later scoring
        # (the caller can fetch it again if needed).
        pass

    return (len(reasons) == 0), reasons

