# selection/compatibility.py
"""Compatibility and feasibility checks for adaptive crypto profile selection.

Design
------
The primary compatibility gate is **hardware constraint checking**, evaluated
independently for the sender (Device A) and receiver (Device B):

1. Security policy   — device.security_requirement must satisfy profile.security_level
2. Minimum CPU level — device.cpu_level must meet profile.minimum_cpu_level
3. Peak memory       — profile's estimated peak RAM must fit inside device.available_memory_kb
4. Session latency   — predicted total latency must satisfy device.latency_requirement_ms

The legacy ``supported_algorithms`` field on a device document is retained for
informational purposes but is **not** the primary compatibility gate.  The
prototype assumes both endpoints can execute all profiles implemented in the
repository (crypto engines verified at runtime).

Benchmark evidence
------------------
If an exact-message-size run exists for a profile, it is used.  If not, the
nearest smaller or larger run is used as an **estimate** and the result is
labelled ``measurement_source = "estimated-scaled"`` with the actual source run
noted.  If no run exists at all the profile is rejected with
``InsufficientEvidenceError``, rather than fabricating a value or using zero.

Demonstration mode
------------------
All local-computer measurements are tagged ``measurement_source = "local-computer"``
by the benchmark engine.  Feasibility decisions made from those measurements
apply to the *host machine model*, not to validated physical-board performance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any

from models.crypto_profile import CryptoProfile
from models.device import Device
from repositories.benchmark_repository import BenchmarkRepository


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ordered security levels: higher index = higher security
_SECURITY_ORDER: Dict[str, int] = {"standard": 0, "high": 1}

# Ordered CPU levels
_CPU_ORDER: Dict[str, int] = {"low": 0, "medium": 1, "high": 2}

# Profiles actually implemented in this repository (family → engine available)
_IMPLEMENTED_FAMILIES = frozenset({"RSA", "ECC"})


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class InsufficientEvidenceError(ValueError):
    """Raised when no benchmark data exists for a profile, making cost
    estimation impossible.  The profile is rejected rather than fabricating
    a cost value.
    """


# ---------------------------------------------------------------------------
# Benchmark retrieval
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkEvidence:
    """Benchmark document plus provenance metadata used by the selector."""

    doc: Dict[str, Any]
    """The raw benchmark document."""

    exact_match: bool
    """True when message_size_bytes in the document equals the requested size."""

    estimation_note: str
    """Human-readable note when an estimate is used instead of an exact match."""


def find_best_benchmark(
    repo: BenchmarkRepository,
    device_id: str,
    profile_id: str,
    message_size: int,
) -> BenchmarkEvidence:
    """Return the most suitable benchmark document for the given parameters.

    Preference order
    ----------------
    1. Exact message_size match, physical-device source.
    2. Exact message_size match, any source.
    3. Nearest-size match (closest by byte count), any source — labelled as estimate.

    Raises
    ------
    InsufficientEvidenceError
        When no benchmark run exists for this (device_id, profile_id) pair at
        any message size.
    """
    # Try exact size first
    exact_candidates = repo.find_runs(
        device_id=device_id,
        profile_id=profile_id,
        message_size_bytes=message_size,
        measurement_source=None,
        success_only=True,
    )
    if exact_candidates:
        phys = [c for c in exact_candidates if c.get("measurement_source") == "physical-device"]
        best = min(phys or exact_candidates, key=lambda d: d["timings_ms"]["total"])
        return BenchmarkEvidence(doc=best, exact_match=True, estimation_note="")

    # Fall back to any size for this device+profile
    any_size_candidates = repo.find_runs(
        device_id=device_id,
        profile_id=profile_id,
        message_size_bytes=None,
        measurement_source=None,
        success_only=True,
    )
    if not any_size_candidates:
        raise InsufficientEvidenceError(
            f"No benchmark data for device='{device_id}', profile='{profile_id}'. "
            "Run the benchmark suite first: "
            "python -m evaluation.benchmark --device <device_id> --dry-run"
        )

    # Choose the nearest size
    best = min(any_size_candidates, key=lambda d: abs(d["message_size_bytes"] - message_size))
    actual_size = best["message_size_bytes"]
    src = best.get("measurement_source", "unknown")
    note = (
        f"No exact benchmark for {message_size} B; using nearest run "
        f"({actual_size} B, source={src}). "
        "Feasibility check is an estimate — run benchmarks at target size for precision."
    )
    # Tag the document so downstream code can detect it
    tagged = dict(best)
    tagged["measurement_source"] = "estimated-scaled"
    tagged["_estimation_note"] = note
    return BenchmarkEvidence(doc=tagged, exact_match=False, estimation_note=note)


# ---------------------------------------------------------------------------
# Individual constraint checks
# ---------------------------------------------------------------------------

def _security_sufficient(device: Device, profile_security_level: str) -> bool:
    """True when ``profile_security_level`` meets or exceeds the device's security_requirement.

    A device with security_requirement='high' accepts only 'high' profiles.
    A device with security_requirement='standard' accepts 'standard' or 'high' profiles.
    """
    return _SECURITY_ORDER.get(profile_security_level, -1) >= _SECURITY_ORDER.get(device.security_requirement, 999)


def _cpu_sufficient(device: Device, required_cpu: str) -> bool:
    """True when the device's cpu_level meets or exceeds ``required_cpu``."""
    return _CPU_ORDER.get(device.cpu_level, -1) >= _CPU_ORDER.get(required_cpu, -1)


def _memory_fits(device: Device, required_peak_kb: float) -> bool:
    """True when device.available_memory_kb >= required_peak_kb."""
    mem = getattr(device, "available_memory_kb", None)
    if not isinstance(mem, (int, float)) or mem <= 0:
        return False
    return mem >= required_peak_kb


def _latency_fits(device: Device, predicted_total_ms: float) -> bool:
    """True when predicted_total_ms is within the device's latency_requirement_ms."""
    req = getattr(device, "latency_requirement_ms", None)
    if req is None:
        return True  # no latency constraint defined
    return predicted_total_ms <= req


def _profile_implemented(profile: CryptoProfile) -> bool:
    """True when the profile's key-establishment family is actually implemented
    by a crypto engine in this repository.  A MongoDB document alone does not
    implement an algorithm.
    """
    return profile.key_establishment.get("family") in _IMPLEMENTED_FAMILIES


# ---------------------------------------------------------------------------
# Main compatibility check
# ---------------------------------------------------------------------------

@dataclass
class CompatibilityResult:
    """Detailed result of a profile compatibility check."""

    compatible: bool
    rejection_reasons: List[str] = field(default_factory=list)

    # Evidence for each endpoint role (None when not retrieved)
    sender_evidence: Optional[BenchmarkEvidence] = None
    receiver_evidence: Optional[BenchmarkEvidence] = None

    # Predicted costs (derived from evidence)
    predicted_sender_total_ms: Optional[float] = None
    predicted_receiver_total_ms: Optional[float] = None
    predicted_sender_peak_kb: Optional[float] = None
    predicted_receiver_peak_kb: Optional[float] = None
    predicted_application_bytes: Optional[int] = None

    # Per-phase breakdown (from sender benchmark; symmetric for ECC)
    timing_breakdown: Dict[str, float] = field(default_factory=dict)

    # Estimation notes when exact-size benchmark data is unavailable
    estimation_notes: List[str] = field(default_factory=list)

    # Whether this result was produced from demonstration-mode (local) data
    is_demonstration_mode: bool = False


def check_profile_compatibility(
    sender: Device,
    receiver: Device,
    profile: CryptoProfile,
    message_size: int,
    benchmark_repo: BenchmarkRepository,
) -> Tuple[bool, List[str]]:
    """Thin compatibility check returning ``(compatible, reasons)`` for backward compatibility.

    Prefer :func:`check_profile_compatibility_detailed` for new code.
    """
    result = check_profile_compatibility_detailed(
        sender=sender,
        receiver=receiver,
        profile=profile,
        message_size=message_size,
        benchmark_repo=benchmark_repo,
    )
    return result.compatible, result.rejection_reasons


def check_profile_compatibility_detailed(
    sender: Device,
    receiver: Device,
    profile: CryptoProfile,
    message_size: int,
    benchmark_repo: BenchmarkRepository,
) -> CompatibilityResult:
    """Evaluate whether *profile* is feasible for (sender, receiver) with *message_size* bytes.

    The check proceeds in this order:

    1. Runtime implementation check — profile family must be implemented in this repo.
    2. Security policy — both devices must satisfy profile.security_level.
    3. Minimum CPU level — both devices must meet profile.minimum_cpu_level.
    4. Benchmark evidence retrieval — for sender and receiver independently.
    5. Memory feasibility — sender and receiver checked independently.
    6. Latency feasibility — combined sender+receiver total vs each device's limit.

    All failures are collected; the check does not short-circuit, so the caller
    receives the full list of rejection reasons.

    Returns
    -------
    CompatibilityResult
        ``compatible=True`` only when all checks pass.
    """
    reasons: List[str] = []
    estimation_notes: List[str] = []
    is_demo = False

    # ── 1. Implementation check ──────────────────────────────────────────────
    if not _profile_implemented(profile):
        family = profile.key_establishment.get("family", "unknown")
        return CompatibilityResult(
            compatible=False,
            rejection_reasons=[f"profile family '{family}' is not implemented by any crypto engine"],
        )

    # ── 2. Security policy ───────────────────────────────────────────────────
    required_sec = profile.security_level
    if not _security_sufficient(sender, required_sec):
        reasons.append(
            f"sender security_requirement='{sender.security_requirement}' "
            f"does not satisfy profile security_level='{required_sec}'"
        )
    if not _security_sufficient(receiver, required_sec):
        reasons.append(
            f"receiver security_requirement='{receiver.security_requirement}' "
            f"does not satisfy profile security_level='{required_sec}'"
        )

    # ── 3. Minimum CPU level ─────────────────────────────────────────────────
    required_cpu = profile.minimum_cpu_level
    if not _cpu_sufficient(sender, required_cpu):
        reasons.append(
            f"sender cpu_level='{sender.cpu_level}' "
            f"does not meet profile minimum_cpu_level='{required_cpu}'"
        )
    if not _cpu_sufficient(receiver, required_cpu):
        reasons.append(
            f"receiver cpu_level='{receiver.cpu_level}' "
            f"does not meet profile minimum_cpu_level='{required_cpu}'"
        )

    # ── 4. Benchmark evidence ────────────────────────────────────────────────
    # Retrieve sender evidence (sender performs key generation + wrap/ECDH + encryption)
    sender_evidence: Optional[BenchmarkEvidence] = None
    receiver_evidence: Optional[BenchmarkEvidence] = None

    try:
        sender_evidence = find_best_benchmark(
            benchmark_repo, sender.device_id, profile.profile_id, message_size
        )
        if not sender_evidence.exact_match:
            estimation_notes.append(f"[sender] {sender_evidence.estimation_note}")
        src = sender_evidence.doc.get("measurement_source", "")
        if "local-computer" in src or "estimated" in src:
            is_demo = True
    except InsufficientEvidenceError as exc:
        reasons.append(f"insufficient benchmark evidence for sender: {exc}")

    try:
        receiver_evidence = find_best_benchmark(
            benchmark_repo, receiver.device_id, profile.profile_id, message_size
        )
        if not receiver_evidence.exact_match:
            estimation_notes.append(f"[receiver] {receiver_evidence.estimation_note}")
        src = receiver_evidence.doc.get("measurement_source", "")
        if "local-computer" in src or "estimated" in src:
            is_demo = True
    except InsufficientEvidenceError as exc:
        reasons.append(f"insufficient benchmark evidence for receiver: {exc}")

    # If we have no evidence, stop here
    if sender_evidence is None or receiver_evidence is None:
        return CompatibilityResult(
            compatible=False,
            rejection_reasons=reasons,
            sender_evidence=sender_evidence,
            receiver_evidence=receiver_evidence,
            estimation_notes=estimation_notes,
            is_demonstration_mode=is_demo,
        )

    # ── 5. Memory feasibility (independent per endpoint) ────────────────────
    sender_peak_kb = sender_evidence.doc.get("peak_memory_kb", 0.0)
    receiver_peak_kb = receiver_evidence.doc.get("peak_memory_kb", 0.0)

    if not _memory_fits(sender, sender_peak_kb):
        reasons.append(
            f"sender available_memory_kb={sender.available_memory_kb:.1f} < "
            f"predicted peak {sender_peak_kb:.1f} KB for profile '{profile.profile_id}'"
        )
    if not _memory_fits(receiver, receiver_peak_kb):
        reasons.append(
            f"receiver available_memory_kb={receiver.available_memory_kb:.1f} < "
            f"predicted peak {receiver_peak_kb:.1f} KB for profile '{profile.profile_id}'"
        )

    # ── 6. Latency feasibility ───────────────────────────────────────────────
    # RSA role split: sender wraps key + encrypts; receiver unwraps + decrypts.
    # ECC: both endpoints perform ECDH; we use the same benchmark for each
    # (symmetric handshake cost).  Key generation and handshake are included
    # in the benchmark's timings_ms.total; this selection optimises for one
    # fresh session (all phases counted).
    sender_total_ms = sender_evidence.doc["timings_ms"]["total"]
    receiver_total_ms = receiver_evidence.doc["timings_ms"]["total"]
    combined_ms = sender_total_ms + receiver_total_ms

    if not _latency_fits(sender, combined_ms):
        reasons.append(
            f"sender latency_requirement_ms={sender.latency_requirement_ms:.0f} < "
            f"predicted combined latency {combined_ms:.2f} ms"
        )
    if not _latency_fits(receiver, combined_ms):
        reasons.append(
            f"receiver latency_requirement_ms={receiver.latency_requirement_ms:.0f} < "
            f"predicted combined latency {combined_ms:.2f} ms"
        )

    # ── 7. Packet / Communication size feasibility ───────────────────────────
    app_bytes = sender_evidence.doc.get("application_bytes", 0)
    limit_a = getattr(sender, "maximum_packet_size_bytes", None)
    limit_b = getattr(receiver, "maximum_packet_size_bytes", None)
    if limit_a is not None and app_bytes > limit_a:
        reasons.append(
            f"sender maximum_packet_size_bytes={limit_a} < "
            f"predicted packet overhead {app_bytes} B for profile '{profile.profile_id}'"
        )
    if limit_b is not None and app_bytes > limit_b:
        reasons.append(
            f"receiver maximum_packet_size_bytes={limit_b} < "
            f"predicted packet overhead {app_bytes} B for profile '{profile.profile_id}'"
        )

    # ── Result ───────────────────────────────────────────────────────────────
    app_bytes = sender_evidence.doc.get("application_bytes", 0)
    breakdown = dict(sender_evidence.doc.get("timings_ms", {}))

    return CompatibilityResult(
        compatible=len(reasons) == 0,
        rejection_reasons=reasons,
        sender_evidence=sender_evidence,
        receiver_evidence=receiver_evidence,
        predicted_sender_total_ms=sender_total_ms,
        predicted_receiver_total_ms=receiver_total_ms,
        predicted_sender_peak_kb=sender_peak_kb,
        predicted_receiver_peak_kb=receiver_peak_kb,
        predicted_application_bytes=app_bytes,
        timing_breakdown=breakdown,
        estimation_notes=estimation_notes,
        is_demonstration_mode=is_demo,
    )
