# selection/selector.py
"""Orchestrator for adaptive profile selection.

Public API
----------
``select_best_profile``  – evaluate all enabled profiles, apply constraint
                            filters, score feasible ones, persist the experiment
                            document, and return a :class:`SelectionResult`.

``prompt_device_selection`` – interactive 1-indexed device menu.

``prompt_message`` – ask the user for the plaintext message to transmit.

Selection objective
-------------------
Minimise the dynamically weighted normalized cost of end-to-end latency,
memory consumption, communication overhead, and energy, subject to mandatory
security and resource constraints.

Tie-breaking (deterministic)
    1. Lower dynamically weighted score.
    2. Lower application_bytes (fewer network bytes).
    3. Lower profile_id string (stable alphabetical order).

Experiment persistence
----------------------
Every call to ``select_best_profile`` upserts an experiment document in the
``experiments`` MongoDB collection. The document records:

- sender_id, receiver_id, message_size_bytes (not the plaintext)
- runtime constraint snapshots and combined constraint bounds
- constraint pressures and dynamic weights
- all candidate profiles, their evidence, normalized metrics, and rejection reasons
- the selected profile and justification
- whether the result is from demonstration (local-computer) data
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional, Tuple

# Indian Standard Time (IST = UTC+05:30)
IST = ZoneInfo("Asia/Kolkata")

from models.device import Device
from models.crypto_profile import CryptoProfile
from repositories.benchmark_repository import BenchmarkRepository
from repositories.profile_repository import ProfileRepository
from selection.compatibility import (
    CompatibilityResult,
    InsufficientEvidenceError,
    check_profile_compatibility_detailed,
)
from selection.scoring import (
    derive_dynamic_weights,
    score_candidates,
    validate_custom_weights,
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class SelectionResult:
    """Full result of an adaptive profile selection run with full explainability.

    Attributes
    ----------
    winning_profile : CryptoProfile
        The selected profile.
    winning_bench_doc : dict
        The sender-side benchmark document used to predict costs.
    winning_score : float
        The normalised weighted score (lower is better).
    experiment_id : str
        Unique ID for this selection run; also stored in MongoDB.
    candidate_details : list[dict]
        Per-profile evidence, predicted costs, feasibility outcomes, and normalized metrics.
    is_demonstration_mode : bool
        True when any evidence comes from ``local-computer`` measurements.
    selection_reason : str
        Human-readable justification for the winning profile.
    dynamic_weights : dict
        Weights used for scoring {'wt': ..., 'wm': ..., 'wc': ..., 'we': ...}.
    constraint_pressures : dict
        Calculated constraint pressures {'p_time': ..., 'p_memory': ..., 'p_communication': ..., 'p_energy': ...}.
    combined_constraints : dict
        Combined constraint summary for Device A and Device B.
    """

    def __init__(
        self,
        winning_profile: CryptoProfile,
        winning_bench_doc: Dict[str, Any],
        winning_score: float,
        experiment_id: str,
        candidate_details: List[Dict[str, Any]],
        is_demonstration_mode: bool,
        selection_reason: str,
        dynamic_weights: Optional[Dict[str, float]] = None,
        constraint_pressures: Optional[Dict[str, float]] = None,
        combined_constraints: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.winning_profile = winning_profile
        self.winning_bench_doc = winning_bench_doc
        self.winning_score = winning_score
        self.experiment_id = experiment_id
        self.candidate_details = candidate_details
        self.is_demonstration_mode = is_demonstration_mode
        self.selection_reason = selection_reason
        self.dynamic_weights = dynamic_weights or {}
        self.constraint_pressures = constraint_pressures or {}
        self.combined_constraints = combined_constraints or {}


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------

def prompt_device_selection(
    prompt_text: str,
    devices: List[Device],
) -> Device:
    """Present a 1-indexed list of devices and return the chosen Device."""
    if not devices:
        raise ValueError("No active devices found in the MongoDB 'devices' collection.")

    displayed = list(devices)
    print(f"\n--- {prompt_text} ---")
    for idx, dev in enumerate(displayed, 1):
        ram = f"{dev.available_memory_kb:.0f} KB RAM"
        sec = f"{dev.security_requirement} sec"
        pwr = f"{dev.power_source} pwr"
        print(f"  {idx}. {dev.name} [{ram}, {sec}, {pwr}]")

    while True:
        try:
            raw = input(f"Enter choice (1-{len(displayed)}): ").strip()
            try:
                num = int(raw)
            except ValueError:
                print(f"  Invalid choice. Enter a number between 1 and {len(displayed)}.")
                continue
            if 1 <= num <= len(displayed):
                selected = displayed[num - 1]
                print(f"-> Selected: {selected.name}\n")
                return selected
            print(f"  Invalid choice. Enter a number between 1 and {len(displayed)}.")
        except (EOFError, KeyboardInterrupt) as exc:
            print(f"\nSelection interrupted: {exc}")
            raise SystemExit(1) from exc


def prompt_message() -> str:
    """Ask the user to enter the message to transmit."""
    print("\n--- Enter the message to transmit ---")
    print("  (Unicode is supported; leave blank and press Enter for an empty message)")
    try:
        msg = input("Message: ")
    except (EOFError, KeyboardInterrupt) as exc:
        print(f"\nInput interrupted: {exc}")
        raise SystemExit(1) from exc

    if msg == "":
        print("  [WARN] Empty message accepted. An empty AES-GCM ciphertext is technically valid.")
    return msg


# ---------------------------------------------------------------------------
# Core selection logic
# ---------------------------------------------------------------------------

def select_best_profile(
    sender: Device,
    receiver: Device,
    message_size_bytes: int,
    profile_repo: Optional[ProfileRepository] = None,
    benchmark_repo: Optional[BenchmarkRepository] = None,
    weights: Optional[Dict[str, float]] = None,
    experiment_id: Optional[str] = None,
    db: Any = None,
) -> Tuple[CryptoProfile, Dict[str, Any], float]:
    """Select the best feasible CryptoProfile for (sender -> receiver).

    Public 3-tuple API for backward compatibility.
    """
    result = select_best_profile_full(
        sender=sender,
        receiver=receiver,
        message_size_bytes=message_size_bytes,
        profile_repo=profile_repo,
        benchmark_repo=benchmark_repo,
        weights=weights,
        experiment_id=experiment_id,
        db=db,
    )
    return result.winning_profile, result.winning_bench_doc, result.winning_score


def select_best_profile_full(
    sender: Device,
    receiver: Device,
    message_size_bytes: int,
    profile_repo: Optional[ProfileRepository] = None,
    benchmark_repo: Optional[BenchmarkRepository] = None,
    weights: Optional[Dict[str, float]] = None,
    experiment_id: Optional[str] = None,
    db: Any = None,
) -> SelectionResult:
    """Full two-stage adaptive selection run returning SelectionResult with provenance.

    Stage 1: Hard constraint filtering (Security, Memory, Packet limit, Latency, CPU).
    Stage 2: Dynamic weight derivation from combined constraints & weighted scoring.
    """
    if profile_repo is None:
        profile_repo = ProfileRepository()
    if benchmark_repo is None:
        benchmark_repo = BenchmarkRepository()
    if experiment_id is None:
        experiment_id = f"exp-{uuid.uuid4().hex[:8]}"

    enabled_profiles = profile_repo.list_enabled()
    if not enabled_profiles:
        raise ValueError("No active crypto profiles found in the 'crypto_profiles' collection.")

    # ── Combined constraints summary ─────────────────────────────────────────
    # Stricter requirement between sender and receiver
    sec_order = {"standard": 0, "high": 1}
    strictest_sec = "high" if (
        sec_order.get(sender.security_requirement, 0) == 1 or
        sec_order.get(receiver.security_requirement, 0) == 1
    ) else "standard"

    combined_constraints = {
        "memory_limit_kb": min(sender.available_memory_kb, receiver.available_memory_kb),
        "latency_limit_ms": min(
            getattr(sender, "latency_requirement_ms", 2000.0) or 2000.0,
            getattr(receiver, "latency_requirement_ms", 2000.0) or 2000.0,
        ),
        "packet_limit_bytes": min(
            getattr(sender, "maximum_packet_size_bytes", 1500) or 1500,
            getattr(receiver, "maximum_packet_size_bytes", 1500) or 1500,
        ),
        "required_security": strictest_sec,
        "sender_power_source": getattr(sender, "power_source", "mains"),
        "receiver_power_source": getattr(receiver, "power_source", "mains"),
    }

    # ── Derive or validate weights ───────────────────────────────────────────
    if weights is not None:
        final_weights = validate_custom_weights(weights)
        pressures = {}
    else:
        final_weights, pressures = derive_dynamic_weights(
            device_a=sender,
            device_b=receiver,
            message_size_bytes=message_size_bytes,
        )

    # ── STAGE 1: Hard filtering on every enabled profile ─────────────────────
    feasible_pairs: List[Tuple[CryptoProfile, CompatibilityResult]] = []
    candidate_details: List[Dict[str, Any]] = []
    any_demo = False

    for profile in enabled_profiles:
        compat = check_profile_compatibility_detailed(
            sender=sender,
            receiver=receiver,
            profile=profile,
            message_size=message_size_bytes,
            benchmark_repo=benchmark_repo,
        )
        if compat.is_demonstration_mode:
            any_demo = True

        sender_run_id = (
            compat.sender_evidence.doc.get("run_id") if compat.sender_evidence else None
        )
        receiver_run_id = (
            compat.receiver_evidence.doc.get("run_id") if compat.receiver_evidence else None
        )
        sender_src = (
            compat.sender_evidence.doc.get("measurement_source") if compat.sender_evidence else None
        )
        receiver_src = (
            compat.receiver_evidence.doc.get("measurement_source") if compat.receiver_evidence else None
        )

        detail: Dict[str, Any] = {
            "profile_id": profile.profile_id,
            "profile_name": profile.name,
            "security_level": profile.security_level,
            "compatible": compat.compatible,
            "rejection_reasons": compat.rejection_reasons,
            "estimation_notes": compat.estimation_notes,
            "is_demonstration_mode": compat.is_demonstration_mode,
            "sender_evidence_run_id": sender_run_id,
            "receiver_evidence_run_id": receiver_run_id,
            "sender_measurement_source": sender_src,
            "receiver_measurement_source": receiver_src,
            "predicted_sender_total_ms": compat.predicted_sender_total_ms,
            "predicted_receiver_total_ms": compat.predicted_receiver_total_ms,
            "predicted_sender_peak_kb": compat.predicted_sender_peak_kb,
            "predicted_receiver_peak_kb": compat.predicted_receiver_peak_kb,
            "predicted_application_bytes": compat.predicted_application_bytes,
            "timing_breakdown": compat.timing_breakdown,
        }
        candidate_details.append(detail)

        if compat.compatible and compat.sender_evidence is not None:
            feasible_pairs.append((profile, compat))

    # ── STAGE 1 failure: No feasible profile ─────────────────────────────────
    if not feasible_pairs:
        all_reasons = {d["profile_id"]: d["rejection_reasons"] for d in candidate_details}
        insufficient = [
            pid for pid, reasons in all_reasons.items()
            if any("insufficient benchmark evidence" in r for r in reasons)
        ]
        no_constraint = [
            pid for pid, reasons in all_reasons.items()
            if reasons and not any("insufficient benchmark evidence" in r for r in reasons)
        ]

        if insufficient and not no_constraint:
            failure_category = "insufficient_benchmark_evidence"
        elif not insufficient:
            failure_category = "no_profile_satisfies_constraints"
        else:
            failure_category = "mixed_evidence_and_constraint_failures"

        _persist_experiment(
            db=db,
            experiment_id=experiment_id,
            sender=sender,
            receiver=receiver,
            message_size_bytes=message_size_bytes,
            candidate_details=candidate_details,
            status="failed",
            failure_category=failure_category,
            selected_profile_id=None,
            selection_reason=None,
            is_demonstration_mode=any_demo,
            dynamic_weights=final_weights,
            constraint_pressures=pressures,
            combined_constraints=combined_constraints,
        )
        raise ValueError(
            f"No compatible crypto profile found "
            f"(sender='{sender.device_id}', receiver='{receiver.device_id}', "
            f"message={message_size_bytes} B). "
            f"Failure category: {failure_category}. "
            f"Per-profile rejections: {all_reasons}"
        )

    # ── STAGE 2: Dynamic optimization & scoring ──────────────────────────────
    bench_docs_for_scoring: List[Dict[str, Any]] = []
    for profile, compat in feasible_pairs:
        doc = dict(compat.sender_evidence.doc)  # type: ignore[union-attr]
        recv_ms = compat.predicted_receiver_total_ms or 0.0
        combined_ms = doc["timings_ms"]["total"] + recv_ms
        doc = dict(doc)
        doc["timings_ms"] = dict(doc["timings_ms"])
        doc["timings_ms"]["total"] = combined_ms
        # Combined memory cost (max peak between endpoints)
        doc["peak_memory_kb"] = max(
            compat.predicted_sender_peak_kb or 0.0,
            compat.predicted_receiver_peak_kb or 0.0,
        )
        doc["_profile_ref"] = profile
        bench_docs_for_scoring.append(doc)

    # Score feasible candidates using dynamic weights
    scored_items = score_candidates(bench_docs_for_scoring, weights=final_weights)

    winning_doc, winning_score, winning_norm = scored_items[0]
    winning_profile: CryptoProfile = winning_doc["_profile_ref"]

    # Attach normalized metric breakdowns and final scores back into candidate_details
    for doc, s_val, norm_dict in scored_items:
        p_ref = doc["_profile_ref"]
        for detail in candidate_details:
            if detail["profile_id"] == p_ref.profile_id:
                detail["final_score"] = s_val
                detail["normalized_metrics"] = norm_dict
                break

    # Build human-readable explainability justification
    winning_compat = next(c for p, c in feasible_pairs if p.profile_id == winning_profile.profile_id)
    combined_ms = (winning_compat.predicted_sender_total_ms or 0.0) + (winning_compat.predicted_receiver_total_ms or 0.0)
    selection_reason = (
        f"Profile '{winning_profile.profile_id}' ({winning_profile.name}) selected. "
        f"Objective: Minimise the dynamically weighted normalized cost of end-to-end "
        f"latency, memory consumption, communication overhead, and energy, "
        f"subject to mandatory security and resource constraints. "
        f"Weights: time={final_weights['wt']*100:.1f}%, mem={final_weights['wm']*100:.1f}%, "
        f"comm={final_weights['wc']*100:.1f}%, energy={final_weights['we']*100:.1f}%. "
        f"Predicted end-to-end latency: {combined_ms:.2f} ms. "
        f"Final weighted score: {winning_score:.4f}."
    )
    if any_demo:
        selection_reason += (
            " [DEMONSTRATION MODE] Evidence is from local-computer benchmarks; "
            "feasibility decisions apply to the host machine, not physical boards."
        )

    _persist_experiment(
        db=db,
        experiment_id=experiment_id,
        sender=sender,
        receiver=receiver,
        message_size_bytes=message_size_bytes,
        candidate_details=candidate_details,
        status="selected",
        failure_category=None,
        selected_profile_id=winning_profile.profile_id,
        selection_reason=selection_reason,
        is_demonstration_mode=any_demo,
        dynamic_weights=final_weights,
        constraint_pressures=pressures,
        combined_constraints=combined_constraints,
    )

    return SelectionResult(
        winning_profile=winning_profile,
        winning_bench_doc=winning_compat.sender_evidence.doc,  # type: ignore[union-attr]
        winning_score=winning_score,
        experiment_id=experiment_id,
        candidate_details=candidate_details,
        is_demonstration_mode=any_demo,
        selection_reason=selection_reason,
        dynamic_weights=final_weights,
        constraint_pressures=pressures,
        combined_constraints=combined_constraints,
    )


# ---------------------------------------------------------------------------
# Experiment persistence
# ---------------------------------------------------------------------------

def _persist_experiment(
    *,
    db: Any,
    experiment_id: str,
    sender: Device,
    receiver: Device,
    message_size_bytes: int,
    candidate_details: List[Dict[str, Any]],
    status: str,
    failure_category: Optional[str],
    selected_profile_id: Optional[str],
    selection_reason: Optional[str],
    is_demonstration_mode: bool,
    dynamic_weights: Optional[Dict[str, float]] = None,
    constraint_pressures: Optional[Dict[str, float]] = None,
    combined_constraints: Optional[Dict[str, Any]] = None,
) -> None:
    """Upsert the selection record into the experiments collection."""
    try:
        if db is None:
            from database.connection import get_database
            db = get_database()

        doc: Dict[str, Any] = {
            "experiment_id": experiment_id,
            "sender_id": sender.device_id,
            "receiver_id": receiver.device_id,
            "sender_name": sender.name,
            "receiver_name": receiver.name,
            "sender_constraints": {
                "available_memory_kb": sender.available_memory_kb,
                "security_requirement": sender.security_requirement,
                "cpu_level": sender.cpu_level,
                "latency_requirement_ms": sender.latency_requirement_ms,
                "power_source": getattr(sender, "power_source", "mains"),
            },
            "receiver_constraints": {
                "available_memory_kb": receiver.available_memory_kb,
                "security_requirement": receiver.security_requirement,
                "cpu_level": receiver.cpu_level,
                "latency_requirement_ms": receiver.latency_requirement_ms,
                "power_source": getattr(receiver, "power_source", "mains"),
            },
            "combined_constraints": combined_constraints or {},
            "constraint_pressures": constraint_pressures or {},
            "dynamic_weights": dynamic_weights or {},
            "message_size_bytes": message_size_bytes,
            "optimization_objective": (
                "Minimise the dynamically weighted normalized cost of end-to-end "
                "latency, memory consumption, communication overhead, and energy, "
                "subject to mandatory security and resource constraints."
            ),
            "candidate_profiles": candidate_details,
            "selected_profile_id": selected_profile_id,
            "selection_reason": selection_reason,
            "failure_category": failure_category,
            "status": status,
            "is_demonstration_mode": is_demonstration_mode,
            "selected_at": datetime.now(IST),
        }

        db["experiments"].update_one(
            {"experiment_id": experiment_id},
            {"$set": doc},
            upsert=True,
        )
    except Exception as exc:
        print(f"[selector] Warning: could not persist experiment record: {exc}", flush=True)


