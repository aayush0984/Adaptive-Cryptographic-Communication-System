# selection/selector.py
"""Orchestrator for adaptive profile selection.

Public API
----------
``select_best_profile``  – evaluate all enabled profiles, apply constraint
                            filters, score feasible ones, persist the experiment
                            document, and return a :class:`SelectionResult`.

``prompt_device_selection`` – interactive 1-indexed device menu (unchanged
                               from Phase 8 except for display cleanup).

``prompt_message`` – ask the user for the plaintext message to transmit.

Selection objective
-------------------
Minimise predicted end-to-end latency (sender_total_ms + receiver_total_ms)
among profiles that satisfy all mandatory constraints.

Tie-breaking (deterministic)
    1. Lower application_bytes (fewer network bytes).
    2. Lower profile_id string (stable alphabetical order).

This matches the requirement: if one profile consistently wins, that is
reported honestly rather than forced to change per scenario.

Experiment persistence
----------------------
Every call to ``select_best_profile`` upserts an experiment document in the
``experiments`` MongoDB collection.  The document records:

- sender_id, receiver_id, message_size_bytes (not the plaintext)
- runtime constraint snapshots
- all candidate profiles, their evidence, and rejection reasons
- the selected profile and justification
- whether the result is from demonstration (local-computer) data

Actual observed results are written separately by the server/client after
the communication round-trip.
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models.device import Device
from models.crypto_profile import CryptoProfile
from repositories.benchmark_repository import BenchmarkRepository
from repositories.profile_repository import ProfileRepository
from selection.compatibility import (
    CompatibilityResult,
    InsufficientEvidenceError,
    check_profile_compatibility_detailed,
)
from selection.scoring import score_candidates


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class SelectionResult:
    """Full result of an adaptive profile selection run.

    Attributes
    ----------
    winning_profile : CryptoProfile
        The selected profile.
    winning_bench_doc : dict
        The sender-side benchmark document used to predict the winner's latency.
    winning_score : float
        The normalised weighted score (lower is better).
    experiment_id : str
        Unique ID for this selection run; also stored in MongoDB.
    candidate_details : list[dict]
        Per-profile evidence, predicted costs, and feasibility check outcomes.
    is_demonstration_mode : bool
        True when any evidence comes from ``local-computer`` measurements.
        Feasibility decisions apply to the host machine, not physical boards.
    selection_reason : str
        Human-readable justification for the winning profile.
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
    ) -> None:
        self.winning_profile = winning_profile
        self.winning_bench_doc = winning_bench_doc
        self.winning_score = winning_score
        self.experiment_id = experiment_id
        self.candidate_details = candidate_details
        self.is_demonstration_mode = is_demonstration_mode
        self.selection_reason = selection_reason


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------

def prompt_device_selection(
    prompt_text: str,
    devices: List[Device],
) -> Device:
    """Present a 1-indexed list of devices and return the chosen Device.

    Validates selections and re-prompts on invalid input.
    """
    if not devices:
        raise ValueError("No active devices found in the MongoDB 'devices' collection.")

    displayed = devices[:10]
    print(f"\n--- {prompt_text} ---")
    for idx, dev in enumerate(displayed, 1):
        ram = f"{dev.available_memory_kb:.0f} KB RAM"
        sec = f"{dev.security_requirement} sec"
        print(f"  {idx}. {dev.name} [{ram}, {sec}]")

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
    """Ask the user to enter the message to transmit.

    Rules
    -----
    - The prompt accepts any Unicode string.
    - An empty string is accepted and triggers a confirmation warning.
    - The plaintext is never stored to MongoDB or written to log files.

    Returns
    -------
    str
        The raw user-entered message string (may be empty).
    """
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
    """Select the best feasible CryptoProfile for (sender → receiver).

    This function is the public API used by ``client.py``.  It returns the same
    3-tuple ``(winning_profile, winning_bench_doc, winning_score)`` as before
    so existing call-sites remain compatible.  Call :func:`select_best_profile_full`
    to also receive the :class:`SelectionResult` with full provenance.

    Raises
    ------
    ValueError
        When no profile passes all mandatory constraints, or when no profiles
        are enabled in the database.
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
    """Full selection run returning :class:`SelectionResult` with provenance.

    Parameters
    ----------
    sender, receiver : Device
        Device A (sender) and Device B (receiver) selected by the user.
    message_size_bytes : int
        UTF-8 byte count of the user-provided message.  Used for benchmark
        retrieval and cost estimation.
    profile_repo, benchmark_repo : optional
        Injected repositories (useful for unit tests).
    weights : optional dict
        Scoring weights ``{wt, wm, wc, we}``.  Defaults to equal (0.25 each).
    experiment_id : optional str
        Correlation ID.  A new UUID is generated when omitted.
    db : optional
        MongoDB database handle for experiment persistence.  Falls back to the
        default connection when ``None``.

    Raises
    ------
    ValueError
        When no enabled profiles exist, or none pass all constraints.
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

    # ── Evaluate every enabled profile ──────────────────────────────────────
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

        # Build evidence provenance for persistence
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

    # ── No feasible profile ──────────────────────────────────────────────────
    if not feasible_pairs:
        # Categorise the failure
        all_reasons = {d["profile_id"]: d["rejection_reasons"] for d in candidate_details}
        insufficient = [
            pid for pid, reasons in all_reasons.items()
            if any("insufficient benchmark evidence" in r for r in reasons)
        ]
        no_constraint = [
            pid for pid, reasons in all_reasons.items()
            if reasons and not any("insufficient benchmark evidence" in r for r in reasons)
        ]

        failure_category: str
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
        )
        raise ValueError(
            f"No compatible crypto profile found "
            f"(sender='{sender.device_id}', receiver='{receiver.device_id}', "
            f"message={message_size_bytes} B). "
            f"Failure category: {failure_category}. "
            f"Per-profile rejections: {all_reasons}"
        )

    # ── Score feasible candidates ────────────────────────────────────────────
    # Build benchmark list for the scorer.  We use the sender benchmark document
    # but add the receiver's predicted latency so the scorer's "time" dimension
    # reflects combined end-to-end latency rather than sender-only cost.
    bench_docs_for_scoring: List[Dict[str, Any]] = []
    for profile, compat in feasible_pairs:
        doc = dict(compat.sender_evidence.doc)  # type: ignore[union-attr]
        # Augment total timing with receiver cost for combined latency objective
        recv_ms = compat.predicted_receiver_total_ms or 0.0
        combined_ms = doc["timings_ms"]["total"] + recv_ms
        doc = dict(doc)
        doc["timings_ms"] = dict(doc["timings_ms"])
        doc["timings_ms"]["total"] = combined_ms
        doc["_profile_ref"] = profile
        bench_docs_for_scoring.append(doc)

    scored = score_candidates(bench_docs_for_scoring, weights=weights)

    # Deterministic tie-breaking: score → application_bytes → profile_id
    scored.sort(
        key=lambda pair: (
            pair[1],
            pair[0].get("application_bytes", 0),
            pair[0].get("profile_id", ""),
        )
    )

    winning_doc, winning_score = scored[0]
    winning_profile: CryptoProfile = winning_doc["_profile_ref"]

    # Build selection reason
    winning_compat = next(c for p, c in feasible_pairs if p.profile_id == winning_profile.profile_id)
    combined_ms = (winning_compat.predicted_sender_total_ms or 0.0) + (winning_compat.predicted_receiver_total_ms or 0.0)
    selection_reason = (
        f"Profile '{winning_profile.profile_id}' ({winning_profile.name}) selected. "
        f"Objective: minimise predicted end-to-end latency. "
        f"Predicted combined latency: {combined_ms:.2f} ms "
        f"(sender {winning_compat.predicted_sender_total_ms:.2f} ms + "
        f"receiver {winning_compat.predicted_receiver_total_ms:.2f} ms). "
        f"Score: {winning_score:.4f}."
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
    )

    return SelectionResult(
        winning_profile=winning_profile,
        winning_bench_doc=winning_compat.sender_evidence.doc,  # type: ignore[union-attr]
        winning_score=winning_score,
        experiment_id=experiment_id,
        candidate_details=candidate_details,
        is_demonstration_mode=any_demo,
        selection_reason=selection_reason,
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
) -> None:
    """Upsert the selection record into the experiments collection.

    The plaintext is never stored.  Only the byte count is persisted.
    """
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
            # Constraint snapshots at selection time
            "sender_constraints": {
                "available_memory_kb": sender.available_memory_kb,
                "security_requirement": sender.security_requirement,
                "cpu_level": sender.cpu_level,
                "latency_requirement_ms": sender.latency_requirement_ms,
            },
            "receiver_constraints": {
                "available_memory_kb": receiver.available_memory_kb,
                "security_requirement": receiver.security_requirement,
                "cpu_level": receiver.cpu_level,
                "latency_requirement_ms": receiver.latency_requirement_ms,
            },
            "message_size_bytes": message_size_bytes,  # byte count only — no plaintext
            "optimization_objective": "minimise_predicted_end_to_end_latency",
            "candidate_profiles": candidate_details,
            "selected_profile_id": selected_profile_id,
            "selection_reason": selection_reason,
            "failure_category": failure_category,
            "status": status,
            "is_demonstration_mode": is_demonstration_mode,
            "selected_at": datetime.now(timezone.utc),
            # observed_results is written separately after the communication round-trip
        }

        db["experiments"].update_one(
            {"experiment_id": experiment_id},
            {"$set": doc},
            upsert=True,
        )
    except Exception as exc:
        # Persistence failure must not interrupt the crypto flow
        print(f"[selector] Warning: could not persist experiment record: {exc}", flush=True)
