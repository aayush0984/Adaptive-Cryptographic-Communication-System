"""Client for the phase-8 secure sender/receiver protocol with adaptive encryption selection."""

from __future__ import annotations

import argparse
import socket
import sys
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any

# Indian Standard Time (IST = UTC+05:30)
IST = ZoneInfo("Asia/Kolkata")

from config import get_env
from communication.protocol import (
    MessageType,
    ProtocolMessage,
    ProtocolSession,
    read_frame_from_socket,
    send_frame_to_socket,
)
from repositories.device_repository import DeviceRepository
from selection.selector import (
    SelectionResult,
    prompt_device_selection,
    prompt_message,
    select_best_profile_full,
)


def run_client(
    host: str = get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1",
    port: int = int(get_env("SERVER_PORT", "5000") or "5000"),
    sender_id: str | None = None,
    receiver_id: str | None = None,
    experiment_id: str | None = None,
    profile_id: str | None = None,
    message: str | None = None,
    timeout_seconds: float = 5.0,
    non_interactive: bool = False,
) -> ProtocolMessage:
    """Perform adaptive profile selection, then execute framed TCP communication.

    Interactive flow (when inputs are omitted)
    ------------------------------------------
    1. Display active devices from MongoDB.
    2. Ask the user to select Device A (sender).
    3. Ask the user to select Device B (receiver).
    4. Ask the user to enter the message.
    5. Compute message_size_bytes from UTF-8 encoded bytes.
    6. Evaluate all enabled profiles against device constraints.
    7. Select the best feasible profile.
    8. Send the user's exact message through the TCP channel.

    The plaintext is kept in memory only; it is never stored in MongoDB.
    """
    dev_repo = DeviceRepository()
    active_devices = dev_repo.list_active()

    if not active_devices:
        raise ValueError(
            "No active devices found in the MongoDB 'devices' collection. "
            "Run 'python scripts/seed_database.py' to populate it."
        )

    # ── Step 1 & 2: Device A selection ──────────────────────────────────────
    if sender_id:
        sender = dev_repo.get_by_id(sender_id)
    elif non_interactive or not sys.stdin.isatty():
        sender = active_devices[0]
        print(f"[client] Defaulting sender to: {sender.name} ({sender.device_id})")
    else:
        sender = prompt_device_selection("Select Sender Device (Device A)", active_devices)

    # ── Step 3: Device B selection ───────────────────────────────────────────
    if receiver_id:
        receiver = dev_repo.get_by_id(receiver_id)
    elif non_interactive or not sys.stdin.isatty():
        receiver = active_devices[1] if len(active_devices) > 1 else active_devices[0]
        print(f"[client] Defaulting receiver to: {receiver.name} ({receiver.device_id})")
    else:
        receiver = prompt_device_selection("Select Receiver Device (Device B)", active_devices)

    # ── Step 4: Message input ────────────────────────────────────────────────
    # message=None  → interactive prompt
    # message=""    → empty message (valid; tested case)
    # message=<str> → provided via CLI --message flag or programmatic call
    if message is None:
        if non_interactive or not sys.stdin.isatty():
            message = "hello-from-client"
            print(f"[client] Defaulting message to: {message!r}")
        else:
            message = prompt_message()

    # ── Step 5: Compute message size from UTF-8 bytes ────────────────────────
    message_bytes = message.encode("utf-8")
    message_size = len(message_bytes)
    print(
        f"[client] Message: {message_size} byte(s) UTF-8 "
        f"({'empty' if message_size == 0 else repr(message[:40]) + ('…' if len(message) > 40 else '')})",
        flush=True,
    )

    # ── Steps 6 & 7: Adaptive profile selection ──────────────────────────────
    if not profile_id:
        if experiment_id is None:
            experiment_id = f"exp-{uuid.uuid4().hex[:8]}"

        print("\n============================================================")
        print("ADAPTIVE CRYPTO SELECTION")
        print("============================================================")
        print(f"[SENDER] Sender       : {sender.name} ({sender.device_id})")
        print(f"[SENDER] Receiver     : {receiver.name} ({receiver.device_id})")
        print(f"[SENDER] Message size : {message_size} bytes")
        print("[SENDER] Evaluating available crypto profiles...\n")

        try:
            selection: SelectionResult = select_best_profile_full(
                sender=sender,
                receiver=receiver,
                message_size_bytes=message_size,
                experiment_id=experiment_id,
            )
        except ValueError as exc:
            err_str = str(exc)
            if "insufficient_benchmark_evidence" in err_str or "No benchmark data" in err_str:
                print("No compatible crypto profile found.\n")
                print("Reason:\nBenchmark data is missing for the selected devices.\n")
                print("Generate development benchmark data using:")
                print(f"python -m evaluation.benchmark --device {sender.device_id} --dry-run")
                print(f"python -m evaluation.benchmark --device {receiver.device_id} --dry-run")
                print("or:")
                print("python -m evaluation.benchmark --all --dry-run\n")
            raise

        winning_prof = selection.winning_profile
        profile_id = winning_prof.profile_id

        sym_alg = winning_prof.symmetric_encryption.get("algorithm", "AES-GCM")
        key_bits = winning_prof.symmetric_encryption.get("key_size_bits", 128)
        enc_fmt = f"{sym_alg}-{key_bits}" if "AES" in sym_alg and str(key_bits) not in sym_alg else sym_alg

        key_est_family = winning_prof.key_establishment.get("family", "N/A")
        key_est_param = winning_prof.key_establishment.get("parameter", "")
        key_est_str = f"{key_est_family} ({key_est_param})" if key_est_param else key_est_family

        mode_str = "Simulated" if selection.is_demonstration_mode else "Measured"

        print(f"Selected Profile : {profile_id} ({winning_prof.name})")
        print(f"Encryption       : {enc_fmt}")
        print(f"Key Exchange     : {key_est_str}")
        print(f"Security Level   : {winning_prof.security_level.capitalize()}")
        print(f"Benchmark Mode   : {mode_str}")
        print("============================================================\n")

        # Explainability: Combined constraints & Dynamic weights
        cc = selection.combined_constraints
        cp = selection.constraint_pressures
        dw = selection.dynamic_weights

        if cp and dw:
            print("[SELECTOR] Constraint Pressures & Dynamic Weights:")
            print(f"  Time          : pressure = {cp.get('p_time', 0.0):.2f} -> weight = {dw.get('wt', 0.25)*100:.1f}%")
            print(f"  Memory        : pressure = {cp.get('p_memory', 0.0):.2f} -> weight = {dw.get('wm', 0.25)*100:.1f}%")
            print(f"  Communication : pressure = {cp.get('p_communication', 0.0):.2f} -> weight = {dw.get('wc', 0.25)*100:.1f}%")
            print(f"  Energy        : pressure = {cp.get('p_energy', 0.0):.2f} -> weight = {dw.get('we', 0.25)*100:.1f}%")
            print()

        # Show candidate evaluation summary
        print("[SELECTOR] Profile evaluations:")
        for detail in selection.candidate_details:
            status = "✓ FEASIBLE" if detail["compatible"] else "✗ REJECTED"
            reasons = "; ".join(detail["rejection_reasons"]) if detail["rejection_reasons"] else ""
            sender_ms = detail.get("predicted_sender_total_ms")
            recv_ms = detail.get("predicted_receiver_total_ms")
            timing = (
                f"latency: {sender_ms + recv_ms:.2f}ms"
                if sender_ms is not None and recv_ms is not None
                else "no timing"
            )
            score_str = f"score: {detail['final_score']:.4f}" if "final_score" in detail else "unranked"
            line = f"  [{detail['profile_id']}] {status:10s} | {timing} | {score_str}"
            if reasons:
                line += f" | Rejections: {reasons}"
            print(line, flush=True)
        print()
    else:
        if experiment_id is None:
            experiment_id = f"exp-{uuid.uuid4().hex[:8]}"
        print(f"[SENDER] Using manually specified profile: {profile_id}", flush=True)


    session = ProtocolSession(
        experiment_id=experiment_id,
        profile_id=profile_id,
        timeout_seconds=timeout_seconds,
    )

    def _execute_communication() -> ProtocolMessage:
        print("================ SECURE COMMUNICATION ================")
        print(f"[SENDER] Original message: {message}")
        print(f"[SENDER] Message size    : {message_size} bytes")
        print(f"[SENDER] Connecting to receiver at {host}:{port}...")

        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            print(f"[SENDER] Connection established. Experiment ID: {session.experiment_id}")
            print(f"[SENDER] Preparing protocol message frame (profile: {session.profile_id})...")
            hello = ProtocolMessage(
                protocol_version=1,
                message_type=MessageType.HELLO,
                experiment_id=session.experiment_id,
                session_id=session.experiment_id,
                profile_id=session.profile_id,
                sequence_number=session.next_sequence(),
                payload={
                    "message": message,  # user's exact plaintext
                    "sender_id": sender.device_id,
                    "receiver_id": receiver.device_id,
                },
            )
            send_frame_to_socket(sock, hello)
            print(f"[SENDER] Sent encrypted frame payload to {receiver.name}.")
            print("[SENDER] Waiting for receiver acknowledgement...")

            reply = read_frame_from_socket(sock, timeout_seconds=timeout_seconds)
            print(f"[SENDER] Received {reply.message_type.value.upper()} response frame from receiver.")
            if reply.message_type != MessageType.ACK:
                raise ValueError(f"Unexpected response from server: {reply.message_type}")

            # Verify the server echoed the exact message back
            echoed = reply.payload.get("received_message", "")
            recovered_ok = echoed == message
            print(f"[SENDER] Receiver processing status: {reply.payload.get('status', 'unknown')}")
            print(f"[SENDER] Message integrity verification: {'PASSED ✓' if recovered_ok else 'FAILED ✗'}")
            if not recovered_ok:
                print(f"[SENDER] Expected: {message!r}")
                print(f"[SENDER] Received: {echoed!r}")

            print("[SENDER] Message sent and verified successfully.")
            print("================ COMMUNICATION COMPLETE ================\n")

            # Persist observed result to experiments collection
            _record_observed_result(
                experiment_id=experiment_id,
                profile_id=profile_id,
                message_size_bytes=message_size,
                sender_id=sender.device_id,
                receiver_id=receiver.device_id,
                recovered_ok=recovered_ok,
                server_status=reply.payload.get("status", "unknown"),
            )

            return reply

    reply = _execute_communication()

    return reply


def _record_observed_result(
    *,
    experiment_id: str,
    profile_id: str,
    message_size_bytes: int,
    sender_id: str,
    receiver_id: str,
    recovered_ok: bool,
    server_status: str,
) -> None:
    """Append observed (not predicted) results to the experiment document.

    This is written after the communication round-trip, separate from the
    prediction block written by the selector.  The plaintext is never stored.
    """
    try:
        from database.connection import get_database
        db = get_database()
        db["experiments"].update_one(
            {"experiment_id": experiment_id},
            {
                "$set": {
                    "observed_results": {
                        "profile_id_used": profile_id,
                        "message_size_bytes": message_size_bytes,
                        "sender_id": sender_id,
                        "receiver_id": receiver_id,
                        "server_status": server_status,
                        "message_recovered": recovered_ok,
                        "observed_at": datetime.now(IST),
                    },
                    "status": "completed" if recovered_ok else "failed",
                }
            },
            upsert=True,
        )
    except Exception as exc:
        print(f"[client] Warning: could not persist observed results: {exc}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Device A client for adaptive crypto selection and framed TCP protocol"
    )
    parser.add_argument(
        "--host",
        default=get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1",
        help="Hostname or IP address to dial",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(get_env("SERVER_PORT", "5000") or "5000"),
        help="TCP port for the server",
    )
    parser.add_argument("--sender", help="Device ID for Device A (sender)")
    parser.add_argument("--receiver", help="Device ID for Device B (receiver)")
    parser.add_argument("--experiment-id", default=None, help="Correlation ID for the experiment")
    parser.add_argument("--profile-id", default=None, help="Override selected profile ID")
    parser.add_argument(
        "--message",
        default=None,
        help="Plaintext to transmit (omit to be prompted interactively)",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Bypass interactive prompts and use defaults/CLI flags",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        response = run_client(
            host=args.host,
            port=args.port,
            sender_id=args.sender,
            receiver_id=args.receiver,
            experiment_id=args.experiment_id,
            profile_id=args.profile_id,
            message=args.message,
            timeout_seconds=args.timeout,
            non_interactive=args.non_interactive,

        )
        # Print only status — do not echo plaintext in final output
        print(
            f"[client] Done. status={response.payload.get('status')}, "
            f"experiment={response.experiment_id}"
        )
    except (OSError, TimeoutError, ValueError, KeyError) as exc:
        print(f"[client] Error: {exc}", flush=True)
        raise SystemExit(1) from exc
