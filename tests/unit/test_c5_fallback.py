"""Unit tests for Phase 10 / C5 Fallback Profile support.

Verifies:
1. Normal selection still works for valid C1–C4 constraints.
2. C5 is never selected when a valid C1–C4 profile exists (never participates in normal scoring).
3. C5 is selected when C1–C4 all fail constraints.
4. C5 is selected even when security_requirement is high (security relaxed as soft constraint).
5. C5 is rejected if a device cannot actually support AES-128-GCM (hard technical constraint).
6. PSK encryption/decryption round-trip succeeds (AES-128-GCM + PSK engine).
7. Tampered ciphertext or wrong key fails authentication (AuthenticationError).
8. Fallback experiment logging and persistence metadata.
9. Required selector log messages during fallback activation.
10. C5 benchmarkability with standard metrics.
"""

from __future__ import annotations

import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from models.device import Device
from models.crypto_profile import CryptoProfile
from crypto.psk_engine import (
    AuthenticationError,
    PSKError,
    decrypt_with_psk,
    encrypt_with_psk,
    get_psk_key,
)
from selection.compatibility import (
    check_c5_technical_feasibility,
    check_profile_compatibility_detailed,
)
from selection.selector import select_best_profile_full


def _make_device(
    device_id: str,
    name: str = "Test Device",
    cpu_level: str = "medium",
    available_memory_kb: float = 2048.0,
    latency_requirement_ms: float = 2000.0,
    security_requirement: str = "standard",
    supported_algorithms: list[str] | None = None,
    power_source: str = "mains",
    maximum_packet_size_bytes: int = 1500,
) -> Device:
    """Create a Device test fixture."""
    return Device(
        device_id=device_id,
        name=name,
        cpu_level=cpu_level,
        available_memory_kb=available_memory_kb,
        maximum_packet_size_bytes=maximum_packet_size_bytes,
        latency_requirement_ms=latency_requirement_ms,
        security_requirement=security_requirement,
        supported_algorithms=supported_algorithms or ["RSA-2048", "ECDH-P256", "AES-128-GCM"],
        battery_level_percent=100.0,
        power_source=power_source,
        active=True,
    )


def _make_c5_profile() -> CryptoProfile:
    """Create the C5 Fallback profile test fixture."""
    return CryptoProfile(
        profile_id="C5",
        name="Fallback PSK with AES-128-GCM",
        security_level="basic",
        minimum_cpu_level="low",
        active=True,
        key_establishment={
            "family": "PSK",
            "algorithm": "PRE-SHARED-KEY",
            "parameter": "128",
        },
        symmetric_encryption={"algorithm": "AES-GCM", "key_size_bits": 128},
        required_algorithms=["AES-128-GCM"],
    )


def _make_standard_profile(
    profile_id: str,
    family: str = "ECC",
    security_level: str = "standard",
    minimum_cpu_level: str = "low",
) -> CryptoProfile:
    """Create a standard C1-C4 profile test fixture."""
    if family == "RSA":
        key_est = {"family": "RSA", "algorithm": "RSA-OAEP", "parameter": "2048"}
        req_algs = ["RSA-2048", "AES-128-GCM"]
    else:
        key_est = {"family": "ECC", "algorithm": "ECDH", "parameter": "P-256"}
        req_algs = ["ECDH-P256", "AES-128-GCM"]

    return CryptoProfile(
        profile_id=profile_id,
        name=f"Profile {profile_id}",
        security_level=security_level,
        minimum_cpu_level=minimum_cpu_level,
        active=True,
        key_establishment=key_est,
        symmetric_encryption={"algorithm": "AES-GCM", "key_size_bits": 128},
        required_algorithms=req_algs,
    )


def _make_bench_doc(
    profile_id: str,
    device_id: str,
    total_ms: float = 20.0,
    peak_kb: float = 100.0,
    app_bytes: int = 200,
    size_bytes: int = 64,
) -> dict:
    """Create a synthetic benchmark document."""
    return {
        "run_id": f"run-{profile_id}-{device_id}",
        "device_id": device_id,
        "profile_id": profile_id,
        "message_size_bytes": size_bytes,
        "timings_ms": {
            "key_generation": total_ms * 0.5,
            "key_establishment": total_ms * 0.3,
            "encryption": total_ms * 0.15,
            "decryption": total_ms * 0.05,
            "total": total_ms,
        },
        "peak_memory_kb": peak_kb,
        "application_bytes": app_bytes,
        "measurement_source": "local-computer",
        "success": True,
    }


def _mock_bench_repo_for(docs_by_device_and_profile: dict) -> MagicMock:
    """Build a BenchmarkRepository mock from a mapping."""
    mock = MagicMock()

    def find_runs(device_id=None, profile_id=None, message_size_bytes=None,
                  measurement_source=None, success_only=True):
        results = []
        for (did, pid), docs in docs_by_device_and_profile.items():
            if device_id and did != device_id:
                continue
            if profile_id and pid != profile_id:
                continue
            for doc in docs:
                if message_size_bytes is not None and doc["message_size_bytes"] != message_size_bytes:
                    continue
                results.append(doc)
        return results

    mock.find_runs.side_effect = find_runs
    return mock


def _mock_profile_repo(profiles: list[CryptoProfile]) -> MagicMock:
    """Build a ProfileRepository mock containing the given profiles."""
    mock = MagicMock()
    mock.list_enabled.return_value = profiles

    def get_by_id(pid: str):
        for p in profiles:
            if p.profile_id == pid:
                return p
        raise KeyError(f"Profile '{pid}' not found")

    mock.get_by_id.side_effect = get_by_id
    return mock


class TestC5FallbackSuite(unittest.TestCase):
    """Comprehensive unit test suite for C5 Fallback Profile support."""

    def setUp(self) -> None:
        self.c1 = _make_standard_profile("C1", family="RSA", security_level="standard", minimum_cpu_level="medium")
        self.c3 = _make_standard_profile("C3", family="ECC", security_level="standard", minimum_cpu_level="low")
        self.c4 = _make_standard_profile("C4", family="ECC", security_level="high", minimum_cpu_level="medium")
        self.c5 = _make_c5_profile()

    # 1. Normal selection still works for valid C1–C4 constraints
    def test_normal_selection_still_works_for_valid_c1_c4(self) -> None:
        sender = _make_device("sender", cpu_level="medium")
        receiver = _make_device("receiver", cpu_level="medium")
        repo = _mock_bench_repo_for({
            ("sender", "C3"): [_make_bench_doc("C3", "sender", total_ms=5.0)],
            ("receiver", "C3"): [_make_bench_doc("C3", "receiver", total_ms=5.0)],
        })
        prof_repo = _mock_profile_repo([self.c1, self.c3, self.c5])
        db = MagicMock()

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=prof_repo,
            benchmark_repo=repo,
            db=db,
        )

        self.assertEqual(result.winning_profile.profile_id, "C3")
        self.assertEqual(result.selection_mode, "normal")
        self.assertFalse(result.fallback_used)
        self.assertIsNone(result.fallback_reason)
        self.assertEqual(result.relaxed_constraints, [])

    # 2. C5 is never selected when a valid C1–C4 profile exists
    def test_c5_never_selected_when_valid_standard_profile_exists(self) -> None:
        """Even if C5 is in the repo and has lower simulated cost, C1-C4 must take precedence."""
        sender = _make_device("sender", cpu_level="low")
        receiver = _make_device("receiver", cpu_level="low")
        repo = _mock_bench_repo_for({
            ("sender", "C3"): [_make_bench_doc("C3", "sender", total_ms=10.0, peak_kb=50.0)],
            ("receiver", "C3"): [_make_bench_doc("C3", "receiver", total_ms=10.0, peak_kb=50.0)],
            ("sender", "C5"): [_make_bench_doc("C5", "sender", total_ms=0.1, peak_kb=1.0)],
            ("receiver", "C5"): [_make_bench_doc("C5", "receiver", total_ms=0.1, peak_kb=1.0)],
        })
        prof_repo = _mock_profile_repo([self.c3, self.c5])
        db = MagicMock()

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=prof_repo,
            benchmark_repo=repo,
            db=db,
        )

        # C3 must win normal scoring; C5 must never participate in normal scoring
        self.assertEqual(result.winning_profile.profile_id, "C3")
        self.assertEqual(result.selection_mode, "normal")
        self.assertFalse(result.fallback_used)
        # Check that C5 was not even in candidate_details during normal run
        cand_ids = [d["profile_id"] for d in result.candidate_details]
        self.assertNotIn("C5", cand_ids)

    # 3. C5 is selected when C1–C4 all fail constraints
    def test_c5_selected_when_all_standard_profiles_fail(self) -> None:
        """When memory or cpu constraints fail for all standard profiles, C5 fallback activates."""
        # Sender has very low memory (50 KB), rejecting C1 (needs 100 KB) and C4 (needs 120 KB)
        sender = _make_device("sender", cpu_level="low", available_memory_kb=50.0)
        receiver = _make_device("receiver", cpu_level="low", available_memory_kb=50.0)
        repo = _mock_bench_repo_for({
            ("sender", "C1"): [_make_bench_doc("C1", "sender", peak_kb=100.0)],
            ("receiver", "C1"): [_make_bench_doc("C1", "receiver", peak_kb=100.0)],
            ("sender", "C4"): [_make_bench_doc("C4", "sender", peak_kb=120.0)],
            ("receiver", "C4"): [_make_bench_doc("C4", "receiver", peak_kb=120.0)],
        })
        prof_repo = _mock_profile_repo([self.c1, self.c4, self.c5])
        db = MagicMock()

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=prof_repo,
            benchmark_repo=repo,
            db=db,
        )

        self.assertEqual(result.winning_profile.profile_id, "C5")
        self.assertEqual(result.selection_mode, "fallback")
        self.assertTrue(result.fallback_used)
        self.assertEqual(result.fallback_reason, "no_profile_satisfies_constraints")
        self.assertIn("security_requirement", result.relaxed_constraints)

    # 4. C5 is selected even when security_requirement is high
    def test_c5_selected_when_security_requirement_is_high(self) -> None:
        """Devices requiring 'high' security accept C5 ('basic') under fallback."""
        sender = _make_device("sender", security_requirement="high", cpu_level="low")
        receiver = _make_device("receiver", security_requirement="high", cpu_level="low")
        # Standard profile C1 has security_level="standard" (fails high)
        # Standard profile C4 has security_level="high", but minimum_cpu_level="medium" (fails low cpu)
        repo = _mock_bench_repo_for({
            ("sender", "C1"): [_make_bench_doc("C1", "sender")],
            ("receiver", "C1"): [_make_bench_doc("C1", "receiver")],
            ("sender", "C4"): [_make_bench_doc("C4", "sender")],
            ("receiver", "C4"): [_make_bench_doc("C4", "receiver")],
        })
        prof_repo = _mock_profile_repo([self.c1, self.c4, self.c5])
        db = MagicMock()

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=prof_repo,
            benchmark_repo=repo,
            db=db,
        )

        self.assertEqual(result.winning_profile.profile_id, "C5")
        self.assertEqual(result.selection_mode, "fallback")
        self.assertTrue(result.fallback_used)
        self.assertIn("security_requirement", result.relaxed_constraints)

    # 5. C5 is rejected if a device cannot actually support AES-128-GCM
    def test_c5_rejected_if_device_lacks_aes_128_gcm(self) -> None:
        """Hard technical constraint: AES-128-GCM must be supported by both devices."""
        sender = _make_device("sender", supported_algorithms=["CHACHA20-POLY1305"])
        receiver = _make_device("receiver", supported_algorithms=["AES-128-GCM"])
        prof_repo = _mock_profile_repo([self.c1, self.c5])
        repo = _mock_bench_repo_for({})
        db = MagicMock()

        with self.assertRaises(ValueError) as ctx:
            select_best_profile_full(
                sender=sender,
                receiver=receiver,
                message_size_bytes=64,
                profile_repo=prof_repo,
                benchmark_repo=repo,
                db=db,
            )

        err_msg = str(ctx.exception)
        self.assertIn("fallback_profile_not_feasible", err_msg)
        self.assertIn("AES-128-GCM", err_msg)

    # 6. PSK encryption/decryption round-trip succeeds
    def test_psk_encryption_decryption_round_trip(self) -> None:
        """Test encryption and decryption with default PSK and custom keys."""
        test_messages = [
            "Hello, IoT Security!",
            "Temperature: 24.5C, Humidity: 60%",
            "",  # empty message
            "A" * 5000,  # large payload
            "Unicode test: 🔒 🛡️ 🚀",
        ]

        for msg in test_messages:
            ciphertext, nonce = encrypt_with_psk(msg)
            self.assertIsInstance(ciphertext, bytes)
            self.assertIsInstance(nonce, bytes)
            self.assertEqual(len(nonce), 12)
            # Ciphertext should include 16-byte authentication tag
            self.assertEqual(len(ciphertext), len(msg.encode("utf-8")) + 16)

            decrypted = decrypt_with_psk(ciphertext, nonce)
            self.assertEqual(decrypted, msg)

    # 7. Tampered ciphertext or wrong key fails authentication
    def test_tampered_ciphertext_or_wrong_key_fails_authentication(self) -> None:
        msg = "Sensitive command: open_valve"
        ciphertext, nonce = encrypt_with_psk(msg)

        # Tampered ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0x01
        with self.assertRaises(AuthenticationError):
            decrypt_with_psk(bytes(tampered_ct), nonce)

        # Tampered nonce
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 0x01
        with self.assertRaises(AuthenticationError):
            decrypt_with_psk(ciphertext, bytes(tampered_nonce))

        # Wrong key
        wrong_key = b"1234567890123456"
        with self.assertRaises(AuthenticationError):
            decrypt_with_psk(ciphertext, nonce, key=wrong_key)

    # 8. Logging output contains required selector lines
    def test_selector_fallback_logging_output(self) -> None:
        sender = _make_device("sender", security_requirement="high", cpu_level="low")
        receiver = _make_device("receiver", security_requirement="high", cpu_level="low")
        repo = _mock_bench_repo_for({
            ("sender", "C1"): [_make_bench_doc("C1", "sender")],
            ("receiver", "C1"): [_make_bench_doc("C1", "receiver")],
        })
        prof_repo = _mock_profile_repo([self.c1, self.c5])
        db = MagicMock()

        captured = io.StringIO()
        with patch("sys.stdout", captured):
            select_best_profile_full(
                sender=sender,
                receiver=receiver,
                message_size_bytes=64,
                profile_repo=prof_repo,
                benchmark_repo=repo,
                db=db,
            )

        output = captured.getvalue()
        self.assertIn("[selector] No standard crypto profile satisfies all constraints.", output)
        self.assertIn("[selector] Activating fallback profile C5.", output)
        self.assertIn("[selector] WARNING: Security requirement has been relaxed.", output)
        self.assertIn("[selector] Selected: C5 - Fallback PSK with AES-128-GCM", output)
        self.assertIn("[selector] Selection mode: FALLBACK", output)

    # 9. Experiment persistence verifies fallback fields in MongoDB doc
    def test_fallback_experiment_persistence_fields(self) -> None:
        sender = _make_device("sender", security_requirement="high", cpu_level="low")
        receiver = _make_device("receiver", security_requirement="high", cpu_level="low")
        repo = _mock_bench_repo_for({
            ("sender", "C1"): [_make_bench_doc("C1", "sender")],
            ("receiver", "C1"): [_make_bench_doc("C1", "receiver")],
        })
        prof_repo = _mock_profile_repo([self.c1, self.c5])
        db = MagicMock()

        select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=prof_repo,
            benchmark_repo=repo,
            db=db,
        )

        db["experiments"].update_one.assert_called()
        call_args = db["experiments"].update_one.call_args[0]
        update_doc = call_args[1]["$set"]
        self.assertEqual(update_doc["selected_profile"], "C5")
        self.assertEqual(update_doc["selection_mode"], "fallback")
        self.assertTrue(update_doc["fallback_used"])
        self.assertEqual(update_doc["fallback_reason"], "no_profile_satisfies_constraints")
        self.assertEqual(update_doc["relaxed_constraints"], ["security_requirement"])

    # 10. End-to-end TCP communication with C5 PSK encryption/decryption
    def test_c5_tcp_smoke_test_with_psk_round_trip(self) -> None:
        """C5 PSK profile: HELLO with encrypted ciphertext -> Server decrypts -> ACK with exact recovered message."""
        import socket
        import threading
        from communication.protocol import MessageType
        from client import run_client
        from server import handle_client

        host = "127.0.0.1"
        test_msg = "IoT Telemetry Data: Temp=21.8C 🔒"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((host, 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            def serve_once() -> None:
                conn, _ = listener.accept()
                with conn:
                    handle_client(conn)

            t = threading.Thread(target=serve_once, daemon=True)
            t.start()
            reply = run_client(
                host=host,
                port=port,
                experiment_id="smoke-c5-fallback",
                profile_id="C5",
                message=test_msg,
                non_interactive=True,
            )
            t.join(timeout=5)

        self.assertEqual(reply.message_type, MessageType.ACK)
        self.assertEqual(reply.payload["status"], "accepted")
        self.assertEqual(reply.payload["received_message"], test_msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
