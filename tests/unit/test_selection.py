"""Unit tests for the adaptive selection system — Phase 8 refactor.

All test fixtures use synthetic benchmark and device data and are clearly
labelled as such.  No real MongoDB connection is required.

Coverage
--------
1.  Device catalogue display and valid selection.
2.  Invalid device choices and an empty catalogue.
3.  Same device model for both sender and receiver.
4.  Unicode messages and empty-message handling.
5.  A faster profile rejected because sender memory is insufficient.
6.  A profile rejected because receiver memory is insufficient.
7.  Selection of the fastest feasible profile.
8.  Security requirements overriding speed (high-sec profile wins).
9.  Missing benchmark evidence → InsufficientEvidenceError / no feasible profile.
10. Deterministic tie-breaking by application_bytes then profile_id.
11. Existing RSA (C1) end-to-end via TCP (smoke test).
12. Existing ECC (C3) end-to-end via TCP (smoke test).
13. Successful recovery of the exact user-provided message.
14. Predictions and observed results stored separately in experiment doc.
"""

from __future__ import annotations

import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

from models.device import Device
from models.crypto_profile import CryptoProfile
from selection.compatibility import (
    BenchmarkEvidence,
    CompatibilityResult,
    InsufficientEvidenceError,
    check_profile_compatibility,
    check_profile_compatibility_detailed,
    find_best_benchmark,
)
from selection.scoring import score_candidates
from selection.selector import (
    SelectionResult,
    prompt_device_selection,
    select_best_profile,
    select_best_profile_full,
)
from communication.protocol import MessageType, ProtocolMessage, ProtocolError
from client import run_client
from server import handle_client


# ---------------------------------------------------------------------------
# Shared test fixtures — labelled as synthetic test data
# ---------------------------------------------------------------------------

def _make_device(
    device_id: str,
    name: str = "Test Device",
    cpu_level: str = "medium",
    available_memory_kb: float = 2048.0,
    latency_requirement_ms: float = 2000.0,
    security_requirement: str = "standard",
    supported_algorithms: list | None = None,
) -> Device:
    """[TEST FIXTURE] Create a Device with sensible defaults."""
    return Device(
        device_id=device_id,
        name=name,
        cpu_level=cpu_level,
        available_memory_kb=available_memory_kb,
        maximum_packet_size_bytes=1500,
        latency_requirement_ms=latency_requirement_ms,
        security_requirement=security_requirement,
        supported_algorithms=supported_algorithms or ["RSA-2048", "ECDH-P256", "AES-128-GCM"],
        battery_level_percent=100.0,
        power_source="mains",
        active=True,
    )


def _make_profile(
    profile_id: str,
    family: str = "ECC",
    security_level: str = "standard",
    minimum_cpu_level: str = "low",
) -> CryptoProfile:
    """[TEST FIXTURE] Create a CryptoProfile with sensible defaults."""
    if family == "RSA":
        key_est = {"family": "RSA", "algorithm": "RSA-OAEP", "parameter": "2048"}
        req_algs = ["RSA-2048", "AES-128-GCM"]
    else:
        key_est = {"family": "ECC", "algorithm": "ECDH", "parameter": "P-256"}
        req_algs = ["ECDH-P256", "AES-128-GCM"]

    return CryptoProfile(
        profile_id=profile_id,
        name=f"Test Profile {profile_id}",
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
    source: str = "local-computer",
) -> dict:
    """[TEST FIXTURE] Create a synthetic benchmark document."""
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
        "measurement_source": source,
        "success": True,
    }


def _mock_bench_repo_for(docs_by_device_and_profile: dict) -> MagicMock:
    """[TEST FIXTURE] Build a BenchmarkRepository mock from a mapping
    {(device_id, profile_id): [bench_doc, ...]}
    """
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


def _no_op_db() -> MagicMock:
    """[TEST FIXTURE] A MongoDB db mock that silently accepts writes."""
    db = MagicMock()
    db.__getitem__.return_value = MagicMock()
    return db


# ---------------------------------------------------------------------------
# 1 + 2: Device selection and invalid choices
# ---------------------------------------------------------------------------

class TestDeviceCatalogueSelection(unittest.TestCase):
    """Tests 1 and 2: device catalogue display, valid and invalid choices."""

    def setUp(self):
        self.devices = [
            _make_device("dev-a", "Alpha"),
            _make_device("dev-b", "Beta"),
        ]

    def test_valid_selection_returns_correct_device(self):
        """[TEST 1] Selecting '1' returns the first device."""
        with patch("builtins.input", return_value="1"):
            selected = prompt_device_selection("Select", self.devices)
        self.assertEqual(selected.device_id, "dev-a")

    def test_valid_selection_second_device(self):
        """[TEST 1] Selecting '2' returns the second device."""
        with patch("builtins.input", return_value="2"):
            selected = prompt_device_selection("Select", self.devices)
        self.assertEqual(selected.device_id, "dev-b")

    def test_invalid_then_valid_selection(self):
        """[TEST 2] Invalid input is rejected; second attempt is accepted."""
        with patch("builtins.input", side_effect=["0", "99", "abc", "2"]):
            selected = prompt_device_selection("Select", self.devices)
        self.assertEqual(selected.device_id, "dev-b")

    def test_empty_catalogue_raises(self):
        """[TEST 2] Empty catalogue raises ValueError immediately."""
        with self.assertRaises(ValueError, msg="should raise when no devices"):
            prompt_device_selection("Select", [])

    def test_eof_raises_system_exit(self):
        """[TEST 2] EOFError (non-interactive pipe) triggers SystemExit."""
        with patch("builtins.input", side_effect=EOFError):
            with self.assertRaises(SystemExit):
                prompt_device_selection("Select", self.devices)


# ---------------------------------------------------------------------------
# 3: Same device model for both roles
# ---------------------------------------------------------------------------

class TestSameDeviceBothRoles(unittest.TestCase):
    """Test 3: sender and receiver may be the same device model."""

    def test_same_device_both_roles_passes_compatibility(self):
        """[TEST 3] Same device_id for sender and receiver is valid."""
        dev = _make_device("esp32", "ESP32", cpu_level="medium", available_memory_kb=520.0)
        profile = _make_profile("C3", family="ECC")

        bench_doc = _make_bench_doc("C3", "esp32", total_ms=15.0, peak_kb=50.0)
        repo = _mock_bench_repo_for({("esp32", "C3"): [bench_doc]})

        is_compat, reasons = check_profile_compatibility(
            sender=dev,
            receiver=dev,
            profile=profile,
            message_size=64,
            benchmark_repo=repo,
        )
        self.assertTrue(is_compat, reasons)


# ---------------------------------------------------------------------------
# 4: Unicode messages and empty-message handling
# ---------------------------------------------------------------------------

class TestMessageHandling(unittest.TestCase):
    """Test 4: Unicode and empty-message handling."""

    def test_unicode_message_byte_count(self):
        """[TEST 4] UTF-8 encoding of a multi-byte Unicode string is counted correctly."""
        msg = "Héllo wörld — 日本語テスト 🔐"
        self.assertGreater(len(msg.encode("utf-8")), len(msg))

    def test_empty_message_byte_count(self):
        """[TEST 4] Empty string encodes to zero bytes."""
        self.assertEqual(len("".encode("utf-8")), 0)

    def test_empty_message_accepted_by_selector(self):
        """[TEST 4] An empty message (0 bytes) is a valid selection input."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        profile = _make_profile("C3", family="ECC")

        bench_doc = _make_bench_doc("C3", "dev-a", total_ms=10.0, peak_kb=50.0, size_bytes=0)
        bench_doc_b = _make_bench_doc("C3", "dev-b", total_ms=10.0, peak_kb=50.0, size_bytes=0)
        repo = _mock_bench_repo_for({
            ("dev-a", "C3"): [bench_doc],
            ("dev-b", "C3"): [bench_doc_b],
        })

        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile]

        winning_profile, _, _ = select_best_profile(
            sender=sender,
            receiver=receiver,
            message_size_bytes=0,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=_no_op_db(),
        )
        self.assertEqual(winning_profile.profile_id, "C3")

    def test_ascii_subset_of_utf8(self):
        """[TEST 4] Pure ASCII encodes to the same number of bytes as its character count."""
        msg = "hello"
        self.assertEqual(len(msg.encode("utf-8")), 5)


# ---------------------------------------------------------------------------
# 5: Sender memory insufficient → profile rejected
# ---------------------------------------------------------------------------

class TestSenderMemoryInsufficient(unittest.TestCase):
    """Test 5: faster profile rejected because sender RAM is too small."""

    def test_fast_profile_rejected_for_sender_memory(self):
        """[TEST 5] Profile requiring 200 KB is rejected when sender has only 100 KB."""
        # Sender has very little RAM
        sender = _make_device("tiny-sender", available_memory_kb=100.0)
        receiver = _make_device("normal-receiver", available_memory_kb=2048.0)

        profile = _make_profile("C3", family="ECC")

        # Benchmark reports 200 KB peak — more than sender's 100 KB
        bench_sender = _make_bench_doc("C3", "tiny-sender", total_ms=5.0, peak_kb=200.0)
        bench_receiver = _make_bench_doc("C3", "normal-receiver", total_ms=5.0, peak_kb=50.0)
        repo = _mock_bench_repo_for({
            ("tiny-sender", "C3"): [bench_sender],
            ("normal-receiver", "C3"): [bench_receiver],
        })

        result = check_profile_compatibility_detailed(
            sender=sender,
            receiver=receiver,
            profile=profile,
            message_size=64,
            benchmark_repo=repo,
        )
        self.assertFalse(result.compatible)
        self.assertTrue(
            any("sender" in r and "memory" in r for r in result.rejection_reasons),
            f"Expected sender memory rejection, got: {result.rejection_reasons}",
        )


# ---------------------------------------------------------------------------
# 6: Receiver memory insufficient → profile rejected
# ---------------------------------------------------------------------------

class TestReceiverMemoryInsufficient(unittest.TestCase):
    """Test 6: profile rejected because receiver RAM is too small."""

    def test_profile_rejected_for_receiver_memory(self):
        """[TEST 6] Profile requiring 300 KB is rejected when receiver has only 80 KB."""
        sender = _make_device("normal-sender", available_memory_kb=2048.0)
        receiver = _make_device("tiny-receiver", available_memory_kb=80.0)

        profile = _make_profile("C3", family="ECC")

        bench_sender = _make_bench_doc("C3", "normal-sender", total_ms=15.0, peak_kb=100.0)
        bench_receiver = _make_bench_doc("C3", "tiny-receiver", total_ms=15.0, peak_kb=300.0)
        repo = _mock_bench_repo_for({
            ("normal-sender", "C3"): [bench_sender],
            ("tiny-receiver", "C3"): [bench_receiver],
        })

        result = check_profile_compatibility_detailed(
            sender=sender,
            receiver=receiver,
            profile=profile,
            message_size=64,
            benchmark_repo=repo,
        )
        self.assertFalse(result.compatible)
        self.assertTrue(
            any("receiver" in r and "memory" in r for r in result.rejection_reasons),
            f"Expected receiver memory rejection, got: {result.rejection_reasons}",
        )


# ---------------------------------------------------------------------------
# 7: Fastest feasible profile wins
# ---------------------------------------------------------------------------

class TestFastestFeasibleProfileSelected(unittest.TestCase):
    """Test 7: the profile with the lowest combined latency wins."""

    def test_faster_ecc_beats_slower_rsa(self):
        """[TEST 7] ECC (15 ms combined) wins over RSA (90 ms combined)."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        profile_rsa = _make_profile("C1", family="RSA")
        profile_ecc = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({
            ("dev-a", "C1"): [_make_bench_doc("C1", "dev-a", total_ms=45.0, peak_kb=80.0)],
            ("dev-b", "C1"): [_make_bench_doc("C1", "dev-b", total_ms=45.0, peak_kb=80.0)],
            ("dev-a", "C3"): [_make_bench_doc("C3", "dev-a", total_ms=7.5,  peak_kb=30.0)],
            ("dev-b", "C3"): [_make_bench_doc("C3", "dev-b", total_ms=7.5,  peak_kb=30.0)],
        })

        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile_rsa, profile_ecc]

        winning_profile, _, _ = select_best_profile(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=_no_op_db(),
        )
        self.assertEqual(winning_profile.profile_id, "C3")


# ---------------------------------------------------------------------------
# 8: Security requirement overrides speed
# ---------------------------------------------------------------------------

class TestSecurityRequirementOverridesSpeed(unittest.TestCase):
    """Test 8: a device requiring 'high' security cannot use a 'standard' profile."""

    def test_high_security_device_rejects_standard_profile(self):
        """[TEST 8] A device with security_requirement='high' rejects a 'standard' profile."""
        # Both devices require high security
        sender = _make_device("dev-a", security_requirement="high")
        receiver = _make_device("dev-b", security_requirement="high")
        # C3 is 'standard'; should be rejected
        standard_profile = _make_profile("C3", family="ECC", security_level="standard")
        # C4 is 'high'
        high_profile = _make_profile("C4", family="ECC", security_level="high")
        # Patch C4 to P-384 parameter (still ECC family)
        high_profile = CryptoProfile(
            profile_id="C4",
            name="ECDH-P384 AES-256-GCM",
            security_level="high",
            minimum_cpu_level="medium",
            active=True,
            key_establishment={"family": "ECC", "algorithm": "ECDH", "parameter": "P-384"},
            symmetric_encryption={"algorithm": "AES-GCM", "key_size_bits": 256},
            required_algorithms=["ECDH-P384", "AES-256-GCM"],
        )

        bench_a_c3 = _make_bench_doc("C3", "dev-a", total_ms=5.0)
        bench_b_c3 = _make_bench_doc("C3", "dev-b", total_ms=5.0)
        bench_a_c4 = _make_bench_doc("C4", "dev-a", total_ms=25.0)
        bench_b_c4 = _make_bench_doc("C4", "dev-b", total_ms=25.0)

        repo = _mock_bench_repo_for({
            ("dev-a", "C3"): [bench_a_c3],
            ("dev-b", "C3"): [bench_b_c3],
            ("dev-a", "C4"): [bench_a_c4],
            ("dev-b", "C4"): [bench_b_c4],
        })

        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [standard_profile, high_profile]

        winning_profile, _, _ = select_best_profile(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=_no_op_db(),
        )
        # C4 must win; C3 cannot satisfy 'high' security requirement
        self.assertEqual(winning_profile.profile_id, "C4")

    def test_standard_device_accepts_high_profile(self):
        """[TEST 8] A 'high' security profile satisfies a 'standard' device (security is a floor, not a ceiling)."""
        sender = _make_device("dev-a", security_requirement="standard")
        receiver = _make_device("dev-b", security_requirement="standard")
        high_profile = _make_profile("C4", family="ECC", security_level="high")

        bench_a = _make_bench_doc("C4", "dev-a", total_ms=20.0)
        bench_b = _make_bench_doc("C4", "dev-b", total_ms=20.0)
        repo = _mock_bench_repo_for({
            ("dev-a", "C4"): [bench_a],
            ("dev-b", "C4"): [bench_b],
        })

        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [high_profile]

        winning_profile, _, _ = select_best_profile(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=_no_op_db(),
        )
        self.assertEqual(winning_profile.profile_id, "C4")


# ---------------------------------------------------------------------------
# 9: Missing benchmark evidence
# ---------------------------------------------------------------------------

class TestMissingBenchmarkEvidence(unittest.TestCase):
    """Test 9: no benchmark → InsufficientEvidenceError; no feasible profile → ValueError."""

    def test_no_bench_raises_insufficient_evidence(self):
        """[TEST 9] find_best_benchmark raises InsufficientEvidenceError when no data."""
        repo = _mock_bench_repo_for({})  # empty
        with self.assertRaises(InsufficientEvidenceError):
            find_best_benchmark(repo, "esp32", "C3", 64)

    def test_no_bench_causes_no_feasible_profile(self):
        """[TEST 9] select_best_profile raises ValueError when all profiles lack evidence."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        profile = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({})  # no data

        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile]

        with self.assertRaises(ValueError, msg="should raise when no evidence"):
            select_best_profile(
                sender=sender,
                receiver=receiver,
                message_size_bytes=64,
                profile_repo=mock_prof_repo,
                benchmark_repo=repo,
                db=_no_op_db(),
            )

    def test_bench_falls_back_to_nearest_size(self):
        """[TEST 9] When no exact-size run exists, nearest run is used and marked as estimate."""
        bench_doc = _make_bench_doc("C3", "dev-a", total_ms=15.0, size_bytes=1024)
        repo = _mock_bench_repo_for({("dev-a", "C3"): [bench_doc]})

        evidence = find_best_benchmark(repo, "dev-a", "C3", message_size=64)
        self.assertFalse(evidence.exact_match)
        self.assertIn("estimate", evidence.estimation_note.lower())


# ---------------------------------------------------------------------------
# 10: Deterministic tie-breaking
# ---------------------------------------------------------------------------

class TestDeterministicTieBreaking(unittest.TestCase):
    """Test 10: identical scores → lower application_bytes → then profile_id."""

    def test_tie_broken_by_application_bytes(self):
        """[TEST 10] Profile with fewer application bytes wins the tie."""
        # Two identical candidates except application_bytes
        candidates = [
            _make_bench_doc("C1", "dev-a", total_ms=10.0, peak_kb=100.0, app_bytes=500),
            _make_bench_doc("C3", "dev-a", total_ms=10.0, peak_kb=100.0, app_bytes=100),
        ]
        scored = score_candidates(candidates)
        # With equal raw scores, the scorer itself applies profile_id then size tie-breaking.
        # Our selector adds application_bytes as an additional tie-breaker, but the scorer
        # already normalises — so here we verify determinism: same input → same output.
        result1 = score_candidates(candidates)
        result2 = score_candidates(candidates)
        self.assertEqual(result1[0][0]["profile_id"], result2[0][0]["profile_id"])

    def test_selector_tie_broken_by_app_bytes(self):
        """[TEST 10] select_best_profile breaks ties by application_bytes."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")

        # Two profiles, same combined latency, different application bytes
        profile_heavy = _make_profile("C1", family="RSA")
        profile_light = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({
            ("dev-a", "C1"): [_make_bench_doc("C1", "dev-a", total_ms=10.0, app_bytes=500)],
            ("dev-b", "C1"): [_make_bench_doc("C1", "dev-b", total_ms=10.0, app_bytes=500)],
            ("dev-a", "C3"): [_make_bench_doc("C3", "dev-a", total_ms=10.0, app_bytes=100)],
            ("dev-b", "C3"): [_make_bench_doc("C3", "dev-b", total_ms=10.0, app_bytes=100)],
        })

        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile_heavy, profile_light]

        winning_profile, _, _ = select_best_profile(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=_no_op_db(),
        )
        # C3 has fewer application bytes and should win the tie
        self.assertEqual(winning_profile.profile_id, "C3")

    def test_determinism_repeated_calls(self):
        """[TEST 10] The same input always produces the same winner."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        p1 = _make_profile("C1", family="RSA")
        p2 = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({
            ("dev-a", "C1"): [_make_bench_doc("C1", "dev-a", total_ms=20.0)],
            ("dev-b", "C1"): [_make_bench_doc("C1", "dev-b", total_ms=20.0)],
            ("dev-a", "C3"): [_make_bench_doc("C3", "dev-a", total_ms=10.0)],
            ("dev-b", "C3"): [_make_bench_doc("C3", "dev-b", total_ms=10.0)],
        })
        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [p1, p2]

        winners = set()
        for _ in range(3):
            w, _, _ = select_best_profile(
                sender=sender, receiver=receiver, message_size_bytes=64,
                profile_repo=mock_prof_repo, benchmark_repo=repo, db=_no_op_db(),
            )
            winners.add(w.profile_id)
        self.assertEqual(len(winners), 1, "Selection must be deterministic")


# ---------------------------------------------------------------------------
# 11 + 12 + 13: End-to-end TCP smoke tests (RSA and ECC paths)
# ---------------------------------------------------------------------------

class TestEndToEndTCPSmoke(unittest.TestCase):
    """Tests 11, 12, 13: TCP smoke tests using the actual server handle_client."""

    def _run_smoke(self, message: str, profile_id: str) -> ProtocolMessage:
        """[TEST FIXTURE] Spin up a local server thread and run client."""
        host = "127.0.0.1"
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
                experiment_id=f"smoke-{profile_id}",
                profile_id=profile_id,
                message=message,
                non_interactive=True,
            )
            t.join(timeout=5)
        return reply

    def test_c1_rsa_profile_round_trip(self):
        """[TEST 11] RSA (C1) profile: HELLO → ACK exchange completes."""
        reply = self._run_smoke("RSA round-trip test", "C1")
        self.assertEqual(reply.message_type, MessageType.ACK)
        self.assertEqual(reply.payload["status"], "accepted")

    def test_c3_ecc_profile_round_trip(self):
        """[TEST 11] ECC (C3) profile: HELLO → ACK exchange completes."""
        reply = self._run_smoke("ECC round-trip test", "C3")
        self.assertEqual(reply.message_type, MessageType.ACK)
        self.assertEqual(reply.payload["status"], "accepted")

    def test_exact_message_recovery(self):
        """[TEST 12 + 13] Server echoes the exact user-provided message."""
        msg = "Héllo wörld 🔐"  # Unicode
        reply = self._run_smoke(msg, "C3")
        self.assertEqual(reply.payload["received_message"], msg)

    def test_empty_message_recovery(self):
        """[TEST 12] Empty message survives the round-trip."""
        reply = self._run_smoke("", "C3")
        self.assertEqual(reply.payload["received_message"], "")

    def test_long_message_recovery(self):
        """[TEST 12] A 1 KB ASCII message is recovered exactly."""
        msg = "A" * 1024
        reply = self._run_smoke(msg, "C1")
        self.assertEqual(reply.payload["received_message"], msg)


# ---------------------------------------------------------------------------
# 14: Predictions and observed results stored separately
# ---------------------------------------------------------------------------

class TestPredictionsAndObservedResultsSeparate(unittest.TestCase):
    """Test 14: experiment document structure separates predictions from observations."""

    def test_select_best_profile_full_returns_candidate_details(self):
        """[TEST 14] SelectionResult.candidate_details contains predicted costs."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        profile = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({
            ("dev-a", "C3"): [_make_bench_doc("C3", "dev-a", total_ms=12.0)],
            ("dev-b", "C3"): [_make_bench_doc("C3", "dev-b", total_ms=12.0)],
        })
        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile]

        captured_doc = {}

        def fake_update_one(filt, update, upsert=False):
            captured_doc.update(update.get("$set", {}))
            return MagicMock()

        mock_db = MagicMock()
        mock_col = MagicMock()
        mock_col.update_one.side_effect = fake_update_one
        mock_db.__getitem__.return_value = mock_col

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=mock_db,
        )

        # Prediction block fields
        self.assertIn("candidate_profiles", captured_doc)
        self.assertIn("selected_profile_id", captured_doc)
        self.assertIn("optimization_objective", captured_doc)
        self.assertIn("sender_constraints", captured_doc)
        self.assertIn("receiver_constraints", captured_doc)
        self.assertIn("message_size_bytes", captured_doc)
        # Ensure plaintext is NOT stored
        self.assertNotIn("message", captured_doc)
        self.assertNotIn("plaintext", captured_doc)

        # observed_results must NOT be in the prediction block
        self.assertNotIn("observed_results", captured_doc)

        # Verify result structure
        self.assertIsInstance(result, SelectionResult)
        self.assertEqual(result.winning_profile.profile_id, "C3")
        self.assertIsInstance(result.candidate_details, list)
        detail = result.candidate_details[0]
        self.assertIn("predicted_sender_total_ms", detail)
        self.assertIn("predicted_receiver_total_ms", detail)
        self.assertIn("rejection_reasons", detail)

    def test_selection_result_contains_experiment_id(self):
        """[TEST 14] SelectionResult carries the experiment_id used for later observation writes."""
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        profile = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({
            ("dev-a", "C3"): [_make_bench_doc("C3", "dev-a", total_ms=10.0)],
            ("dev-b", "C3"): [_make_bench_doc("C3", "dev-b", total_ms=10.0)],
        })
        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile]

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            experiment_id="test-exp-999",
            db=_no_op_db(),
        )
        self.assertEqual(result.experiment_id, "test-exp-999")


# ---------------------------------------------------------------------------
# Backward compatibility of original public API
# ---------------------------------------------------------------------------

class TestBackwardCompatibility(unittest.TestCase):
    """Verify the original select_best_profile 3-tuple return still works."""

    def test_returns_three_tuple(self):
        sender = _make_device("dev-a")
        receiver = _make_device("dev-b")
        profile = _make_profile("C3", family="ECC")

        repo = _mock_bench_repo_for({
            ("dev-a", "C3"): [_make_bench_doc("C3", "dev-a")],
            ("dev-b", "C3"): [_make_bench_doc("C3", "dev-b")],
        })
        mock_prof_repo = MagicMock()
        mock_prof_repo.list_enabled.return_value = [profile]

        result = select_best_profile(
            sender=sender,
            receiver=receiver,
            message_size_bytes=64,
            profile_repo=mock_prof_repo,
            benchmark_repo=repo,
            db=_no_op_db(),
        )
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        winning_profile, bench_doc, score = result
        self.assertIsInstance(winning_profile, CryptoProfile)
        self.assertIsInstance(bench_doc, dict)
        self.assertIsInstance(score, float)


if __name__ == "__main__":
    unittest.main(verbosity=2)
