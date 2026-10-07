"""Phase 9 unit tests – PacketCapture.

These tests exercise the capture module's logic without requiring TShark to be
installed or a live network connection.  All TShark subprocess calls are
patched.

Run with::

    python -m pytest tests/unit/test_packet_capture.py -v
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from capture.packet_capture import (
    CaptureError,
    PacketCapture,
    TSharkNotFoundError,
    _capture_filename,
    _resolve_capture_dir,
    get_loopback_interface,
    list_interfaces,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_exp_id() -> str:
    return f"exp-{uuid.uuid4().hex[:8]}"


class _FakePopen:
    """Minimal fake subprocess.Popen for testing."""

    def __init__(self, *, returncode: int | None = None, stderr_data: bytes = b"") -> None:
        self._returncode = returncode
        self._stderr_data = stderr_data
        self.stderr = MagicMock()
        self.stderr.read.return_value = stderr_data
        self._stopped = False

    @property
    def returncode(self) -> int | None:
        return self._returncode if self._stopped else None

    def poll(self) -> int | None:
        # Simulate process still running (poll returns None) unless it should
        # have exited immediately.
        return self._returncode if self._returncode is not None and not self._stopped else None

    def send_signal(self, sig: int) -> None:
        self._stopped = True
        self._returncode = 0

    def terminate(self) -> None:
        self._stopped = True
        self._returncode = 0

    def kill(self) -> None:
        self._stopped = True
        self._returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        return self._returncode or 0


class _ImmediatelyExitingPopen(_FakePopen):
    """Simulates TShark that exits immediately (bad interface)."""

    def poll(self) -> int | None:
        return 1  # non-zero means error


# ---------------------------------------------------------------------------
# Filename helpers
# ---------------------------------------------------------------------------

class TestCaptureFilename:
    def test_basic_name_format(self) -> None:
        name = _capture_filename("exp-abc12345", "RSA-2048", 100)
        assert name == "experiment_exp-abc12345_RSA-2048_100B.pcapng"

    def test_special_chars_in_profile_replaced(self) -> None:
        name = _capture_filename("exp-1", "AES/GCM 256", 50)
        assert "/" not in name
        assert " " not in name
        assert name.endswith(".pcapng")

    def test_zero_message_size(self) -> None:
        name = _capture_filename("exp-0", "ECC-P256", 0)
        assert "0B" in name


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------

class TestLoopbackInterface:
    def test_macos_returns_lo0(self) -> None:
        with patch("platform.system", return_value="Darwin"):
            assert get_loopback_interface() == "lo0"

    def test_linux_returns_lo(self) -> None:
        with patch("platform.system", return_value="Linux"):
            assert get_loopback_interface() == "lo"

    def test_unknown_os_returns_lo(self) -> None:
        with patch("platform.system", return_value="FreeBSD"):
            result = get_loopback_interface()
            assert isinstance(result, str)
            assert len(result) > 0


class TestListInterfaces:
    def test_parses_tshark_d_output(self) -> None:
        fake_output = (
            "1. lo0 (Loopback)\n"
            "2. en0 (Wi-Fi)\n"
            "3. utun0\n"
        )
        mock_result = MagicMock()
        mock_result.stdout = fake_output

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.run", return_value=mock_result):
                ifaces = list_interfaces()

        assert len(ifaces) == 3
        assert ifaces[0]["name"] == "lo0"
        assert ifaces[0]["description"] == "Loopback"
        assert ifaces[1]["name"] == "en0"
        assert ifaces[2]["name"] == "utun0"
        assert ifaces[2]["description"] == ""

    def test_raises_when_tshark_missing(self) -> None:
        with patch("capture.packet_capture._find_tshark", side_effect=TSharkNotFoundError("not found")):
            with pytest.raises(TSharkNotFoundError):
                list_interfaces()


# ---------------------------------------------------------------------------
# PacketCapture construction
# ---------------------------------------------------------------------------

class TestPacketCaptureInit:
    def test_default_interface_is_loopback(self) -> None:
        cap = PacketCapture(_make_exp_id())
        assert cap.interface == get_loopback_interface()

    def test_explicit_interface_overrides_default(self) -> None:
        cap = PacketCapture(_make_exp_id(), interface="en0")
        assert cap.interface == "en0"

    def test_default_filter_uses_server_port(self) -> None:
        cap = PacketCapture(_make_exp_id())
        # Default SERVER_PORT is 5000
        assert "5000" in cap.capture_filter
        assert "tcp" in cap.capture_filter

    def test_explicit_filter_overrides_default(self) -> None:
        cap = PacketCapture(_make_exp_id(), capture_filter="tcp port 9999")
        assert cap.capture_filter == "tcp port 9999"

    def test_capture_file_is_in_captures_dir(self) -> None:
        cap = PacketCapture("exp-test01", "RSA-2048", 128)
        assert "captures" in cap.capture_file
        assert cap.capture_file.endswith(".pcapng")

    def test_capture_file_contains_experiment_id(self) -> None:
        eid = "exp-deadbeef"
        cap = PacketCapture(eid, "RSA-2048", 64)
        assert eid in cap.capture_file

    def test_capture_file_path_is_project_relative(self) -> None:
        cap = PacketCapture(_make_exp_id())
        # Should not be an absolute path (i.e. it should be relative to project root)
        assert not Path(cap.capture_file).is_absolute()

    def test_initial_status_is_not_started(self) -> None:
        cap = PacketCapture(_make_exp_id())
        assert cap.capture_status == "not_started"


# ---------------------------------------------------------------------------
# PacketCapture.start() – mocked TShark
# ---------------------------------------------------------------------------

class TestPacketCaptureStart:
    def _make_cap(self, popen_inst: _FakePopen) -> tuple[PacketCapture, MagicMock]:
        cap = PacketCapture(
            _make_exp_id(),
            "AES-256",
            32,
            startup_wait_seconds=0.0,
        )
        mock_popen = MagicMock(return_value=popen_inst)
        return cap, mock_popen

    def test_start_sets_running_status(self) -> None:
        popen_inst = _FakePopen()
        cap, mock_popen = self._make_cap(popen_inst)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", mock_popen):
                cap.start()

        assert cap.capture_status == "running"

    def test_start_raises_when_tshark_missing(self) -> None:
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)
        with patch("capture.packet_capture._find_tshark", side_effect=TSharkNotFoundError("not found")):
            with pytest.raises(TSharkNotFoundError):
                cap.start()

    def test_start_raises_when_tshark_exits_immediately(self) -> None:
        popen_inst = _ImmediatelyExitingPopen()
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                with pytest.raises(CaptureError):
                    cap.start()

        assert cap.capture_status == "failed"

    def test_start_raises_on_permission_error(self) -> None:
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", side_effect=PermissionError("denied")):
                with pytest.raises(CaptureError, match="Permission denied"):
                    cap.start()


# ---------------------------------------------------------------------------
# PacketCapture.stop() – mocked TShark
# ---------------------------------------------------------------------------

class TestPacketCaptureStop:
    def _start_cap(self, popen_inst: _FakePopen) -> PacketCapture:
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)
        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                cap.start()
        return cap

    def test_stop_completed_when_file_exists(self, tmp_path: Path) -> None:
        popen_inst = _FakePopen()
        cap = self._start_cap(popen_inst)
        # Simulate a file having been written
        cap._abs_path = tmp_path / "test.pcapng"
        cap._abs_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # fake pcapng magic

        cap.stop()
        assert cap.capture_status == "completed"

    def test_stop_marks_empty_when_no_file(self, tmp_path: Path) -> None:
        popen_inst = _FakePopen()
        cap = self._start_cap(popen_inst)
        cap._abs_path = tmp_path / "missing.pcapng"  # does not exist

        cap.stop()
        assert cap.capture_status in {"empty", "failed"}

    def test_stop_with_experiment_failed_sets_capture_with_error(self, tmp_path: Path) -> None:
        popen_inst = _FakePopen()
        cap = self._start_cap(popen_inst)
        cap._abs_path = tmp_path / "partial.pcapng"
        cap._abs_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        cap.stop(experiment_failed=True)
        assert cap.capture_status == "capture_with_error"

    def test_stop_is_idempotent(self) -> None:
        """Calling stop() twice must not raise."""
        popen_inst = _FakePopen()
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)
        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                cap.start()
        cap.stop()
        cap.stop()  # second call must be a no-op


# ---------------------------------------------------------------------------
# PacketCapture context manager
# ---------------------------------------------------------------------------

class TestPacketCaptureContextManager:
    def test_context_manager_calls_start_and_stop(self) -> None:
        popen_inst = _FakePopen()
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                with cap:
                    assert cap.capture_status == "running"

        # After __exit__ the process should be cleaned up
        assert cap._process is None

    def test_context_manager_stops_capture_on_exception(self) -> None:
        popen_inst = _FakePopen()
        cap = PacketCapture(_make_exp_id(), startup_wait_seconds=0.0)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                with pytest.raises(RuntimeError):
                    with cap:
                        raise RuntimeError("experiment error")

        # TShark must be cleaned up even after the exception
        assert cap._process is None


# ---------------------------------------------------------------------------
# metadata() output
# ---------------------------------------------------------------------------

class TestPacketCaptureMetadata:
    def test_metadata_contains_required_keys(self, tmp_path: Path) -> None:
        popen_inst = _FakePopen()
        cap = PacketCapture(
            "exp-meta01",
            "RSA-2048",
            100,
            device_a_id="dev-esp32-01",
            device_b_id="dev-rpi4-01",
            startup_wait_seconds=0.0,
        )
        cap._abs_path = tmp_path / "meta.pcapng"
        cap._abs_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                cap.start()
        cap.stop()

        meta = cap.metadata()
        assert meta["experiment_id"] == "exp-meta01"
        assert meta["profile_id"] == "RSA-2048"
        assert meta["device_a_id"] == "dev-esp32-01"
        assert meta["device_b_id"] == "dev-rpi4-01"
        assert "capture_file" in meta
        assert "capture_interface" in meta
        assert "capture_filter" in meta
        assert "capture_status" in meta
        assert "capture_file_bytes" in meta
        assert "capture_file_sha256" in meta
        assert "created_at" in meta

    def test_metadata_does_not_contain_secrets(self, tmp_path: Path) -> None:
        """No plaintext, keys, or passphrases in metadata."""
        popen_inst = _FakePopen()
        cap = PacketCapture("exp-secrets", "AES-256", 32, startup_wait_seconds=0.0)
        cap._abs_path = tmp_path / "sec.pcapng"
        cap._abs_path.write_bytes(b"\x00" * 24)

        with patch("capture.packet_capture._find_tshark", return_value="/usr/bin/tshark"):
            with patch("subprocess.Popen", return_value=popen_inst):
                cap.start()
        cap.stop()

        meta = cap.metadata()
        meta_str = str(meta).lower()
        for forbidden in ("private_key", "session_key", "aes_key", "password", "plaintext"):
            assert forbidden not in meta_str, f"Secret field '{forbidden}' found in metadata"

    def test_metadata_capture_file_is_not_absolute(self) -> None:
        cap = PacketCapture("exp-relpath", "ECC-P256", 64)
        # Even before start/stop, the path should be project-relative
        assert not Path(cap.capture_file).is_absolute()

    def test_persist_to_db_writes_to_traffic(self) -> None:
        cap = PacketCapture(
            "exp-db-test",
            "ECC-P256",
            64,
            device_a_id="dev-A",
            device_b_id="dev-B",
        )
        traffic_mock = MagicMock()
        experiments_mock = MagicMock()
        mock_db = {
            "traffic": traffic_mock,
            "experiments": experiments_mock,
        }
        mock_get_db = MagicMock(return_value=mock_db)

        with patch("database.connection.get_database", mock_get_db):
            cap.persist_to_db()

        traffic_mock.update_one.assert_called_once()
        call_args = traffic_mock.update_one.call_args
        assert call_args[0][0] == {"experiment_id": "exp-db-test"}
        assert "$set" in call_args[0][1]
        assert call_args[0][1]["$set"]["device_a_id"] == "dev-A"
        assert call_args[0][1]["$set"]["device_b_id"] == "dev-B"
        assert call_args[1]["upsert"] is True

