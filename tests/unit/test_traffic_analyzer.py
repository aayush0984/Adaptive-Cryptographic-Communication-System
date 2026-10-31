"""Unit tests for Phase 10 — PyShark Traffic Analysis."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from analysis.traffic_analyzer import TrafficAnalyzer

IST = ZoneInfo("Asia/Kolkata")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
_candidate_backend = BACKEND_ROOT / "captures" / "experiment_exp-a207ff8e_C4_4B.pcapng"
_candidate_root = PROJECT_ROOT / "captures" / "experiment_exp-a207ff8e_C4_4B.pcapng"
SAMPLE_PCAP = _candidate_backend if _candidate_backend.exists() else _candidate_root


@pytest.fixture
def analyzer() -> TrafficAnalyzer:
    return TrafficAnalyzer(project_root=BACKEND_ROOT, server_port=5000)


def test_analyze_sample_pcap(analyzer: TrafficAnalyzer) -> None:
    """Validate traffic analysis on the real experiment capture."""
    if not SAMPLE_PCAP.exists():
        pytest.skip("Sample pcapng not found")

    result = analyzer.analyze_pcap(
        pcap_path=SAMPLE_PCAP,
        original_message_size_bytes=4,
        server_port=5000,
    )

    assert result["analysis_status"] == "completed"
    assert result["total_packets"] == 12
    assert result["tcp_packets"] == 12
    assert result["total_captured_bytes"] == 1203
    assert result["capture_file_bytes"] == 1964
    assert result["min_packet_size_bytes"] == 56
    assert result["max_packet_size_bytes"] == 323
    assert result["average_packet_size_bytes"] == 100.25
    assert result["sender_to_receiver_packets"] == 6
    assert result["receiver_to_sender_packets"] == 6
    assert result["sender_to_receiver_bytes"] == 588
    assert result["receiver_to_sender_bytes"] == 615
    assert result["tcp_payload_bytes"] == 507
    assert result["tcp_retransmissions"] == 0
    assert result["application_data_packets"] == 2
    assert result["network_overhead_bytes"] == 1199
    assert result["network_overhead_percent"] == 29975.0
    assert "TCP" in result["protocols_seen"]
    assert "IP" in result["protocols_seen"]
    assert result["first_packet_at"] is not None
    assert result["last_packet_at"] is not None
    assert result["traffic_duration_seconds"] > 0
    assert result["analysis_error"] is None
    assert len(result["packets"]) == 12


def test_zero_size_message_overhead(analyzer: TrafficAnalyzer) -> None:
    """Ensure zero-size messages do not trigger ZeroDivisionError."""
    if not SAMPLE_PCAP.exists():
        pytest.skip("Sample pcapng not found")

    result = analyzer.analyze_pcap(
        pcap_path=SAMPLE_PCAP,
        original_message_size_bytes=0,
        server_port=5000,
    )

    assert result["analysis_status"] == "completed"
    assert result["total_captured_bytes"] == 1203
    assert result["network_overhead_bytes"] == 1203
    assert result["network_overhead_percent"] == 0.0


def test_missing_pcap_file(analyzer: TrafficAnalyzer) -> None:
    """Handling missing capture files."""
    result = analyzer.analyze_pcap(
        pcap_path="captures/non_existent.pcapng",
        original_message_size_bytes=10,
    )

    assert result["analysis_status"] == "failed"
    assert "not found" in result["analysis_error"].lower()


def test_empty_pcap_file(analyzer: TrafficAnalyzer, tmp_path: Path) -> None:
    """Handling empty 0-byte capture files."""
    empty_file = tmp_path / "empty.pcapng"
    empty_file.write_bytes(b"")

    result = analyzer.analyze_pcap(
        pcap_path=empty_file,
        original_message_size_bytes=10,
    )

    assert result["analysis_status"] == "failed"
    assert "empty" in result["analysis_error"].lower()


def test_missing_message_size(analyzer: TrafficAnalyzer) -> None:
    """Handling missing original message size."""
    if not SAMPLE_PCAP.exists():
        pytest.skip("Sample pcapng not found")

    result = analyzer.analyze_pcap(
        pcap_path=SAMPLE_PCAP,
        original_message_size_bytes=None,
    )

    assert result["analysis_status"] == "failed"
    assert "message size" in result["analysis_error"].lower()


def test_format_summary_completed(analyzer: TrafficAnalyzer) -> None:
    """Test string representation of completed analysis."""
    dummy_analysis = {
        "analysis_status": "completed",
        "capture_status": "completed",
        "sender_id": "esp32",
        "sender_name": "ESP32",
        "receiver_id": "raspberry_pi_4",
        "receiver_name": "Raspberry Pi 4",
        "profile_id": "C4",
        "profile_name": "ECDH-P384 + AES-256-GCM",
        "capture_interface": "lo0",
        "message_size_bytes": 4,
        "total_packets": 12,
        "sender_to_receiver_packets": 6,
        "receiver_to_sender_packets": 6,
        "application_data_packets": 2,
        "total_captured_bytes": 1203,
        "tcp_payload_bytes": 507,
        "min_packet_size_bytes": 56,
        "max_packet_size_bytes": 323,
        "average_packet_size_bytes": 100.25,
        "tcp_retransmissions": 0,
        "traffic_duration_seconds": 0.121,
        "network_overhead_bytes": 1199,
        "network_overhead_percent": 29975.0,
        "packets": [
            {"index": 1, "direction": "A -> B", "flags": "SYN", "payload_bytes": 0, "frame_bytes": 68},
            {"index": 2, "direction": "B -> A", "flags": "SYN, ACK", "payload_bytes": 0, "frame_bytes": 68},
        ],
    }

    summary = analyzer.format_summary("exp-test", dummy_analysis)
    assert "exp-test" in summary
    assert "EXPERIMENT DETAILS" in summary
    assert "Sender (A)        : ESP32 [esp32]" in summary
    assert "Receiver (B)      : Raspberry Pi 4 [raspberry_pi_4]" in summary
    assert "Crypto Profile    : C4 - ECDH-P384 + AES-256-GCM" in summary
    assert "Message Size      : 4 B" in summary
    assert "Capture Interface : lo0" in summary
    assert "TRAFFIC SUMMARY" in summary
    assert "Total Packets     : 12" in summary
    assert "A -> B Packets    : 6" in summary
    assert "B -> A Packets    : 6" in summary
    assert "Data Packets      : 2" in summary
    assert "Captured Bytes    : 1203 B" in summary
    assert "TCP Payload       : 507 B" in summary
    assert "Min Packet Size   : 56 B" in summary
    assert "Max Packet Size   : 323 B" in summary
    assert "Avg Packet Size   : 100.25 B" in summary
    assert "Retransmissions   : 0" in summary
    assert "Traffic Duration  : 0.121 s" in summary
    assert "NETWORK OVERHEAD" in summary
    assert "Overhead Bytes    : 1199 B" in summary
    assert "Overhead Percent  : 29975.00%" in summary
    assert "PACKET DETAILS" in summary
    assert "1   A -> B     SYN         0           68" in summary
    assert "2   B -> A     SYN, ACK    0           68" in summary
    assert "Capture Status    : completed" in summary
    assert "Analysis Status   : completed" in summary


def test_format_summary_failed(analyzer: TrafficAnalyzer) -> None:
    """Test string representation of failed analysis."""
    dummy_analysis = {
        "analysis_status": "failed",
        "analysis_error": "File not found",
    }

    summary = analyzer.format_summary("exp-test", dummy_analysis)
    assert "exp-test" in summary
    assert "Analysis Status   : failed" in summary
    assert "Error             : File not found" in summary

