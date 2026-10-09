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
    assert result["total_captured_bytes"] == 1964
    assert result["min_packet_size_bytes"] == 56
    assert result["max_packet_size_bytes"] == 323
    assert result["average_packet_size_bytes"] == 163.67
    assert result["sender_to_receiver_packets"] == 6
    assert result["receiver_to_sender_packets"] == 6
    assert result["sender_to_receiver_bytes"] == 588
    assert result["receiver_to_sender_bytes"] == 615
    assert result["tcp_payload_bytes"] == 507
    assert result["tcp_retransmissions"] == 0
    assert result["application_data_packets"] == 2
    assert result["network_overhead_bytes"] == 1960
    assert result["network_overhead_percent"] == 49000.0
    assert "TCP" in result["protocols_seen"]
    assert "IP" in result["protocols_seen"]
    assert result["first_packet_at"] is not None
    assert result["last_packet_at"] is not None
    assert result["traffic_duration_seconds"] > 0
    assert result["analysis_error"] is None


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
    assert result["network_overhead_bytes"] == 1964
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
        "message_size_bytes": 4,
        "total_packets": 12,
        "total_captured_bytes": 1964,
        "tcp_payload_bytes": 507,
        "tcp_retransmissions": 0,
        "network_overhead_bytes": 1960,
        "network_overhead_percent": 49000.0,
    }

    summary = analyzer.format_summary("exp-test", dummy_analysis)
    assert "exp-test" in summary
    assert "Message size     : 4 B" in summary
    assert "Packets          : 12" in summary
    assert "Captured bytes   : 1964" in summary
    assert "TCP payload      : 507 B" in summary
    assert "Retransmissions  : 0" in summary
    assert "Network overhead : 1960 B" in summary
    assert "Overhead         : 49000.00%" in summary
    assert "Status           : completed" in summary


def test_format_summary_failed(analyzer: TrafficAnalyzer) -> None:
    """Test string representation of failed analysis."""
    dummy_analysis = {
        "analysis_status": "failed",
        "analysis_error": "File not found",
    }

    summary = analyzer.format_summary("exp-test", dummy_analysis)
    assert "exp-test" in summary
    assert "Status           : failed" in summary
    assert "Error            : File not found" in summary

