"""Unit tests for the detailed transmission workflow endpoint /api/transmit/detailed."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from api import TransmissionRequest, transmit_detailed
from communication.protocol import MessageType, ProtocolMessage


@pytest.fixture
def mock_ack_reply():
    return ProtocolMessage(
        protocol_version=1,
        message_type=MessageType.ACK,
        experiment_id="exp-test-mock",
        payload={
            "status": "accepted",
            "received_message": "temperature=24.5",
            "sender_id": "esp32",
            "receiver_id": "raspberry_pi_4",
        },
    )


@pytest.mark.parametrize("profile_id", ["C1", "C2", "C3", "C4", "C5"])
def test_transmit_detailed_all_profiles(profile_id: str, mock_ack_reply) -> None:
    message = "temperature=24.5"
    payload = TransmissionRequest(
        sender_id="esp32",
        receiver_id="raspberry_pi_4",
        message=message,
        profile_id=profile_id,
        experiment_id=f"exp-unit-{profile_id.lower()}",
    )

    with patch("api.run_client", return_value=mock_ack_reply):
        res = transmit_detailed(payload)

    assert res["experiment_id"] == f"exp-unit-{profile_id.lower()}"
    assert res["profile_id"] == profile_id
    assert res["sender_name"] == "ESP32"
    assert res["receiver_name"] == "Raspberry Pi 4"
    assert res["message_size_bytes"] == len(message.encode("utf-8"))
    assert res["overall_status"] == "success"

    # Verify Sender Stage
    sender = res["sender"]
    assert "key_generation" in sender
    assert "encryption" in sender
    assert sender["encryption"]["tag_size_bytes"] == 16
    assert len(sender["encryption"]["ciphertext_b64"]) > 0
    assert sender["encryption"]["time_ms"] >= 0

    # Verify Network Stage
    network = res["network"]
    assert network["protocol"] == "TCP (framed JSON v1)"
    assert network["port"] == 5000
    assert network["status"] == "delivered"
    assert network["frame_size_bytes"] > 0

    # Verify Receiver Stage
    receiver = res["receiver"]
    assert "decryption" in receiver
    dec = receiver["decryption"]
    assert dec["tag_verified"] is True
    assert dec["recovered_plaintext"] == message
    assert dec["integrity_match"] is True
    assert dec["time_ms"] >= 0

