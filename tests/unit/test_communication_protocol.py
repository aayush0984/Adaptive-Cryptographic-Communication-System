import socket
import threading

import pytest

from client import run_client
from communication.protocol import (
    MessageType,
    ProtocolError,
    ProtocolMessage,
    deserialize_frame,
    serialize_frame,
)
from server import handle_client


def test_protocol_message_round_trip_and_length_prefixing() -> None:
    message = ProtocolMessage(
        protocol_version=1,
        message_type=MessageType.HELLO,
        experiment_id="exp-123",
        profile_id="RSA-2048",
        sequence_number=7,
        payload={"role": "sender"},
        timestamp=1234567890,
    )

    json_payload = message.to_json()
    decoded = ProtocolMessage.from_json(json_payload)
    assert decoded == message

    frame = serialize_frame(message)
    result = deserialize_frame(frame)
    assert result == message
    assert len(frame) >= 4


def test_protocol_rejects_unknown_version_or_missing_profile() -> None:
    with pytest.raises(ProtocolError):
        ProtocolMessage(
            protocol_version=999,
            message_type=MessageType.HELLO,
            experiment_id="exp-1",
            sequence_number=1,
        )

    with pytest.raises(ProtocolError):
        ProtocolMessage(
            protocol_version=1,
            message_type=MessageType.SETUP,
            experiment_id="exp-1",
            sequence_number=1,
            profile_id="",
        )


def test_invalid_frame_rejected() -> None:
    with pytest.raises(ProtocolError):
        deserialize_frame(b"\x00\x00\x00\x05not")

    with pytest.raises(ProtocolError):
        deserialize_frame(b"\x00\x00\x00\x00")


def test_local_tcp_smoke_test_completes_hello_ack_exchange() -> None:
    host = "127.0.0.1"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((host, 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_once() -> None:
            connection, _ = listener.accept()
            with connection:
                handle_client(connection)

        server_thread = threading.Thread(target=serve_once)
        server_thread.start()
        response = run_client(
            host=host,
            port=port,
            experiment_id="smoke-test",
            profile_id="test-profile",
            message="direct client/server test",
        )
        server_thread.join(timeout=5)

    assert not server_thread.is_alive()

    assert response.message_type == MessageType.ACK
    assert response.payload["status"] == "accepted"
    assert response.payload["received_message"] == "direct client/server test"
