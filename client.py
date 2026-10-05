"""Client for the phase-8 secure sender/receiver protocol."""

from __future__ import annotations

import argparse
import socket
import uuid

from config import get_env
from communication.protocol import (
    MessageType,
    ProtocolMessage,
    ProtocolSession,
    read_frame_from_socket,
    send_frame_to_socket,
)


def run_client(
    host: str = get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1",
    port: int = int(get_env("SERVER_PORT", "5000") or "5000"),
    experiment_id: str | None = None,
    profile_id: str | None = None,
    message: str = "hello-from-client",
    timeout_seconds: float = 5.0,
) -> ProtocolMessage:
    """Open a TCP socket, exchange a HELLO/ACK handshake, and return the server response."""
    if experiment_id is None:
        experiment_id = f"exp-{uuid.uuid4().hex[:8]}"

    session = ProtocolSession(experiment_id=experiment_id, profile_id=profile_id, timeout_seconds=timeout_seconds)
    print(f"[client] Connecting to {host}:{port}", flush=True)
    with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
        print(f"[client] Connected; experiment ID: {session.experiment_id}", flush=True)
        hello = ProtocolMessage(
            protocol_version=1,
            message_type=MessageType.HELLO,
            experiment_id=session.experiment_id,
            session_id=session.experiment_id,
            profile_id=session.profile_id,
            sequence_number=session.next_sequence(),
            payload={"message": message},
        )
        send_frame_to_socket(sock, hello)
        print(
            f"[client] Sent HELLO (sequence {hello.sequence_number}): {message!r}",
            flush=True,
        )
        reply = read_frame_from_socket(sock, timeout_seconds=timeout_seconds)
        print(
            f"[client] Received {reply.message_type.value} for experiment "
            f"{reply.experiment_id}",
            flush=True,
        )
        if reply.message_type != MessageType.ACK:
            raise ValueError(f"Unexpected response from server: {reply.message_type}")
        print(
            f"[client] Server status: {reply.payload.get('status', 'unknown')}; "
            f"echo: {reply.payload.get('received_message', '')!r}",
            flush=True,
        )
        return reply


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Device A client for the framed TCP protocol")
    parser.add_argument("--host", default=get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1", help="Hostname or IP address to dial")
    parser.add_argument("--port", type=int, default=int(get_env("SERVER_PORT", "5000") or "5000"), help="TCP port for the server")
    parser.add_argument("--experiment-id", default=None, help="Correlation ID for the experiment")
    parser.add_argument("--profile-id", default=None, help="Selected profile ID to include in the setup message")
    parser.add_argument("--message", default="hello-from-client", help="Payload to send in the HELLO message")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        response = run_client(
            host=args.host,
            port=args.port,
            experiment_id=args.experiment_id,
            profile_id=args.profile_id,
            message=args.message,
            timeout_seconds=args.timeout,
        )
        print(response.to_json())
    except (OSError, TimeoutError, ValueError) as exc:
        print(f"[client] Error: {exc}", flush=True)
        raise SystemExit(1) from exc
