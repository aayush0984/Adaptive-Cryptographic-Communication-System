"""Server for the phase-8 secure sender/receiver protocol."""

from __future__ import annotations

import argparse
import socket

from config import get_env
from communication.protocol import (
    MessageType,
    ProtocolMessage,
    ProtocolSession,
    read_frame_from_socket,
    send_frame_to_socket,
)


def handle_client(sock: socket.socket) -> None:
    peer = sock.getpeername()
    print(f"[server] Waiting for a message from {peer[0]}:{peer[1]}", flush=True)
    message = read_frame_from_socket(sock, timeout_seconds=5.0)
    print(
        f"[server] Received {message.message_type.value} from experiment "
        f"{message.experiment_id} (sequence {message.sequence_number})",
        flush=True,
    )
    if message.message_type == MessageType.HELLO:
        received_message = message.payload.get("message", "")
        print(f"[server] Message content: {received_message!r}", flush=True)
        session = ProtocolSession(experiment_id=message.experiment_id or "unknown", profile_id=message.profile_id)
        reply = ProtocolMessage(
            protocol_version=1,
            message_type=MessageType.ACK,
            experiment_id=session.experiment_id,
            session_id=session.experiment_id,
            profile_id=session.profile_id,
            sequence_number=session.next_sequence(),
            payload={"status": "accepted", "received_message": received_message},
        )
        send_frame_to_socket(sock, reply)
        print(f"[server] Sent ACK for experiment {session.experiment_id}", flush=True)
        return

    print(f"[server] Rejected unexpected message type {message.message_type.value}", flush=True)
    error = ProtocolMessage(
        protocol_version=1,
        message_type=MessageType.ERROR,
        experiment_id=message.experiment_id or "unknown",
        session_id=message.experiment_id or "unknown",
        sequence_number=message.sequence_number + 1,
        payload={"reason": "expected HELLO message"},
    )
    send_frame_to_socket(sock, error)


def run_server(
    host: str = get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1",
    port: int = int(get_env("SERVER_PORT", "5000") or "5000"),
    backlog: int = 5,
) -> None:
    """Listen on a local TCP port and handle one client connection at a time."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(backlog)
        print(f"[server] Listening on {host}:{port}", flush=True)
        while True:
            conn, _ = server_sock.accept()
            with conn:
                print(f"[server] Connection accepted from {conn.getpeername()}", flush=True)
                try:
                    handle_client(conn)
                except (OSError, TimeoutError, ValueError) as exc:
                    print(f"[server] Connection error: {exc}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Device B server for the framed TCP protocol")
    parser.add_argument("--host", default=get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=int(get_env("SERVER_PORT", "5000") or "5000"), help="TCP port to bind")
    parser.add_argument("--backlog", type=int, default=5, help="Socket backlog for the listener")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        run_server(host=args.host, port=args.port, backlog=args.backlog)
    except KeyboardInterrupt:
        print("[server] Stopped", flush=True)
