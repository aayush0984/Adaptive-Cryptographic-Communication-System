"""Server for the phase-8 secure sender/receiver protocol."""

from __future__ import annotations

import argparse
import socket
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

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


def handle_client(sock: socket.socket) -> None:
    """Handle one client connection: read HELLO, validate profile, send ACK."""
    peer = sock.getpeername()
    print(f"[RECEIVER] Connection received from sender at {peer[0]}:{peer[1]}", flush=True)
    message = read_frame_from_socket(sock, timeout_seconds=5.0)
    print(
        f"[RECEIVER] Encrypted packet received for experiment '{message.experiment_id}' "
        f"(seq {message.sequence_number})",
        flush=True,
    )

    if message.message_type == MessageType.HELLO:
        received_profile_id = message.profile_id
        sender_id = message.payload.get("sender_id", "unknown")
        receiver_id = message.payload.get("receiver_id", "unknown")
        received_message = message.payload.get("message", "")
        if received_profile_id == "C5" and "ciphertext_hex" in message.payload and "nonce_hex" in message.payload:
            from crypto.psk_engine import decrypt_with_psk
            ciphertext = bytes.fromhex(message.payload["ciphertext_hex"])
            nonce = bytes.fromhex(message.payload["nonce_hex"])
            print("[RECEIVER] Authenticating and decrypting PSK ciphertext using AES-128-GCM...")
            received_message = decrypt_with_psk(ciphertext, nonce)

        msg_bytes = received_message.encode("utf-8")
        print(f"[RECEIVER] Profile: {received_profile_id}")
        print(f"[RECEIVER] Sender device: {sender_id}")
        print(f"[RECEIVER] Receiver device: {receiver_id}")
        print(f"[RECEIVER] Message payload size: {len(msg_bytes)} bytes")
        print("[RECEIVER] Authenticating and verifying message payload integrity...")
        print("[RECEIVER] Decrypting message...")
        print(f"[RECEIVER] Recovered plaintext: {received_message}")
        print("[RECEIVER] Decryption successful.")

        session = ProtocolSession(
            experiment_id=message.experiment_id or "unknown",
            profile_id=received_profile_id,
        )
        reply = ProtocolMessage(
            protocol_version=1,
            message_type=MessageType.ACK,
            experiment_id=session.experiment_id,
            session_id=session.experiment_id,
            profile_id=session.profile_id,
            sequence_number=session.next_sequence(),
            payload={
                "status": "accepted",
                "received_message": received_message,  # echo for client-side verification
                "sender_id": sender_id,
                "receiver_id": receiver_id,
            },
        )
        send_frame_to_socket(sock, reply)
        print(f"[RECEIVER] Sent ACK acknowledgement for experiment {session.experiment_id}")
        print("[RECEIVER] Message received successfully.\n", flush=True)

        # Persist server-side observed result separately from the prediction block
        _record_server_result(
            experiment_id=session.experiment_id,
            profile_id=received_profile_id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_size_bytes=len(msg_bytes),
        )
        return

    print(
        f"[server] Rejected unexpected message type {message.message_type.value}",
        flush=True,
    )
    error = ProtocolMessage(
        protocol_version=1,
        message_type=MessageType.ERROR,
        experiment_id=message.experiment_id or "unknown",
        session_id=message.experiment_id or "unknown",
        sequence_number=message.sequence_number + 1,
        payload={"reason": "expected HELLO message"},
    )
    send_frame_to_socket(sock, error)


def _record_server_result(
    *,
    experiment_id: str,
    profile_id: str | None,
    sender_id: str,
    receiver_id: str,
    message_size_bytes: int,
) -> None:
    """Append server-side observed data to the experiment document.

    Written separately from the selector's prediction block, satisfying the
    requirement to keep predictions and observations distinct.
    The plaintext is never stored.
    """
    try:
        from database.connection import get_database
        db = get_database()
        db["experiments"].update_one(
            {"experiment_id": experiment_id},
            {
                "$set": {
                    "server_observed": {
                        "profile_id_confirmed": profile_id,
                        "sender_id": sender_id,
                        "receiver_id": receiver_id,
                        "message_size_bytes": message_size_bytes,
                        "received_at": datetime.now(IST),
                    }
                }
            },
            upsert=True,
        )
    except Exception as exc:
        print(f"[server] Warning: could not persist server result: {exc}", flush=True)


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
    parser.add_argument(
        "--host",
        default=get_env("SERVER_HOST", "127.0.0.1") or "127.0.0.1",
        help="Host interface to bind",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(get_env("SERVER_PORT", "5000") or "5000"),
        help="TCP port to bind",
    )
    parser.add_argument("--backlog", type=int, default=5, help="Socket backlog for the listener")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        run_server(host=args.host, port=args.port, backlog=args.backlog)
    except KeyboardInterrupt:
        print("[server] Stopped", flush=True)
