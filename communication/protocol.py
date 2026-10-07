"""Framed JSON protocol used by the TCP sender/receiver phase."""

from __future__ import annotations

import base64
import json
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from enum import Enum
from typing import Any

# Indian Standard Time (IST = UTC+05:30)
IST = ZoneInfo("Asia/Kolkata")

SUPPORTED_PROTOCOL_VERSION = 1
MAX_FRAME_SIZE = 1_048_576


class ProtocolError(ValueError):
    """Raised when a protocol message or frame is malformed or unsupported."""


class MessageType(str, Enum):
    """Valid protocol message types."""

    HELLO = "hello"
    SETUP = "setup"
    KEY_EXCHANGE = "key_exchange"
    ENCRYPTED = "encrypted"
    ACK = "ack"
    ERROR = "error"
    CLOSE = "close"

    @classmethod
    def coerce(cls, value: "str | MessageType") -> "MessageType":
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            try:
                return cls(normalized)
            except ValueError as exc:
                raise ProtocolError(f"Unsupported message type '{value}'") from exc
        raise ProtocolError(f"Message type must be a string or MessageType, got {type(value).__name__}")


_BINARY_FIELDS = {"public_key", "wrapped_key", "salt", "nonce", "ciphertext", "signature", "session_key"}


@dataclass
class ProtocolSession:
    """Tracks session state while a sender or receiver exchanges framed messages."""

    experiment_id: str
    profile_id: str | None = None
    sequence_number: int = 0
    timeout_seconds: float = 5.0
    protocol_version: int = SUPPORTED_PROTOCOL_VERSION
    state: str = "created"

    def next_sequence(self) -> int:
        self.sequence_number += 1
        return self.sequence_number


@dataclass
class ProtocolMessage:
    """A single framed message exchanged across the TCP channel."""

    protocol_version: int = SUPPORTED_PROTOCOL_VERSION
    message_type: str | MessageType = MessageType.HELLO
    experiment_id: str | None = None
    session_id: str | None = None
    profile_id: str | None = None
    sequence_number: int = 0
    timestamp: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.protocol_version = int(self.protocol_version)
        if self.protocol_version != SUPPORTED_PROTOCOL_VERSION:
            raise ProtocolError(f"Unsupported protocol version '{self.protocol_version}'; expected {SUPPORTED_PROTOCOL_VERSION}")

        self.message_type = MessageType.coerce(self.message_type)
        self.experiment_id = self.experiment_id or self.session_id
        self.session_id = self.session_id or self.experiment_id
        if not self.experiment_id:
            raise ProtocolError("experiment_id/session_id is required")
        if self.profile_id is not None and not str(self.profile_id).strip():
            raise ProtocolError("profile_id must be a non-empty string when supplied")
        if not isinstance(self.payload, dict):
            raise ProtocolError("payload must be a dictionary")
        if self.timestamp is None:
            self.timestamp = int(time.time() * 1000)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "message_type": self.message_type.value,
            "experiment_id": self.experiment_id,
            "session_id": self.session_id,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
        }
        if self.profile_id is not None:
            data["profile_id"] = self.profile_id
        for key, value in self.payload.items():
            if key in {"protocol_version", "message_type", "experiment_id", "session_id", "profile_id", "sequence_number", "timestamp"}:
                continue
            data[key] = _encode_protocol_value(value)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "ProtocolMessage":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not isinstance(raw, str):
            raise ProtocolError("JSON payload must be a string or bytes")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProtocolError("Malformed JSON in protocol message") from exc

        if not isinstance(data, dict):
            raise ProtocolError("Protocol message payload must decode to a JSON object")

        payload = dict(data)
        for reserved in {"protocol_version", "message_type", "experiment_id", "session_id", "profile_id", "sequence_number", "timestamp"}:
            payload.pop(reserved, None)

        message_type = data.get("message_type", MessageType.HELLO.value)
        experiment_id = data.get("experiment_id") or data.get("session_id")
        session_id = data.get("session_id") or experiment_id
        profile_id = data.get("profile_id")
        sequence_number = int(data.get("sequence_number", 0))
        timestamp = data.get("timestamp")
        normalized_payload = {k: _decode_protocol_value(v) for k, v in payload.items()}

        return cls(
            protocol_version=int(data.get("protocol_version", SUPPORTED_PROTOCOL_VERSION)),
            message_type=message_type,
            experiment_id=experiment_id,
            session_id=session_id,
            profile_id=profile_id,
            sequence_number=sequence_number,
            timestamp=timestamp,
            payload=normalized_payload,
        )


def _encode_protocol_value(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, dict):
        return {str(key): _encode_protocol_value(inner) for key, inner in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_protocol_value(item) for item in value]
    return value


def _decode_protocol_value(value: Any) -> Any:
    if isinstance(value, str):
        if value and value.startswith("base64:"):
            return base64.b64decode(value[7:])
        return value
    if isinstance(value, dict):
        return {str(key): _decode_protocol_value(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_decode_protocol_value(item) for item in value]
    return value


def serialize_frame(message: ProtocolMessage | dict[str, Any] | str) -> bytes:
    """Serialize a protocol message into a length-prefixed frame."""
    if isinstance(message, ProtocolMessage):
        payload = message.to_json().encode("utf-8")
    elif isinstance(message, dict):
        payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    elif isinstance(message, str):
        payload = message.encode("utf-8")
    else:
        raise ProtocolError("Unsupported message type for frame serialization")

    if len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError(f"Frame exceeds maximum allowed size of {MAX_FRAME_SIZE} bytes")

    return struct.pack("!I", len(payload)) + payload


def deserialize_frame(frame: bytes) -> ProtocolMessage:
    """Decode a length-prefixed frame into a ProtocolMessage."""
    if not isinstance(frame, (bytes, bytearray)):
        raise ProtocolError("Frame must be bytes")
    frame_bytes = bytes(frame)
    if len(frame_bytes) < 4:
        raise ProtocolError("Frame is too short to contain a length prefix")

    length = struct.unpack("!I", frame_bytes[:4])[0]
    if length == 0:
        raise ProtocolError("Frame length prefix cannot be zero")
    if length > MAX_FRAME_SIZE:
        raise ProtocolError(f"Frame exceeds maximum allowed size of {MAX_FRAME_SIZE} bytes")
    if len(frame_bytes) != 4 + length:
        raise ProtocolError("Frame length does not match the announced payload size")

    body = frame_bytes[4:]
    try:
        return ProtocolMessage.from_json(body.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProtocolError("Frame payload is not valid UTF-8 JSON") from exc


def recv_exact(sock: socket.socket, expected_length: int) -> bytes:
    """Read exactly expected_length bytes from the socket, handling partial reads."""
    chunks: list[bytes] = []
    remaining = expected_length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("Socket closed before the full frame was received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame_from_socket(sock: socket.socket, timeout_seconds: float | None = None) -> ProtocolMessage:
    """Read one protocol frame from a connected socket."""
    if timeout_seconds is not None:
        sock.settimeout(timeout_seconds)
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    if length == 0:
        raise ProtocolError("Received a zero-length protocol frame")
    if length > MAX_FRAME_SIZE:
        raise ProtocolError(f"Frame length {length} exceeds maximum allowed size of {MAX_FRAME_SIZE} bytes")
    payload = recv_exact(sock, length)
    return ProtocolMessage.from_json(payload.decode("utf-8"))


def send_frame_to_socket(sock: socket.socket, message: ProtocolMessage | dict[str, Any] | str) -> None:
    """Write one protocol frame to a connected socket."""
    sock.sendall(serialize_frame(message))


def update_experiment_status(
    experiment_id: str,
    status: str,
    *,
    db: Any | None = None,
    message: str | None = None,
    **extra_fields: Any,
) -> dict[str, Any]:
    """Persist a lifecycle status update for a correlated experiment record."""
    if not experiment_id or not str(experiment_id).strip():
        raise ValueError("experiment_id must be a non-empty string")
    allowed_statuses = {"selected", "connected", "encrypted", "transmitted", "decrypted", "completed", "failed"}
    if status not in allowed_statuses:
        raise ValueError(f"status must be one of {sorted(allowed_statuses)}")

    if db is None:
        from database.connection import get_collection

        collection = get_collection("experiments")
    else:
        collection = db["experiments"] if isinstance(db, dict) else db["experiments"]

    update_doc: dict[str, Any] = {
        "status": status,
        "updated_at": datetime.now(IST),
    }
    if message is not None:
        update_doc["status_message"] = message
    update_doc.update(extra_fields)

    collection.update_one(
        {"$or": [{"experiment_id": experiment_id}, {"_id": experiment_id}]},
        {"$set": update_doc},
        upsert=True,
    )
    return {"experiment_id": experiment_id, "status": status, **extra_fields}
