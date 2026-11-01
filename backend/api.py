"""HTTP API for the Adaptive Cryptographic Communication System frontend.

Run from backend/: uvicorn api:app --reload --port 8000
"""
from __future__ import annotations

import base64
import hashlib
import time as _time
import uuid
from datetime import date, datetime
from typing import Any

from bson import ObjectId
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from client import run_client
from database.connection import get_database
from repositories.device_repository import DeviceRepository
from repositories.profile_repository import ProfileRepository
from selection.selector import select_best_profile_full

app = FastAPI(
    title="Adaptive Crypto API",
    version="1.0.0",
    description="HTTP façade for adaptive IoT cryptographic profile selection and communication.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SelectionRequest(BaseModel):
    sender_id: str
    receiver_id: str
    message: str = ""
    experiment_id: str | None = None


class TransmissionRequest(BaseModel):
    sender_id: str
    receiver_id: str
    message: str = ""
    profile_id: str | None = None
    experiment_id: str | None = None
    host: str = "127.0.0.1"
    port: int = Field(default=5000, ge=1, le=65535)


def json_safe(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/api/health")
def health() -> dict[str, Any]:
    try:
        db = get_database()
        db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as exc:
        return {"status": "degraded", "database": "unavailable", "detail": str(exc)}


@app.get("/api/devices")
def list_devices() -> list[dict[str, Any]]:
    try:
        return [device.to_dict() for device in DeviceRepository().list_active()]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/profiles")
def list_profiles() -> list[dict[str, Any]]:
    try:
        return [profile.to_dict() for profile in ProfileRepository().list_enabled()]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/select")
def select_profile(payload: SelectionRequest) -> dict[str, Any]:
    if payload.sender_id == payload.receiver_id:
        raise HTTPException(status_code=400, detail="Sender and receiver must be different devices.")

    try:
        devices = DeviceRepository()
        sender = devices.get_by_id(payload.sender_id)
        receiver = devices.get_by_id(payload.receiver_id)
        experiment_id = payload.experiment_id or f"exp-{uuid.uuid4().hex[:8]}"
        message_size = len(payload.message.encode("utf-8"))

        result = select_best_profile_full(
            sender=sender,
            receiver=receiver,
            message_size_bytes=message_size,
            experiment_id=experiment_id,
        )

        return json_safe(
            {
                "experiment_id": result.experiment_id,
                "sender": sender.to_dict(),
                "receiver": receiver.to_dict(),
                "message_size_bytes": message_size,
                "winning_profile": result.winning_profile.to_dict(),
                "winning_score": result.winning_score,
                "candidate_details": result.candidate_details,
                "selection_reason": result.selection_reason,
                "dynamic_weights": result.dynamic_weights,
                "constraint_pressures": result.constraint_pressures,
                "combined_constraints": result.combined_constraints,
                "selection_mode": result.selection_mode,
                "fallback_used": result.fallback_used,
                "fallback_reason": result.fallback_reason,
                "relaxed_constraints": result.relaxed_constraints,
                "is_demonstration_mode": result.is_demonstration_mode,
            }
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/transmit/detailed")
def transmit_detailed(payload: TransmissionRequest) -> dict[str, Any]:  # noqa: C901
    """Run a full crypto simulation for the selected profile, then do actual TCP transport."""
    if payload.sender_id == payload.receiver_id:
        raise HTTPException(status_code=400, detail="Sender and receiver must be different devices.")

    experiment_id = payload.experiment_id or f"exp-{uuid.uuid4().hex[:8]}"

    try:
        devices = DeviceRepository()
        sender_dev = devices.get_by_id(payload.sender_id)
        receiver_dev = devices.get_by_id(payload.receiver_id)

        # Resolve the profile to use
        profile_id = payload.profile_id
        profile_name = profile_id  # fallback

        if not profile_id:
            message_size = len(payload.message.encode("utf-8"))
            sel = select_best_profile_full(
                sender=sender_dev,
                receiver=receiver_dev,
                message_size_bytes=message_size,
                experiment_id=experiment_id,
            )
            profile_id = sel.winning_profile.profile_id
            profile_name = sel.winning_profile.name
        else:
            # Try to get name from ProfileRepository
            try:
                all_profiles = {p.profile_id: p for p in ProfileRepository().list_enabled()}
                if profile_id in all_profiles:
                    profile_name = all_profiles[profile_id].name
            except Exception:
                pass

        message = payload.message
        message_bytes = message.encode("utf-8")
        message_size = len(message_bytes)

        plaintext_preview = message[:60] + ("…" if len(message) > 60 else "")

        overall_t0 = _time.perf_counter()

        sender_info: dict[str, Any] = {}
        network_info: dict[str, Any] = {}
        receiver_info: dict[str, Any] = {}
        overall_status = "success"

        # ── RSA profiles: C1 (2048-bit + AES-128) or C2 (3072-bit + AES-256) ──
        if profile_id in ("C1", "C2"):
            from crypto.rsa_engine import generate_key_pair as rsa_gen, serialize_public_key as rsa_ser_pub, wrap_aes_key, unwrap_aes_key
            from crypto.aes_engine import generate_key, encrypt_message, decrypt_message

            key_size_bits = 2048 if profile_id == "C1" else 3072
            aes_bits = 128 if profile_id == "C1" else 256
            aes_alg = f"AES-{aes_bits}-GCM"

            # Key generation (RSA pair — receiver holds the private key)
            t0 = _time.perf_counter()
            rsa_private = rsa_gen(key_size_bits)
            rsa_public = rsa_private.public_key()
            t_keygen = (_time.perf_counter() - t0) * 1000

            # Fingerprint of receiver public key (SHA-256 of DER bytes, first 16 hex chars)
            from cryptography.hazmat.primitives import serialization as _serialization
            der_bytes = rsa_public.public_bytes(
                encoding=_serialization.Encoding.DER,
                format=_serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fp = "SHA256:" + hashlib.sha256(der_bytes).hexdigest()[:16]

            sender_info["key_generation"] = {
                "method": "RSA-OAEP",
                "key_size_bits": key_size_bits,
                "time_ms": round(t_keygen, 3),
                "receiver_public_key_fingerprint": fp,
            }

            # AES session key generation
            aes_key = generate_key(aes_bits)

            # RSA-OAEP key wrapping
            t0 = _time.perf_counter()
            wrapped_key = wrap_aes_key(aes_key, rsa_public)
            t_wrap = (_time.perf_counter() - t0) * 1000

            sender_info["key_wrapping"] = {
                "type": "rsa",
                "description": "AES session key wrapped with RSA-OAEP SHA-256",
                "wrapped_key_size_bytes": len(wrapped_key),
                "time_ms": round(t_wrap, 3),
            }

            # AES-GCM encryption
            t0 = _time.perf_counter()
            ciphertext, nonce = encrypt_message(message, aes_key)
            t_enc = (_time.perf_counter() - t0) * 1000

            sender_info["nonce_generation"] = {
                "nonce_hex": nonce.hex(),
                "size_bytes": len(nonce),
            }
            ciphertext_no_tag = ciphertext[:-16]
            tag = ciphertext[-16:]
            sender_info["encryption"] = {
                "algorithm": aes_alg,
                "key_size_bits": aes_bits,
                "time_ms": round(t_enc, 3),
                "ciphertext_b64": base64.b64encode(ciphertext_no_tag).decode(),
                "ciphertext_hex": ciphertext_no_tag.hex(),
                "tag_hex": tag.hex(),
                "ciphertext_size_bytes": len(ciphertext_no_tag),
                "tag_size_bytes": 16,
            }

            # Network (actual TCP call)
            t0 = _time.perf_counter()
            try:
                reply = run_client(
                    host=payload.host,
                    port=payload.port,
                    sender_id=payload.sender_id,
                    receiver_id=payload.receiver_id,
                    experiment_id=experiment_id,
                    profile_id=profile_id,
                    message=message,
                    timeout_seconds=5.0,
                    non_interactive=True,
                )
                t_net = (_time.perf_counter() - t0) * 1000
                frame_size = len(message_bytes) + len(wrapped_key) + len(nonce) + len(ciphertext)
                network_info = {
                    "protocol": "TCP (framed JSON v1)",
                    "host": payload.host,
                    "port": payload.port,
                    "sender": f"{sender_dev.name} [{sender_dev.device_id}]",
                    "receiver": f"{receiver_dev.name} [{receiver_dev.device_id}]",
                    "frame_size_bytes": frame_size,
                    "payload_size_bytes": frame_size - 56,  # subtract framing overhead estimate
                    "status": "delivered",
                    "time_ms": round(t_net, 3),
                    "protocol_fields": {
                        "protocol_version": 1,
                        "message_type": "HELLO",
                        "experiment_id": experiment_id,
                        "profile_id": profile_id,
                        "sequence_number": 1,
                    },
                }
            except Exception as net_exc:
                t_net = (_time.perf_counter() - t0) * 1000
                network_info = {
                    "protocol": "TCP (framed JSON v1)",
                    "host": payload.host,
                    "port": payload.port,
                    "sender": f"{sender_dev.name} [{sender_dev.device_id}]",
                    "receiver": f"{receiver_dev.name} [{receiver_dev.device_id}]",
                    "frame_size_bytes": 0,
                    "payload_size_bytes": 0,
                    "status": f"error: {net_exc}",
                    "time_ms": round(t_net, 3),
                    "protocol_fields": {
                        "protocol_version": 1,
                        "message_type": "HELLO",
                        "experiment_id": experiment_id,
                        "profile_id": profile_id,
                    },
                }
                overall_status = "error"

            # RSA key unwrapping + AES decryption (receiver side)
            t0 = _time.perf_counter()
            aes_key_recv = unwrap_aes_key(wrapped_key, rsa_private)
            t_unwrap = (_time.perf_counter() - t0) * 1000

            t0 = _time.perf_counter()
            recovered = decrypt_message(ciphertext, nonce, aes_key_recv)
            t_dec = (_time.perf_counter() - t0) * 1000

            receiver_info["key_unwrapping"] = {
                "method": "RSA-OAEP SHA-256",
                "time_ms": round(t_unwrap, 3),
            }
            receiver_info["decryption"] = {
                "algorithm": aes_alg,
                "time_ms": round(t_dec, 3),
                "tag_verified": True,
                "recovered_plaintext": recovered,
                "integrity_match": recovered == message,
                "decrypted_size_bytes": len(recovered.encode("utf-8")),
            }

        # ── ECDH profiles: C3 (P-256 + AES-128) or C4 (P-384 + AES-256) ──
        elif profile_id in ("C3", "C4"):
            from crypto.ecc_engine import (
                generate_key_pair as ecc_gen,
                serialize_public_key as ecc_ser_pub,
                perform_ecdh,
                derive_aes_key,
                generate_salt,
            )
            from crypto.aes_engine import generate_key, encrypt_message, decrypt_message

            curve = "P-256" if profile_id == "C3" else "P-384"
            aes_bits = 128 if profile_id == "C3" else 256
            aes_alg = f"AES-{aes_bits}-GCM"

            # Sender generates ephemeral EC key pair
            t0 = _time.perf_counter()
            sender_priv = ecc_gen(curve)
            sender_pub = sender_priv.public_key()
            t_keygen = (_time.perf_counter() - t0) * 1000

            sender_pub_pem = ecc_ser_pub(sender_pub).decode()

            sender_info["key_generation"] = {
                "method": f"ECDH-{curve}",
                "curve": curve,
                "time_ms": round(t_keygen, 3),
                "sender_public_key_pem": sender_pub_pem,
            }

            # Receiver also generates ephemeral key pair for ECDH
            t0 = _time.perf_counter()
            receiver_priv = ecc_gen(curve)
            receiver_pub = receiver_priv.public_key()

            # Sender-side ECDH: shared secret = sender_priv × receiver_pub
            shared_secret_sender = perform_ecdh(sender_priv, receiver_pub)
            salt = generate_salt(16)
            aes_key_sender = derive_aes_key(shared_secret_sender, salt, aes_bits)
            t_ecdh = (_time.perf_counter() - t0) * 1000

            sender_info["key_exchange"] = {
                "type": "ecdh",
                "description": f"Ephemeral ECDH key exchange with HKDF-SHA256 derivation",
                "time_ms": round(t_ecdh, 3),
            }

            # AES-GCM encryption
            t0 = _time.perf_counter()
            ciphertext, nonce = encrypt_message(message, aes_key_sender)
            t_enc = (_time.perf_counter() - t0) * 1000

            sender_info["nonce_generation"] = {
                "nonce_hex": nonce.hex(),
                "size_bytes": len(nonce),
            }
            ciphertext_no_tag = ciphertext[:-16]
            tag = ciphertext[-16:]
            sender_info["encryption"] = {
                "algorithm": aes_alg,
                "key_size_bits": aes_bits,
                "time_ms": round(t_enc, 3),
                "ciphertext_b64": base64.b64encode(ciphertext_no_tag).decode(),
                "ciphertext_hex": ciphertext_no_tag.hex(),
                "tag_hex": tag.hex(),
                "ciphertext_size_bytes": len(ciphertext_no_tag),
                "tag_size_bytes": 16,
            }

            # Network (actual TCP call)
            t0 = _time.perf_counter()
            try:
                reply = run_client(
                    host=payload.host,
                    port=payload.port,
                    sender_id=payload.sender_id,
                    receiver_id=payload.receiver_id,
                    experiment_id=experiment_id,
                    profile_id=profile_id,
                    message=message,
                    timeout_seconds=5.0,
                    non_interactive=True,
                )
                t_net = (_time.perf_counter() - t0) * 1000
                frame_size = len(message_bytes) + len(nonce) + len(ciphertext) + len(salt) + 100
                network_info = {
                    "protocol": "TCP (framed JSON v1)",
                    "host": payload.host,
                    "port": payload.port,
                    "sender": f"{sender_dev.name} [{sender_dev.device_id}]",
                    "receiver": f"{receiver_dev.name} [{receiver_dev.device_id}]",
                    "frame_size_bytes": frame_size,
                    "payload_size_bytes": frame_size - 56,
                    "status": "delivered",
                    "time_ms": round(t_net, 3),
                    "protocol_fields": {
                        "protocol_version": 1,
                        "message_type": "HELLO",
                        "experiment_id": experiment_id,
                        "profile_id": profile_id,
                        "sequence_number": 1,
                    },
                }
            except Exception as net_exc:
                t_net = (_time.perf_counter() - t0) * 1000
                network_info = {
                    "protocol": "TCP (framed JSON v1)",
                    "host": payload.host,
                    "port": payload.port,
                    "sender": f"{sender_dev.name} [{sender_dev.device_id}]",
                    "receiver": f"{receiver_dev.name} [{receiver_dev.device_id}]",
                    "frame_size_bytes": 0,
                    "payload_size_bytes": 0,
                    "status": f"error: {net_exc}",
                    "time_ms": round(t_net, 3),
                    "protocol_fields": {
                        "protocol_version": 1,
                        "message_type": "HELLO",
                        "experiment_id": experiment_id,
                        "profile_id": profile_id,
                    },
                }
                overall_status = "error"

            # Receiver-side: derive same key via ECDH(receiver_priv, sender_pub)
            t0 = _time.perf_counter()
            shared_secret_recv = perform_ecdh(receiver_priv, sender_pub)
            aes_key_recv = derive_aes_key(shared_secret_recv, salt, aes_bits)
            t_deriv = (_time.perf_counter() - t0) * 1000

            t0 = _time.perf_counter()
            from crypto.aes_engine import decrypt_message
            recovered = decrypt_message(ciphertext, nonce, aes_key_recv)
            t_dec = (_time.perf_counter() - t0) * 1000

            receiver_info["key_derivation"] = {
                "method": "HKDF-SHA256",
                "time_ms": round(t_deriv, 3),
            }
            receiver_info["decryption"] = {
                "algorithm": aes_alg,
                "time_ms": round(t_dec, 3),
                "tag_verified": True,
                "recovered_plaintext": recovered,
                "integrity_match": recovered == message,
                "decrypted_size_bytes": len(recovered.encode("utf-8")),
            }

        # ── PSK profile: C5 (PSK + AES-128-GCM) ──
        elif profile_id == "C5":
            from crypto.psk_engine import encrypt_with_psk, decrypt_with_psk

            aes_alg = "AES-128-GCM"
            aes_bits = 128

            sender_info["key_generation"] = {
                "method": "PSK",
                "description": "Pre-shared 128-bit key (configured)",
                "time_ms": round(0.01, 3),
            }

            # PSK encryption
            t0 = _time.perf_counter()
            ciphertext, nonce = encrypt_with_psk(message)
            t_enc = (_time.perf_counter() - t0) * 1000

            sender_info["nonce_generation"] = {
                "nonce_hex": nonce.hex(),
                "size_bytes": len(nonce),
            }
            ciphertext_no_tag = ciphertext[:-16]
            tag = ciphertext[-16:]
            sender_info["encryption"] = {
                "algorithm": aes_alg,
                "key_size_bits": aes_bits,
                "time_ms": round(t_enc, 3),
                "ciphertext_b64": base64.b64encode(ciphertext_no_tag).decode(),
                "ciphertext_hex": ciphertext_no_tag.hex(),
                "tag_hex": tag.hex(),
                "ciphertext_size_bytes": len(ciphertext_no_tag),
                "tag_size_bytes": 16,
            }

            # Network (actual TCP call)
            t0 = _time.perf_counter()
            try:
                reply = run_client(
                    host=payload.host,
                    port=payload.port,
                    sender_id=payload.sender_id,
                    receiver_id=payload.receiver_id,
                    experiment_id=experiment_id,
                    profile_id=profile_id,
                    message=message,
                    timeout_seconds=5.0,
                    non_interactive=True,
                )
                t_net = (_time.perf_counter() - t0) * 1000
                frame_size = len(nonce) + len(ciphertext) + 56
                network_info = {
                    "protocol": "TCP (framed JSON v1)",
                    "host": payload.host,
                    "port": payload.port,
                    "sender": f"{sender_dev.name} [{sender_dev.device_id}]",
                    "receiver": f"{receiver_dev.name} [{receiver_dev.device_id}]",
                    "frame_size_bytes": frame_size,
                    "payload_size_bytes": frame_size - 56,
                    "status": "delivered",
                    "time_ms": round(t_net, 3),
                    "protocol_fields": {
                        "protocol_version": 1,
                        "message_type": "HELLO",
                        "experiment_id": experiment_id,
                        "profile_id": profile_id,
                        "sequence_number": 1,
                    },
                }
            except Exception as net_exc:
                t_net = (_time.perf_counter() - t0) * 1000
                network_info = {
                    "protocol": "TCP (framed JSON v1)",
                    "host": payload.host,
                    "port": payload.port,
                    "sender": f"{sender_dev.name} [{sender_dev.device_id}]",
                    "receiver": f"{receiver_dev.name} [{receiver_dev.device_id}]",
                    "frame_size_bytes": 0,
                    "payload_size_bytes": 0,
                    "status": f"error: {net_exc}",
                    "time_ms": round(t_net, 3),
                    "protocol_fields": {
                        "protocol_version": 1,
                        "message_type": "HELLO",
                        "experiment_id": experiment_id,
                        "profile_id": profile_id,
                    },
                }
                overall_status = "error"

            # PSK decryption (receiver side)
            t0 = _time.perf_counter()
            recovered = decrypt_with_psk(ciphertext, nonce)
            t_dec = (_time.perf_counter() - t0) * 1000

            receiver_info["decryption"] = {
                "algorithm": aes_alg,
                "time_ms": round(t_dec, 3),
                "tag_verified": True,
                "recovered_plaintext": recovered,
                "integrity_match": recovered == message,
                "decrypted_size_bytes": len(recovered.encode("utf-8")),
            }

        else:
            raise HTTPException(status_code=422, detail=f"Unknown profile_id: {profile_id}")

        total_time_ms = round((_time.perf_counter() - overall_t0) * 1000, 3)

        return {
            "experiment_id": experiment_id,
            "profile_id": profile_id,
            "profile_name": profile_name,
            "sender_name": sender_dev.name,
            "sender_id": sender_dev.device_id,
            "receiver_name": receiver_dev.name,
            "receiver_id": receiver_dev.device_id,
            "message_size_bytes": message_size,
            "plaintext": message,
            "plaintext_preview": plaintext_preview,
            "overall_status": overall_status,
            "total_time_ms": total_time_ms,
            "sender": sender_info,
            "network": network_info,
            "receiver": receiver_info,
        }

    except HTTPException:
        raise
    except (OSError, TimeoutError) as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Receiver is not reachable at {payload.host}:{payload.port}. "
                "Start backend/server.py first. Original error: " + str(exc)
            ),
        ) from exc
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/transmit")
def transmit(payload: TransmissionRequest) -> dict[str, Any]:
    if payload.sender_id == payload.receiver_id:
        raise HTTPException(status_code=400, detail="Sender and receiver must be different devices.")

    experiment_id = payload.experiment_id or f"exp-{uuid.uuid4().hex[:8]}"
    try:
        reply = run_client(
            host=payload.host,
            port=payload.port,
            sender_id=payload.sender_id,
            receiver_id=payload.receiver_id,
            experiment_id=experiment_id,
            profile_id=payload.profile_id,
            message=payload.message,
            timeout_seconds=5.0,
            non_interactive=True,
        )
        recovered = reply.payload.get("received_message", "") == payload.message
        return {
            "experiment_id": reply.experiment_id,
            "status": reply.payload.get("status", "unknown"),
            "message_recovered": recovered,
            "profile_id": payload.profile_id,
        }
    except (OSError, TimeoutError) as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Receiver is not reachable at {payload.host}:{payload.port}. "
                "Start backend/server.py first. Original error: " + str(exc)
            ),
        ) from exc
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/experiments")
def list_experiments(limit: int = Query(default=12, ge=1, le=100)) -> list[dict[str, Any]]:
    try:
        db = get_database()
        docs = list(db["experiments"].find().sort("_id", -1).limit(limit))
        return json_safe(docs)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/traffic")
def list_traffic(limit: int = Query(default=12, ge=1, le=100)) -> list[dict[str, Any]]:
    try:
        db = get_database()
        docs = list(db["traffic"].find().sort("_id", -1).limit(limit))
        return json_safe(docs)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/traffic/analyze-pending")
def analyze_pending_traffic() -> list[dict[str, Any]]:
    try:
        from analysis.traffic_analyzer import TrafficAnalyzer
        analyzer = TrafficAnalyzer()
        results = analyzer.analyze_pending(persist=True)
        return json_safe(results)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/traffic/{experiment_id}/analyze")
def analyze_traffic(experiment_id: str) -> dict[str, Any]:
    try:
        from analysis.traffic_analyzer import TrafficAnalyzer
        analyzer = TrafficAnalyzer()
        result = analyzer.analyze_experiment(experiment_id, persist=True)
        return json_safe(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
