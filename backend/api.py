"""HTTP API for the Adaptive Cryptographic Communication System frontend.

Run from backend/: uvicorn api:app --reload --port 8000
"""
from __future__ import annotations

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
