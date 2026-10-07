"""Repository helpers for experiment lifecycle tracking."""

from __future__ import annotations

from typing import Any

from database.connection import get_collection

EXPERIMENT_STATUSES = {"selected", "connected", "encrypted", "transmitted", "decrypted", "completed", "failed"}


def update_experiment_status(
    experiment_id: str,
    status: str,
    *,
    message: str | None = None,
    db: Any | None = None,
    **extra_fields: Any,
) -> dict[str, Any]:
    """Store the next lifecycle phase of an experiment.

    This function intentionally keeps the MongoDB document update shallow and
    protocol-safe: it only records lifecycle metadata, not raw credentials or
    secrets from the cryptographic exchange.
    """
    if not experiment_id or not str(experiment_id).strip():
        raise ValueError("experiment_id must be a non-empty string")
    if status not in EXPERIMENT_STATUSES:
        raise ValueError(f"status must be one of {sorted(EXPERIMENT_STATUSES)}")

    collection = db["experiments"] if db is not None else get_collection("experiments")
    update_doc: dict[str, Any] = {"status": status}
    if message is not None:
        update_doc["status_message"] = message
    update_doc.update(extra_fields)

    collection.update_one(
        {"$or": [{"experiment_id": experiment_id}, {"_id": experiment_id}]},
        {"$set": update_doc},
        upsert=True,
    )
    return {"experiment_id": experiment_id, "status": status}
