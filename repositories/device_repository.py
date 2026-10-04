"""Repository layer for IoT Devices MongoDB collection operations."""

from __future__ import annotations

from typing import Any
from pymongo.database import Database

from database.connection import get_database
from models.device import Device


class DeviceRepository:
    """Repository for managing devices in MongoDB."""

    def __init__(self, db: Database[dict[str, Any]] | None = None) -> None:
        self.db = db if db is not None else get_database()
        self.collection = self.db["devices"]

    def list_active(self) -> list[Device]:
        """List all active devices."""
        docs = list(self.collection.find({"active": True}))
        return [Device.from_doc(doc) for doc in docs]

    def get_by_id(self, device_id: str) -> Device:
        """Get a device by its device_id."""
        doc = self.collection.find_one({"device_id": device_id})
        if not doc:
            raise KeyError(f"Device '{device_id}' not found")
        return Device.from_doc(doc)

    def upsert(self, device: Device) -> bool:
        """Insert or update a device document."""
        res = self.collection.update_one(
            {"device_id": device.device_id},
            {"$set": device.to_dict()},
            upsert=True,
        )
        return bool(res.upserted_id or res.modified_count)
