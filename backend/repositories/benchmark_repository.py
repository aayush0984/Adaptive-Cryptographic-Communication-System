"""Repository layer for benchmark documents in the iot_security.benchmarks collection."""

from __future__ import annotations

from typing import Any
from pymongo.database import Database

from database.connection import get_database


class BenchmarkRepository:
    """Repository for raw benchmark run documents."""

    def __init__(self, db: Database[dict[str, Any]] | None = None) -> None:
        self.db = db if db is not None else get_database()
        self.collection = self.db["benchmarks"]

    def insert_run(self, doc: dict[str, Any]) -> str:
        """Insert a single raw benchmark document and return its run_id."""
        result = self.collection.insert_one(doc)
        return doc.get("run_id", str(result.inserted_id))

    def insert_many_runs(self, docs: list[dict[str, Any]]) -> int:
        """Bulk-insert benchmark documents. Returns count inserted."""
        if not docs:
            return 0
        result = self.collection.insert_many(docs, ordered=False)
        return len(result.inserted_ids)

    def find_runs(
        self,
        device_id: str | None = None,
        profile_id: str | None = None,
        message_size_bytes: int | None = None,
        measurement_source: str | None = None,
        success_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Retrieve benchmark documents matching the given filters."""
        query: dict[str, Any] = {}
        if success_only:
            query["success"] = True
        if device_id:
            query["device_id"] = device_id
        if profile_id:
            query["profile_id"] = profile_id
        if message_size_bytes is not None:
            query["message_size_bytes"] = message_size_bytes
        if measurement_source:
            query["measurement_source"] = measurement_source
        return list(self.collection.find(query))

    def aggregate_timings(
        self,
        device_id: str | None = None,
        profile_id: str | None = None,
        message_size_bytes: int | None = None,
    ) -> list[dict[str, Any]]:
        """Run a MongoDB aggregation to compute avg/min/max timings per (profile, size).

        Returns a list of aggregated summary documents.
        """
        match_stage: dict[str, Any] = {"success": True}
        if device_id:
            match_stage["device_id"] = device_id
        if profile_id:
            match_stage["profile_id"] = profile_id
        if message_size_bytes is not None:
            match_stage["message_size_bytes"] = message_size_bytes

        pipeline = [
            {"$match": match_stage},
            {
                "$group": {
                    "_id": {
                        "profile_id": "$profile_id",
                        "message_size_bytes": "$message_size_bytes",
                    },
                    "count": {"$sum": 1},
                    "avg_total_ms": {"$avg": "$timings_ms.total"},
                    "min_total_ms": {"$min": "$timings_ms.total"},
                    "max_total_ms": {"$max": "$timings_ms.total"},
                    "avg_key_gen_ms": {"$avg": "$timings_ms.key_generation"},
                    "avg_key_est_ms": {"$avg": "$timings_ms.key_establishment"},
                    "avg_enc_ms": {"$avg": "$timings_ms.encryption"},
                    "avg_dec_ms": {"$avg": "$timings_ms.decryption"},
                    "avg_peak_mem_kb": {"$avg": "$peak_memory_kb"},
                    "avg_app_bytes": {"$avg": "$application_bytes"},
                }
            },
            {"$sort": {"_id.profile_id": 1, "_id.message_size_bytes": 1}},
        ]
        return list(self.collection.aggregate(pipeline))
