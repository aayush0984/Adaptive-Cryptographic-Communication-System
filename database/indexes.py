"""MongoDB index creation utilities for iot_security collections."""

from __future__ import annotations

from typing import Any
from pymongo.database import Database
from database.connection import get_database


def create_indexes(db: Database[dict[str, Any]] | None = None) -> dict[str, list[str]]:
    """Create required MongoDB indexes idempotently across collections."""
    database = db if db is not None else get_database()
    created = {}

    # devices collection indexes
    devices_col = database["devices"]
    dev_idx1 = devices_col.create_index("device_id", unique=True)
    created["devices"] = [dev_idx1]

    # crypto_profiles collection indexes
    profiles_col = database["crypto_profiles"]
    prof_idx1 = profiles_col.create_index("profile_id", unique=True)
    created["crypto_profiles"] = [prof_idx1]

    # benchmarks collection indexes (sparse=True so null/missing run_id doesn't crash)
    benchmarks_col = database["benchmarks"]
    bench_idx1 = benchmarks_col.create_index("run_id", unique=True, sparse=True)
    bench_idx2 = benchmarks_col.create_index([("device_id", 1), ("profile_id", 1), ("message_size_bytes", 1)])
    created["benchmarks"] = [bench_idx1, bench_idx2]

    # experiments collection indexes
    experiments_col = database["experiments"]
    exp_idx1 = experiments_col.create_index([("created_at", -1), ("status", 1)])
    created["experiments"] = [exp_idx1]

    return created
