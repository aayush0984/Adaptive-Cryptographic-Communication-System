#!/usr/bin/env python3
"""Idempotent migration / backfill script for the iot_security database.

What this script does
---------------------
1. Ensures required indexes exist on all collections.
2. Backfills any existing experiment documents that are missing the new
   fields introduced in the Phase 8 refactor:
   - ``sender_constraints`` / ``receiver_constraints``
   - ``optimization_objective``
   - ``is_demonstration_mode``
   - ``failure_category``
3. Ensures the ``devices`` and ``crypto_profiles`` collections have the
   expected seed documents (upsert — never overwrites existing data).

Idempotency
-----------
Every operation is an upsert or a conditional update (``$set`` on missing
fields only, using ``$setOnInsert`` or checking for field existence).
Running the script multiple times produces the same result.

Safety guarantees
-----------------
- Does NOT delete any collection.
- Does NOT overwrite existing genuine measurements.
- Does NOT store plaintext.
- The ``--dry-run`` flag prints what would change without touching the DB.

Usage
-----
    # Preview changes (no writes)
    python scripts/migrate_experiments.py --dry-run

    # Apply to the default database (mongodb://localhost:27017/iot_security)
    python scripts/migrate_experiments.py

    # Apply to a custom URI / database
    python scripts/migrate_experiments.py --uri mongodb://host:27017/ --db mydb
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import Any

# Ensure project root is importable
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


NEW_EXPERIMENT_FIELDS = {
    "optimization_objective": "minimise_predicted_end_to_end_latency",
    "is_demonstration_mode": False,
    "failure_category": None,
    "sender_constraints": {},
    "receiver_constraints": {},
    "candidate_profiles": [],
}

REQUIRED_INDEXES = {
    "devices": [
        {"keys": [("device_id", 1)], "kwargs": {"unique": True, "name": "device_id_unique"}},
        {"keys": [("active", 1)], "kwargs": {"name": "active_idx"}},
    ],
    "crypto_profiles": [
        {"keys": [("profile_id", 1)], "kwargs": {"unique": True, "name": "profile_id_unique"}},
        {"keys": [("active", 1)], "kwargs": {"name": "active_idx"}},
    ],
    "benchmarks": [
        {"keys": [("device_id", 1), ("profile_id", 1), ("message_size_bytes", 1)],
         "kwargs": {"name": "bench_lookup_idx"}},
        {"keys": [("run_id", 1)], "kwargs": {"unique": True, "name": "run_id_unique"}},
        {"keys": [("success", 1)], "kwargs": {"name": "success_idx"}},
    ],
    "experiments": [
        {"keys": [("experiment_id", 1)], "kwargs": {"unique": True, "name": "experiment_id_unique"}},
        {"keys": [("sender_id", 1), ("receiver_id", 1)], "kwargs": {"name": "endpoint_idx"}},
        {"keys": [("status", 1)], "kwargs": {"name": "status_idx"}},
    ],
}


def _ensure_indexes(db: Any, dry_run: bool) -> None:
    print("\n[migrate] Checking indexes …")
    for collection_name, index_specs in REQUIRED_INDEXES.items():
        col = db[collection_name]
        existing = {idx["name"] for idx in col.list_indexes()}
        for spec in index_specs:
            name = spec["kwargs"].get("name", "unnamed")
            if name in existing:
                print(f"  [skip]  {collection_name}.{name} already exists")
                continue
            if dry_run:
                print(f"  [dry]   would create index {collection_name}.{name}")
            else:
                col.create_index(spec["keys"], **spec["kwargs"])
                print(f"  [done]  created {collection_name}.{name}")


def _backfill_experiments(db: Any, dry_run: bool) -> int:
    """Add missing Phase-8 fields to existing experiment documents.

    Uses ``$set`` only on documents where the field does not already exist,
    preserving any values set by the current code.
    """
    print("\n[migrate] Backfilling experiment documents …")
    col = db["experiments"]
    total_docs = col.count_documents({})
    print(f"  Total experiment documents: {total_docs}")

    updated = 0
    for field, default_value in NEW_EXPERIMENT_FIELDS.items():
        # Find documents missing this field
        query = {field: {"$exists": False}}
        count = col.count_documents(query)
        if count == 0:
            print(f"  [skip]  all documents already have '{field}'")
            continue
        if dry_run:
            print(f"  [dry]   would add '{field}' to {count} document(s)")
        else:
            result = col.update_many(query, {"$set": {field: default_value}})
            print(f"  [done]  added '{field}' to {result.modified_count} document(s)")
            updated += result.modified_count

    return updated


def _ensure_seed_data(db: Any, dry_run: bool) -> None:
    """Upsert the canonical device and profile seed documents.

    Uses ``$setOnInsert`` so existing documents are never modified.
    """
    from database.seed_database import SEED_DEVICES, SEED_CRYPTO_PROFILES

    print("\n[migrate] Ensuring seed data …")

    col_devices = db["devices"]
    for dev in SEED_DEVICES:
        doc_exists = col_devices.count_documents({"device_id": dev["device_id"]}) > 0
        if doc_exists:
            print(f"  [skip]  device '{dev['device_id']}' already exists")
            continue
        if dry_run:
            print(f"  [dry]   would insert device '{dev['device_id']}'")
        else:
            col_devices.update_one(
                {"device_id": dev["device_id"]},
                {"$setOnInsert": dev},
                upsert=True,
            )
            print(f"  [done]  inserted device '{dev['device_id']}'")

    col_profiles = db["crypto_profiles"]
    for prof in SEED_CRYPTO_PROFILES:
        doc_exists = col_profiles.count_documents({"profile_id": prof["profile_id"]}) > 0
        if doc_exists:
            print(f"  [skip]  profile '{prof['profile_id']}' already exists")
            continue
        if dry_run:
            print(f"  [dry]   would insert profile '{prof['profile_id']}'")
        else:
            col_profiles.update_one(
                {"profile_id": prof["profile_id"]},
                {"$setOnInsert": prof},
                upsert=True,
            )
            print(f"  [done]  inserted profile '{prof['profile_id']}'")


def run_migration(uri: str | None, db_name: str | None, dry_run: bool) -> None:
    from database.connection import get_database
    db = get_database(uri=uri, db_name=db_name)

    print(f"[migrate] Connected to database '{db.name}'")
    if dry_run:
        print("[migrate] DRY RUN — no writes will be made\n")

    _ensure_indexes(db, dry_run)
    _backfill_experiments(db, dry_run)
    _ensure_seed_data(db, dry_run)

    print("\n[migrate] Migration complete.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Idempotent Phase-8 database migration and backfill script"
    )
    parser.add_argument("--uri", default=None, help="MongoDB URI (overrides MONGODB_URI env var)")
    parser.add_argument("--db", default=None, help="Database name (overrides MONGODB_DB env var)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without making any writes",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        run_migration(uri=args.uri, db_name=args.db, dry_run=args.dry_run)
    except Exception as exc:
        print(f"[migrate] Error: {exc}", flush=True)
        sys.exit(1)
