"""Database seeder module for populating initial devices and crypto profiles into MongoDB idempotently."""

from __future__ import annotations

from typing import Any
from pymongo.database import Database

from database.connection import get_database
from database.indexes import create_indexes

SEED_CRYPTO_PROFILES = [
    {
        "profile_id": "C1",
        "name": "RSA-2048 with AES-128-GCM",
        "security_level": "standard",
        "minimum_cpu_level": "low",
        "active": True,
        "key_establishment": {
            "family": "RSA",
            "algorithm": "RSA-OAEP",
            "parameter": "2048",
            "hash": "SHA-256",
        },
        "key_derivation": None,
        "symmetric_encryption": {
            "algorithm": "AES-GCM",
            "key_size_bits": 128,
            "nonce_size_bytes": 12,
            "authentication_tag_size_bytes": 16,
        },
        "required_algorithms": ["RSA-2048", "AES-128-GCM"],
        "baseline_metrics": {
            "total_ms": None,
            "peak_memory_kb": None,
            "communication_bytes": None,
            "energy_proxy": None,
        },
    },
    {
        "profile_id": "C2",
        "name": "RSA-3072 with AES-256-GCM",
        "security_level": "high",
        "minimum_cpu_level": "high",
        "active": True,
        "key_establishment": {
            "family": "RSA",
            "algorithm": "RSA-OAEP",
            "parameter": "3072",
            "hash": "SHA-256",
        },
        "key_derivation": None,
        "symmetric_encryption": {
            "algorithm": "AES-GCM",
            "key_size_bits": 256,
            "nonce_size_bytes": 12,
            "authentication_tag_size_bytes": 16,
        },
        "required_algorithms": ["RSA-3072", "AES-256-GCM"],
        "baseline_metrics": {
            "total_ms": None,
            "peak_memory_kb": None,
            "communication_bytes": None,
            "energy_proxy": None,
        },
    },
    {
        "profile_id": "C3",
        "name": "ECDH-P256 with AES-128-GCM",
        "security_level": "standard",
        "minimum_cpu_level": "low",
        "active": True,
        "key_establishment": {
            "family": "ECC",
            "algorithm": "ECDH",
            "parameter": "P-256",
            "hash": None,
        },
        "key_derivation": {
            "algorithm": "HKDF-SHA256",
            "output_key_size_bits": 128,
        },
        "symmetric_encryption": {
            "algorithm": "AES-GCM",
            "key_size_bits": 128,
            "nonce_size_bytes": 12,
            "authentication_tag_size_bytes": 16,
        },
        "required_algorithms": ["ECDH-P256", "AES-128-GCM"],
        "baseline_metrics": {
            "total_ms": None,
            "peak_memory_kb": None,
            "communication_bytes": None,
            "energy_proxy": None,
        },
    },
    {
        "profile_id": "C4",
        "name": "ECDH-P384 with AES-256-GCM",
        "security_level": "high",
        "minimum_cpu_level": "medium",
        "active": True,
        "key_establishment": {
            "family": "ECC",
            "algorithm": "ECDH",
            "parameter": "P-384",
            "hash": None,
        },
        "key_derivation": {
            "algorithm": "HKDF-SHA256",
            "output_key_size_bits": 256,
        },
        "symmetric_encryption": {
            "algorithm": "AES-GCM",
            "key_size_bits": 256,
            "nonce_size_bytes": 12,
            "authentication_tag_size_bytes": 16,
        },
        "required_algorithms": ["ECDH-P384", "AES-256-GCM"],
        "baseline_metrics": {
            "total_ms": None,
            "peak_memory_kb": None,
            "communication_bytes": None,
            "energy_proxy": None,
        },
    },
]

SEED_DEVICES = [
    {
        "device_id": "device_a",
        "name": "IoT Client Gateway (Device A)",
        "cpu_level": "medium",
        "available_memory_kb": 2048,
        "battery_level_percent": 80,
        "maximum_packet_size_bytes": 1500,
        "latency_requirement_ms": 500,
        "security_requirement": "standard",
        "supported_algorithms": ["RSA-2048", "RSA-3072", "ECDH-P256", "ECDH-P384", "AES-128-GCM", "AES-256-GCM"],
        "active": True,
    },
    {
        "device_id": "device_b",
        "name": "IoT Sensor Node (Device B)",
        "cpu_level": "low",
        "available_memory_kb": 512,
        "battery_level_percent": 45,
        "maximum_packet_size_bytes": 1024,
        "latency_requirement_ms": 300,
        "security_requirement": "standard",
        "supported_algorithms": ["RSA-2048", "ECDH-P256", "AES-128-GCM"],
        "active": True,
    },
]


def seed_database(db: Database[dict[str, Any]] | None = None) -> dict[str, int]:
    """Seed devices and crypto profiles using upsert operations."""
    database = db if db is not None else get_database()
    create_indexes(database)

    # Seed crypto profiles
    profiles_col = database["crypto_profiles"]
    prof_count = 0
    for prof in SEED_CRYPTO_PROFILES:
        res = profiles_col.update_one(
            {"profile_id": prof["profile_id"]},
            {"$set": prof},
            upsert=True,
        )
        if res.upserted_id or res.matched_count or res.modified_count:
            prof_count += 1

    # Seed devices
    devices_col = database["devices"]
    dev_count = 0
    for dev in SEED_DEVICES:
        res = devices_col.update_one(
            {"device_id": dev["device_id"]},
            {"$set": dev},
            upsert=True,
        )
        if res.upserted_id or res.matched_count or res.modified_count:
            dev_count += 1

    return {"crypto_profiles": prof_count, "devices": dev_count}


if __name__ == "__main__":
    result = seed_database()
    print("Database seeding completed:", result)
