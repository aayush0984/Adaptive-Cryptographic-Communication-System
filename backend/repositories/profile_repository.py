"""Repository layer for Cryptographic Profiles MongoDB collection operations."""

from __future__ import annotations

from typing import Any
from pymongo.database import Database

from database.connection import get_database
from models.crypto_profile import CryptoProfile, validate_profile_doc, ALLOWED_SECURITY_LEVELS


class ProfileRepository:
    """Repository for managing crypto profiles in MongoDB."""

    def __init__(self, db: Database[dict[str, Any]] | None = None) -> None:
        self.db = db if db is not None else get_database()
        self.collection = self.db["crypto_profiles"]

    def list_enabled(self) -> list[CryptoProfile]:
        """List all active/enabled crypto profiles."""
        docs = list(self.collection.find({"active": True}))
        return [validate_profile_doc(doc) for doc in docs]

    def list_all(self) -> list[CryptoProfile]:
        """List all crypto profiles."""
        docs = list(self.collection.find())
        return [validate_profile_doc(doc) for doc in docs]

    def get_by_id(self, profile_id: str) -> CryptoProfile:
        """Get a profile by its profile_id."""
        doc = self.collection.find_one({"profile_id": profile_id})
        if not doc:
            raise KeyError(f"CryptoProfile '{profile_id}' not found")
        return validate_profile_doc(doc)

    def filter_by_security(self, min_security_level: str) -> list[CryptoProfile]:
        """Filter enabled profiles by minimum security level."""
        if min_security_level not in ALLOWED_SECURITY_LEVELS:
            raise ValueError(f"Invalid min_security_level '{min_security_level}'. Allowed: {ALLOWED_SECURITY_LEVELS}")

        enabled = self.list_enabled()
        if min_security_level == "high":
            return [p for p in enabled if p.security_level == "high"]
        if min_security_level == "standard":
            return [p for p in enabled if p.security_level in ("standard", "high")]
        return [p for p in enabled if p.security_level in ("basic", "standard", "high")]
