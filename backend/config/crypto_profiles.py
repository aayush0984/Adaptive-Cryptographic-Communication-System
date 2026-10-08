"""Phase 5 — Cryptographic Profile Catalogue module.

Maintains backward compatibility by forwarding to models and repositories.
"""

from __future__ import annotations

from typing import Any
from pymongo.database import Database

from models.crypto_profile import (
    CryptoProfile,
    ProfileValidationError,
    validate_profile_doc,
    ALLOWED_SECURITY_LEVELS,
)
from repositories.profile_repository import ProfileRepository


def load_crypto_profiles(
    db: Database[dict[str, Any]] | None = None,
    active_only: bool = True,
) -> list[CryptoProfile]:
    repo = ProfileRepository(db)
    return repo.list_enabled() if active_only else repo.list_all()


def get_crypto_profile(
    profile_id: str,
    db: Database[dict[str, Any]] | None = None,
) -> CryptoProfile:
    repo = ProfileRepository(db)
    return repo.get_by_id(profile_id)


def filter_profiles_by_security(
    min_security_level: str,
    profiles: list[CryptoProfile],
) -> list[CryptoProfile]:
    if min_security_level not in ALLOWED_SECURITY_LEVELS:
        raise ValueError(f"Invalid min_security_level '{min_security_level}'. Allowed: {ALLOWED_SECURITY_LEVELS}")

    if min_security_level == "high":
        return [p for p in profiles if p.security_level == "high"]
    if min_security_level == "standard":
        return [p for p in profiles if p.security_level in ("standard", "high")]
    return [p for p in profiles if p.security_level in ("basic", "standard", "high")]
