"""Cryptographic Profile data model and schema validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ALLOWED_SECURITY_LEVELS = {"standard", "high"}
ALLOWED_CPU_LEVELS = {"low", "medium", "high"}
ALLOWED_KEY_FAMILIES = {"RSA", "ECC"}


class ProfileValidationError(ValueError):
    """Raised when a cryptographic profile document fails schema or rule validation."""


@dataclass(frozen=True)
class CryptoProfile:
    """Represents a validated cryptographic configuration profile."""

    profile_id: str
    name: str
    security_level: str
    minimum_cpu_level: str
    active: bool
    key_establishment: dict[str, Any]
    symmetric_encryption: dict[str, Any]
    required_algorithms: list[str]
    key_derivation: dict[str, Any] | None = None
    baseline_metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert CryptoProfile back to a dictionary representation."""
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "security_level": self.security_level,
            "minimum_cpu_level": self.minimum_cpu_level,
            "active": self.active,
            "key_establishment": dict(self.key_establishment),
            "key_derivation": dict(self.key_derivation) if self.key_derivation else None,
            "symmetric_encryption": dict(self.symmetric_encryption),
            "required_algorithms": list(self.required_algorithms),
            "baseline_metrics": dict(self.baseline_metrics),
        }


def validate_profile_doc(doc: dict[str, Any]) -> CryptoProfile:
    """Validate a raw dictionary/MongoDB document against the CryptoProfile schema rules."""
    if not isinstance(doc, dict):
        raise ProfileValidationError("Profile document must be a dictionary")

    profile_id = doc.get("profile_id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        raise ProfileValidationError("profile_id must be a non-empty string")

    name = doc.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ProfileValidationError(f"[{profile_id}] name must be a non-empty string")

    sec_level = doc.get("security_level")
    if sec_level not in ALLOWED_SECURITY_LEVELS:
        raise ProfileValidationError(
            f"[{profile_id}] security_level must be one of {ALLOWED_SECURITY_LEVELS}, got '{sec_level}'"
        )

    cpu_level = doc.get("minimum_cpu_level")
    if cpu_level not in ALLOWED_CPU_LEVELS:
        raise ProfileValidationError(
            f"[{profile_id}] minimum_cpu_level must be one of {ALLOWED_CPU_LEVELS}, got '{cpu_level}'"
        )

    active = doc.get("active", True)
    if not isinstance(active, bool):
        raise ProfileValidationError(f"[{profile_id}] active must be a boolean")

    key_est = doc.get("key_establishment")
    if not isinstance(key_est, dict):
        raise ProfileValidationError(f"[{profile_id}] key_establishment must be a dict")

    family = key_est.get("family")
    if family not in ALLOWED_KEY_FAMILIES:
        raise ProfileValidationError(
            f"[{profile_id}] key_establishment.family must be one of {ALLOWED_KEY_FAMILIES}, got '{family}'"
        )

    algorithm = key_est.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise ProfileValidationError(f"[{profile_id}] key_establishment.algorithm must be a non-empty string")

    parameter = key_est.get("parameter")
    if not isinstance(parameter, str) or not parameter.strip():
        raise ProfileValidationError(f"[{profile_id}] key_establishment.parameter must be a non-empty string")

    sym_enc = doc.get("symmetric_encryption")
    if not isinstance(sym_enc, dict):
        raise ProfileValidationError(f"[{profile_id}] symmetric_encryption must be a dict")

    sym_alg = sym_enc.get("algorithm")
    if sym_alg != "AES-GCM":
        raise ProfileValidationError(f"[{profile_id}] symmetric_encryption.algorithm must be 'AES-GCM'")

    key_size = sym_enc.get("key_size_bits")
    if key_size not in (128, 256):
        raise ProfileValidationError(f"[{profile_id}] symmetric_encryption.key_size_bits must be 128 or 256")

    req_algs = doc.get("required_algorithms")
    if not isinstance(req_algs, list) or not req_algs:
        raise ProfileValidationError(f"[{profile_id}] required_algorithms must be a non-empty list of strings")

    key_derivation = doc.get("key_derivation")
    if key_derivation is not None and not isinstance(key_derivation, dict):
        raise ProfileValidationError(f"[{profile_id}] key_derivation must be a dict or None")

    baseline_metrics = doc.get("baseline_metrics", {})
    if not isinstance(baseline_metrics, dict):
        raise ProfileValidationError(f"[{profile_id}] baseline_metrics must be a dict")

    return CryptoProfile(
        profile_id=profile_id,
        name=name,
        security_level=sec_level,
        minimum_cpu_level=cpu_level,
        active=active,
        key_establishment=dict(key_est),
        key_derivation=dict(key_derivation) if key_derivation else None,
        symmetric_encryption=dict(sym_enc),
        required_algorithms=list(req_algs),
        baseline_metrics=dict(baseline_metrics),
    )
