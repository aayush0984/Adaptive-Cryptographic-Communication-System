"""MongoDB document schema validators and rule helpers."""

from __future__ import annotations

from typing import Any


class ValidationError(ValueError):
    """Raised when a document fails schema validation."""


def validate_device_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """Validate a raw device document."""
    if not isinstance(doc, dict):
        raise ValidationError("Device document must be a dictionary")

    device_id = doc.get("device_id")
    if not isinstance(device_id, str) or not device_id.strip():
        raise ValidationError("device_id must be a non-empty string")

    cpu_level = doc.get("cpu_level")
    if cpu_level not in ("low", "medium", "high"):
        raise ValidationError(f"[{device_id}] cpu_level must be 'low', 'medium', or 'high'")

    mem = doc.get("available_memory_kb")
    if not isinstance(mem, (int, float)) or mem <= 0:
        raise ValidationError(f"[{device_id}] available_memory_kb must be a positive number")

    battery = doc.get("battery_level_percent")
    if battery is not None and (not isinstance(battery, (int, float)) or not (0 <= battery <= 100)):
        raise ValidationError(f"[{device_id}] battery_level_percent must be between 0 and 100")

    sec_req = doc.get("security_requirement")
    if sec_req not in ("standard", "high"):
        raise ValidationError(f"[{device_id}] security_requirement must be 'standard' or 'high'")

    supported_algs = doc.get("supported_algorithms")
    if not isinstance(supported_algs, list) or not supported_algs:
        raise ValidationError(f"[{device_id}] supported_algorithms must be a non-empty list")

    return doc
