"""Device configuration data model and validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from database.validators import validate_device_doc


@dataclass(frozen=True)
class Device:
    """Represents an IoT device capability and constraint profile."""

    device_id: str
    name: str
    cpu_level: str
    available_memory_kb: float
    maximum_packet_size_bytes: int
    latency_requirement_ms: float
    security_requirement: str
    supported_algorithms: list[str]
    battery_level_percent: float = 100.0
    power_source: str = "mains"
    category: str | None = None
    manufacturer: str | None = None
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "cpu_level": self.cpu_level,
            "available_memory_kb": self.available_memory_kb,
            "battery_level_percent": self.battery_level_percent,
            "maximum_packet_size_bytes": self.maximum_packet_size_bytes,
            "latency_requirement_ms": self.latency_requirement_ms,
            "security_requirement": self.security_requirement,
            "supported_algorithms": list(self.supported_algorithms),
            "power_source": self.power_source,
            "category": self.category,
            "manufacturer": self.manufacturer,
            "active": self.active,
        }

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> Device:
        validated = validate_device_doc(doc)
        return cls(
            device_id=validated["device_id"],
            name=validated.get("name", validated["device_id"]),
            cpu_level=validated["cpu_level"],
            available_memory_kb=float(validated["available_memory_kb"]),
            battery_level_percent=float(validated.get("battery_level_percent", 100.0)),
            maximum_packet_size_bytes=int(validated.get("maximum_packet_size_bytes", 1500)),
            latency_requirement_ms=float(validated.get("latency_requirement_ms", 1000)),
            security_requirement=validated["security_requirement"],
            supported_algorithms=list(validated["supported_algorithms"]),
            power_source=validated.get("power_source", "mains"),
            category=validated.get("category"),
            manufacturer=validated.get("manufacturer"),
            active=bool(validated.get("active", True)),
        )
