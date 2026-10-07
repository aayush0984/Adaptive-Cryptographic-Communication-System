"""Configuration helpers for IoT Encryption project."""

from __future__ import annotations

import os
from pathlib import Path


def load_environment(path: str | Path | None = None) -> dict[str, str]:
    """Load environment variables from the project root .env file if present."""
    env_path = Path(path) if path is not None else Path(__file__).resolve().parents[1] / ".env"
    values: dict[str, str] = {}

    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value

    os.environ.setdefault("MONGODB_URI", values.get("MONGODB_URI", "mongodb://localhost:27017/"))
    os.environ.setdefault("MONGODB_DB", values.get("MONGODB_DB", "iot_security"))
    os.environ.setdefault("SERVER_HOST", values.get("SERVER_HOST", "127.0.0.1"))
    os.environ.setdefault("SERVER_PORT", values.get("SERVER_PORT", "5000"))
    return values


def get_env(name: str, default: str | None = None) -> str | None:
    """Return an environment variable from the process or the project .env file."""
    if name in os.environ:
        return os.environ[name]
    values = load_environment()
    if name in values:
        return values[name]
    return default


load_environment()
