"""Database connection module (backwards-compatibility wrapper around database.connection)."""

from database.connection import get_collection, get_database, get_mongo_client

__all__ = ["get_mongo_client", "get_database", "get_collection"]
