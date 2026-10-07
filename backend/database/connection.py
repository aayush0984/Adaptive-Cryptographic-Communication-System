"""MongoDB database connection management for IoT Encryption project."""

from __future__ import annotations

from typing import Any

import pymongo
from pymongo.database import Database

from config import get_env

DEFAULT_MONGO_URI = get_env("MONGODB_URI", "mongodb://localhost:27017/")
DEFAULT_DB_NAME = get_env("MONGODB_DB", "iot_security")

_client_cache: dict[str, pymongo.MongoClient[dict[str, Any]]] = {}


def get_mongo_client(uri: str | None = None) -> pymongo.MongoClient[dict[str, Any]]:
    """Get or create a cached MongoClient instance for the given URI."""
    connection_uri = uri or DEFAULT_MONGO_URI
    if connection_uri not in _client_cache:
        _client_cache[connection_uri] = pymongo.MongoClient(connection_uri, serverSelectionTimeoutMS=3000)
    return _client_cache[connection_uri]


def get_database(uri: str | None = None, db_name: str | None = None) -> Database[dict[str, Any]]:
    """Get the MongoDB database instance for iot_security."""
    client = get_mongo_client(uri)
    target_db_name = db_name or DEFAULT_DB_NAME
    return client[target_db_name]


def get_collection(
    collection_name: str,
    uri: str | None = None,
    db_name: str | None = None,
) -> pymongo.collection.Collection[dict[str, Any]]:
    """Get a specific collection handle from the MongoDB database."""
    db = get_database(uri, db_name)
    return db[collection_name]
