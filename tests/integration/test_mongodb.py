"""Integration tests for MongoDB connection, repository querying, and seeding."""

import unittest
from pymongo.errors import ServerSelectionTimeoutError

from database.connection import get_database, get_mongo_client
from database.seed_database import seed_database
from repositories.device_repository import DeviceRepository
from repositories.profile_repository import ProfileRepository


class TestMongoDBIntegration(unittest.TestCase):
    def setUp(self) -> None:
        try:
            client = get_mongo_client()
            client.admin.command("ping")
        except (ServerSelectionTimeoutError, Exception) as exc:
            self.skipTest(f"MongoDB not reachable for integration tests: {exc}")

    def test_database_connection_and_seeding(self) -> None:
        db = get_database()
        result = seed_database(db)
        self.assertGreaterEqual(result["crypto_profiles"], 1)
        self.assertGreaterEqual(result["devices"], 1)

    def test_profile_repository(self) -> None:
        repo = ProfileRepository()
        profiles = repo.list_enabled()
        self.assertGreaterEqual(len(profiles), 4)

        p1 = repo.get_by_id("C1")
        self.assertEqual(p1.profile_id, "C1")
        self.assertEqual(p1.security_level, "standard")

    def test_device_repository(self) -> None:
        repo = DeviceRepository()
        devices = repo.list_active()
        self.assertGreaterEqual(len(devices), 2)

        dev_a = repo.get_by_id("device_a")
        self.assertEqual(dev_a.device_id, "device_a")


if __name__ == "__main__":
    unittest.main()
