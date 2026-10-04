"""Unit tests for Phase 5 — Cryptographic Profile Catalogue."""

import unittest
from unittest.mock import MagicMock

from config.crypto_profiles import (
    CryptoProfile,
    ProfileValidationError,
    filter_profiles_by_security,
    get_crypto_profile,
    load_crypto_profiles,
    validate_profile_doc,
)


def sample_c1_doc() -> dict:
    return {
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
        "baseline_metrics": {"total_ms": None},
    }


def sample_c4_doc() -> dict:
    return {
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
        "baseline_metrics": {"total_ms": None},
    }


class TestCryptoProfiles(unittest.TestCase):
    def test_valid_profile_validation(self) -> None:
        c1 = validate_profile_doc(sample_c1_doc())
        self.assertEqual(c1.profile_id, "C1")
        self.assertEqual(c1.security_level, "standard")
        self.assertEqual(c1.key_establishment["family"], "RSA")

        c4 = validate_profile_doc(sample_c4_doc())
        self.assertEqual(c4.profile_id, "C4")
        self.assertEqual(c4.security_level, "high")
        self.assertEqual(c4.key_derivation["algorithm"], "HKDF-SHA256") # type: ignore

    def test_to_dict(self) -> None:
        c1 = validate_profile_doc(sample_c1_doc())
        d = c1.to_dict()
        self.assertEqual(d["profile_id"], "C1")
        self.assertEqual(d["security_level"], "standard")

    def test_validation_errors(self) -> None:
        invalid_cases = [
            ("not a dict", "not a dict"),
            ("missing profile_id", {**sample_c1_doc(), "profile_id": ""}),
            ("invalid security level", {**sample_c1_doc(), "security_level": "ultra"}),
            ("invalid cpu level", {**sample_c1_doc(), "minimum_cpu_level": "quantum"}),
            ("invalid key family", {**sample_c1_doc(), "key_establishment": {"family": "DSA", "algorithm": "x", "parameter": "1"}}),
            ("invalid symmetric alg", {**sample_c1_doc(), "symmetric_encryption": {"algorithm": "DES", "key_size_bits": 128}}),
            ("invalid key size", {**sample_c1_doc(), "symmetric_encryption": {"algorithm": "AES-GCM", "key_size_bits": 512}}),
            ("empty required algorithms", {**sample_c1_doc(), "required_algorithms": []}),
        ]
        for name, doc in invalid_cases:
            with self.subTest(case=name):
                with self.assertRaises(ProfileValidationError):
                    validate_profile_doc(doc) # type: ignore

    def test_filter_profiles_by_security(self) -> None:
        c1 = validate_profile_doc(sample_c1_doc())
        c4 = validate_profile_doc(sample_c4_doc())
        profiles = [c1, c4]

        standard_allowed = filter_profiles_by_security("standard", profiles)
        self.assertEqual(len(standard_allowed), 2)

        high_only = filter_profiles_by_security("high", profiles)
        self.assertEqual(len(high_only), 1)
        self.assertEqual(high_only[0].profile_id, "C4")

    def test_load_crypto_profiles_with_mock_db(self) -> None:
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_collection.find.return_value = [sample_c1_doc(), sample_c4_doc()]

        profiles = load_crypto_profiles(db=mock_db, active_only=True)
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0].profile_id, "C1")
        self.assertEqual(profiles[1].profile_id, "C4")

    def test_get_crypto_profile_with_mock_db(self) -> None:
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_collection.find_one.return_value = sample_c1_doc()

        p = get_crypto_profile("C1", db=mock_db)
        self.assertEqual(p.profile_id, "C1")

        mock_collection.find_one.return_value = None
        with self.assertRaises(KeyError):
            get_crypto_profile("NONEXISTENT", db=mock_db)


if __name__ == "__main__":
    unittest.main()
