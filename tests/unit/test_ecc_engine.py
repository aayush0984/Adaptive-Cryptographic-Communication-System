"""Unit tests for Phase 4 ECC/ECDH engine and key derivation."""

import unittest

from crypto.aes_engine import decrypt_message, encrypt_message
from crypto.ecc_engine import (
    ECCError,
    derive_aes_key,
    generate_key_pair,
    generate_salt,
    load_public_key,
    perform_ecdh,
    serialize_public_key,
)


class TestEccEngine(unittest.TestCase):
    def test_ecdh_and_hkdf_round_trip_for_supported_curves(self) -> None:
        profiles = [
            ("P-256", 128),
            ("P-384", 256),
        ]
        for curve_name, key_size in profiles:
            with self.subTest(curve=curve_name, key_size=key_size):
                # 1. Both devices generate ephemeral key pairs
                priv_a = generate_key_pair(curve_name) # type: ignore
                pub_a = priv_a.public_key()

                priv_b = generate_key_pair(curve_name) # type: ignore
                pub_b = priv_b.public_key()

                # 2. Serialize and load public keys
                bytes_pub_a = serialize_public_key(pub_a)
                bytes_pub_b = serialize_public_key(pub_b)

                loaded_pub_a = load_public_key(bytes_pub_a, curve_name) # type: ignore
                loaded_pub_b = load_public_key(bytes_pub_b, curve_name) # type: ignore

                # 3. Perform ECDH exchange on both sides
                secret_a = perform_ecdh(priv_a, loaded_pub_b)
                secret_b = perform_ecdh(priv_b, loaded_pub_a)

                self.assertEqual(secret_a, secret_b)

                # 4. Derive AES keys with salt & info
                salt = generate_salt()
                info = b"iot-security-handshake-v1"

                aes_key_a = derive_aes_key(secret_a, salt, key_size, info)
                aes_key_b = derive_aes_key(secret_b, salt, key_size, info)

                self.assertEqual(aes_key_a, aes_key_b)
                self.assertEqual(len(aes_key_a), key_size // 8)

                # 5. Integration with AES-GCM engine
                message = "Secure IoT payload using ECDH + HKDF"
                ciphertext, nonce = encrypt_message(message, aes_key_a)
                decrypted = decrypt_message(ciphertext, nonce, aes_key_b)
                self.assertEqual(decrypted, message)

    def test_different_hkdf_salt_or_info_produces_different_keys(self) -> None:
        priv_a = generate_key_pair("P-256")
        priv_b = generate_key_pair("P-256")
        secret = perform_ecdh(priv_a, priv_b.public_key())

        salt1 = generate_salt()
        salt2 = generate_salt()
        info1 = b"info-1"
        info2 = b"info-2"

        key1 = derive_aes_key(secret, salt1, 128, info1)
        key2 = derive_aes_key(secret, salt2, 128, info1)
        key3 = derive_aes_key(secret, salt1, 128, info2)

        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)

    def test_curve_mismatch_fails(self) -> None:
        priv_p256 = generate_key_pair("P-256")
        priv_p384 = generate_key_pair("P-384")

        pub_p384 = priv_p384.public_key()
        bytes_p384 = serialize_public_key(pub_p384)

        # 1. Validation during load_public_key
        with self.assertRaises(ECCError):
            load_public_key(bytes_p384, "P-256")

        # 2. Validation during perform_ecdh
        with self.assertRaises(ECCError):
            perform_ecdh(priv_p256, pub_p384)

    def test_corrupted_public_key_fails(self) -> None:
        with self.assertRaises(ECCError):
            load_public_key(b"-----BEGIN PUBLIC KEY-----\ncorrupted\n-----END PUBLIC KEY-----")

    def test_invalid_arguments(self) -> None:
        with self.assertRaises(ValueError):
            generate_key_pair("invalid-curve")  # type: ignore

        with self.assertRaises(TypeError):
            serialize_public_key("not a key")  # type: ignore

        with self.assertRaises(TypeError):
            load_public_key(12345)  # type: ignore

        priv = generate_key_pair("P-256")
        with self.assertRaises(TypeError):
            perform_ecdh("not priv key", priv.public_key())  # type: ignore

        secret = b"\x00" * 32
        with self.assertRaises(ValueError):
            derive_aes_key(secret, b"salt", 192)


if __name__ == "__main__":
    unittest.main()
