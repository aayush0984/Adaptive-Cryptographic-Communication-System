"""Unit tests for the Phase 2 AES-GCM engine."""

import unittest

from crypto.aes_engine import (
    NONCE_SIZE_BYTES,
    AuthenticationError,
    decrypt_message,
    encrypt_message,
    generate_key,
)


class TestAesEngine(unittest.TestCase):
    def test_aes_128_and_256_round_trips_for_required_messages(self) -> None:
        messages = [
            "", "Temperature = 31.4 C",
            "IoT reading:  Temperatue = 25.6 °C",
            "a" * 1024, "b" * (100 * 1024),
        ]
        for key_size in (128, 256):
            for message in messages:
                with self.subTest(key_size=key_size, message_length=len(message)):
                    key = generate_key(key_size)
                    ciphertext, nonce = encrypt_message(message, key)
                    self.assertEqual(decrypt_message(ciphertext, nonce, key), message)
                    self.assertEqual(len(nonce), NONCE_SIZE_BYTES)
                    if message:
                        self.assertNotIn(message.encode("utf-8"), ciphertext)

    def test_associated_data_round_trip(self) -> None:
        key = generate_key()
        metadata = b'{"sender":"device_a","receiver":"device_b"}'
        ciphertext, nonce = encrypt_message("authenticated metadata", key, metadata)
        self.assertEqual(decrypt_message(ciphertext, nonce, key, metadata), "authenticated metadata")

    def test_wrong_key_fails(self) -> None:
        key = generate_key()
        ciphertext, nonce = encrypt_message("secret reading", key)
        with self.assertRaises(AuthenticationError):
            decrypt_message(ciphertext, nonce, generate_key())

    def test_changed_nonce_fails(self) -> None:
        key = generate_key()
        ciphertext, nonce = encrypt_message("secret reading", key)
        changed_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
        with self.assertRaises(AuthenticationError):
            decrypt_message(ciphertext, changed_nonce, key)

    def test_modified_ciphertext_fails(self) -> None:
        key = generate_key()
        ciphertext, nonce = encrypt_message("secret reading", key)
        modified = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaises(AuthenticationError):
            decrypt_message(modified, nonce, key)

    def test_changed_associated_data_fails(self) -> None:
        key = generate_key()
        ciphertext, nonce = encrypt_message("secret", key, b"type:reading")
        with self.assertRaises(AuthenticationError):
            decrypt_message(ciphertext, nonce, key, b"type:command")

    def test_repeated_encryption_uses_fresh_nonce(self) -> None:
        key = generate_key(256)
        first_ciphertext, first_nonce = encrypt_message("same message", key)
        second_ciphertext, second_nonce = encrypt_message("same message", key)
        self.assertNotEqual(first_nonce, second_nonce)
        self.assertNotEqual(first_ciphertext, second_ciphertext)

    def test_rejects_unsupported_key_sizes(self) -> None:
        for invalid_size in (0, 64, 192, 512):
            with self.subTest(invalid_size=invalid_size):
                with self.assertRaisesRegex(ValueError, "128 or 256"):
                    generate_key(invalid_size)

    def test_rejects_invalid_argument_types(self) -> None:
        key = generate_key()
        with self.assertRaisesRegex(TypeError, "message must be a string"):
            encrypt_message(b"not text", key)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "associated_data must be bytes"):
            encrypt_message("message", key, "metadata")  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "ciphertext must be bytes"):
            decrypt_message("not bytes", b"0" * 12, key)  # type: ignore[arg-type]

    def test_rejects_invalid_key_and_nonce_lengths(self) -> None:
        with self.assertRaisesRegex(ValueError, "key must be"):
            encrypt_message("message", b"short")
        key = generate_key()
        with self.assertRaisesRegex(ValueError, "nonce must be exactly"):
            decrypt_message(b"ciphertext", b"short", key)


if __name__ == "__main__":
    unittest.main()
