"""Unit tests for the Phase 3 RSA engine."""

import unittest

from crypto.aes_engine import generate_key as generate_aes_key
from crypto.rsa_engine import (
    RSAError,
    generate_key_pair,
    load_public_key,
    serialize_public_key,
    unwrap_aes_key,
    wrap_aes_key,
)


class TestRsaEngine(unittest.TestCase):
    def test_rsa_round_trip_for_supported_key_sizes(self) -> None:
        for rsa_size in (2048, 3072):
            for aes_size in (128, 256):
                with self.subTest(rsa_size=rsa_size, aes_size=aes_size):
                    # 1. Device B generates RSA key pair
                    private_key = generate_key_pair(rsa_size)
                    public_key = private_key.public_key()
                    
                    # 2. Device B serializes public key
                    serialized_pub = serialize_public_key(public_key)
                    self.assertIn(b"BEGIN PUBLIC KEY", serialized_pub)
                    self.assertNotIn(b"PRIVATE KEY", serialized_pub)
                    
                    # 3. Device A loads public key and generates AES key
                    loaded_pub = load_public_key(serialized_pub)
                    aes_key = generate_aes_key(aes_size)
                    
                    # 4. Device A wraps AES key
                    wrapped_key = wrap_aes_key(aes_key, loaded_pub)
                    self.assertNotEqual(aes_key, wrapped_key)
                    
                    # 5. Device B unwraps AES key
                    unwrapped_key = unwrap_aes_key(wrapped_key, private_key)
                    self.assertEqual(aes_key, unwrapped_key)

    def test_wrong_private_key_fails(self) -> None:
        private_key1 = generate_key_pair(2048)
        private_key2 = generate_key_pair(2048)
        
        aes_key = generate_aes_key(128)
        wrapped_key = wrap_aes_key(aes_key, private_key1.public_key())
        
        with self.assertRaises(RSAError):
            unwrap_aes_key(wrapped_key, private_key2)

    def test_modified_wrapped_key_fails(self) -> None:
        private_key = generate_key_pair(2048)
        aes_key = generate_aes_key(128)
        wrapped_key = wrap_aes_key(aes_key, private_key.public_key())
        
        # Modify the last byte
        modified = wrapped_key[:-1] + bytes([wrapped_key[-1] ^ 1])
        
        with self.assertRaises(RSAError):
            unwrap_aes_key(modified, private_key)

    def test_invalid_public_key_data_fails_to_load(self) -> None:
        with self.assertRaises(RSAError):
            load_public_key(b"not a valid pem public key")

    def test_rejects_invalid_key_size(self) -> None:
        with self.assertRaises(ValueError):
            generate_key_pair(1024)
            
    def test_invalid_argument_types(self) -> None:
        private_key = generate_key_pair(2048)
        with self.assertRaises(TypeError):
            wrap_aes_key("not bytes", private_key.public_key())  # type: ignore
        with self.assertRaises(TypeError):
            unwrap_aes_key("not bytes", private_key)  # type: ignore


if __name__ == "__main__":
    unittest.main()
