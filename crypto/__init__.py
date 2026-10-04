"""Cryptographic building blocks for secure IoT communication."""

from .aes_engine import (
    AES_KEY_SIZES,
    NONCE_SIZE_BYTES,
    AuthenticationError,
    decrypt_message,
    encrypt_message,
    generate_key,
)

__all__ = [
    "AES_KEY_SIZES",
    "NONCE_SIZE_BYTES",
    "AuthenticationError",
    "decrypt_message",
    "encrypt_message",
    "generate_key",
]
