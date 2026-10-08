"""Cryptographic building blocks for secure IoT communication."""

from .aes_engine import (
    AES_KEY_SIZES,
    NONCE_SIZE_BYTES,
    AuthenticationError,
    decrypt_message,
    encrypt_message,
    generate_key,
)
from .psk_engine import (
    PSKError,
    decrypt_with_psk,
    encrypt_with_psk,
    get_psk_key,
)

__all__ = [
    "AES_KEY_SIZES",
    "NONCE_SIZE_BYTES",
    "AuthenticationError",
    "decrypt_message",
    "encrypt_message",
    "generate_key",
    "PSKError",
    "decrypt_with_psk",
    "encrypt_with_psk",
    "get_psk_key",
]
