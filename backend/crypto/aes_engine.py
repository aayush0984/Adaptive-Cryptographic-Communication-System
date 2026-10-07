"""AES-GCM encryption helpers used by the IoT communication protocol.

The authentication tag is appended to the ciphertext by ``AESGCM.encrypt`` and
is therefore carried as part of the returned ciphertext bytes.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZES = frozenset({128, 256})
NONCE_SIZE_BYTES = 12


class AuthenticationError(ValueError):
    """Raised when ciphertext authentication or decryption fails."""


def generate_key(key_size_bits: int = 128) -> bytes:
    """Generate a cryptographically secure AES session key.

    Args:
        key_size_bits: AES key size in bits. This project supports 128 and 256.

    Returns:
        A newly generated AES key.

    Raises:
        TypeError: If ``key_size_bits`` is not an integer.
        ValueError: If the requested size is unsupported.
    """
    if isinstance(key_size_bits, bool) or not isinstance(key_size_bits, int):
        raise TypeError("key_size_bits must be an integer")
    if key_size_bits not in AES_KEY_SIZES:
        raise ValueError("key_size_bits must be 128 or 256")
    return AESGCM.generate_key(bit_length=key_size_bits)


def encrypt_message(
    message: str,
    key: bytes,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt and authenticate a UTF-8 message with AES-GCM.

    A fresh 96-bit nonce is generated for every call. The return order is
    ``(ciphertext, nonce)``; ciphertext includes the 16-byte GCM tag.
    """
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    _validate_key(key)
    _validate_associated_data(associated_data)

    nonce = os.urandom(NONCE_SIZE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        message.encode("utf-8"),
        associated_data,
    )
    return ciphertext, nonce


def decrypt_message(
    ciphertext: bytes,
    nonce: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> str:
    """Authenticate, decrypt and UTF-8 decode an AES-GCM message.

    Any authentication failure is reported through ``AuthenticationError``.
    The exception intentionally does not reveal whether the key, nonce,
    ciphertext, tag, or associated data was incorrect.
    """
    _validate_bytes("ciphertext", ciphertext)
    _validate_bytes("nonce", nonce)
    _validate_key(key)
    _validate_associated_data(associated_data)
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError(f"nonce must be exactly {NONCE_SIZE_BYTES} bytes")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise AuthenticationError(
            "message authentication failed; data may be invalid or modified"
        ) from exc


def _validate_key(key: bytes) -> None:
    _validate_bytes("key", key)
    if len(key) not in {16, 32}:
        raise ValueError("key must be 16 bytes (AES-128) or 32 bytes (AES-256)")


def _validate_associated_data(associated_data: bytes | None) -> None:
    if associated_data is not None:
        _validate_bytes("associated_data", associated_data)


def _validate_bytes(name: str, value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
