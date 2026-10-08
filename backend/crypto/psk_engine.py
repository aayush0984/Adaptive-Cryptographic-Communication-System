"""PSK (Pre-Shared Key) encryption engine for C5 fallback profile.

Provides AES-128-GCM authenticated encryption and decryption using a
pre-shared 128-bit key loaded from environment/configuration without RSA/ECDH.
"""

from __future__ import annotations

from typing import Optional

from config import get_env
from crypto.aes_engine import (
    AuthenticationError,
    decrypt_message,
    encrypt_message,
)

DEFAULT_FALLBACK_PSK_HEX = "0123456789abcdef0123456789abcdef"  # 128-bit hex key


class PSKError(ValueError):
    """Raised when PSK configuration or parameters are invalid."""


def get_psk_key() -> bytes:
    """Retrieve the configured 128-bit Pre-Shared Key (PSK) for fallback encryption.

    Checks FALLBACK_PSK_HEX, FALLBACK_PSK, C5_PSK_HEX, and C5_PSK.
    Accepts 32-character hexadecimal strings or 16-byte UTF-8/raw strings.
    """
    raw = (
        get_env("FALLBACK_PSK_HEX")
        or get_env("FALLBACK_PSK")
        or get_env("C5_PSK_HEX")
        or get_env("C5_PSK")
    )
    if not raw:
        raw = DEFAULT_FALLBACK_PSK_HEX

    raw = raw.strip()
    # Try hex decoding first
    try:
        key_bytes = bytes.fromhex(raw)
        if len(key_bytes) == 16:
            return key_bytes
    except ValueError:
        pass

    # Try raw bytes encoding
    key_bytes = raw.encode("utf-8")
    if len(key_bytes) == 16:
        return key_bytes

    raise PSKError(
        f"Invalid Pre-Shared Key (PSK) configuration: expected 16 bytes (128 bits), got {len(key_bytes)} bytes"
    )


def encrypt_with_psk(
    message: str,
    key: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> tuple[bytes, bytes]:
    """Encrypt and authenticate a UTF-8 message using AES-128-GCM and the pre-shared key.

    Returns:
        tuple[bytes, bytes]: (ciphertext_with_tag, nonce)
    """
    psk = key if key is not None else get_psk_key()
    return encrypt_message(message, psk, associated_data=associated_data)


def decrypt_with_psk(
    ciphertext: bytes,
    nonce: bytes,
    key: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    """Authenticate and decrypt an AES-128-GCM ciphertext using the pre-shared key.

    Raises:
        AuthenticationError: If tag authentication fails or data was tampered with.
    """
    psk = key if key is not None else get_psk_key()
    return decrypt_message(ciphertext, nonce, psk, associated_data=associated_data)

