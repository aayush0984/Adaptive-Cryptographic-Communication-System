"""Elliptic-Curve Diffie-Hellman (ECDH) key exchange and HKDF key derivation engine."""

from __future__ import annotations

import os
from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SUPPORTED_CURVES = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
}

CurveName = Literal["P-256", "P-384"]


class ECCError(ValueError):
    """Raised when ECC key exchange, loading, or key derivation fails."""


def generate_key_pair(curve_name: CurveName = "P-256") -> ec.EllipticCurvePrivateKey:
    """Generate an ephemeral EC private key.

    Args:
        curve_name: "P-256" or "P-384".

    Returns:
        The generated EC private key.
    """
    if curve_name not in SUPPORTED_CURVES:
        raise ValueError(f"Unsupported curve: {curve_name}. Supported: {list(SUPPORTED_CURVES.keys())}")
    
    curve = SUPPORTED_CURVES[curve_name]()
    return ec.generate_private_key(curve)


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize an EC public key to PEM format."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("public_key must be an EllipticCurvePublicKey instance")

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(data: bytes, expected_curve_name: CurveName | None = None) -> ec.EllipticCurvePublicKey:
    """Load an EC public key from PEM format bytes and validate its curve.

    Args:
        data: PEM bytes of the public key.
        expected_curve_name: Optional curve name ("P-256" or "P-384") to validate against.

    Returns:
        The loaded EC public key.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    try:
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("Loaded key is not an Elliptic Curve public key")

        if expected_curve_name is not None:
            if expected_curve_name not in SUPPORTED_CURVES:
                raise ValueError(f"Unsupported expected curve: {expected_curve_name}")
            expected_curve_cls = SUPPORTED_CURVES[expected_curve_name]
            if not isinstance(key.curve, expected_curve_cls):
                raise ECCError(
                    f"Public key curve '{key.curve.name}' does not match expected curve '{expected_curve_name}'"
                )

        return key
    except Exception as exc:
        if isinstance(exc, (TypeError, ECCError)):
            raise
        raise ECCError("Failed to load EC public key") from exc


def perform_ecdh(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    """Perform ECDH to compute raw shared secret between private key and peer public key.

    Args:
        private_key: Own EC private key.
        peer_public_key: Peer's EC public key.

    Returns:
        Raw shared secret bytes.
    """
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("private_key must be an EllipticCurvePrivateKey instance")
    if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("peer_public_key must be an EllipticCurvePublicKey instance")

    if type(private_key.curve) is not type(peer_public_key.curve):
        raise ECCError(
            f"Curve mismatch between private key ({private_key.curve.name}) and peer public key ({peer_public_key.curve.name})"
        )

    try:
        return private_key.exchange(ec.ECDH(), peer_public_key)
    except Exception as exc:
        raise ECCError("ECDH exchange failed") from exc


def derive_aes_key(
    shared_secret: bytes,
    salt: bytes,
    key_size_bits: int = 128,
    info: bytes = b"iot-security-handshake",
) -> bytes:
    """Derive an AES session key from raw ECDH shared secret using HKDF-SHA256.

    Args:
        shared_secret: Raw shared secret bytes from ECDH.
        salt: Fresh random salt bytes.
        key_size_bits: Desired key length (128 or 256).
        info: Application/protocol specific context bytes.

    Returns:
        Derived AES session key bytes (16 or 32 bytes).
    """
    if not isinstance(shared_secret, bytes):
        raise TypeError("shared_secret must be bytes")
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")
    if not isinstance(info, bytes):
        raise TypeError("info must be bytes")
    if key_size_bits not in (128, 256):
        raise ValueError("key_size_bits must be 128 or 256")

    length_bytes = key_size_bits // 8

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length_bytes,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_secret)
    except Exception as exc:
        raise ECCError("HKDF key derivation failed") from exc


def generate_salt(length_bytes: int = 16) -> bytes:
    """Generate cryptographically secure random salt for HKDF."""
    if not isinstance(length_bytes, int) or length_bytes < 8:
        raise ValueError("salt length must be an integer >= 8")
    return os.urandom(length_bytes)
