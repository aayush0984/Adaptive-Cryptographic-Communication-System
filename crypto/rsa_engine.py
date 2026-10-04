"""RSA engine for wrapping and unwrapping AES session keys."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization


class RSAError(ValueError):
    """Raised when RSA key wrapping, unwrapping, or loading fails."""


def generate_key_pair(key_size_bits: int = 2048) -> rsa.RSAPrivateKey:
    """Generate a new RSA private key.
    
    Args:
        key_size_bits: The size of the RSA key in bits (e.g., 2048, 3072).
        
    Returns:
        The generated RSA private key.
    """
    if not isinstance(key_size_bits, int) or key_size_bits < 2048:
        raise ValueError("key_size_bits must be an integer >= 2048")
        
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
    )


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data: bytes) -> rsa.RSAPublicKey:
    """Load an RSA public key from PEM format bytes."""
    try:
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("Loaded key is not an RSA public key")
        return key
    except Exception as exc:
        raise RSAError("Failed to load public key") from exc


def wrap_aes_key(aes_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Wrap an AES session key using RSA-OAEP with SHA-256."""
    if not isinstance(aes_key, bytes):
        raise TypeError("aes_key must be bytes")
    
    try:
        return public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as exc:
        raise RSAError("Failed to wrap AES key") from exc


def unwrap_aes_key(wrapped_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Unwrap an AES session key using RSA-OAEP with SHA-256."""
    if not isinstance(wrapped_key, bytes):
        raise TypeError("wrapped_key must be bytes")
        
    try:
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as exc:
        raise RSAError("Failed to unwrap AES key") from exc
