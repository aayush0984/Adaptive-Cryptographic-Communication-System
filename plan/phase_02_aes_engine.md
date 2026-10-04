# Phase 2 — AES-GCM Engine

## Goal

Encrypt and authenticate the actual sender-to-receiver message using AES-128-GCM or AES-256-GCM as specified by the selected MongoDB profile.

## Tasks

1. Receive the selected profile document from the selection layer.
2. Read `message_encryption.key_size`; do not hardcode 128 or 256.
3. Generate a fresh session key with `AESGCM.generate_key()`.
4. Generate a unique 12-byte nonce with `os.urandom(12)`.
5. Encode plaintext as UTF-8 and encrypt it.
6. Use stable protocol metadata as authenticated associated data.
7. Return bytes internally and Base64-encode only at the JSON protocol boundary.
8. Measure encryption and decryption time.
9. Store only timings, sizes and success status in MongoDB—not keys, nonce reuse state or plaintext.

## Interface

```python
encrypt_message(plaintext, key, nonce, associated_data=None)
decrypt_message(ciphertext, key, nonce, associated_data=None)
```

## Security rules

- Never use ECB.
- Never reuse a nonce with the same key.
- Never log or store the AES key.
- Authentication failure must abort the session.
- Database data is configuration metadata, not key storage.

## Tests

Test both key sizes, Unicode and varying message sizes. Wrong keys, changed nonces, modified ciphertext and altered associated data must fail.

## Deliverable

`crypto/aes_engine.py` and automated tests integrated with the selected `crypto_profiles` document.

