# Phase 4 — ECC/ECDH-Based Communication

## Goal

Implement profiles C3 and C4 loaded from `iot_security.crypto_profiles`.

## Profiles

- C3: ECDH P-256 + HKDF-SHA256 + AES-128-GCM
- C4: ECDH P-384 + HKDF-SHA256 + AES-256-GCM

## Sender-receiver flow

1. A and B generate ephemeral key pairs on the curve named by the selected profile.
2. They exchange only serialized public keys.
3. Each validates the peer key and performs ECDH.
4. Each supplies the shared secret, fresh salt and protocol-specific `info` to HKDF-SHA256.
5. Both independently derive the same AES key length specified by the profile.
6. A encrypts with AES-GCM and B authenticates/decrypts.

## MongoDB integration

Store curve, profile ID, timing, public-message sizes and success status in `experiments`. Never store EC private keys, derived AES keys or raw shared secrets.

## Security rules

- Do not use the raw ECDH secret as an AES key.
- Reject incorrect curves and invalid public keys.
- Use ephemeral keys per session.
- Bind session/profile metadata through HKDF `info` and/or AES associated data.

## Tests

Verify identical derived keys, both profiles, modified public keys, mismatched curves, different HKDF inputs and full client-server communication.

## Deliverable

`crypto/ecc_engine.py` integrated with AES, TCP framing and experiment updates.

