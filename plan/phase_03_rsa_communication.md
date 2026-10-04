# Phase 3 — RSA-Based Hybrid Communication

## Goal

Implement profiles C1 and C2 loaded from `iot_security.crypto_profiles`.

## Profiles

- C1: RSA-2048 OAEP/SHA-256 + AES-128-GCM
- C2: RSA-3072 OAEP/SHA-256 + AES-256-GCM

The key size, padding, hash and AES size must come from the selected profile document.

## Sender-receiver flow

1. Device B generates the configured RSA key pair.
2. B serializes and sends its public key.
3. A validates the key size and generates a fresh AES session key.
4. A encrypts the message with AES-GCM.
5. A wraps the AES key using RSA-OAEP with SHA-256 and MGF1.
6. A sends the selected profile ID, wrapped key, nonce and ciphertext.
7. B unwraps the key and decrypts/authenticates the message.

## MongoDB integration

Store in `experiments`:

- selected profile ID;
- sender and receiver device IDs;
- key-generation, wrap, unwrap, encryption and decryption timings;
- message and ciphertext sizes;
- success/failure and sanitized error category.

Never store RSA private keys, AES keys, wrapped-key plaintext or message plaintext.

## Tests

Test both RSA profiles, wrong private keys, modified wrapped keys, profile/key-size mismatch and end-to-end round trips.

## Deliverable

`crypto/rsa_engine.py` integrated with AES, TCP framing and experiment updates.

