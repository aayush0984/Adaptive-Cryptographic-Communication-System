# Phase 5 — MongoDB Cryptographic Profile Catalogue

## Goal

Store all selectable configurations in `iot_security.crypto_profiles` so the selection logic contains no hardcoded algorithm list.

## Example document

```json
{
  "_id": "C3",
  "name": "ECDH-P256 + AES-128-GCM",
  "key_establishment": {
    "algorithm": "ECDH",
    "curve": "P-256",
    "key_derivation": "HKDF-SHA256"
  },
  "message_encryption": {
    "algorithm": "AES",
    "key_size": 128,
    "mode": "GCM"
  },
  "required_capabilities": ["ECDH-P256", "AES-128-GCM"],
  "security_level": 1,
  "enabled": true
}
```

## Required seed profiles

Create C1, C2, C3 and C4 matching the project overview. Use stable string IDs because these IDs appear in protocol messages, benchmarks, experiments and capture filenames.

## Tasks

1. Seed profiles idempotently with `update_one(..., upsert=True)`.
2. Query only `{"enabled": true}`.
3. Validate algorithm-specific fields.
4. Check that `required_capabilities` contains both key-establishment and symmetric capabilities.
5. Keep performance data out of profile documents; it belongs in `benchmarks`.
6. Create a unique index on `name`.

## Compatibility rule

A profile is compatible only if:

```text
set(profile.required_capabilities)
    is a subset of
common capabilities of Device A and Device B
```

## Deliverable

A validated MongoDB profile catalogue and `profile_repository.py`.

