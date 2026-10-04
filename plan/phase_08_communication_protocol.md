# Phase 8 — Secure Sender-Receiver Protocol

## Goal

Perform real TCP communication between Device A (client/sender) and Device B (server/receiver) using the profile selected from MongoDB.

## Initial deployment

Use `127.0.0.1:5000` for same-computer development, then allow configurable hosts for separate machines.

## Framing

Serialize protocol objects as UTF-8 JSON. Prefix each object with a four-byte unsigned network-order length. The receiver must read exactly four bytes and then exactly the announced length. Apply timeouts and a maximum frame size.

## Fields

- protocol version and message type;
- experiment/session ID;
- selected profile ID;
- RSA public/wrapped key or ECDH public key;
- HKDF salt where applicable;
- AES-GCM nonce and ciphertext;
- timestamp and sequence number.

Binary fields are Base64-encoded at the protocol boundary.

## MongoDB role

Load the selected profile before connecting. Use the experiment ID for correlation, but do not query MongoDB in the middle of low-level cryptographic operations. Update the experiment after each major stage: `selected`, `connected`, `encrypted`, `transmitted`, `decrypted`, `completed` or `failed`.

Do not send MongoDB credentials or database documents over the IoT protocol.

## Tests

Test partial reads, disconnects, malformed JSON, excessive length, unknown version/profile, replayed session IDs and successful RSA/ECDH flows.

## Deliverable

`client.py`, `server.py`, `communication/protocol.py` and experiment-status updates.

