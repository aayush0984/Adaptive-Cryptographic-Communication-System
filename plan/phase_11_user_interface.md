# Phase 11 — Integrated CLI and Demonstration

## Goal

Provide one command-line interface that coordinates MongoDB device selection, adaptive selection, secure communication, capture analysis and result display.

## User flow

1. Verify MongoDB connectivity to `iot_security`.
2. Query and display active devices.
3. Select Device A (sender) and Device B (receiver).
4. Enter runtime states, security requirement and plaintext message.
5. Query compatible profiles and benchmark data.
6. Display accepted and rejected profiles with reasons.
7. Display scores and announce the winner.
8. Create the experiment document.
9. Connect, encrypt, transmit, authenticate and decrypt.
10. Update timings and status.
11. Analyze the associated capture with PyShark.
12. Display and store traffic metrics.

## Suggested commands

```bash
python -m app.seed_database
python server.py --host 127.0.0.1 --port 5000
python main.py --mongo-db iot_security --message "Temperature = 31.4 C"
python -m evaluation.traffic_analyzer --experiment-id <id>
```

The URI should come from `MONGODB_URI`, not from a command-line password.

## Administration options

Include CLI commands to list/add/deactivate devices and list/enable/disable profiles. Validate every write and require confirmation before destructive catalogue changes.

## Error handling

Handle database unavailable, invalid catalogue documents, missing benchmarks, no compatible profile, server unavailable, authentication failure, malformed frames, missing capture and TShark errors. Update failed experiments with a sanitized reason.

## Final demonstration

1. Show the four MongoDB collections.
2. Select sender and receiver from the live device list.
3. Run a normal scenario.
4. Change a runtime constraint and demonstrate a different selection.
5. Show successful decryption.
6. Show the Wireshark capture and absence of plaintext.
7. Run PyShark and show the MongoDB experiment updated with traffic results.

## Deliverable

A polished MongoDB-backed CLI, idempotent seed script, reproducible demo procedure and completed experiment records.

