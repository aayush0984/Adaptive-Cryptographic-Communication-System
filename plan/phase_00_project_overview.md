# Phase 0 — Project Overview and MongoDB Architecture

## Project title

**Adaptive Cryptographic Configuration Selection and Traffic Analysis for Secure IoT Communication**

## Core idea

The system models secure communication between two IoT devices:

- **Device A:** sender/client
- **Device B:** receiver/server

The user selects both devices from the MongoDB device catalogue. The program reads their capabilities, asks for current runtime constraints and security requirements, finds cryptographic profiles supported by both devices, and selects the lowest-cost valid profile. Device A then encrypts and sends a real message to Device B. Wireshark captures the exchange, PyShark analyzes the capture, and the final results are stored in MongoDB.

No device, sender, receiver or winning algorithm is hardcoded.

## Database

Database name:

```text
iot_security
```

Collections:

| Collection | Purpose |
|---|---|
| `devices` | Reusable catalogue of IoT device models and supported algorithms |
| `crypto_profiles` | Candidate hybrid configurations such as RSA-2048 + AES-128-GCM |
| `benchmarks` | Raw and summarized performance measurements |
| `experiments` | One complete sender-receiver run, selection decision and traffic results |

MongoDB stores metadata and measurements, but not private keys, AES keys, ECDH secrets or plaintext messages.

## Static and runtime information

The `devices` collection stores stable properties such as model name, CPU, total RAM and supported algorithms. Values that change during a run—available memory, battery percentage, network condition, latency limit and role—belong in the `experiments` document.

## Candidate profiles

| ID | Key establishment | Message encryption | Level |
|---|---|---|---|
| C1 | RSA-2048 OAEP/SHA-256 | AES-128-GCM | Standard |
| C2 | RSA-3072 OAEP/SHA-256 | AES-256-GCM | High |
| C3 | ECDH P-256 + HKDF-SHA256 | AES-128-GCM | Standard |
| C4 | ECDH P-384 + HKDF-SHA256 | AES-256-GCM | High |

AES-GCM encrypts and authenticates the message. RSA wraps the AES session key, while ECDH allows both devices to derive the same AES key.

## Meaning of “best”

The best profile is the one that:

1. Is enabled in `crypto_profiles`.
2. Is supported by both selected devices.
3. Meets the required security level.
4. Fits sender and receiver memory limits independently.
5. Meets latency and communication constraints.
6. Has the lowest weighted cost using benchmark data.

Security is mandatory; it is never traded away for speed.

## End-to-end workflow

1. Connect to MongoDB and open `iot_security`.
2. Query active documents from `devices`.
3. Let the user select Device A and Device B.
4. Collect runtime state and session requirements.
5. Query enabled `crypto_profiles`.
6. Retain profiles whose required capabilities are supported by both devices.
7. Load applicable records from `benchmarks`.
8. Filter profiles that violate mandatory constraints.
9. Normalize costs, score candidates and select one.
10. Create an `experiments` document with status `selected`.
11. Perform RSA or ECDH key establishment.
12. Encrypt the message using AES-GCM.
13. Send the framed protocol data over TCP.
14. Authenticate and decrypt at Device B.
15. Update the experiment with timings and success status.
16. Capture the exchange with Wireshark.
17. Analyze the PCAPNG file with PyShark.
18. Store the traffic summary in the same experiment.

## MongoDB connection

Use `pymongo` and keep the URI outside source code:

```python
import os
from pymongo import MongoClient

client = MongoClient(os.environ["MONGODB_URI"])
db = client["iot_security"]
```

Store `MONGODB_URI` in an uncommitted `.env` file during development. Keep a local MongoDB or seed-file fallback for demonstrations if internet access is unreliable.

## RSA sender-receiver path

1. Device B creates an RSA key pair.
2. B sends only its public key to A.
3. A creates a fresh AES key and nonce.
4. A encrypts the message with AES-GCM.
5. A wraps the AES key with B's RSA public key using OAEP.
6. A sends the profile ID, wrapped key, nonce and ciphertext.
7. B unwraps the AES key and authenticates/decrypts the ciphertext.

## ECDH sender-receiver path

1. A and B generate ephemeral EC key pairs.
2. They exchange only public keys.
3. Both calculate the ECDH shared secret.
4. Both derive an AES key with HKDF-SHA256.
5. A encrypts and sends the message.
6. B authenticates and decrypts it.

## Benchmarking and data honesty

Benchmark documents must record the device, profile, message size, repetitions, statistics and measurement source:

- `physical-device`
- `local-computer`
- `published`
- `simulated`

Laptop measurements must not be presented as measurements from an ESP32 or another physical device.

## Traffic analysis

Wireshark captures the real TCP exchange. PyShark calculates packet counts, byte totals, direction, timing, retransmissions and overhead. Encryption should hide plaintext contents, but addresses, ports, sizes and timing remain observable.

## Expected outcome

The prototype demonstrates that two different IoT devices can dynamically choose a mutually supported and resource-appropriate security profile, exchange an authenticated encrypted message, and produce repeatable computational and network-overhead evidence stored in MongoDB.

## Phase map

- Phase 1: MongoDB device catalogue and selection
- Phase 2: AES-GCM engine
- Phase 3: RSA hybrid communication
- Phase 4: ECDH hybrid communication
- Phase 5: MongoDB cryptographic-profile catalogue
- Phase 6: MongoDB-backed benchmarking
- Phase 7: Adaptive selection
- Phase 8: TCP sender-receiver protocol
- Phase 9: Wireshark capture
- Phase 10: PyShark analysis and database update
- Phase 11: Integrated CLI and demonstration

