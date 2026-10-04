# Recommended Project Structure

## Project root

```text
adaptive-iot-security/
├── README.md
├── requirements.txt
├── .env
├── .env.example
├── .gitignore
├── pyproject.toml
│
├── main.py
├── client.py
├── server.py
│
├── database/
│   ├── __init__.py
│   ├── connection.py
│   ├── indexes.py
│   ├── validators.py
│   └── seed_database.py
│
├── repositories/
│   ├── __init__.py
│   ├── device_repository.py
│   ├── profile_repository.py
│   ├── benchmark_repository.py
│   └── experiment_repository.py
│
├── devices/
│   ├── __init__.py
│   ├── device_selector.py
│   ├── runtime_input.py
│   └── capability_service.py
│
├── crypto/
│   ├── __init__.py
│   ├── aes_engine.py
│   ├── rsa_engine.py
│   ├── ecc_engine.py
│   ├── key_derivation.py
│   ├── serialization.py
│   └── exceptions.py
│
├── selection/
│   ├── __init__.py
│   ├── compatibility.py
│   ├── benchmark_provider.py
│   ├── normalization.py
│   ├── scoring.py
│   ├── policies.py
│   └── selector.py
│
├── communication/
│   ├── __init__.py
│   ├── framing.py
│   ├── protocol.py
│   ├── sender.py
│   ├── receiver.py
│   └── session.py
│
├── evaluation/
│   ├── __init__.py
│   ├── benchmark.py
│   ├── memory_monitor.py
│   ├── statistics.py
│   ├── traffic_analyzer.py
│   └── report_generator.py
│
├── capture/
│   ├── __init__.py
│   ├── capture_manager.py
│   └── filters.py
│
├── cli/
│   ├── __init__.py
│   ├── menus.py
│   ├── device_admin.py
│   ├── profile_admin.py
│   └── output.py
│
├── models/
│   ├── __init__.py
│   ├── device.py
│   ├── crypto_profile.py
│   ├── benchmark.py
│   ├── experiment.py
│   └── protocol_message.py
│
├── utils/
│   ├── __init__.py
│   ├── base64_utils.py
│   ├── ids.py
│   ├── logging_config.py
│   └── time_utils.py
│
├── scripts/
│   ├── seed_devices.py
│   ├── seed_profiles.py
│   ├── create_indexes.py
│   ├── run_benchmarks.py
│   └── analyze_capture.py
│
├── data/
│   ├── seeds/
│   │   ├── devices.json
│   │   └── crypto_profiles.json
│   └── exports/
│       └── .gitkeep
│
├── captures/
│   ├── raw/
│   │   └── .gitkeep
│   └── screenshots/
│       └── .gitkeep
│
├── reports/
│   ├── charts/
│   │   └── .gitkeep
│   └── tables/
│       └── .gitkeep
│
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── unit/
    │   ├── test_aes_engine.py
    │   ├── test_rsa_engine.py
    │   ├── test_ecc_engine.py
    │   ├── test_compatibility.py
    │   ├── test_scoring.py
    │   ├── test_framing.py
    │   └── test_validators.py
    └── integration/
        ├── test_mongodb.py
        ├── test_rsa_session.py
        ├── test_ecc_session.py
        └── test_end_to_end.py
```

## MongoDB database

```text
iot_security
├── devices
├── crypto_profiles
├── benchmarks
└── experiments
```

MongoDB is the authoritative store. Files under `data/seeds/` only provide repeatable initial data and backup imports; the running application selects devices and profiles from MongoDB.

## Root files

### `main.py`

Coordinates the full application:

1. connect to MongoDB;
2. display devices;
3. select sender and receiver;
4. collect runtime constraints;
5. choose a cryptographic profile;
6. create an experiment;
7. run secure communication; and
8. display/store results.

### `client.py`

Starts Device A independently. It connects to Device B, performs the selected key-establishment flow, encrypts the message and sends it.

### `server.py`

Starts Device B independently. It accepts a connection, performs RSA or ECDH setup, receives the encrypted message and authenticates/decrypts it.

### `.env`

Contains local secrets and configuration:

```text
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=iot_security
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
```

Never commit this file.

### `.env.example`

Contains the same variable names with safe placeholder values.

### `.gitignore`

At minimum:

```gitignore
.env
.venv/
__pycache__/
*.pyc
.pytest_cache/
captures/raw/*.pcap
captures/raw/*.pcapng
reports/charts/*
reports/tables/*
!**/.gitkeep
```

## Database layer

### `database/connection.py`

Creates the `MongoClient`, selects `iot_security`, tests connectivity and exposes collection handles safely.

### `database/indexes.py`

Creates required indexes idempotently:

- unique device name;
- unique profile name;
- unique benchmark run ID;
- device/profile/message-size benchmark index;
- experiment creation-time/status index.

### `database/validators.py`

Defines MongoDB collection validators or Python validation helpers for device, profile, benchmark and experiment documents.

### `database/seed_database.py`

Calls the device/profile seeders and creates indexes. It must use upserts so it can be run repeatedly without duplicates.

## Repository layer

Only repository files should contain routine MongoDB queries. Business logic should not directly call collections throughout the codebase.

### `device_repository.py`

- list active devices;
- get a device by ID;
- insert/update/deactivate a device.

### `profile_repository.py`

- list enabled profiles;
- get by profile ID;
- enable/disable profiles.

### `benchmark_repository.py`

- insert raw benchmark runs;
- retrieve applicable measurements;
- execute summary aggregations.

### `experiment_repository.py`

- create an experiment;
- update its status;
- store the selection decision;
- store crypto timings;
- store capture and PyShark results.

## Device-selection layer

### `device_selector.py`

Displays documents retrieved from MongoDB and lets the user choose Device A and Device B.

### `runtime_input.py`

Collects battery percentage, available memory, network type, packet limit, latency limit and security requirement.

### `capability_service.py`

Calculates mutually supported capabilities and identifies profiles whose `required_capabilities` are supported by both devices.

## Cryptographic layer

### `aes_engine.py`

Handles AES-128/256-GCM encryption and authenticated decryption.

### `rsa_engine.py`

Handles RSA key generation and RSA-OAEP wrapping/unwrapping of AES keys.

### `ecc_engine.py`

Handles ephemeral P-256/P-384 keys and ECDH.

### `key_derivation.py`

Uses HKDF-SHA256 to derive AES keys from ECDH shared secrets.

### `serialization.py`

Serializes and loads public keys. Private-key serialization is not needed for the initial session-based prototype.

## Selection layer

### `compatibility.py`

Applies mandatory checks:

- mutual algorithm support;
- minimum security;
- sender memory;
- receiver memory;
- latency; and
- communication constraints.

### `benchmark_provider.py`

Loads the most relevant benchmark measurements from MongoDB and records their source.

### `normalization.py`

Normalizes time, memory, communication and energy-proxy costs.

### `policies.py`

Stores weight sets for normal, low-battery, low-memory, slow-network and real-time scenarios.

### `scoring.py`

Calculates the final score for every valid profile.

### `selector.py`

Coordinates filtering, scoring, tie-breaking and selection explanations.

## Communication layer

### `framing.py`

Implements four-byte length-prefixed TCP frames and exact-length reads.

### `protocol.py`

Validates message versions, types and fields. It converts protocol objects to and from JSON.

### `sender.py`

Implements Device A's RSA and ECDH workflows.

### `receiver.py`

Implements Device B's RSA and ECDH workflows.

### `session.py`

Tracks session ID, selected profile, sequence number, timeout and protocol state.

## Evaluation and capture

### `evaluation/benchmark.py`

Measures cryptographic operations and writes raw benchmark documents.

### `memory_monitor.py`

Provides consistent `tracemalloc` and `psutil` measurements.

### `statistics.py`

Calculates mean, median, standard deviation, minimum and maximum.

### `capture/capture_manager.py`

Starts/stops TShark captures when automated capture is enabled and associates filenames with experiment IDs.

### `traffic_analyzer.py`

Uses PyShark to calculate packet and traffic metrics and updates the associated experiment.

### `report_generator.py`

Queries MongoDB and generates comparison tables/charts without making exported files authoritative.

## Models

Models provide one consistent internal representation for MongoDB documents and protocol messages. They may be implemented using dataclasses or Pydantic.

Do not return raw MongoDB documents throughout the application without validation. Convert them to models near the repository boundary.

## Scripts

Scripts provide explicit maintenance and experiment commands:

```bash
python -m scripts.seed_devices
python -m scripts.seed_profiles
python -m scripts.create_indexes
python -m scripts.run_benchmarks
python -m scripts.analyze_capture --experiment-id <id>
```

## Recommended implementation order

1. Create environment configuration and MongoDB connection.
2. Implement schemas, repositories, indexes and seeders.
3. Implement device selection and runtime input.
4. Implement and test AES-GCM.
5. Implement and test RSA-OAEP.
6. Implement and test ECDH/HKDF.
7. Seed and retrieve cryptographic profiles.
8. Implement benchmarking and store results.
9. Implement compatibility filtering and scoring.
10. Implement TCP framing and sender/receiver flows.
11. Integrate experiment status updates.
12. Add Wireshark/TShark capture and PyShark analysis.
13. Complete the CLI and end-to-end tests.

## Simplified structure for the first working version

If the complete structure feels too large initially, start with:

```text
adaptive-iot-security/
├── README.md
├── requirements.txt
├── .env
├── .gitignore
├── main.py
├── client.py
├── server.py
├── database/
│   ├── connection.py
│   ├── seed_database.py
│   └── repositories.py
├── crypto/
│   ├── aes_engine.py
│   ├── rsa_engine.py
│   └── ecc_engine.py
├── selection/
│   └── selector.py
├── communication/
│   └── protocol.py
├── evaluation/
│   ├── benchmark.py
│   └── traffic_analyzer.py
├── captures/
└── tests/
    ├── test_crypto.py
    ├── test_selector.py
    └── test_end_to_end.py
```

Expand into the full structure as each phase is implemented.
