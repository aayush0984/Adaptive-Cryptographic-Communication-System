# Adaptive Cryptographic Configuration Selection & Secure IoT Communication

An end-to-end adaptive security and network analysis framework for resource-constrained Internet of Things (IoT) devices.

The system dynamically evaluates cryptographic profiles (**AES-GCM**, **RSA-OAEP**, **ECDH with HKDF**) against hardware constraints (**RAM, CPU, security policy, packet size limits, latency ceilings, and power source**) using empirical benchmark evidence from MongoDB. It derives real-time multi-objective weights based on endpoint pressures and message payload size, selects the optimal cipher suite, transmits encrypted data over a framed TCP protocol, captures wire traffic in an isolated network monitor using **TShark**, and performs offline deep packet inspection using **PyShark** to quantify communication overhead.

---

## The Problem

Deploying cryptography on heterogeneous IoT networks presents fundamental trade-offs:
* **Resource Constraints**: Low-power microcontrollers (e.g., ESP32, STM32) have limited RAM (hundreds of KB) and battery power, making asymmetric operations like RSA-3072 prohibitive in execution time and memory.
* **Security Requirements**: High-value gateways or servers mandate strong cryptographic security (e.g., 256-bit security floors), preventing the use of legacy or standard-tier ciphers.
* **Static Configuration Fragility**: Hardcoding a single cipher suite across diverse devices leads to either security vulnerabilities or device crashes from resource exhaustion.
* **Network & Framing Overhead**: For small IoT telemetry payloads (e.g., 4–16 bytes), cryptographic expansion, protocol framing, and TCP handshakes generate significant protocol overhead that must be measured and optimized.

This framework solves these challenges by dynamically negotiating the optimal cryptographic profile per transaction and measuring the resulting wire performance.

---

## High-Level Architecture

The system operates across a **four-stage distributed workflow**:

```text
+---------------------------------------------------------------------------------------------------+
|                                      MongoDB (iot_security)                                       |
|   - devices           - crypto_profiles           - benchmarks           - experiments   - traffic|
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+-----------------------+             +-----------------------+             +-----------------------+
|  Device A (Sender)    | ──────────> |   Adaptive Selector   | <────────── |  Device B (Receiver)   |
|  - RAM, CPU, Sec Floor|             |  Stage 1: Hard Filter |             |  - RAM, CPU, Sec Floor|
|  - Battery / Mains    |             |  Stage 2: Score & Rank|             |  - Battery / Mains    |
|  - User Plaintext     |             +-----------┬-----------+             |  - Decrypt & Echo ACK |
+-----------------------+                         │                         +-----------------------+
                                                  │ Selected Profile (e.g., C4)
                                                  ▼
                                      +-----------------------+
                                      | Framed TCP Connection |
                                      |   (Port 5000, lo0)    |
                                      +-----------┬-----------+
                                                  │
                                      ┌───────────┴───────────┐
                                      ▼                       ▼
                           [Terminal 1: SERVER]    [Terminal 2: CLIENT]
                                      │                       │
                                      └───────────┬───────────┘
                                                  │ TCP Wire Packets
                                                  ▼
                                      [Terminal 3: CAPTURE MONITOR]
                                      (TShark Sniffer on lo0 :5000)
                                                  │
                                                  ▼
                                      captures/experiment_<id>.pcapng
                                                  │
                                                  ▼
                                      [Terminal 4: TRAFFIC ANALYZER]
                                      (PyShark Offline Dissection)
                                                  │
                                                  ▼
                                      iot_security.traffic (Updated)
```

---

## Current Project Structure

```text
IoTEncryption/
├── client.py                    # Terminal 2: Device A client CLI & sender workflow
├── server.py                    # Terminal 1: Device B TCP listener & message verification
├── capture_monitor.py           # Terminal 3: Long-running TShark loopback network monitor
├── analyze_traffic.py           # Phase 10 CLI: PyShark offline traffic analysis entry point
├── SYSTEM_FLOW.md               # Comprehensive technical walkthrough, math, and packet flows
├── requirements.txt             # Python dependencies (cryptography, pymongo, psutil, pyshark)
├── pyproject.toml               # Package build metadata
├── .env                         # Local runtime environment configuration
│
├── analysis/                    # Phase 10: PyShark packet dissection & overhead engine
│   ├── __init__.py
│   └── traffic_analyzer.py      # Core TrafficAnalyzer class & metric extractors
│
├── capture/                     # Phase 9: Wireshark / TShark capture wrapper
│   ├── __init__.py
│   └── packet_capture.py        # Reusable PacketCapture manager & loopback interface detector
│
├── captures/                    # Destination directory for raw .pcapng files
│   └── .gitkeep
│
├── communication/               # Length-prefixed JSON protocol framing
│   ├── __init__.py
│   └── protocol.py              # Frame serializer/deserializer, sockets, and session state
│
├── config/                      # Centralized configuration loaders
│   └── __init__.py              # .env parsing and environment variable fallbacks
│
├── crypto/                      # Low-level cryptographic primitives
│   ├── __init__.py
│   ├── aes_engine.py            # AES-128/256-GCM authenticated encryption
│   ├── ecc_engine.py            # Ephemeral ECDH (P-256, P-384) + HKDF-SHA256
│   └── rsa_engine.py            # RSA-OAEP (2048/3072-bit) with SHA-256
│
├── database/                    # MongoDB connection lifecycle & schemas
│   ├── __init__.py
│   ├── connection.py            # Cached MongoClient & Database accessors
│   ├── indexes.py               # Idempotent index creation across all collections
│   └── seed_database.py         # Initial hardware devices and profile seeding script
│
├── evaluation/                  # Benchmarking engine for empirical evidence
│   ├── __init__.py
│   ├── benchmark.py             # Performance measurement harness (timing, RAM, RSS)
│   ├── memory_monitor.py        # tracemalloc memory profiler
│   └── statistics.py            # Outlier detection & summary statistics
│
├── models/                      # Dataclasses and domain validation
│   ├── __init__.py
│   ├── crypto_profile.py        # Profile structure, security level, and cipher suite models
│   └── device.py                # Device hardware constraints and power source models
│
├── repositories/                # Repository layer for MongoDB persistence
│   ├── __init__.py
│   ├── benchmark_repository.py  # Querying benchmark timing and memory metrics
│   ├── device_repository.py     # Active device query and lookups
│   ├── experiment_repository.py # Experiment logging and provenance tracking
│   └── profile_repository.py    # Crypto profile queries
│
├── selection/                   # Two-stage adaptive selection algorithm
│   ├── __init__.py
│   ├── compatibility.py         # Stage 1: Mandatory hard constraint filters
│   ├── scoring.py               # Stage 2: Scenario pressures, weights, and scoring
│   └── selector.py              # Orchestrator, interactive prompts, and decision logging
│
├── scripts/                     # Maintenance tools
│   └── migrate_experiments.py   # Historical schema migration and index sync
│
└── tests/                       # Automated test suite
    ├── unit/                    # Unit tests for crypto, protocol, capture, and analysis
    └── integration/             # Integration tests for MongoDB and socket flows
```

---

## Technologies & Dependencies

* **Python 3.10+**: Core programming language.
* **MongoDB (Community Server 7.0+)**: Primary document database (`iot_security`).
* **`pymongo`**: Python driver for MongoDB database operations.
* **`cryptography` (hazmat)**: High-speed, robust cryptographic implementations of AES-GCM, RSA-OAEP, ECDH, and HKDF.
* **Wireshark / TShark (CLI)**: Packet capture engine used by `capture_monitor.py` for live loopback capture.
* **PyShark**: Python wrapper for TShark packet dissection, used by `analyze_traffic.py` to parse `.pcapng` structures.
* **`pytest`**: Unit and integration test runner.

---

## MongoDB Collections & Schema Roles

All documents reside in the **`iot_security`** database:

| Collection | Description | Key Identifier |
| :--- | :--- | :--- |
| **`devices`** | Catalog of IoT hardware specifications: CPU level, available RAM (`available_memory_kb`), max packet MTU, latency ceilings, security policy (`standard`/`high`), and power source (`battery`/`mains`). | `device_id` (Unique) |
| **`crypto_profiles`** | Catalog of supported cipher suites: `C1` (RSA-2048 + AES-128-GCM), `C2` (RSA-3072 + AES-256-GCM), `C3` (ECDH-P256 + AES-128-GCM), `C4` (ECDH-P384 + AES-256-GCM). | `profile_id` (Unique) |
| **`benchmarks`** | Empirical execution timings (`key_generation`, `key_establishment`, `encryption`, `decryption`) and peak heap allocations (`tracemalloc`) across message sizes. | `run_id` (Unique, Sparse) |
| **`experiments`** | Records adaptive selection decisions, candidate rejection reasons, dynamic weights, constraint pressures, and observed round-trip status. | `experiment_id` (Indexed) |
| **`traffic`** | Stores Phase 9 capture metadata (`.pcapng` path, interface, filter, SHA-256 hash, timestamps) and Phase 10 nested `traffic_analysis` results. | `experiment_id` (Unique) |

---

## Phase-wise Overview (Phases 0–10)

* **Phase 0 — Setup & Environment**: Repository structure, virtual environment, and MongoDB configuration.
* **Phase 1 — Device Profiles Catalog**: Registered hardware specs (ESP32, Raspberry Pi 4, etc.) in MongoDB.
* **Phase 2 — Cryptographic Primitives**: AES-GCM, RSA-OAEP, and ECDH/HKDF engine implementations.
* **Phase 3 — Empirical Benchmarking**: Benchmark harness measuring execution timings and memory for each profile/device pairing.
* **Phase 4 — Hard Constraint Filtering (Stage 1)**: Rejects profiles violating security policy floor, CPU capability, memory capacity, latency ceilings, or MTU.
* **Phase 5 — Dynamic Scenario Weighting (Stage 2)**: Computes continuous time, memory, communication, and energy pressures to dynamically weight optimization goals.
* **Phase 6 — Multi-Objective Ranking**: Normalizes candidate metrics and calculates weighted cost scores with deterministic tie-breaking.
* **Phase 7 — Explainability & Experiment Logging**: Generates rejection reasons, score breakdowns, and audit trails stored in `experiments`.
* **Phase 8 — Secure TCP Communication**: Framing protocol over TCP socket; encrypts user message with chosen profile, verifies HMAC/tag, and echoes verification.
* **Phase 9 — Wireshark/TShark Packet Capture**: Independent capture monitor (`capture_monitor.py`) listening on loopback interface, recording wire traffic into timestamped `.pcapng` files and storing metadata in `traffic`.
* **Phase 10 — PyShark Network Traffic Analysis**: Offline deep packet inspector (`analyze_traffic.py`) calculating directional packet counts, TCP payload size, retransmissions, and wire overhead percentage.
* **(Phase 11 — Future Work**: Multi-run comparative visual analytics and aggregate evaluation reporting).*

---

## Installation & Setup

### 1. Prerequisites
* **Python**: 3.10, 3.11, or 3.12 recommended.
* **MongoDB**: Running locally at `mongodb://localhost:27017/`.
* **Wireshark / TShark**:
  * macOS: `brew install wireshark`
  * Debian/Ubuntu: `sudo apt install tshark`
  * Ensure your user has permissions to capture on loopback (`/dev/bpf*` on macOS, or add to `wireshark` group on Linux).

### 2. Environment Setup

```bash
# Clone repository and enter directory
cd /path/to/IoTEncryption

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration (`.env`)

Create or verify `.env` in the project root:

```env
MONGODB_URI=YOUR_DATABASE_URL
MONGODB_DB=YOUR_DATABASE_NAME
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
CAPTURE_INTERFACE=lo0
CAPTURE_DIR=captures
```

### 4. Database Initialization

Populate the database with device specifications, cryptographic profiles, initial benchmarks, and indexes:

```bash
# Seed devices and crypto profiles
python -m database.seed_database

# Create MongoDB indexes
python -c "from database.indexes import create_indexes; print(create_indexes())"

# (Optional) Run local benchmarks for simulated performance evidence
python -m evaluation.benchmark --all --dry-run
```

---

## How to Run the System

The project uses a **three-terminal runtime architecture** plus an **analysis step**:

```text
Terminal 1              Terminal 3              Terminal 2              Terminal 4 / Shell
SERVER                  NETWORK MONITOR         CLIENT                  TRAFFIC ANALYZER
python server.py        python capture_monitor.py python client.py      python analyze_traffic.py
Receiver (Device B)     TShark Loopback Sniffer Sender (Device A)       PyShark Offline Metrics
```

### Execution Steps in Exact Order:

#### Step 1: Start the Receiver Server (Terminal 1)
```bash
python server.py
```
*Listens on TCP port 5000, awaits HELLO frames, verifies profiles, decrypts ciphertext, and echoes ACK verification.*

#### Step 2: Start the Network Capture Monitor (Terminal 3)
```bash
python capture_monitor.py
```
*Initializes TShark sniffer on loopback interface (`lo0`, `tcp port 5000`). Prints live packet summaries in real time without exposing plaintext or secrets.*

```text
================ NETWORK CAPTURE ================
Interface : lo0
Filter    : tcp port 5000
Status    : Listening...
```

#### Step 3: Run the Sender Client (Terminal 2)
```bash
# Interactive mode (prompts for Device A, Device B, and message):
python client.py

# Or non-interactive / automated mode:
python client.py --sender esp32 --receiver raspberry_pi_4 --message "Hello IoT Security"
```

*The client performs adaptive selection, prints the decision rationale, connects to Server, sends the encrypted frame, receives the ACK, and finishes.*

#### Step 4: Inspect the Capture & Run Phase 10 Traffic Analysis
Once the communication completes:
* `capture_monitor.py` detects TCP session termination, finalizes the `.pcapng` file under `captures/`, and records metadata in `iot_security.traffic`.
* Run `analyze_traffic.py` to perform PyShark analysis:

```bash
# Analyze a specific experiment:
python analyze_traffic.py --experiment exp-a207ff8e

# Or analyze all pending unanalyzed captures:
python analyze_traffic.py

# Or list all captures and status:
python analyze_traffic.py --list
```

---

## Example Output & Interpretation

### Capture Monitor (Terminal 3):
```text
================ NETWORK CAPTURE ================
Interface : lo0
Filter    : tcp port 5000
Status    : Listening...
[NETWORK] 127.0.0.1:49942 -> 127.0.0.1:5000 TCP SYN
[NETWORK] 127.0.0.1:5000 -> 127.0.0.1:49942 TCP 68 bytes
[NETWORK] 127.0.0.1:49942 -> 127.0.0.1:5000 TCP 56 bytes
[NETWORK] 127.0.0.1:49942 -> 127.0.0.1:5000 TCP 296 bytes
[NETWORK] 127.0.0.1:5000 -> 127.0.0.1:49942 TCP 323 bytes
[NETWORK] 127.0.0.1:49942 -> 127.0.0.1:5000 TCP FIN
[NETWORK] 127.0.0.1:5000 -> 127.0.0.1:49942 TCP FIN
```

### PyShark Analysis Output (`analyze_traffic.py`):
```text
============= TRAFFIC ANALYSIS =============
Experiment       : exp-a207ff8e
Message size     : 4 B
Packets          : 12
Captured bytes   : 1964
TCP payload      : 507 B
Retransmissions  : 0
Network overhead : 1960 B
Overhead         : 49000.00%
Status           : completed
============================================
```

### Understanding Network Overhead:
* **Message Size (4 B)**: The raw plaintext payload.
* **TCP Payload (507 B)**: The JSON protocol frames transferred over the connection (Sender HELLO frame: 240 B + Receiver ACK frame: 267 B).
* **Captured Bytes (1964 B)**: The total on-wire packet capture size including Ethernet/Null headers, IPv4 headers, TCP headers, handshake packets (SYN, SYN-ACK, ACK), data frames, ACK responses, and teardown packets (FIN-ACK).
* **Network Overhead (1960 B / 49,000%)**: For ultra-short telemetry payloads (4 bytes), full-transport overhead naturally dominates wire communication. This is a property of transport and cryptographic framing, not 49,000% cipher expansion.

---

## Verifying in MongoDB

Check the updated record in the `traffic` collection:

```javascript
use iot_security;

db.traffic.findOne(
  { experiment_id: "exp-a207ff8e" },
  {
    experiment_id: 1,
    profile_id: 1,
    message_size_bytes: 1,
    capture_file: 1,
    traffic_analysis: 1
  }
);
```

---

## Test Suite

Run all unit tests using `pytest`:

```bash
# Run unit test suite (crypto engines, protocol, capture manager, traffic analyzer)
pytest tests/unit/ -v
```
