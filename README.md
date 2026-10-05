# Adaptive Cryptographic Configuration Selection & Secure IoT Communication

An adaptive security framework for Internet of Things (IoT) resource-constrained endpoints. The system dynamically evaluates candidate cryptographic profiles (AES-GCM, RSA-OAEP, ECDH/HKDF) against hardware constraints (RAM, CPU, security policy, packet size limits, latency limits) and benchmark performance evidence for both sender and receiver endpoints. It derives dynamic objective weights from endpoint pressures and message payload size, selecting the optimal profile to encrypt and exchange messages over framed TCP.

For a detailed technical walkthrough of the architectural concepts, Stage 1/2 selection math, and complete end-to-end execution flow, see [SYSTEM_FLOW.md](file:///Users/aayushvivekraj/Developer/IoTEncryption/SYSTEM_FLOW.md).

---

## System Architecture & Data Flow

```
                      +-----------------------------+
                      |   MongoDB: iot_security     |
                      |   - devices                 |
                      |   - crypto_profiles         |
                      |   - benchmarks              |
                      |   - experiments             |
                      +--------------+--------------+
                                     |
                                     v
+-----------------------+   +-------------------+   +-----------------------+
|  Device A (Sender)    |---| Adaptive Selector |---| Device B (Receiver)   |
|  - RAM, CPU, Sec Req  |   | Stage 1: Hard Filter  | - RAM, CPU, Sec Req   |
|  - Power Source       |   | Stage 2: Dynamic  |   | - Power Source        |
|  - User Plaintext     |   |   Weight & Score  |   | - Decrypt & Echo      |
+-----------------------+   +---------+---------+   +-----------------------+
                                      |
                                      v
                        +---------------------------+
                        |  Framed TCP Communication |
                        |  - Profile Verification   |
                        |  - Session Persistence    |
                        +---------------------------+
```

---

## Key Features

### 1. Two-Stage Adaptive Selection System (`selection/`)
- **Stage 1 — Mandatory Hard Filtering**: Checks mandatory constraints across both endpoints:
  - Security Policy Floor (`standard` vs `high`)
  - Minimum CPU Level (`low`, `medium`, `high`)
  - Endpoint Memory Feasibility ($\text{RAM}_{\text{available}} \ge \text{Peak Memory}_{\text{predicted}}$)
  - Combined Session Latency Limit ($\text{Latency}_{\text{predicted}} \le \text{Latency}_{\text{limit}}$)
  - Maximum Packet Capacity ($\text{Overhead}_{\text{predicted}} \le \text{PacketLimit}$)
  - Engine Implementation Verification
- **Stage 2 — Dynamic Multi-Objective Optimization**: Derives dynamic normalized weights $(w_{\text{time}}, w_{\text{memory}}, w_{\text{comm}}, w_{\text{energy}})$ based on real-time scenario pressures:
  - **Time Pressure ($P_{\text{time}}$)**: Derived from the strictest endpoint latency requirement via continuous logarithmic interpolation.
  - **Memory Pressure ($P_{\text{memory}}$)**: Derived from the lowest available RAM between Device A and B.
  - **Communication Pressure ($P_{\text{comm}}$)**: Derived from the UTF-8 payload byte size relative to effective packet limits.
  - **Energy Pressure ($P_{\text{energy}}$)**: Derived strictly from endpoint power sources (`mains` vs `battery`), assigning elevated priority ($0.80$ to $0.95$) to battery-powered nodes without inferring battery percentage.

### 2. Multi-Engine Cryptographic Library (`crypto/`)
- **AES-GCM Engine** (`crypto/aes_engine.py`): AES-128-GCM & AES-256-GCM authenticated encryption with 96-bit nonces and 128-bit authentication tags.
- **RSA Engine** (`crypto/rsa_engine.py`): RSA-OAEP key wrapping/unwrapping (2048-bit & 3072-bit keys) using SHA-256.
- **ECC Engine** (`crypto/ecc_engine.py`): Ephemeral ECDH key exchange on NIST P-256 & P-384 curves, with HKDF-SHA256 session key derivation.

### 3. Device & Profile Catalogues (`models/`, `repositories/`)
- Hardware catalog with 10 device profiles (ESP32, Raspberry Pi 4, ESP8266, STM32, Jetson Nano, etc.).
- 4 pre-configured Cryptographic Profiles (`C1` to `C4`):
  - `C1`: RSA-2048 + AES-128-GCM (Standard Security, Low Min-CPU)
  - `C2`: RSA-3072 + AES-256-GCM (High Security, High Min-CPU)
  - `C3`: ECDH-P256 + AES-128-GCM (Standard Security, Low Min-CPU)
  - `C4`: ECDH-P384 + AES-256-GCM (High Security, Medium Min-CPU)

### 4. Performance Benchmarking Framework (`evaluation/`)
- Measures execution timings (`key_generation`, `key_establishment`, `encryption`, `decryption`, `total`) and peak heap memory (`tracemalloc`).
- Distinguishes physical hardware measurements (`"measured"`) from local host development runs (`"simulated"`).
- Stores reproducible raw runs in `iot_security.benchmarks` using MongoDB upserts.

### 5. Framed TCP Protocol & CLI (`communication/`, `client.py`, `server.py`)
- Length-prefixed JSON protocol framing (`struct` binary header + UTF-8 payload).
- Interactive CLI prompt flow for Device A, Device B, and user plaintext input.
- Structured console output with `[SENDER]`, `[RECEIVER]`, `[SELECTOR]` status indicators and full explainability logs.

---

## Quick Start Guide

### Prerequisites
- Python 3.10+
- MongoDB instance running locally on `localhost:27017`

### Setup

```bash
# Clone and set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 1. Seed Database & Run Benchmarks

```bash
# Seed default devices and crypto profiles
python -m database.seed_database

# Run benchmark suite for all devices (populates MongoDB benchmarks collection)
python -m evaluation.benchmark --all

# Or benchmark specific devices in dry-run simulation mode
python -m evaluation.benchmark --device esp32 --dry-run
python -m evaluation.benchmark --device raspberry_pi_4 --dry-run
```

### 2. Database Migration

```bash
# Check database indexes and backfill experiment metadata
python scripts/migrate_experiments.py
```

### 3. Running TCP Server & Client

**Terminal 1 — Receiver Server:**
```bash
python server.py
```

**Terminal 2 — Sender Client:**
```bash
python client.py
```

---

## Project Structure

```text
IoTEncryption/
├── client.py                    # Sender CLI & adaptive client workflow
├── server.py                    # Receiver TCP server & message verification
├── SYSTEM_FLOW.md               # Detailed technical workflow & mathematical documentation
├── communication/               # Length-prefixed JSON protocol framing
│   └── protocol.py
├── config/                      # Environment settings & profile loader
├── crypto/                      # Core cryptographic engines
│   ├── aes_engine.py
│   ├── ecc_engine.py
│   └── rsa_engine.py
├── database/                    # MongoDB connection & seeding
│   ├── connection.py
│   ├── indexes.py
│   └── seed_database.py
├── evaluation/                  # Benchmarking suite & statistics
│   ├── benchmark.py
│   ├── memory_monitor.py
│   └── statistics.py
├── models/                      # Dataclasses & schema validators
│   ├── crypto_profile.py
│   └── device.py
├── repositories/                # MongoDB collection operations
│   ├── benchmark_repository.py
│   ├── device_repository.py
│   ├── experiment_repository.py
│   └── profile_repository.py
├── selection/                   # Adaptive selection algorithm & dynamic weighting
│   ├── compatibility.py
│   ├── scoring.py
│   └── selector.py
├── scripts/                     # Maintenance & migration tools
│   └── migrate_experiments.py
└── tests/                      # Unit & integration test suite
    ├── unit/
    └── integration/
```

---

## Test Suite

Run unit and integration tests using `pytest`:

```bash
# Run unit selection, crypto, dynamic weighting, and protocol tests
python -m pytest tests/unit/ -v
```
