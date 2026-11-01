# Adaptive Cryptographic Configuration Selection & Secure IoT Communication

An end-to-end adaptive security and network analysis framework for resource-constrained Internet of Things (IoT) devices, featuring an intelligent multi-objective selection engine, framed TCP transmission, live TShark packet sniffing, deep PyShark traffic dissection, and a modern full-stack web control plane.

---

## Overview & Problem Statement

Deploying secure communication across heterogeneous IoT networks presents fundamental challenges:
* **Severe Resource Disparity**: Low-power microcontrollers (e.g., ESP32, STM32, Arduino) have limited RAM (often hundreds of KB) and battery power, making heavy asymmetric operations like RSA-3072 prohibitive in execution time and memory.
* **Rigid Security Policies**: Edge servers and cloud gateways mandate strict security floors (e.g., 256-bit security), rejecting standard or legacy ciphers.
* **Static Configuration Fragility**: Hardcoding a single cipher suite across diverse devices leads to either security vulnerabilities or device crashes from resource exhaustion.
* **Wire & Framing Overhead**: For small IoT telemetry payloads (e.g., 4–32 bytes), cryptographic expansion, protocol headers, and TCP handshakes generate significant protocol overhead that must be measured and optimized.

This framework solves these challenges by dynamically negotiating the optimal cryptographic profile per transaction based on real-time endpoint pressures, executing secure transmissions, capturing wire traffic on loopback, and dissecting network overhead.

---

## System Architecture

The framework provides both an interactive **Full-Stack Web Application** and a scriptable **Terminal / CLI Workflow**:

```text
+---------------------------------------------------------------------------------------------------+
|                                      MongoDB (iot_security)                                       |
|   - devices           - crypto_profiles           - benchmarks           - experiments   - traffic|
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                           Adaptive Cryptographic Decision Engine                                  |
|  Stage 1: Hard Constraint Filtering (RAM, CPU, Security Floor, MTU, Latency Ceilings)              |
|  Stage 2: Multi-Objective Dynamic Weighting (Time, Memory, Communication, Energy Pressures)       |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
                         ┌─────────────────────────────────────────────────┐
                         │ Selected Profile: C1 | C2 | C3 | C4 | C5        │
                         └────────────────────────┬────────────────────────┘
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                  Communication & Wire Capture                                     |
|  1. Sender (Device A)   ──[ Framed TCP / Port 5000 ]──>   2. Receiver Server (Device B)           |
|                                                                                                   |
|  3. Network Capture Monitor (TShark listening on lo0 :5000) ──> captures/experiment_<id>.pcapng   |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                Offline PyShark Traffic Analysis                                   |
|  - Directional packet counts (A -> B vs B -> A)       - Exact frame lengths vs file size          |
|  - TCP flag decoding (SYN, ACK, PSH, FIN, RST)        - Wire overhead percentage vs plaintext     |
|  - Export formatted report: backend/analysis/data/<experiment_id>.txt                             |
+---------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+---------------------------------------------------------------------------------------------------+
|                                  Frontend Web Control Plane                                       |
|  - Experiment Tab: Constraint selection, pressure bars, candidate trace, and interactive live    |
|    step-by-step cryptographic workflow timeline (Device A -> TCP Wire -> Device B verification)  |
|  - Traffic Tab: Session detail inspection, packet details table, per-profile cost comparison      |
|  - Profiles Tab: Cryptographic catalog (C1 through C5)                                            |
|  - History Tab: Chronological selection decisions and transmission audit log                      |
+---------------------------------------------------------------------------------------------------+
```

---

## Cryptographic Profiles Catalog

The system evaluates five complete cryptographic suites:

| ID | Suite Name | Key Establishment / KEM | Symmetric Encryption | Security Level | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`C1`** | RSA-2048 with AES-128-GCM | RSA-OAEP (2048-bit, SHA-256) | AES-128-GCM | Standard | Medium-power devices, legacy RSA infrastructure |
| **`C2`** | RSA-3072 with AES-256-GCM | RSA-OAEP (3072-bit, SHA-256) | AES-256-GCM | High | High-capability single-board computers, strict security floors |
| **`C3`** | ECDH-P256 with AES-128-GCM | Ephemeral ECDH (SECP256R1) + HKDF-SHA256 | AES-128-GCM | Standard | Highly resource-constrained MCUs (fast, lightweight) |
| **`C4`** | ECDH-P384 with AES-256-GCM | Ephemeral ECDH (SECP384R1) + HKDF-SHA256 | AES-256-GCM | High | Top-tier security with low memory footprint |
| **`C5`** | Fallback PSK with AES-128-GCM | Pre-Shared Key (256-bit symmetric) | AES-128-GCM | Basic / Fallback | Extreme constraint fallback when asymmetric key exchange fails |

---

## Repository Structure

```text
IoTEncryption/
├── README.md                        # Project documentation
│
├── backend/                         # Backend Python services & engine
│   ├── .env                         # Runtime configuration
│   ├── requirements.txt             # Python package dependencies
│   ├── api.py                       # FastAPI REST API (port 8000)
│   ├── server.py                    # Receiver TCP server (Device B, port 5000)
│   ├── client.py                    # Sender CLI client (Device A)
│   ├── capture_monitor.py           # TShark packet capture monitor daemon
│   ├── analyze_traffic.py           # Phase 10 CLI: PyShark offline traffic analysis entry point
│   │
│   ├── analysis/                    # Packet dissection & network metrics engine
│   │   ├── traffic_analyzer.py      # Core TrafficAnalyzer class & formatters
│   │   └── data/                    # Exported analysis reports (*.txt, git-ignored)
│   │
│   ├── capture/                     # TShark sniffer wrapper & loopback detector
│   │   └── packet_capture.py
│   ├── captures/                    # Destination directory for raw .pcapng files
│   │
│   ├── crypto/                      # Low-level cryptographic primitives
│   │   ├── aes_engine.py            # AES-128/256-GCM authenticated encryption
│   │   ├── ecc_engine.py            # Ephemeral ECDH (P-256, P-384) + HKDF-SHA256
│   │   ├── rsa_engine.py            # RSA-OAEP (2048/3072-bit) with SHA-256
│   │   └── psk_engine.py            # Pre-Shared Key (PSK) + AES-128-GCM fallback
│   │
│   ├── database/                    # MongoDB connection & collections
│   │   ├── connection.py            # MongoClient accessor & database singleton
│   │   ├── indexes.py               # Database indexing across all collections
│   │   └── seed_database.py         # Hardware devices and crypto profiles seeder
│   │
│   ├── evaluation/                  # Benchmarking engine
│   │   ├── benchmark.py             # Performance measurement harness (timing, RAM)
│   │   └── memory_monitor.py        # Memory profiler (tracemalloc)
│   │
│   ├── models/                      # Domain dataclasses (Device, CryptoProfile)
│   ├── repositories/                # MongoDB abstraction layer (Device, Profile, Experiment, Benchmark)
│   └── selection/                   # Two-stage adaptive selector
│       ├── compatibility.py         # Stage 1: Hard constraint evaluation
│       ├── scoring.py               # Stage 2: Scenario pressures, weights, scoring
│       └── selector.py              # Selection orchestrator
│
├── frontend/                        # Web Control Plane (React 19 + Vite)
│   ├── package.json
│   ├── vite.config.js               # Vite config with API proxy to port 8000
│   └── src/
│       ├── App.jsx                  # Main app shell & navigation (Experiment, Traffic, Profiles, History)
│       ├── TransmissionTimeline.jsx # Animated step-by-step secure communication workflow timeline
│       ├── timeline.css             # Timeline & technical step card styles
│       ├── TrafficTab.jsx           # Traffic Analysis dashboard & packet details table
│       ├── traffic.css              # Traffic dashboard styles
│       └── styles.css               # Base theme & UI component styles
│
└── tests/                           # Automated test suite (147 tests)
    ├── unit/                        # Crypto, selector, detailed transmission, protocol, packet capture, analyzer tests
    └── integration/                 # MongoDB and end-to-end socket integration tests
```

---

## Technologies & Stack

* **Backend & Cryptography**:
  * Python 3.10+
  * `cryptography` (hazmat): AES-GCM, RSA-OAEP, ECDH, HKDF
  * `pymongo`: MongoDB database driver
  * `fastapi` & `uvicorn`: RESTful API backend
  * `pytest`: Unit and integration test runner
* **Network & Traffic Dissection**:
  * Wireshark / `tshark`: Wire sniffing on loopback interface
  * `pyshark`: Packet inspection and TCP header dissection
* **Database**:
  * MongoDB Community Server 7.0+ (`iot_security` database)
* **Frontend**:
  * React 19 & Vite 8
  * Lucide React icons
  * Modern Dark-Mode IoT Control Plane UI

---

## Setup & Installation

### 1. System Prerequisites

Install MongoDB and Wireshark/TShark on your host:

```bash
# macOS (Homebrew)
brew install mongodb-community wireshark
brew services start mongodb-community

# Ubuntu / Debian
sudo apt update && sudo apt install -y mongodb-org tshark
sudo systemctl start mongod
```

On macOS, allow non-root loopback packet capture:
```bash
sudo chmod 666 /dev/bpf*
```

---

### 2. Backend Setup

```bash
cd backend

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

Verify `backend/.env` exists:
```env
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=iot_security
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
CAPTURE_INTERFACE=lo0
FALLBACK_PSK_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Initialize the database:
```bash
# Seed 20 devices and 5 cryptographic profiles
python -m database.seed_database

# Create indexes across collections
python -c "from database.indexes import create_indexes; print(create_indexes())"

# (Optional) Seed local benchmark evidence
python -m evaluation.benchmark --all --dry-run
```

---

### 3. Frontend Setup

```bash
cd ../frontend
npm install
```

---

## How to Run

### Method A: Full-Stack Web Application (Recommended)

Start the services across separate terminal tabs:

1. **Terminal 1 — FastAPI Backend**:
   ```bash
   cd backend && source .venv/bin/activate
   uvicorn api:app --reload --port 8000
   ```
2. **Terminal 2 — Receiver Server (Device B)**:
   ```bash
   cd backend && source .venv/bin/activate
   python server.py
   ```
3. **Terminal 3 — Network Capture Monitor (TShark)**:
   ```bash
   cd backend && source .venv/bin/activate
   python capture_monitor.py
   ```
4. **Terminal 4 — React Frontend (Vite)**:
   ```bash
   cd frontend
   npm run dev
   ```

Open your browser at **`http://localhost:5173`**:
* **Experiment Tab**: Pick Sender (A), Receiver (B), and a payload string. Click **Analyze & select profile**, then click **Transmit securely**. This triggers live end-to-end cryptographic execution and mounts the interactive vertical timeline:
  * **Device A — Sender**: Original plaintext size, key pair generation (RSA-OAEP, ECDH-P256/P384, or PSK), key wrapping/derivation, CSPRNG nonce generation, and authenticated AES-GCM encryption with exact timings.
  * **Network Transmission**: Wire metrics over TCP port 5000, length-prefixed framing headers, payload bytes, and transmission latency.
  * **Device B — Receiver**: Private key unwrapping or ECDH HKDF derivation, AES-GCM GHASH tag verification (`TAG VERIFIED ✓`), decryption latency, side-by-side original vs. recovered message comparison, and integrity confirmation (`PASSED ✓`).
* **Traffic Tab**: Inspect the session details on top (metadata, traffic summary, network overhead, directional breakdown, and the per-packet frame table). View the **Traffic cost by profile** comparison on the bottom across C1–C5.
* **Profiles Tab**: Inspect cipher suite specifications.
* **History Tab**: Review historical decisions.

---

### Method B: Terminal / CLI Workflow

1. **Terminal 1 — Receiver Server**:
   ```bash
   cd backend && source .venv/bin/activate
   python server.py
   ```
2. **Terminal 2 — Capture Monitor**:
   ```bash
   cd backend && source .venv/bin/activate
   python capture_monitor.py
   ```
3. **Terminal 3 — Sender Client**:
   ```bash
   cd backend && source .venv/bin/activate
   # Interactive prompt:
   python client.py
   # Or automated command:
   python client.py --sender esp32 --receiver raspberry_pi_4 --message "temperature=24.5; humidity=60"
   ```
4. **Terminal 4 — Traffic Analysis CLI**:
   ```bash
   cd backend && source .venv/bin/activate
   python analyze_traffic.py --experiment exp-a207ff8e
   ```

---

## Traffic Analysis Output Format

When running traffic analysis via CLI (`analyze_traffic.py`) or inspecting captures in the Web UI, the framework parses the raw `.pcapng` file using PyShark and formats an exact breakdown:

```text
================== TRAFFIC ANALYSIS ==================

EXPERIMENT DETAILS
------------------------------------------------------
Experiment ID     : exp-a207ff8e
Sender (A)        : ESP32 [esp32]
Receiver (B)      : Raspberry Pi 4 [raspberry_pi_4]
Crypto Profile    : C4 - ECDH-P384 with AES-256-GCM
Message Size      : 4 B
Capture Interface : lo0

TRAFFIC SUMMARY
------------------------------------------------------
Total Packets     : 12
A -> B Packets    : 6
B -> A Packets    : 6
Data Packets      : 2
Captured Bytes    : 1203 B
TCP Payload       : 507 B
Min Packet Size   : 56 B
Max Packet Size   : 323 B
Avg Packet Size   : 100.25 B
Retransmissions   : 0
Traffic Duration  : 0.121 s

NETWORK OVERHEAD
------------------------------------------------------
Overhead Bytes    : 1199 B
Overhead Percent  : 29975.00%

PACKET DETAILS
------------------------------------------------------
#   Direction  Flags       Payload(B)  Frame(B)
------------------------------------------------------
1   A -> B     SYN         0           68
2   B -> A     SYN, ACK    0           68
3   A -> B     ACK         0           56
4   B -> A     ACK         0           56
5   A -> B     PSH, ACK    240         296
6   B -> A     ACK         0           56
7   B -> A     PSH, ACK    267         323
8   A -> B     ACK         0           56
9   A -> B     FIN, ACK    0           56
10  B -> A     ACK         0           56
11  B -> A     FIN, ACK    0           56
12  A -> B     ACK         0           56
------------------------------------------------------
Capture Status    : completed
Analysis Status   : completed
======================================================
```

Every analysis run automatically generates an exported report text file under `backend/analysis/data/<experiment_id>.txt`.

---

## Running Automated Tests

The comprehensive test suite covers cryptographic primitives, two-stage adaptive selection, PSK fallback, communication framing, capture management, and PyShark analysis:

```bash
# Run all 147 tests
PYTHONPATH=backend backend/.venv/bin/pytest tests/ -v

# Run transmission workflow unit tests
PYTHONPATH=backend backend/.venv/bin/pytest tests/unit/test_transmit_detailed.py -v

# Run only traffic analyzer unit tests
PYTHONPATH=backend backend/.venv/bin/pytest tests/unit/test_traffic_analyzer.py -v
```

---

## License

This project is developed for educational and academic research into adaptive security for constrained IoT environments.
