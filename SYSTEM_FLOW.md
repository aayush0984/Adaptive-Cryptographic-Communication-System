# Technical System Flow & Adaptive Selection Architecture

This document provides a comprehensive technical walkthrough of the **Adaptive Cryptographic Configuration Selection** framework for secure IoT communication.

---

## 1. High-Level Architecture Diagram

```text
                               +-----------------------------+
                               |   MongoDB: iot_security     |
                               |   - devices                 |
                               |   - crypto_profiles         |
                               |   - benchmarks              |
                               |   - experiments             |
                               +--------------+--------------+
                                              |
                                              v
+------------------------+          +-------------------+          +------------------------+
|   Device A (Sender)    | -------->| Adaptive Selector | <--------|  Device B (Receiver)   |
|   - available_memory_kb|          |                   |          |   - available_memory_kb|
|   - latency_req_ms     |          |  STAGE 1: HARD    |          |   - latency_req_ms     |
|   - max_packet_size    |          |  FILTERING        |          |   - max_packet_size    |
|   - security_req       |          |        |          |          |   - security_req       |
|   - power_source       |          |        v          |          |   - power_source       |
+------------------------+          |  STAGE 2: DYNAMIC |          +------------------------+
            |                       |  WEIGHTING & SCORE|                      |
            |                       +---------+---------+                      |
            v                                 |                                v
    User Plaintext Message                    v                    Encrypted Packet Received
    (UTF-8 Bytes Calculation)           Selected Profile                   (Framed TCP Socket)
            |                                 |                                |
            +---------------------------------+--------------------------------+
                                              v
                               +-----------------------------+
                               |  Cryptographic Engine Execution|
                               |  - Key Establish (RSA/ECDH) |
                               |  - Symmetric Cipher (AES-GCM)|
                               +-----------------------------+
```

---

## 2. End-to-End Execution Sequence

The complete operational flow executes across the following 10 steps:

```text
[Step 1: Input Collection]
  Sender selects Device A & Receiver selects Device B from catalog.
  User inputs plaintext message string (e.g. "Hello world").
         │
[Step 2: Message Size Calculation]
  Calculate UTF-8 byte length (message_size_bytes = len(msg.encode('utf-8'))).
         │
[Step 3: MongoDB Profile & Benchmark Retrieval]
  Query active crypto profiles (C1–C4) & fetch matching benchmark evidence
  for (Device A, profile, size) and (Device B, profile, size).
         │
[Step 4: STAGE 1 — Hard Constraint Filtering]
  Evaluate every profile against mandatory security, memory, latency, CPU, and packet capacity limits.
  Reject non-compliant profiles with detailed rejection logs.
         │
[Step 5: STAGE 2 — Dynamic Pressure Calculation]
  Calculate scenario pressures (P_time, P_memory, P_comm, P_energy) from combined constraints.
         │
[Step 6: Dynamic Weight Derivation]
  Normalize pressures into objective weights (w_time, w_memory, w_comm, w_energy) summing to 1.0.
         │
[Step 7: Weighted Normalized Scoring]
  Normalize candidate costs against benchmark bounds and compute final weighted score.
  Select profile with the lowest score (deterministic tie-breaking).
         │
[Step 8: Selection Provenance & Experiment Persistence]
  Persist prediction block, pressures, dynamic weights, and candidate evaluation metadata
  to MongoDB collection `iot_security.experiments`.
         │
[Step 9: Sender Cryptographic Execution & Transmission]
  Establish session key (RSA-OAEP wrap or ECDH + HKDF-SHA256).
  Encrypt plaintext payload using AES-GCM (128/256-bit).
  Send length-prefixed JSON frame over TCP to receiver.
         │
[Step 10: Receiver Decryption & Echo Verification]
  Receiver reads frame header, verifies profile ID, derives session key, decrypts ciphertext.
  Validates tag integrity, echoes recovered message ACK, and records observed metrics in MongoDB.
```

---

## 3. Detailed Stage 1: Hard Constraint Filtering

In Stage 1, candidate profiles are evaluated against mandatory hardware and security boundaries. If a profile violates any single constraint, it is immediately rejected. **A good weighted score in Stage 2 cannot compensate for a Stage 1 hard constraint failure.**

### Constraint Evaluation Rules

1. **Security Policy Floor**:
   $$\text{profile.security\_level} \ge \max(\text{security}_A, \text{security}_B)$$
   - Devices with `high` security requirement reject `standard` security profiles.
   - Devices with `standard` security requirement accept both `standard` and `high` profiles.

2. **Minimum CPU Level**:
   $$\text{device.cpu\_level} \ge \text{profile.minimum\_cpu\_level}$$
   - CPU ordering: $\text{low} < \text{medium} < \text{high}$.

3. **Independent Endpoint Peak Memory**:
   $$\text{available\_memory}_A \ge \text{peak\_memory\_kb}_{A, \text{predicted}}$$
   $$\text{available\_memory}_B \ge \text{peak\_memory\_kb}_{B, \text{predicted}}$$
   - Evaluated independently per endpoint (RAM is not combined).

4. **Combined Session Latency Ceiling**:
   $$\text{latency}_{\text{combined}} = \text{total\_ms}_A + \text{total\_ms}_B \le \min(\text{latency\_limit}_A, \text{latency\_limit}_B)$$

5. **Maximum Packet Overhead Ceiling**:
   $$\text{application\_bytes}_{\text{predicted}} \le \min(\text{packet\_limit}_A, \text{packet\_limit}_B)$$

6. **Engine Implementation Verification**:
   - Ensures the key establishment family (`RSA` or `ECC`) is backed by an active python crypto engine.

---

## 4. Detailed Stage 2: Dynamic Pressure & Weight Derivation

Stage 2 ranks all feasible profiles using dynamically derived scenario weights $(w_{\text{time}}, w_{\text{memory}}, w_{\text{comm}}, w_{\text{energy}})$.

### A. Pressure Calculation Formulas

1. **Time Pressure ($P_{\text{time}}$)**:
   Determined by the strictest latency requirement $\text{lat}_{\min} = \min(\text{lat}_A, \text{lat}_B)$:
   - If $\text{lat}_{\min} \le 50\text{ ms} \implies P_{\text{time}} = 1.0$ (maximum urgency).
   - If $\text{lat}_{\min} \ge 2000\text{ ms} \implies P_{\text{time}} = 0.05$ (floor).
   - Otherwise, continuous inverted logarithmic interpolation:
     $$P_{\text{time}} = 0.05 + 0.95 \cdot \frac{\ln(2000) - \ln(\text{lat}_{\min})}{\ln(2000) - \ln(50)}$$

2. **Memory Pressure ($P_{\text{memory}}$)**:
   Determined by the lowest available RAM $\text{mem}_{\min} = \min(\text{mem}_A, \text{mem}_B)$:
   - If $\text{mem}_{\min} \le 32\text{ KB} \implies P_{\text{memory}} = 1.0$.
   - If $\text{mem}_{\min} \ge 524288\text{ KB } (512\text{ MB}) \implies P_{\text{memory}} = 0.05$.
   - Otherwise, continuous inverted logarithmic interpolation:
     $$P_{\text{memory}} = 0.05 + 0.95 \cdot \frac{\ln(524288) - \ln(\text{mem}_{\min})}{\ln(524288) - \ln(32)}$$

3. **Communication Pressure ($P_{\text{comm}}$)**:
   Determined by the message size relative to the effective packet capacity $\text{capacity} = \min(\text{packet}_A, \text{packet}_B)$:
   $$\text{ratio} = \frac{\text{message\_size\_bytes}}{\text{capacity}}$$
   - If $\text{ratio} \le 0.05 \implies P_{\text{comm}} = 0.05$.
   - If $\text{ratio} \ge 1.00 \implies P_{\text{comm}} = 1.00$.
   - Otherwise, continuous linear interpolation:
     $$P_{\text{comm}} = 0.05 + 0.95 \cdot \frac{\text{ratio} - 0.05}{0.95}$$

4. **Energy Pressure ($P_{\text{energy}}$)**:
   Derived strictly from endpoint `power_source` (`"mains"` vs `"battery"`):
   - $\text{power}_A = \text{mains}$ and $\text{power}_B = \text{mains} \implies P_{\text{energy}} = 0.20$.
   - Either endpoint $\text{power} = \text{battery} \implies P_{\text{energy}} = 0.80$.
   - Both endpoints $\text{power} = \text{battery} \implies P_{\text{energy}} = 0.95$.

### B. Weight Normalization

The four pressures are normalized to sum to $1.0$:
$$\text{Total} = P_{\text{time}} + P_{\text{memory}} + P_{\text{comm}} + P_{\text{energy}}$$
$$w_i = \frac{P_i}{\text{Total}} \quad \text{for } i \in \{\text{time}, \text{memory}, \text{comm}, \text{energy}\}$$

---

## 5. Candidate Metric Normalization & Scoring

For each feasible profile $k$, raw metric values are extracted from benchmark evidence:
- **Time ($T_k$)**: Combined sender + receiver predicted total latency ($\text{ms}$).
- **Memory ($M_k$)**: Peak heap memory ($\text{KB}$).
- **Communication ($C_k$)**: Application payload overhead ($\text{bytes}$).
- **Energy ($E_k$)**: Energy proxy cost ($\text{ms} \times 0.001$).

### Min-Max Normalization Function
Each raw metric $V_k$ is normalized to $\mathcal{N}(V_k) \in [0, 1]$:
$$\mathcal{N}(V_k) = \frac{V_k - V_{\min}}{V_{\max} - V_{\min}}$$
*(If $V_{\max} = V_{\min}$, $\mathcal{N}(V_k) = 0.0$ to prevent division by zero).*

### Final Weighted Score Formula
$$\text{Score}_k = w_{\text{time}} \cdot \mathcal{N}(T_k) + w_{\text{memory}} \cdot \mathcal{N}(M_k) + w_{\text{comm}} \cdot \mathcal{N}(C_k) + w_{\text{energy}} \cdot \mathcal{N}(E_k)$$

### Deterministic Tie-Breaking Order
1. **Lower Final Score** (cheapest composite cost).
2. **Lower Application Bytes** (fewer network bytes transferred).
3. **Alphabetical Profile ID** (`C1` < `C2` < `C3` < `C4`).

---

## 6. MongoDB Collection Schema Reference

### Collection 1: `devices`
```json
{
  "device_id": "esp32",
  "name": "ESP32",
  "cpu_level": "medium",
  "available_memory_kb": 520.0,
  "maximum_packet_size_bytes": 1500,
  "latency_requirement_ms": 1000.0,
  "security_requirement": "standard",
  "power_source": "battery",
  "active": true
}
```

### Collection 2: `crypto_profiles`
```json
{
  "profile_id": "C4",
  "name": "ECDH-P384 with AES-256-GCM",
  "security_level": "high",
  "minimum_cpu_level": "medium",
  "active": true,
  "key_establishment": {
    "family": "ECC",
    "algorithm": "ECDH",
    "parameter": "P-384"
  },
  "symmetric_encryption": {
    "algorithm": "AES-GCM",
    "key_size_bits": 256
  }
}
```

### Collection 3: `benchmarks`
```json
{
  "run_id": "run-uuid-1234",
  "device_id": "esp32",
  "profile_id": "C4",
  "message_size_bytes": 64,
  "repetition": 1,
  "timings_ms": {
    "key_generation": 1.25,
    "key_establishment": 3.40,
    "encryption": 0.15,
    "decryption": 0.12,
    "total": 4.92
  },
  "peak_memory_kb": 45.2,
  "process_rss_kb": 14200.0,
  "application_bytes": 180,
  "measurement_source": "local-computer",
  "benchmark_mode": "simulated",
  "success": true
}
```

### Collection 4: `experiments`
```json
{
  "experiment_id": "exp-4a2b8c9d",
  "sender_id": "esp32",
  "receiver_id": "raspberry_pi_4",
  "sender_constraints": { "available_memory_kb": 520.0, "power_source": "battery" },
  "receiver_constraints": { "available_memory_kb": 2097152.0, "power_source": "mains" },
  "combined_constraints": { "memory_limit_kb": 520.0, "required_security": "high" },
  "constraint_pressures": { "p_time": 0.41, "p_memory": 0.73, "p_communication": 0.05, "p_energy": 0.80 },
  "dynamic_weights": { "wt": 0.205, "wm": 0.366, "wc": 0.025, "we": 0.403 },
  "message_size_bytes": 11,
  "selected_profile_id": "C4",
  "selection_reason": "Profile 'C4' (ECDH-P384 with AES-256-GCM) selected...",
  "status": "completed",
  "is_demonstration_mode": true
}
```

---

## 7. Operational Scenarios & Explainability Examples

### Scenario 1: Constrained Battery Node $\rightarrow$ Mains Server (ESP32 $\rightarrow$ Raspberry Pi 4)
- **Input**: Message = `"Hello world"` (11 B).
- **Pressures**: $P_{\text{time}} = 0.41$, $P_{\text{memory}} = 0.73$, $P_{\text{comm}} = 0.05$, $P_{\text{energy}} = 0.80$.
- **Dynamic Weights**: $w_{\text{time}} = 20.5\%$, $w_{\text{memory}} = 36.6\%$, $w_{\text{comm}} = 2.5\%$, $w_{\text{energy}} = 40.3\%$.
- **Outcome**: `C1` and `C3` are rejected in Stage 1 because Raspberry Pi 4 requires `high` security. Between `C2` and `C4`, **`C4` (ECDH-P384 / AES-256-GCM)** wins due to significantly lower memory and energy footprint.

### Scenario 2: High-Performance Mains Nodes (Jetson Nano $\rightarrow$ Raspberry Pi 4)
- **Input**: Message = `"Telemetry Payload"` (39 B).
- **Pressures**: $P_{\text{time}} = 0.54$, $P_{\text{memory}} = 0.05$, $P_{\text{comm}} = 0.05$, $P_{\text{energy}} = 0.20$.
- **Dynamic Weights**: $w_{\text{time}} = 64.2\%$, $w_{\text{memory}} = 6.0\%$, $w_{\text{comm}} = 6.0\%$, $w_{\text{energy}} = 23.8\%$.
- **Outcome**: Both nodes have abundant RAM (2 GB / 4 GB) and mains power. Time pressure dominates ($64.2\%$), selecting **`C4`** as the fastest high-security profile.
