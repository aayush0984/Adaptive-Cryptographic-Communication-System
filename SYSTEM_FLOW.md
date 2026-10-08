# Technical System Flow & End-to-End Architecture

This document provides a comprehensive, deep-dive technical specification of the implemented **Adaptive Cryptographic Configuration Selection, Secure IoT Communication, and Network Traffic Analysis** framework (Phases 0–10).

It describes every stage of execution from initial user input through two-stage adaptive optimization, cryptographic framing, three-terminal TCP communication, live TShark loopback sniffing, and offline PyShark packet analysis.

---

## 1. Complete End-to-End Execution Flow

```text
User Input: Device A (Sender) + Device B (Receiver) + Plaintext Message
                                │
                                ▼
1. Device Data Fetch (MongoDB: iot_security.devices)
   - CPU level, RAM (available_memory_kb), latency ceiling, MTU, security policy, power source
                                │
                                ▼
2. Stage 1: Mandatory Hard Constraint Filtering (selection/compatibility.py)
   - Security Policy Floor: profile.security_level >= max(security_A, security_B)
   - CPU Capability: device.cpu_level >= profile.minimum_cpu_level
   - Memory Feasibility: available_memory >= peak_memory_kb (independent per node)
   - Latency Ceiling: total_predicted_latency <= min(latency_limit_A, latency_limit_B)
   - MTU Ceiling: application_bytes <= min(packet_limit_A, packet_limit_B)
   - Engine Availability: verification of crypto engines
   - [EDGE CASE] If all standard profiles (C1–C4) fail constraints:
     ├── Activate Fallback Profile C5 (Loaded from MongoDB: iot_security.crypto_profiles)
     ├── Relax security requirement as soft constraint (basic security accepted)
     └── Strictly verify hard technical constraints (AES-128-GCM support, RAM, CPU, MTU)
                                │
                                ▼
3. Empirical Benchmark Retrieval (MongoDB: iot_security.benchmarks)
   - Lookup timing (key_gen, key_est, enc, dec) and peak heap memory per candidate
                                │
                                ▼
4. Stage 2: Dynamic Scenario Weighting & Multi-Objective Scoring (selection/scoring.py)
   - Continuous pressure derivations: P_time, P_memory, P_comm, P_energy
   - Dynamic weight normalization: w_time + w_memory + w_comm + w_energy = 1.0
   - Candidate min-max normalization & weighted composite scoring (standard candidates only)
   - Deterministic tie-breaking (score -> wire size -> profile ID)
                                │
                                ▼
5. Selection Audit & Logging (MongoDB: iot_security.experiments)
   - Records experiment_id, candidates evaluated, rejections, dynamic weights, winner (e.g., C4 or C5)
   - Records selection_mode ("normal" vs "fallback"), fallback_used, fallback_reason, relaxed_constraints
                                │
                                ▼
6. Sender Cryptographic Execution (client.py & crypto/)
   - For C1–C4: Ephemeral key generation (RSA/ECDH), HKDF session key extraction, AES-GCM encryption
   - For C5: Pre-Shared Key (128-bit PSK loaded from .env) + AES-128-GCM authenticated encryption
                                │
                                ▼
7. Framed TCP Transmission (communication/protocol.py)
   - 4-byte big-endian binary length header + UTF-8 JSON ProtocolMessage (Type: HELLO)
   - Transported over TCP port 5000 via loopback interface (lo0)
                                │
                                ▼
8. Receiver Processing & Verification (server.py & crypto/)
   - Length-prefixed frame extraction & protocol deserialization
   - For C1–C4: Profile validation, asymmetric key derivation / unwrapping, AES-GCM decryption
   - For C5: PSK lookup from configuration and AES-128-GCM authentication tag verification + decryption
   - GCM authentication tag verification; echoes verified payload in ACK frame
   - Server writes execution result to MongoDB: iot_security.experiments
                                │
                                ▼
9. Phase 9: Live TShark Network Capture (capture_monitor.py & capture/)
   - Independent background daemon sniffs lo0 filtered on `tcp port 5000`
   - Streams live packet summaries to Terminal 3 without leaking plaintext or keys
   - Slices session on connection close; computes SHA-256 integrity hash
   - Saves `captures/experiment_<id>_<profile>_<size>B.pcapng`
   - Persists capture metadata to MongoDB: iot_security.traffic
                                │
                                ▼
10. Phase 10: PyShark Packet Analysis & Overhead Quantification (analyze_traffic.py & analysis/)
    - Opens .pcapng using PyShark FileCapture (keep_packets=False)
    - Directional classification (Sender -> Receiver vs Receiver -> Sender based on port 5000)
    - Extracts packet counts, byte counts, min/max/avg packet size, TCP payload, retransmissions
    - Computes network overhead bytes and network overhead percentage
    - Persists nested `traffic_analysis` subdocument into MongoDB: iot_security.traffic
```

---

## 2. Detailed Technical Breakdown by Stage

---

### Stage 1: Device Configuration & Input Acquisition

#### Inputs
* `sender_id` (Device A ID, e.g., `"esp32"`).
* `receiver_id` (Device B ID, e.g., `"raspberry_pi_4"`).
* Plaintext string (e.g., `"test"`).

#### Processing
1. In interactive mode, `client.py` queries `iot_security.devices` via `DeviceRepository.list_active()`, rendering a numbered selection menu.
2. The user inputs or confirms the target sender, receiver, and message string.
3. Message length is computed as raw UTF-8 bytes:
   $$B_{\text{message}} = \text{len}(\text{message.encode('utf-8')})$$
   *Plaintext is retained only in working memory and is never persisted to database records or packet headers.*

#### MongoDB Reads
* `iot_security.devices`:
  ```javascript
  db.devices.find({ active: true })
  ```

#### Outputs to Next Stage
* `Device` model objects for Sender ($A$) and Receiver ($B$).
* `message_size_bytes` ($B_{\text{message}}$).

---

### Stage 2: Stage 1 Mandatory Hard Constraint Filtering

#### Purpose
Ensures that no cryptographic profile is selected that would crash a device due to insufficient RAM, exceed maximum packet sizes, violate device security baselines, or exceed real-time latency deadlines.

#### Combined Constraints Derivation
To evaluate end-to-end communication, constraints from Device A and Device B are merged:
* **Combined Available Memory**: Not combined into a sum. Evaluated independently per device:
  $$\text{RAM}_{\text{avail}, A} \quad \text{and} \quad \text{RAM}_{\text{avail}, B}$$
* **Required Security Floor**:
  $$S_{\text{req}} = \max(S_A, S_B) \quad \text{where } \text{"standard"} < \text{"high"}$$
* **Combined Session Latency Ceiling**:
  $$L_{\text{limit}} = \min(L_A, L_B)$$
  where $L_A, L_B$ are `latency_requirement_ms`.
* **Effective Packet Capacity (MTU Ceiling)**:
  $$C_{\text{packet}} = \min(M_A, M_B)$$
  where $M_A, M_B$ are `maximum_packet_size_bytes`.

#### Filtering Rules & Rejection Conditions
For each profile $k \in \{C1, C2, C3, C4\}$:

1. **Security Policy Rule**:
   $$\text{profile.security\_level} \ge S_{\text{req}}$$
   *Rejection Reason*: `"receiver security_requirement='high' does not satisfy profile security_level='standard'"`

2. **CPU Capability Rule**:
   $$\text{device}_A\text{.cpu\_level} \ge \text{profile.minimum\_cpu\_level} \quad \land \quad \text{device}_B\text{.cpu\_level} \ge \text{profile.minimum\_cpu\_level}$$
   with ordering $\text{"low"} < \text{"medium"} < \text{"high"}$.
   *Rejection Reason*: `"sender cpu_level='medium' does not meet profile minimum_cpu_level='high'"`

3. **Peak Heap Memory Capacity Rule**:
   $$\text{RAM}_{\text{avail}, A} \ge M_{k, A, \text{predicted}} \quad \land \quad \text{RAM}_{\text{avail}, B} \ge M_{k, B, \text{predicted}}$$
   where $M_{k, \text{node}, \text{predicted}}$ is the peak memory in KB measured during benchmarks.

4. **Session Latency Limit Rule**:
   $$T_{k, A, \text{predicted}} + T_{k, B, \text{predicted}} \le L_{\text{limit}}$$

5. **Packet Size Limit Rule**:
   $$C_{k, \text{predicted}} \le C_{\text{packet}}$$
   where $C_{k, \text{predicted}}$ is the total serialized wire payload size in bytes.

6. **Engine Implementation Rule**:
   Verifies that the underlying engine (`crypto/rsa_engine.py`, `crypto/ecc_engine.py`, `crypto/aes_engine.py`) is implemented and operational.

#### Edge-Case Handling: Fallback Cryptographic Profile (`C5`)

When hardware constraints (e.g. low CPU, low RAM) or high security requirements prevent **all** standard profiles (`C1`–`C4`) from satisfying compatibility checks (`feasible_pairs` is empty), the selector triggers the C5 fallback path:

```text
Evaluate C1–C4 ──► [None Feasible] ──► Load C5 from MongoDB
                                                │
                                                ▼
                                    check_c5_technical_feasibility()
                                    ├── Relax Security Level: "high" accepted for "basic"
                                    ├── Verify Hard Constraint: AES-128-GCM supported
                                    ├── Verify Hard Constraint: RAM >= peak_kb (default 2.0 KB)
                                    ├── Verify Hard Constraint: cpu_level >= "low"
                                    └── Verify Hard Constraint: packet_size <= MTU
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          ▼                                           ▼
                    [Infeasible]                                 [Feasible]
                 Raise ValueError:                        Emit 5 [selector] logs
          "fallback_profile_not_feasible"                 Persist fallback experiment
                                                          Select C5 (PSK + AES-128-GCM)
```

##### 1. Strict Isolation from Standard Scoring
* `C5` is filtered out before Stage 1 compatibility checks:
  $$\text{standard\_profiles} = [p \in \text{enabled\_profiles} \mid p.\text{profile\_id} \ne \text{"C5"}]$$
* `C5` never participates in Stage 2 multi-objective scoring alongside `C1`–`C4`. It is evaluated only if all standard profiles fail.

##### 2. Soft Security Constraint vs. Hard Technical Constraints
* **Soft Constraint (Relaxed)**: During fallback, the security requirement floor is relaxed. If a device requires `security_requirement = "high"`, `C5` (`basic`) is not rejected.
* **Hard Constraints (Strictly Enforced)**:
  1. **Algorithm Support**: Both Device A and Device B must explicitly list `"AES-128-GCM"` in their `supported_algorithms`.
  2. **Memory Feasibility**: $\text{RAM}_{\text{avail}, A} \ge 2.0\text{ KB}$ and $\text{RAM}_{\text{avail}, B} \ge 2.0\text{ KB}$.
  3. **CPU Level**: $\text{device.cpu\_level} \ge \text{"low"}$.
  4. **MTU Limit**: $B_{\text{message}} + 28 \le \min(\text{MTU}_A, \text{MTU}_B)$ (28 bytes accounts for 12-byte GCM nonce + 16-byte GCM tag).
* If any technical constraint fails, selection aborts with:
  $$\text{failure\_category} = \text{"fallback\_profile\_not\_feasible"}$$
  recording per-device technical failure reasons in `experiments`.

##### 3. Selector Fallback Logging Output
Upon successful fallback activation, the selector prints:
```text
[selector] No standard crypto profile satisfies all constraints.
[selector] Activating fallback profile C5.
[selector] WARNING: Security requirement has been relaxed.
[selector] Selected: C5 - Fallback PSK with AES-128-GCM
[selector] Selection mode: FALLBACK
```

#### MongoDB Reads
* `iot_security.crypto_profiles`: Fetches all active profiles (and dynamically retrieves `C5` via `get_by_id("C5")` if fallback activates).
* `iot_security.benchmarks`: Fetches nearest empirical benchmark runs for $(A, k, B_{\text{message}})$ and $(B, k, B_{\text{message}})$.

---

### Stage 3: Stage 2 Dynamic Pressure Calculation & Multi-Objective Scoring

#### Purpose
When multiple profiles pass Stage 1 hard filtering, Stage 2 derives scenario-specific dynamic weights and scores candidate profiles.

#### Mathematical Formulations

##### 1. Time Pressure ($P_{\text{time}}$)
Derived from the strictest latency ceiling $L_{\min} = \min(L_A, L_B)$:
* If $L_{\min} \le 50\text{ ms} \implies P_{\text{time}} = 1.0$ (highest urgency).
* If $L_{\min} \ge 2000\text{ ms} \implies P_{\text{time}} = 0.05$ (floor).
* For $50 < L_{\min} < 2000$: Continuous inverted logarithmic interpolation:
  $$P_{\text{time}} = 0.05 + 0.95 \cdot \frac{\ln(2000) - \ln(L_{\min})}{\ln(2000) - \ln(50)}$$

##### 2. Memory Pressure ($P_{\text{memory}}$)
Derived from the most memory-constrained device $\text{RAM}_{\min} = \min(\text{RAM}_A, \text{RAM}_B)$:
* If $\text{RAM}_{\min} \le 32\text{ KB} \implies P_{\text{memory}} = 1.0$.
* If $\text{RAM}_{\min} \ge 524288\text{ KB } (512\text{ MB}) \implies P_{\text{memory}} = 0.05$.
* For $32 < \text{RAM}_{\min} < 524288$: Continuous inverted logarithmic interpolation:
  $$P_{\text{memory}} = 0.05 + 0.95 \cdot \frac{\ln(524288) - \ln(\text{RAM}_{\min})}{\ln(524288) - \ln(32)}$$

##### 3. Communication Pressure ($P_{\text{comm}}$)
Derived from message size relative to packet MTU:
$$R = \frac{B_{\text{message}}}{C_{\text{packet}}}$$
* If $R \le 0.05 \implies P_{\text{comm}} = 0.05$.
* If $R \ge 1.00 \implies P_{\text{comm}} = 1.00$.
* For $0.05 < R < 1.00$: Continuous linear interpolation:
  $$P_{\text{comm}} = 0.05 + 0.95 \cdot \frac{R - 0.05}{0.95}$$

##### 4. Energy Pressure ($P_{\text{energy}}$)
Derived from hardware power source topology:
* If both endpoints are on mains ($\text{power}_A = \text{mains} \land \text{power}_B = \text{mains}$):
  $$P_{\text{energy}} = 0.20$$
* If either endpoint is on battery:
  $$P_{\text{energy}} = 0.80$$
* If both endpoints are on battery:
  $$P_{\text{energy}} = 0.95$$

##### Dynamic Weight Normalization
Pressures are normalized into objective weights that sum to $1.0$:
$$\Sigma_P = P_{\text{time}} + P_{\text{memory}} + P_{\text{comm}} + P_{\text{energy}}$$
$$w_i = \frac{P_i}{\Sigma_P} \quad \text{for } i \in \{\text{time}, \text{memory}, \text{comm}, \text{energy}\}$$

##### Metric Min-Max Normalization
For each feasible candidate profile $k$, raw metrics are extracted:
* Latency: $T_k = \text{total\_ms}_{A, k} + \text{total\_ms}_{B, k}$
* Peak Memory: $M_k = \max(\text{peak\_kb}_{A, k}, \text{peak\_kb}_{B, k})$
* Communication Overhead: $C_k = \text{application\_bytes}_k$
* Energy Proxy: $E_k = T_k \times 0.001$

Each metric is normalized across feasible candidates:
$$\mathcal{N}(V_k) = \begin{cases} 0.0 & \text{if } V_{\max} = V_{\min} \\ \frac{V_k - V_{\min}}{V_{\max} - V_{\min}} & \text{otherwise} \end{cases}$$

##### Final Weighted Composite Score
$$\text{Score}_k = w_{\text{time}} \cdot \mathcal{N}(T_k) + w_{\text{memory}} \cdot \mathcal{N}(M_k) + w_{\text{comm}} \cdot \mathcal{N}(C_k) + w_{\text{energy}} \cdot \mathcal{N}(E_k)$$

##### Deterministic Tie-Breaking
1. Lower composite score ($\text{Score}_k$).
2. Lower application bytes ($C_k$).
3. Lower alphabetical profile ID (`C1` < `C2` < `C3` < `C4`).

#### MongoDB Writes
* `iot_security.experiments`: Writes prediction block and decision audit document:
  ```json
  {
    "experiment_id": "exp-a207ff8e",
    "sender_id": "esp32",
    "receiver_id": "raspberry_pi_4",
    "selected_profile_id": "C4",
    "status": "selected",
    "dynamic_weights": { "wt": 0.2051, "wm": 0.3665, "wc": 0.0252, "we": 0.4032 },
    "constraint_pressures": { "p_time": 0.407, "p_memory": 0.7271, "p_communication": 0.05, "p_energy": 0.8 },
    "candidate_profiles": [ ... ],
    "selected_at": "ISODate(...)"
  }
  ```

---

### Stage 4: Cryptographic Execution & Wire Framing

#### Supported Profiles

| Profile | Key Establishment | Symmetric Cipher | Security Floor | Min CPU |
| :--- | :--- | :--- | :--- | :--- |
| **`C1`** | RSA-OAEP (2048-bit, SHA-256) | AES-128-GCM | standard | low |
| **`C2`** | RSA-OAEP (3072-bit, SHA-256) | AES-256-GCM | high | high |
| **`C3`** | ECDH (NIST P-256) + HKDF-SHA256 | AES-128-GCM | standard | low |
| **`C4`** | ECDH (NIST P-384) + HKDF-SHA256 | AES-256-GCM | high | medium |
| **`C5`** | Pre-Shared Key (128-bit PSK) | AES-128-GCM | basic | low |

#### Cryptographic Lifecycle

##### For ECC Profiles (`C3`, `C4`):
1. **Ephemeral Key Generation**: Sender generates an ephemeral private key $d_S$ and computes public key $Q_S = d_S \cdot G$.
2. **Receiver Public Key**: Sender uses Receiver's static/ephemeral public key $Q_R$.
3. **Shared Secret**: Sender computes $S = d_S \cdot Q_R$.
4. **Key Derivation (HKDF)**:
   $$K_{\text{session}} = \text{HKDF-SHA256}(\text{ikm}=S, \text{salt}=\text{None}, \text{info}=b"\text{iot-session-key}", \text{len}=16 \text{ or } 32)$$
5. **Authenticated Encryption (AES-GCM)**:
   Sender generates a 96-bit (12-byte) random nonce $N$.
   $$(\text{ciphertext}, \text{tag}) = \text{AES-GCM-Encrypt}(K_{\text{session}}, N, \text{plaintext}, \text{aad}=\text{None})$$
   where `tag` is a 128-bit (16-byte) authentication tag.

##### For RSA Profiles (`C1`, `C2`):
1. Sender generates a random 128-bit or 256-bit symmetric session key $K_{\text{session}}$.
2. Key wrapping using RSA-OAEP with MGF1(SHA-256) and receiver public key:
   $$C_{\text{key}} = \text{RSA-OAEP-Encrypt}(PK_R, K_{\text{session}})$$
3. Payload encrypted with AES-GCM using $K_{\text{session}}$.

##### For PSK Fallback Profile (`C5`):
1. **Pre-Shared Key Acquisition**: The 128-bit key $K_{\text{psk}}$ is retrieved from environment configuration (`FALLBACK_PSK_HEX` via `config.get_env()`). Asymmetric key pairs and mathematical scalar multiplications are skipped entirely.
2. **Authenticated Encryption (AES-GCM)**:
   Sender generates a 96-bit (12-byte) random nonce $N$.
   $$(\text{ciphertext}, \text{tag}) = \text{AES-GCM-Encrypt}(K_{\text{psk}}, N, \text{plaintext}, \text{aad}=\text{None})$$
   The `ciphertext_hex` and `nonce_hex` are embedded into the protocol frame payload alongside the message.
3. **Receiver Decryption & Integrity Authentication**:
   Receiver loads the same configured 128-bit PSK and verifies the GCM authentication tag:
   $$\text{plaintext} = \text{AES-GCM-Decrypt}(K_{\text{psk}}, N, \text{ciphertext}, \text{aad}=\text{None})$$
   Any modification of the ciphertext or nonce raises an `AuthenticationError`, failing the exchange.

---

### Stage 5: Framed TCP Socket Communication

#### Wire Frame Structure
To prevent TCP stream fragmentation issues, communication uses binary length-prefixed JSON framing:

```text
+-----------------------+-------------------------------------------------------+
|  Frame Length (4 B)   |               Frame Payload (JSON UTF-8)              |
|  struct.pack('!I', L) |               L bytes of JSON text                    |
+-----------------------+-------------------------------------------------------+
```

* **Header**: Exactly 4 bytes, unsigned 32-bit integer in big-endian network byte order (`!I`).
* **Maximum Frame Size**: Enforced limit of 1,048,576 bytes (1 MB) to prevent buffer exhaustion attacks.

#### JSON Payload Structure

##### Sender HELLO Message Frame:
```json
{
  "protocol_version": 1,
  "message_type": "hello",
  "experiment_id": "exp-a207ff8e",
  "session_id": "exp-a207ff8e",
  "profile_id": "C4",
  "sequence_number": 1,
  "payload": {
    "message": "test",
    "sender_id": "esp32",
    "receiver_id": "raspberry_pi_4"
  },
  "timestamp": "2026-10-08T01:16:38.649704+05:30"
}
```

##### Receiver ACK Response Frame:
```json
{
  "protocol_version": 1,
  "message_type": "ack",
  "experiment_id": "exp-a207ff8e",
  "session_id": "exp-a207ff8e",
  "profile_id": "C4",
  "sequence_number": 2,
  "payload": {
    "status": "accepted",
    "received_message": "test",
    "profile_id": "C4",
    "sender_id": "esp32",
    "receiver_id": "raspberry_pi_4"
  },
  "timestamp": "2026-10-08T01:16:38.770812+05:30"
}
```

#### Message Integrity Verification
Upon receiving the ACK frame:
1. Client verifies `reply.message_type == MessageType.ACK`.
2. Client checks `reply.payload["received_message"] == original_message`.
3. If valid, client marks `message_integrity: PASSED` and updates `experiments` status to `"completed"`.

---

### Stage 6: Phase 9 Live TShark Network Capture

#### The Three-Terminal Runtime Architecture

```text
Terminal 1 (SERVER)         Terminal 2 (CLIENT)         Terminal 3 (CAPTURE MONITOR)
python server.py            python client.py            python capture_monitor.py
      │                           │                                  │
      │◄─── TCP Handshake (SYN) ──│                                  │
      │──── TCP SYN-ACK ─────────►│                                  │
      │◄─── TCP ACK ──────────────│                                  │
      │                           │                                  │
      │◄─── Framed HELLO (240 B) ─│                                  │
      │──── TCP ACK ─────────────►│                                  │
      │                           │                                  │
      │──── Framed ACK (267 B) ──►│                                  │
      │◄─── TCP ACK ──────────────│                                  │
      │                           │                                  │
      │◄─── TCP FIN-ACK ──────────│                                  │
      │──── TCP FIN-ACK ─────────►│                                  │
      │                           │                                  │
      ▼                           ▼                                  ▼
[Loopback TCP Socket]       [Loopback TCP Socket]       [TShark Sniffer on lo0 :5000]
                                                                     │
                                                                     ▼
                                                        captures/experiment_<id>.pcapng
                                                                     │
                                                                     ▼
                                                        iot_security.traffic (MongoDB)
```

#### Why Loopback (`lo0`)?
In local simulation mode, both Client and Server execute on the host machine (`127.0.0.1`). Traffic passes through the OS loopback virtual interface (`lo0` on macOS, `lo` on Linux).
Capturing on `lo0` guarantees that all wire packets (handshake, headers, data frames, teardown) are captured without requiring simulated traffic generators.

#### Capture Monitor Mechanics (`capture_monitor.py`)
1. **Startup**: Starts TShark with live stdout streaming:
   ```bash
   tshark -i lo0 -f "tcp port 5000" -w captures/temp.pcapng -P -l
   ```
2. **Non-Blocking Parsing**: Uses `select.select()` to read TShark stdout without blocking. Prints formatted live packet logs in Terminal 3:
   ```text
   [NETWORK] 127.0.0.1:49942 -> 127.0.0.1:5000 TCP SYN
   [NETWORK] 127.0.0.1:5000 -> 127.0.0.1:49942 TCP 68 bytes
   ```
3. **Session Slicing**: When traffic ceases for >1.5 seconds following active packet transmission, the monitor triggers teardown:
   - Stops the current TShark process cleanly via `SIGINT`.
   - Polls `iot_security.experiments` for the most recent experiment.
   - Renames `temp.pcapng` to the deterministic canonical name:
     `captures/experiment_<experiment_id>_<profile_id>_<message_size>B.pcapng`
   - Computes SHA-256 checksum over the raw `.pcapng` binary.
   - Upserts record to `iot_security.traffic`.
   - Re-arms TShark for subsequent experiments.

---

### Stage 7: Phase 10 PyShark Traffic Analysis & Metrics

#### Purpose
Analyzes the resulting `.pcapng` file offline without starting network interfaces or decrypting payloads, calculating exact packet dynamics and transport overhead.

#### Metrics & Formulations

##### 1. Total Captured Bytes ($B_{\text{total}}$)
The total size of the recorded `.pcapng` wire capture file on disk:
$$B_{\text{total}} = \text{file\_size\_bytes}(.pcapng)$$

##### 2. Average Packet Size ($B_{\text{avg}}$)
$$B_{\text{avg}} = \frac{B_{\text{total}}}{N}$$
where $N$ is total packet count.

##### 3. Capture Duration ($T$)
$$T = t_{\text{last}} - t_{\text{first}}$$
where $t_{\text{first}}$ and $t_{\text{last}}$ are sniffing timestamps of the first and last packet.

##### 4. Network Overhead Bytes ($O_{\text{bytes}}$)
Quantifies total transport and protocol overhead relative to original plaintext:
$$O_{\text{bytes}} = B_{\text{total}} - B_{\text{message}}$$
where $B_{\text{message}}$ is the original plaintext byte size.

##### 5. Network Overhead Percentage ($O_{\%}$)
$$O_{\%} = \begin{cases} 0.0 & \text{if } B_{\text{message}} = 0 \\ \frac{O_{\text{bytes}}}{B_{\text{message}}} \times 100 & \text{otherwise} \end{cases}$$

##### 6. Directional Traffic Breakdown
* **Sender $\rightarrow$ Receiver**: Packets with `tcp.dstport == server_port` (Port 5000).
* **Receiver $\rightarrow$ Sender**: Packets with `tcp.srcport == server_port` (Port 5000).
* Directional packets and directional bytes are accumulated independently.

##### 7. TCP Payload Bytes ($B_{\text{payload}}$)
Sum of `tcp.len` across all TCP packets:
$$B_{\text{payload}} = \sum_{i=1}^{N} \text{tcp.len}_i$$

##### 8. Retransmissions ($R_{\text{tcp}}$)
Count of packets where Wireshark analysis flag `analysis_retransmission` is set.

---

## 3. End-to-End Walkthrough Examples

### Walkthrough A: Standard Adaptive Selection (`C4` Winner)

#### Setup:
* **Device A**: `esp32` (Available RAM: 520 KB, CPU: `medium`, Security: `standard`, Power: `battery`, Latency Limit: 1000 ms, MTU: 1500 B).
* **Device B**: `raspberry_pi_4` (Available RAM: 2 GB, CPU: `high`, Security: `high`, Power: `mains`, Latency Limit: 500 ms, MTU: 1500 B).
* **Message**: `"test"` ($4\text{ bytes}$).

#### Execution Trace:
1. **Constraint Evaluation**:
   - Raspberry Pi 4 requires `high` security $\implies$ `C1` and `C3` (standard security) are rejected.
   - ESP32 has `medium` CPU $\implies$ `C2` (requires `high` CPU) is rejected.
   - Profile `C4` (ECDH-P384 + AES-256-GCM) satisfies all constraints.
2. **Selection**:
   - `C4` is selected with dynamic weights prioritizing battery power ($w_{\text{energy}} = 40.3\%$).
   - Record created in `experiments` under ID `exp-a207ff8e` with `selection_mode: "normal"` and `fallback_used: false`.
3. **Execution & Framing**:
   - Client establishes ephemeral ECDH-P384 key exchange, derives AES-256 key, encrypts `"test"`.
   - Sends length-prefixed frame to `127.0.0.1:5000`.
4. **Verification**:
   - Server decrypts ciphertext, validates tag, echoes verified status in ACK.
5. **Capture (Terminal 3)**:
   - `capture_monitor.py` captures 12 TCP packets on `lo0`.
   - Saves `captures/experiment_exp-a207ff8e_C4_4B.pcapng` (1964 bytes, SHA-256 verified).
   - Writes record to `iot_security.traffic`.
6. **PyShark Analysis (Terminal 4)**:
   - `python analyze_traffic.py --experiment exp-a207ff8e` computes 507 bytes TCP payload, 0 retransmissions, 1960 bytes overhead ($49,000.00\%$), and updates `traffic_analysis`.

---

### Walkthrough B: Edge-Case C5 Fallback (`C5` Activated)

#### Setup:
* **Device A**: Resource-constrained microcontroller (e.g., Available RAM: 40 KB, CPU: `low`, Security: `high`, Power: `battery`, MTU: 1500 B).
* **Device B**: Sensor node (e.g., Available RAM: 64 KB, CPU: `low`, Security: `high`, Power: `battery`, MTU: 1500 B).
* **Message**: `"alert: threshold exceeded"` ($25\text{ bytes}$).

#### Execution Trace:
1. **Stage 1 Standard Constraint Evaluation (C1–C4)**:
   - `C1` (RSA-2048): Rejected — Security floor `standard` < Device requirement `high`; heap memory exceeds 40 KB.
   - `C2` (RSA-3072): Rejected — Requires `high` CPU; CPU is `low`; heap memory exceeds 40 KB.
   - `C3` (ECDH-P256): Rejected — Security floor `standard` < Device requirement `high`.
   - `C4` (ECDH-P384): Rejected — Requires `medium` CPU; CPU is `low`.
   - Result: Zero standard profiles are feasible (`len(feasible_pairs) == 0`).
2. **Fallback Activation**:
   - Selector logs:
     ```text
     [selector] No standard crypto profile satisfies all constraints.
     [selector] Activating fallback profile C5.
     [selector] WARNING: Security requirement has been relaxed.
     ```
   - Dynamically loads `C5` from MongoDB `crypto_profiles`.
3. **Technical Feasibility Verification**:
   - Soft check: Security requirement (`high`) relaxed for `basic` profile.
   - Hard check: Both devices list `"AES-128-GCM"` in `supported_algorithms` $\implies$ PASSED.
   - Hard check: Device RAM ($40\text{ KB}$) $\ge 2.0\text{ KB}$ $\implies$ PASSED.
   - Hard check: Device CPU (`low`) $\ge \text{profile.minimum\_cpu\_level}$ (`low`) $\implies$ PASSED.
   - Hard check: Packet size ($25 + 28 = 53\text{ B}$) $\le 1500\text{ B}$ $\implies$ PASSED.
   - Selector logs:
     ```text
     [selector] Selected: C5 - Fallback PSK with AES-128-GCM
     [selector] Selection mode: FALLBACK
     ```
4. **Audit Persistence**:
   - Persists experiment record with:
     ```json
     {
       "selected_profile": "C5",
       "selection_mode": "fallback",
       "fallback_used": true,
       "fallback_reason": "no_profile_satisfies_constraints",
       "relaxed_constraints": ["security_requirement"]
     }
     ```
5. **Execution & Framing**:
   - Client retrieves 128-bit PSK from `FALLBACK_PSK_HEX`.
   - Encrypts payload with `AES-128-GCM` (skipping RSA/ECDH).
   - Sends protocol frame with `ciphertext_hex` and `nonce_hex`.
6. **Server Processing**:
   - Server loads configured PSK, verifies GCM tag, and decrypts ciphertext.
   - Echoes verified message in ACK frame.
7. **Network Capture & Traffic Analysis**:
   - Capture monitor and PyShark analyzer process traffic identically to standard profiles, recording exact on-wire overhead and performance metrics.
