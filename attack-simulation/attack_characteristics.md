# SecureMesh AI — Attack Characteristics & Telemetry Signatures
**Reference Guide for Member 3 (ML / IDS Feature Engineering)**

## 1. Overview & Purpose
This document specifies the expected network telemetry signatures and statistical behavioral patterns for each class in the SecureMesh AI dataset:
- `Normal`
- `DoS`
- `Replay`
- `Spoofing`
- `Rogue_Node` (legacy controller-driven path only — see section E)
- `Drop_Anomaly` (produced by the current autonomous Node 4 firmware's 4th cycle phase — see section F)

These characteristics serve as ground-truth engineering reference for **Member 3's ML Pipeline** (feature extraction, normalization, threshold tuning, and model evaluation).

This document is strictly an analytical reference for detection modeling; it does not contain attack implementation instructions.

---

## 2. Telemetry Feature Schema

The dataset generator produces continuous rolling telemetry records adhering to the following 12-column schema:

| Column Name | Data Type | Units / Range | Definition & Expected Baseline |
|---|---|---|---|
| `timestamp` | Float | Epoch seconds | High-precision Unix timestamp of sample window evaluation. |
| `source_node_id` | String / Int | Valid IDs: `1..5` | Originating ESP32 mesh node identifier. |
| `destination_node_id` | String / Int | Valid IDs: `1..5` | Destination ESP32 mesh node identifier. |
| `packet_rate` | Float | Packets / second | Rate of packet transmission observed over a rolling 2-second window. |
| `packet_loss` | Float | Percentage `[0.0, 100.0]` | Packet loss ratio derived from expected vs received sequence numbers. |
| `latency_ms` | Float | Milliseconds | Round-trip or hop-transit latency. |
| `rssi` | Int | dBm `[-90, -30]` | Received Signal Strength Indicator averaged across window. |
| `retransmissions` | Int | Integer count | Number of layer-2 / application retransmission attempts. |
| `sequence_number` | Int | `[0, 65535]` | 16-bit monotonic packet sequence counter per link. |
| `duplicate_packets` | Int | Count per window | Detected frames with identical sequence numbers or backwards sequence jump. |
| `node_identity_status` | Int | `0` or `1` | `0` = Known / Authenticated node ID; `1` = Unrecognized / Suspicious node. |
| `label` | String | Categorical | Ground truth class: `Normal`, `DoS`, `Replay`, `Spoofing`, `Rogue_Node`. |

---

## 3. Attack Telemetry Signatures & Behavioral Analysis

### A. Normal Operation (`Normal`)
- **Behavioral Description**: Healthy ESP32 mesh participating in periodic sensor sampling (DHT11/DHT22), heartbeat synchronization, and standard route maintenance.
- **Key Metric Signatures**:
  - `packet_rate`: **Low to moderate** (typically $2.0 \text{ to } 5.0\text{ pkts/sec}$ per node).
  - `packet_loss`: **Minimal** (normally $0.0\% \text{ to } 3.0\%$, occasional RF fading $< 5.0\%$).
  - `latency_ms`: **Low and stable** ($5 \text{ to } 25\text{ ms}$ over 1–2 hops).
  - `rssi`: **Stationary with low variance** (Gaussian-like drift $\pm 2.0\text{ dBm}$ depending on physical distance, e.g. $-50 \text{ to } -65\text{ dBm}$).
  - `retransmissions`: **Zero to very low** ($0 \text{ to } 1$ per window).
  - `sequence_number`: **Strictly monotonic incremental** ($seq_{k+1} = seq_k + 1$).
  - `duplicate_packets`: **0**.
  - `node_identity_status`: **0** (Valid node in lookup table).

---

### B. Denial of Service (`DoS`)
- **Behavioral Description**: Attacker board floods the shared 2.4 GHz ESP-NOW radio medium with high-frequency uncoordinated frames, causing radio buffer saturation, channel contention, and dropped packets for legitimate nodes.
- **Key Metric Signatures**:
  - `packet_rate`: **Severe spike** ($> 20.0 \text{ to } 60.0+\text{ pkts/sec}$).
  - `packet_loss`: **High elevation** ($> 15.0\% \text{ to } 50.0+\%$) due to queue overflow and frame collisions.
  - `latency_ms`: **Significant latency degradation** ($> 80 \text{ to } 300+\text{ ms}$) caused by channel access delays and retries.
  - `retransmissions`: **Elevated** ($> 5 \text{ to } 20+$ retries per window).
  - `rssi`: **Stable** (originates from physical attacker location), but link quality variance increases for competing links.
  - `sequence_number`: Rapidly advancing sequence numbers from the flooding node ID.
  - `duplicate_packets`: Low to moderate (occasional retransmission duplicates).
  - `node_identity_status`: Typically `0` (if flooding as a compromised member) or `1` (if flooding from outside).
- **ML Detection Indicators**: `packet_rate` $\times$ `packet_loss` joint anomaly; sudden jump in rolling `packet_rate` exceeding 3 standard deviations from baseline.

---

### C. Replay Attack (`Replay`)
- **Behavioral Description**: Attacker eavesdrops on legitimate network traffic and injects previously recorded valid frames back into the mesh at a later time.
- **Key Metric Signatures**:
  - `duplicate_packets`: **High spike** ($> 3 \text{ to } 15+$ duplicate sequence numbers detected in the rolling window).
  - `sequence_number`: **Non-monotonic jumps or retrograde sequences** (e.g. sequence numbers jump backwards to earlier numbers, or repeat already processed sequences: $seq_{t} \le seq_{t-1}$).
  - `packet_rate`: **Slight elevation** (normal traffic rate + replayed frames rate).
  - `packet_loss`: **Apparent anomaly** (sequence discontinuity may trigger false packet gap calculations if not separated).
  - `rssi`: **Constant / Stationary** (emitted from attacker's fixed location; payload claims to be from a distant node but RSSI matches attacker).
  - `node_identity_status`: `0` (payload contains a valid node ID).
  - `retransmissions`: Normal / baseline.
- **ML Detection Indicators**: High ratio of `duplicate_packets` to `packet_rate`; negative first-order delta in `sequence_number` ($\Delta seq \le 0$).

---

### D. Identity / MAC Spoofing (`Spoofing`)
- **Behavioral Description**: Attacker node assumes the `source_node_id` or MAC address of an existing legitimate node, transmitting concurrent or interleaved frames under the stolen identity.
- **Key Metric Signatures**:
  - `rssi`: **Bimodal or high-variance RSSI distribution** for the *same* `source_node_id`. Because physical location dictates RF attenuation, frames from the legitimate node arrive at e.g. $-48\text{ dBm}$, while frames from the spoofer arrive at e.g. $-75\text{ dBm}$. A rolling RSSI variance or instantaneous jump ($|\Delta RSSI| > 15\text{ dBm}$) on the same node link is a strong indicator.
  - `sequence_number`: **Desynchronized sequence clashes** (two independent transmitters advancing sequence counters independently cause rapid alternating sequence leaps and gaps).
  - `packet_rate`: **Intermittent doubling** of packet rate for that specific node ID.
  - `node_identity_status`: `0` (the node ID itself is valid, but the physical signature is conflicting).
- **ML Detection Indicators**: High rolling standard deviation of `rssi` ($\sigma_{rssi} > 8.0\text{ dBm}$); sequence number jitter ($\text{Var}(\Delta seq) \gg 1$).

---

### E. Rogue Node Injection (`Rogue_Node`)
- **Behavioral Description**: An unauthenticated, foreign ESP32 attempts to join the mesh or inject telemetry without valid network credentials, or uses an unauthorized node ID not present in the network topology whitelist.
- **Key Metric Signatures**:
  - `node_identity_status`: **`1` (Suspicious / Unverified)**. The node ID does not match any entry in the authorized node registry (`NODE_01` .. `NODE_05`).
  - `source_node_id`: Unrecognized integer/string ID (e.g., `99`, `0`, `13`, `"ROGUE_X"`).
  - `routing_history`: Zero prior routing or heartbeat records in gateway tables.
  - `rssi`: Variable depending on physical proximity of rogue hardware.
  - `packet_loss` / `latency`: Uncoordinated with mesh schedule; may cause routing reject errors.
- **ML Detection Indicators**: Categorical / binary flag `node_identity_status == 1`; unrecognized categorical feature value for `source_node_id`.
- **Note**: not produced by the current autonomous Node 4 firmware (its 4th cycle phase is `Drop_Anomaly` below, sent under Node 4's own registered ID, not an unrecognized one). Still relevant via the legacy `attack_controller.py --port ... ROGUE_NODE` path with an `unauthorized_id` parameter, or `--simulate` scenario testing.

---

### F. Sequence-Skip Drop Anomaly (`Drop_Anomaly`)
- **Behavioral Description**: The 4th phase of Node 4's autonomous cycle (`esp32_attacker/esp32_attacker.ino`, `runRogueNodeMode()` — named for its enum, relabeled here to avoid confusion with section E). Originally specified as a relay-blackhole ("accept packets meant for forwarding, then drop them"), but `firmware/mesh_node/mesh_node.ino` now restricts normal nodes to only route through 1-3, so Node 4 is never selected as a relay hop and has no relayed traffic to drop. The implemented behavior instead sends under Node 4's **own, registered** ID and jumps its sequence counter forward by 10 on every packet, simulating missing packets without ever repeating or going backward.
- **Key Metric Signatures**:
  - `drops` / sequence gaps: **Rapid, steady climb** — exactly 9 missing sequence numbers per packet sent (`current_seq_num += 10`), so the gateway's cumulative `drops` counter for this peer rises linearly and quickly.
  - `packet_rate`: **Moderate and steady** (~10 pps, throttled by a 100ms delay) — not a DoS-level flood.
  - `rssi`: **Stable**, single physical origin (Node 4's actual location), unlike Spoofing's bimodal signature.
  - `duplicate_packets`: **0** — this is a forward skip, never a repeat or backward jump (distinguishes it from Replay).
  - `node_identity_status`: **`0`** — the sender ID (`4`) is a known, registered ID, so this does **not** look like `Rogue_Node` despite the enum name in the firmware.
- **ML Detection Indicators**: Steady, non-zero rate of sequence gaps (`drops` increasing roughly linearly with packet count) combined with `node_identity_status == 0` and normal/stable `rssi` — the combination that rules out Replay, Spoofing and Rogue_Node.

---

## 4. Feature Summary & Correlation Matrix

| Feature | Normal | DoS | Replay | Spoofing | Rogue Node | Drop Anomaly |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `packet_rate` | Low (~2–5) | **Very High (>20)** | Moderate (+20–40%) | Moderate | Variable | Moderate (~10) |
| `packet_loss` | Low (<3%) | **High (>15%)** | Low–Med (calc jitter) | Low | Low | **High, steady climb** |
| `latency_ms` | Low (<25ms) | **High (>80ms)** | Normal | Normal | Normal | Normal |
| `rssi` Variance | Very Low ($\pm 2$) | Low | Low | **Very High (>15 jump)** | Normal | Low (single origin) |
| `retransmissions` | 0–1 | **High (>5)** | Normal | Normal | Normal | Normal |
| `duplicate_packets` | **0** | Low (0–2) | **Very High (>3)** | Low (0–1) | 0 | **0** |
| $\Delta sequence\_number$ | Strict +1 | Rapid +1 | **$\le 0$ (Backward/Dup)** | Jittery / Clashing | Sequential | **Always +10 (steady forward skip)** |
| `node_identity_status`| **0** | 0 | 0 | 0 | **1 (Suspicious)** | 0 |

---

## 5. Guidance for Member 3 ML Pipeline

1. **Window Size**: Compute rolling statistical aggregates over a **2.0-second sliding window** (matching `backend/telemetry/telemetry_parser.py` and `dataset_generator.py`).
2. **Derived Features Recommended**:
   - `rssi_delta`: $|rssi_t - \overline{rssi}_{t-1}|$ (critical for Spoofing detection).
   - `seq_delta`: $seq_t - seq_{t-1}$ (critical for Replay detection: negative or zero values).
   - `packet_rate_loss_ratio`: $packet\_rate \times packet\_loss$ (critical for DoS detection).
3. **Transition Discard**: Ensure rows within 1.5 seconds of ground-truth state transitions are filtered out of training sets to maintain clean label purity.
