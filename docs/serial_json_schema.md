# Serial Monitor JSON Schema

Every line printed to the Serial Monitor by any ESP32 node is a valid JSON object. The `type` field identifies the message category.

---

## 1. `PACKET` — A received mesh data packet

Printed by the Gateway when it receives or overhears a packet from another node.

```json
{
    "src":    1,         // Sender Node ID (1-5)
    "dst":    3,         // Final destination Node ID (1-5)
    "seq":    105,       // Monotonic sequence number from the sender
    "type":   "DATA",    // Packet type: "DATA" | "HEARTBEAT" | "ROUTE_SYNC"
    "ttl":    4,         // Time-to-Live (decrements with each hop)
    "rssi":   -52        // Hardware radio signal strength in dBm
}
```

**Also printed by the Gateway when it generates its own outbound packet** (with `rssi: 0` since there is no radio reception involved).

---

## 2. `DELIVERY` — Hardware ACK status after sending a packet

Printed by every node immediately after `esp_now_send()`. Reports whether the target ESP32's radio acknowledged receipt.

```json
{
    "type":   "DELIVERY",
    "node":   1,          // Which node sent the packet
    "status": "SUCCESS"   // "SUCCESS" = target ACK'd | "FAIL" = target offline/out of range
}
```

---

## 3. `TELEMETRY` — Rolling 1-second window statistics

Printed by the Gateway once per second. Summarizes the traffic profile of each peer node over the last 1000ms. **This is the primary input for the ML/AI model.**

```json
{
    "telemetry": true,
    "reporter": 3,        // The node that calculated this (usually the Gateway)
    "target":   1,        // The peer node being profiled
    "rate":     12,       // Packets received from this peer in the last 1 second
    "avg_rssi": -48,      // Average signal strength from this peer
    "drops":    0         // Cumulative missing sequence numbers (gaps detected)
}
```

### How the AI uses these fields:

| Field      | Normal Range | Attack Signature                  | Attack Type        |
|------------|-------------|-----------------------------------|--------------------|
| `rate`     | 1 – 5 pps  | Spike to 30+ pps                  | DoS Flood          |
| `avg_rssi` | Stable ±5  | Sudden jump of 20+ dBm           | MAC Spoofing       |
| `drops`    | 0           | Rapidly increasing count          | Blackhole / Rogue  |
| `seq`      | Always ↑    | Backwards / duplicate numbers     | Replay Attack      |

---

## 4. `ALERT` — Attack detected and node isolated *(Future Phase)*

Will be printed when the on-device TinyML model classifies a node as compromised.

```json
{
    "type":     "ALERT",
    "action":   "ISOLATED",
    "attacker": 1,
    "detected_by": 3,
    "threat":   "DOS"
}
```

---

## Summary Table

| Type        | Frequency        | Emitted By     | Purpose                       |
|-------------|-----------------|----------------|-------------------------------|
| `PACKET`    | Per packet       | Gateway        | Raw mesh traffic log          |
| `DELIVERY`  | Per send attempt | All nodes      | Hardware ACK confirmation     |
| `TELEMETRY` | Every 1 second   | Gateway        | AI feature vector input       |
| `ALERT`     | On detection     | Detecting node | Attack notification           |
