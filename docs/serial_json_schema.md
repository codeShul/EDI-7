# Serial Monitor JSON Schema

Every line printed to the Serial Monitor by any ESP32 node is a single, self-contained JSON object. The `type` field identifies the event.

---

## 1. `TX` — Packet Sent (with delivery status)

Printed after every `esp_now_send()`. Contains the full packet info AND whether the target acknowledged it.

```json
{
    "type":     "TX",
    "src":      1,          // Who sent it (this node)
    "dst":      3,          // Final destination Node ID
    "seq":      105,        // Sequence number
    "ttl":      4,          // Time-to-Live
    "hop":      2,          // Physical next-hop Node ID (radio target)
    "delivery": "SUCCESS"   // "SUCCESS" = ACK received | "FAIL" = target offline
}
```

---

## 2. `RX` — Packet Received (with routing action)

Printed when the node's antenna catches an incoming packet. Contains full packet data, signal strength, AND what the node decided to do with it.

```json
{
    "type":     "RX",
    "src":      1,          // Original sender Node ID
    "dst":      3,          // Final destination Node ID
    "seq":      105,        // Sequence number
    "pkt_type": "DATA",     // "DATA" | "HEARTBEAT" | "ROUTE_SYNC"
    "ttl":      4,          // Time-to-Live remaining
    "rssi":     -52,        // Hardware radio signal strength (dBm)
    "receiver": 2,          // Which node caught this packet (this node)
    "action":   "RELAYING"  // "CONSUMED" | "RELAYING" | "TTL_EXPIRED"
}
```

---

## 3. `TELEMETRY` — Rolling 1-second statistics

Printed by the Gateway once per second. Summarizes traffic from each peer. **Primary input for the ML/AI model.**

```json
{
    "telemetry": true,
    "reporter":  3,         // Node that computed this
    "target":    1,         // Peer node being profiled
    "rate":      12,        // Packets received in last 1 second
    "avg_rssi":  -48,       // Average signal strength
    "drops":     0          // Cumulative missing sequence numbers
}
```

### AI Detection Thresholds:

| Field      | Normal   | Attack Signature           | Attack Type      |
|------------|----------|----------------------------|------------------|
| `rate`     | 1–5 pps  | Spike to 30+ pps           | DoS Flood        |
| `avg_rssi` | Stable ±5| Sudden jump of 20+ dBm     | MAC Spoofing     |
| `drops`    | 0        | Rapidly increasing          | Blackhole/Rogue  |
| `seq`      | Always ↑ | Backwards / duplicates      | Replay Attack    |

---

## 4. `ALERT` — Attack detected *(Future Phase)*

```json
{
    "type":        "ALERT",
    "action":      "ISOLATED",
    "attacker":    1,
    "detected_by": 3,
    "threat":      "DOS"
}
```

---

## Summary

| Type        | When                | Contains                              |
|-------------|---------------------|---------------------------------------|
| `TX`        | After every send    | Packet info + delivery SUCCESS/FAIL   |
| `RX`        | On every receive    | Packet info + RSSI + routing action   |
| `TELEMETRY` | Every 1 second      | Per-peer rate, RSSI, drops            |
| `ALERT`     | On attack detection | Attacker ID, threat type, action      |
