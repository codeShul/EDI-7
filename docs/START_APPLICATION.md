# How to Start the SecureMesh AI Application

This guide explains how to launch the complete end-to-end system: starting the backend server, connecting the hardware, and viewing the live dashboard.

## 1. Prerequisites (First Time Only)

Open a terminal in the root of your project folder (`c:\Camputer\Projects\EDI`) and install the required Python packages for the backend server:

```bash
pip install fastapi uvicorn aiosqlite pyserial networkx
```

## 2. Hardware Setup

1. **Gateway Node (Node 3):** Plug Node 3 into your PC via USB. This is the node that bridges the mesh network to your computer.
2. **Close Serial Monitor:** Make sure the Arduino IDE Serial Monitor is **CLOSED**. If it is open, Python cannot read the COM port.
3. **Power other nodes:** Plug in your normal mesh nodes (Nodes 1 and 2) and your Attacker node (Node 4) to power banks or wall chargers so they start communicating.

## 3. Starting the Backend Server

The Python backend connects to the Gateway ESP32, processes the telemetry, runs the AI decision engine, and streams the data to the web dashboard.

1. Open a terminal in your project root (`c:\Camputer\Projects\EDI`).
2. Run the server using Uvicorn:

```bash
uvicorn backend.server:app --reload
```

3. Look at the terminal output. You should see a message saying the server has successfully connected to the COM port and that Uvicorn is running on `http://0.0.0.0:8000`.

## 4. Opening the Live Dashboard

The dashboard website (located in the `dashboard/` directory) is automatically hosted by the backend server.

1. Open a modern web browser (Google Chrome or Microsoft Edge).
2. Navigate to: [http://localhost:8000](http://localhost:8000)

## What to Expect
- **Live Traffic:** You will immediately see nodes on the screen with animated lines representing the packets flying between them.
- **Telemetry:** The packet rate, RSSI, and drop counters will update in real-time.
- **Attack Detection:** When Node 4 cycles into an attack mode (like DoS or Blackhole), the Python backend will detect the anomaly, the dashboard will flash a red alert, and the offending node will be visually "Isolated" from the network graph!

---

### Troubleshooting
- **Address already in use:** If the terminal says port 8000 is in use, you likely have another terminal window already running the server. Close it and try again.
- **Permission Denied (COM Port):** This means the Arduino IDE (or another program) is still watching the COM port. Close it!
- **No data on the dashboard:** Make sure the Gateway (Node 3) is physically plugged in before you start the `uvicorn` command.
