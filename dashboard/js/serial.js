/* WebSerial bridge: reads newline-delimited JSON from a gateway ESP32 over USB
 * (115200 baud) and forwards each packet to POST /api/telemetry, so it goes
 * through the same aggregation / decision-engine / database path as every
 * other data source. The backend's built-in simulator is paused while connected.
 * Requires a Chromium browser (Chrome / Edge) on localhost or https. */
var SerialBridge = (function () {
  "use strict";

  var BAUD = 115200;
  var MAX_QUEUE = 500;

  var port = null, reader = null, closedPromise = null;
  var running = false, draining = false, queue = [];
  var callbacks = { onChange: function () {}, onMessage: function () {} };

  function supported() { return "serial" in navigator; }
  function isConnected() { return running; }

  function post(path, body) {
    return fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  }

  function drain() {
    if (draining) return Promise.resolve();
    draining = true;
    return (async function () {
      while (queue.length && running) {
        try { await post("/api/telemetry", queue.shift()); } catch (e) { /* backend unreachable: drop the packet */ }
      }
      draining = false;
    })();
  }

  function handleLine(line) {
    if (!line || line.charAt(0) !== "{") return;
    try {
      var packet = JSON.parse(line);
      // Every gateway line is a JSON object (RX / TX / TELEMETRY / ALERT, see
      // docs/serial_json_schema.md); the backend decides what to do with each.
      if (packet === null || typeof packet !== "object" || Array.isArray(packet)) return;
      if (queue.length >= MAX_QUEUE) queue.shift();
      queue.push(packet);
      drain();
    } catch (e) { /* partial or non-JSON boot line: ignore */ }
  }

  async function cleanup() {
    running = false;
    queue = [];
    try { if (reader) await reader.cancel(); } catch (e) {}
    try { if (closedPromise) await closedPromise; } catch (e) {}
    try { if (port) await port.close(); } catch (e) {}
    port = reader = closedPromise = null;
    try { await post("/api/simulate/enabled", { enabled: true }); } catch (e) {}
    callbacks.onChange(false);
  }

  async function connect() {
    if (!supported()) {
      callbacks.onMessage("Web Serial is not available in this browser. Use Chrome or Edge.", "error");
      return;
    }
    try {
      port = await navigator.serial.requestPort();
      await port.open({ baudRate: BAUD });
    } catch (e) {
      port = null;
      callbacks.onMessage(e && e.name === "NotFoundError" ? "No serial port selected." : "Could not open the serial port: " + e.message, "error");
      return;
    }

    running = true;
    try { await post("/api/simulate/enabled", { enabled: false }); } catch (e) {}
    callbacks.onChange(true);

    var decoder = new TextDecoderStream();
    closedPromise = port.readable.pipeTo(decoder.writable).catch(function () {});
    reader = decoder.readable.getReader();

    var buffer = "";
    try {
      while (running) {
        var chunk = await reader.read();
        if (chunk.done) break;
        buffer += chunk.value;
        var newline;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          handleLine(buffer.slice(0, newline).trim());
          buffer = buffer.slice(newline + 1);
        }
      }
    } catch (e) {
      callbacks.onMessage("Serial read error: " + e.message, "error");
    } finally {
      await cleanup();
    }
  }

  function disconnect() {
    running = false;
    if (reader) reader.cancel().catch(function () {});
  }

  function init(cb) {
    callbacks = cb;
  }

  return { init: init, supported: supported, isConnected: isConnected, connect: connect, disconnect: disconnect };
})();
