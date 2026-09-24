/* SecureMesh AI dashboard: state, REST + WebSocket wiring, node matrix,
 * status bar and demo controls. Visual pieces live in topology.js,
 * packet_inspector.js, logs.js and serial.js. */
(function () {
  "use strict";

  var RATE_WINDOW_MS = 3000;
  var WS_URL = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";

  var state = { status: null, nodes: [], topology: null, alerts: 0 };
  var perNode = {};            // node id -> { times[], sent, blocked, rssi }
  var recent = [];             // timestamps of delivered packets, for the net-rate stat
  var matrixRows = {};         // node id -> { tr, cells }
  var selectedNode = null;
  var refreshTimer = null;
  var ws = null, wsWasUp = null;

  function $(id) { return document.getElementById(id); }

  async function api(path, options) {
    var res = await fetch(path, options);
    var body = null;
    try { body = await res.json(); } catch (e) { /* empty body */ }
    if (!res.ok) throw new Error((body && body.detail) || res.statusText);
    return body;
  }

  function post(path, body) {
    return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  }

  function statsFor(id) {
    if (!perNode[id]) perNode[id] = { times: [], sent: 0, blocked: 0, rssi: null };
    return perNode[id];
  }

  /* ---------------- rendering ---------------- */
  function setStat(el, dotClass, text) {
    el.textContent = "";
    if (dotClass) {
      var dot = document.createElement("span");
      dot.className = "dot " + dotClass;
      el.appendChild(dot);
    }
    el.appendChild(document.createTextNode(text));
  }

  function renderStatusBar() {
    var s = state.status;
    if (!s) return;

    var isolated = state.topology ? state.topology.isolated : [];
    if (s.network_status === "HEALTHY") {
      setStat($("statNetwork"), "good", "HEALTHY");
    } else {
      setStat($("statNetwork"), "bad", "UNDER ATTACK" +
        (isolated.length ? " — " + isolated.map(function (n) { return "N" + n; }).join(", ") + " isolated" : ""));
    }
    setStat($("statLinks"), null, s.active_links + " / " + s.total_links);

    var cutoff = Date.now() - RATE_WINDOW_MS;
    while (recent.length && recent[0] < cutoff) recent.shift();
    setStat($("statRate"), null, (recent.length / (RATE_WINDOW_MS / 1000)).toFixed(1) + " pkts/s");
    setStat($("statAlerts"), null, String(state.alerts));

    var mode = $("modeBadge");
    var labels = { SIMULATED: "Mode: simulated traffic", EXTERNAL: "Mode: external gateway", SERIAL: "Mode: gateway serial" };
    mode.textContent = labels[s.mode] || "Mode: " + s.mode;
    mode.setAttribute("data-state", s.mode === "SIMULATED" ? "warn" : "good");

    document.querySelectorAll(".attack").forEach(function (btn) {
      btn.disabled = !s.attack_simulation;
      btn.title = s.attack_simulation ? "" : "Attack injection needs the built-in simulator as the data source";
    });
    $("btnReset").disabled = !s.attack_simulation;
  }

  function statusBadgeNode(status) {
    var wrapper = document.createElement("span");
    wrapper.className = "status-cell";
    var dot = document.createElement("span");
    dot.className = "dot " + (status === "ISOLATED" ? "bad" : status === "SUSPICIOUS" ? "warn" : "good");
    wrapper.appendChild(dot);
    wrapper.appendChild(document.createTextNode(status === "HEALTHY" ? "OK" : status));
    return wrapper;
  }

  function ensureMatrixRow(id) {
    if (matrixRows[id]) return matrixRows[id];
    var tr = document.createElement("tr");
    tr.className = "clickable";
    var cells = [];
    for (var i = 0; i < 6; i++) { var td = document.createElement("td"); tr.appendChild(td); cells.push(td); }
    cells[0].textContent = "N" + id;
    tr.addEventListener("click", function () { selectNode(selectedNode === id ? null : id); });
    $("nodeMatrix").querySelector("tbody").appendChild(tr);
    matrixRows[id] = { tr: tr, cells: cells };
    return matrixRows[id];
  }

  function renderMatrix() {
    var cutoff = Date.now() - RATE_WINDOW_MS;
    state.nodes.forEach(function (node) {
      var id = Number(node.node_id);
      var stats = statsFor(id);
      while (stats.times.length && stats.times[0] < cutoff) stats.times.shift();
      var row = ensureMatrixRow(id);

      row.cells[1].textContent = "";
      row.cells[1].appendChild(statusBadgeNode(node.status));
      row.cells[2].textContent = (stats.times.length / (RATE_WINDOW_MS / 1000)).toFixed(1) + "/s";
      row.cells[3].textContent = stats.rssi === null ? "–" : stats.rssi + " dBm";
      row.cells[4].textContent = stats.sent.toLocaleString();
      row.cells[5].textContent = stats.blocked.toLocaleString();
      row.tr.classList.toggle("selected", selectedNode === id);
    });
  }

  function renderTargetSelect() {
    var select = $("targetNode");
    var wanted = state.nodes.map(function (n) { return String(n.node_id); });
    var have = Array.prototype.map.call(select.options, function (o) { return o.value; });
    if (wanted.join() === have.join()) return;

    var previous = select.value;
    select.textContent = "";
    wanted.forEach(function (id) {
      var option = document.createElement("option");
      option.value = id;
      option.textContent = "N" + id;
      select.appendChild(option);
    });
    select.value = wanted.indexOf(previous) !== -1 ? previous : (wanted.indexOf("2") !== -1 ? "2" : wanted[0]);
  }

  function selectNode(id) {
    selectedNode = id;
    Topology.select(id);
    if (id !== null) $("targetNode").value = String(id);
    renderMatrix();
  }

  /* ---------------- data ---------------- */
  async function refreshAll() {
    try {
      var results = await Promise.all([
        api("/api/status"), api("/api/nodes"), api("/api/topology"), api("/api/events?limit=200")
      ]);
      state.status = results[0];
      state.nodes = results[1];
      state.topology = results[2];
      state.alerts = results[3].filter(function (e) { return e.event_type === "ATTACK_DETECTED"; }).length;

      Topology.update(state.topology, state.nodes);
      Logs.setEvents(results[3]);
      renderTargetSelect();
      renderMatrix();
      renderStatusBar();
    } catch (e) {
      /* backend unreachable: the WebSocket badge already tells the user */
    }
  }

  function scheduleRefresh() {
    if (refreshTimer) return;
    refreshTimer = setTimeout(function () { refreshTimer = null; refreshAll(); }, 150);
  }

  function onTelemetry(t) {
    var src = Number(t.source), dst = Number(t.destination);
    var stats = statsFor(src);
    var kind = "ok";

    if (t.packet_status === "BLOCKED") {
      stats.blocked = t.blocked_total || stats.blocked + 1;
      kind = "blocked";
    } else {
      var now = Date.now();
      stats.times.push(now);
      recent.push(now);
      stats.sent++;
      if (t.rssi_instant !== null && t.rssi_instant !== undefined) stats.rssi = t.rssi_instant;
      if (t.packet_status === "DUP" || t.packet_status === "GAP") kind = "warn";
    }

    PacketInspector.add(t);
    Topology.pulse(src, dst, kind);
  }

  function connectWebSocket() {
    ws = new WebSocket(WS_URL);

    ws.onopen = function () {
      setWsBadge(true);
      if (wsWasUp === false) Logs.addSystem("WebSocket reconnected");
      wsWasUp = true;
      refreshAll();
    };

    ws.onmessage = function (evt) {
      var msg = JSON.parse(evt.data);
      if (msg.type === "telemetry") {
        onTelemetry(msg.data);
      } else if (msg.type === "security_event") {
        if (msg.data.event_type === "SIM_RESET") {
          Object.keys(perNode).forEach(function (id) { perNode[id].blocked = 0; });
        }
        scheduleRefresh();
      } else if (msg.type === "topology") {
        scheduleRefresh();
      }
    };

    ws.onclose = function () {
      setWsBadge(false);
      if (wsWasUp !== false) Logs.addSystem("WebSocket disconnected; retrying", "WARN");
      wsWasUp = false;
      setTimeout(connectWebSocket, 2000);
    };
    ws.onerror = function () { ws.close(); };
  }

  function setWsBadge(up) {
    $("wsBadge").setAttribute("data-state", up ? "good" : "bad");
    $("wsText").textContent = up ? "Live stream" : "Disconnected";
  }

  /* ---------------- controls ---------------- */
  function setMessage(text, kind) {
    var el = $("ctrlMsg");
    el.textContent = text;
    el.className = "ctrl-msg" + (kind ? " " + kind : "");
  }

  async function runAction(request, describe) {
    setMessage("Working…");
    try {
      var result = await request();
      setMessage(describe(result), "ok");
    } catch (err) {
      setMessage(err.message, "error");
    }
    scheduleRefresh();
  }

  function targetNode() { return Number($("targetNode").value); }

  function wireControls() {
    document.querySelectorAll(".attack").forEach(function (btn) {
      btn.addEventListener("click", function () {
        runAction(function () {
          return post("/api/simulate/attack", { attack: btn.getAttribute("data-attack"), node_id: targetNode() });
        }, function (r) { return r.detail; });
      });
    });
    $("btnReset").addEventListener("click", function () {
      runAction(function () { return post("/api/simulate/reset"); }, function () { return "All attacks stopped, every node restored."; });
    });
    $("btnIsolate").addEventListener("click", function () {
      runAction(function () { return post("/api/control/isolate", { node_id: targetNode() }); },
        function () { return "N" + targetNode() + " isolated."; });
    });
    $("btnRestore").addEventListener("click", function () {
      runAction(function () { return post("/api/control/restore", { node_id: targetNode() }); },
        function () { return "N" + targetNode() + " restored."; });
    });
    $("targetNode").addEventListener("change", function () {
      var id = targetNode();
      selectedNode = id;
      Topology.select(id);
      renderMatrix();
    });

    var serialButton = $("btnSerial");
    if (!SerialBridge.supported()) {
      serialButton.disabled = true;
      serialButton.title = "Web Serial is not available in this browser (use Chrome or Edge)";
    }
    SerialBridge.init({
      onChange: function (connected) {
        serialButton.textContent = connected ? "Disconnect USB" : "Connect USB (WebSerial)";
        Logs.addSystem(connected ? "USB gateway connected; simulator paused" : "USB gateway disconnected; simulator resumed");
        scheduleRefresh();
      },
      onMessage: function (text, kind) { setMessage(text, kind); }
    });
    serialButton.addEventListener("click", function () {
      if (SerialBridge.isConnected()) SerialBridge.disconnect(); else SerialBridge.connect();
    });
  }

  /* ---------------- start ---------------- */
  function init() {
    Topology.init($("topology"), function (id) {
      selectedNode = id;
      if (id !== null) $("targetNode").value = String(id);
      renderMatrix();
    });
    PacketInspector.init();
    Logs.init();
    wireControls();
    connectWebSocket();
    refreshAll();

    setInterval(function () { renderMatrix(); renderStatusBar(); }, 500);
    setInterval(refreshAll, 5000);
  }

  init();
})();
