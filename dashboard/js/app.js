// SecureMesh AI — basic draft dashboard.
// Plain fetch() for REST reads/writes, one WebSocket for live push updates.
// No canvas/SVG topology drawing here on purpose — backend routes/logic are
// the focus of this draft; visualization stays a set of plain tables.

const WS_URL = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";

async function fetchJSON(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(path + " failed: " + res.status);
  return res.json();
}

async function postJSON(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(path + " failed: " + res.status);
  return res.json();
}

function fmtTime(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleTimeString();
}

function nodeLabel(id) {
  return "N" + id;
}

async function refreshStatus() {
  const s = await fetchJSON("/api/status");
  document.getElementById("netStatus").textContent = s.network_status;
  document.getElementById("activeNodes").textContent = s.active_nodes + " / " + s.total_nodes;
  document.getElementById("suspiciousNodes").textContent = s.suspicious_nodes;
  document.getElementById("isolatedNodes").textContent = s.isolated_nodes;
  document.getElementById("activeLinks").textContent = s.active_links + " / " + s.total_links;
}

async function refreshNodes() {
  const nodes = await fetchJSON("/api/nodes");
  const tbody = document.querySelector("#nodesTable tbody");
  tbody.innerHTML = nodes.map((n) => (
    "<tr><td>" + nodeLabel(n.node_id) + "</td>" +
    "<td class=\"status-" + n.status + "\">" + n.status + "</td>" +
    "<td>" + fmtTime(n.last_seen) + "</td></tr>"
  )).join("");
}

async function refreshRoutes() {
  const routes = await fetchJSON("/api/routes");
  const tbody = document.querySelector("#routesTable tbody");
  tbody.innerHTML = routes.map((r) => (
    "<tr><td>" + nodeLabel(r.source) + "</td><td>" + nodeLabel(r.destination) + "</td>" +
    "<td>" + (r.path ? r.path.map(nodeLabel).join(" → ") : "-") + "</td>" +
    "<td class=\"status-" + r.status + "\">" + r.status + "</td></tr>"
  )).join("");
}

async function refreshEvents() {
  const events = await fetchJSON("/api/events?limit=50");
  const tbody = document.querySelector("#eventsTable tbody");
  tbody.innerHTML = events.map((e) => (
    "<tr><td>" + fmtTime(e.timestamp) + "</td><td>" + nodeLabel(e.node_id) + "</td>" +
    "<td>" + (e.attack_type || e.event_type) + "</td>" +
    "<td>" + (e.confidence != null ? Math.round(e.confidence * 100) + "%" : "-") + "</td>" +
    "<td>" + (e.action || "-") + "</td><td>" + e.status + "</td></tr>"
  )).join("");
}

function prependRow(tbody, html, max) {
  tbody.insertAdjacentHTML("afterbegin", html);
  while (tbody.rows.length > max) tbody.deleteRow(tbody.rows.length - 1);
}

function connectWebSocket() {
  const ws = new WebSocket(WS_URL);

  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);

    if (msg.type === "telemetry") {
      const t = msg.data;
      const tbody = document.querySelector("#telemetryTable tbody");
      prependRow(tbody,
        "<tr><td>" + fmtTime(t.timestamp) + "</td><td>" + nodeLabel(t.source) + "</td>" +
        "<td>" + nodeLabel(t.destination) + "</td><td>" + t.packet_rate.toFixed(1) + "/s</td>" +
        "<td>" + t.packet_loss.toFixed(1) + "%</td><td>" + (t.rssi != null ? t.rssi : "-") + "</td>" +
        "<td>" + (t.sequence_number != null ? t.sequence_number : "-") + "</td></tr>",
        50);
    } else if (msg.type === "security_event") {
      refreshEvents();
      refreshNodes();
      refreshStatus();
    } else if (msg.type === "topology") {
      refreshRoutes();
      refreshStatus();
    }
  };

  ws.onclose = () => setTimeout(connectWebSocket, 2000);
  ws.onerror = () => ws.close();
}

document.getElementById("btnIsolate").addEventListener("click", async () => {
  const nodeId = Number(document.getElementById("nodeIdInput").value);
  await postJSON("/api/control/isolate", { node_id: nodeId });
  await Promise.all([refreshNodes(), refreshRoutes(), refreshStatus()]);
});

document.getElementById("btnRestore").addEventListener("click", async () => {
  const nodeId = Number(document.getElementById("nodeIdInput").value);
  await postJSON("/api/control/restore", { node_id: nodeId });
  await Promise.all([refreshNodes(), refreshRoutes(), refreshStatus()]);
});

async function init() {
  await Promise.all([refreshStatus(), refreshNodes(), refreshRoutes(), refreshEvents()]);
  connectWebSocket();
  setInterval(refreshStatus, 5000);
}

init();
