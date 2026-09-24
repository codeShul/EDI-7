/* Live packet stream + deep inspector ("Wireshark mini").
 * Rows are built with textContent only: packet fields come from the mesh and
 * must never be interpreted as HTML. */
var PacketInspector = (function () {
  "use strict";

  var MAX_BUFFER = 500;   // packets kept in memory
  var MAX_ROWS = 100;     // rows kept in the DOM
  // network_packet.packet_type from docs/mesh_base_plan.md
  var TYPE_CODE = { DATA: 0, HEARTBEAT: 1, ROUTE_SYNC: 2 };

  var buffer = [], counter = 0, paused = false, selected = null;
  var body, wrap, detail, elHex, elJson, elSeq, elNote, elCount, btnPause;

  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function clock(seconds) {
    var d = new Date(seconds * 1000);
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function hex2(n) { return (n < 16 ? "0" : "") + n.toString(16).toUpperCase(); }
  function orDash(v) { return v === null || v === undefined ? "–" : v; }

  function cell(text, className) {
    var td = document.createElement("td");
    td.textContent = text;
    if (className) td.className = className;
    return td;
  }

  function statusCell(status, className) {
    var td = document.createElement("td");
    var tag = document.createElement("span");
    tag.className = "tag " + (className || "tag-" + String(status).toLowerCase());
    tag.textContent = status;
    td.appendChild(tag);
    return td;
  }

  /* Rebuild the frame as the gateway saw it. The gateway JSON carries the
   * header fields only, so checksum/payload bytes appear only if it forwards them. */
  function frameBytes(p) {
    var seq = (p.sequence_number === null || p.sequence_number === undefined ? 0 : p.sequence_number) >>> 0;
    var typeCode = TYPE_CODE[p.type] === undefined ? 255 : TYPE_CODE[p.type];
    var bytes = [
      Number(p.source) & 255, Number(p.destination) & 255,
      seq & 255, (seq >>> 8) & 255, (seq >>> 16) & 255, (seq >>> 24) & 255,
      typeCode, (p.ttl === null || p.ttl === undefined ? 0 : p.ttl) & 255
    ];
    if (typeof p.checksum === "number") bytes.push(p.checksum & 255, (p.checksum >>> 8) & 255);
    if (typeof p.payload === "string") {
      (p.payload.replace(/[^0-9a-fA-F]/g, "").match(/../g) || []).forEach(function (h) {
        bytes.push(parseInt(h, 16));
      });
    }
    return bytes;
  }

  function hexDump(bytes) {
    var lines = [];
    for (var i = 0; i < bytes.length; i += 8) {
      var chunk = bytes.slice(i, i + 8);
      var hex = chunk.map(hex2).join(" ");
      var ascii = chunk.map(function (b) { return b >= 32 && b < 127 ? String.fromCharCode(b) : "."; }).join("");
      lines.push(("000" + i.toString(16)).slice(-4) + "  " + (hex + "                        ").slice(0, 23) + "  |" + ascii + "|");
    }
    return lines.join("\n");
  }

  function routingNote(p) {
    var at = p.receiver ? "N" + p.receiver : "the receiver";
    switch (p.action) {
      case "CONSUMED": return " Delivered to " + at + " (final destination).";
      case "RELAYING": return " " + at + " is not the destination and forwards it with TTL " +
        (p.ttl === null || p.ttl === undefined ? "?" : p.ttl - 1) + ".";
      case "TTL_EXPIRED": return " TTL exhausted at " + at + "; the frame is dropped.";
      default: return "";
    }
  }

  function sequenceAnalysis(p) {
    var link = "N" + p.source + " → N" + p.destination;

    if (p.direction === "TX") {
      var next = p.hop ? "N" + p.hop : "its next hop";
      return p.delivery === "FAIL"
        ? { cls: "dup", text: "Delivery FAILED: " + next + " did not acknowledge the frame (offline or out of range)." }
        : { cls: "", text: "Sent towards " + next + ": radio ACK received. Outgoing frames are not sequence-checked." };
    }

    switch (p.packet_status) {
      case "DUP":
        return { cls: "dup", text: "Sequence gap: 0 — exact repeat (same #" + p.sequence_number + " and TTL) from N" +
          p.source + ". Repeated frames are the replay signature." + routingNote(p) };
      case "GAP":
        return { cls: "gap", text: "Sequence jumped to #" + p.sequence_number + " for N" + p.source +
          ". Normal when the sender also talks to other nodes." + routingNote(p) };
      case "BLOCKED":
        return { cls: "blocked", text: "Dropped at the gateway: N" + p.source + " or N" + p.destination +
          " is isolated. Not evaluated by the decision engine." };
      default:
        return { cls: "", text: "Sequence continuity OK — #" + p.sequence_number + " from N" + p.source +
          " on " + link + "." + routingNote(p) };
    }
  }

  function jsonView(p) {
    return {
      packet: p.n,
      time: new Date(p.timestamp * 1000).toISOString(),
      direction: p.direction || "RX",
      src: "N" + p.source,
      dst: "N" + p.destination,
      receiver: p.receiver ? "N" + p.receiver : "–",
      hop: p.hop ? "N" + p.hop : "–",
      type: p.type,
      action: orDash(p.action),
      delivery: orDash(p.delivery),
      ttl: orDash(p.ttl),
      seq: orDash(p.sequence_number),
      rssi_dbm: orDash(p.rssi_instant),
      status: p.packet_status,
      link_rate_pps: p.packet_rate,
      link_loss_pct: p.packet_loss,
      window_duplicates: orDash(p.duplicate_count),
      window_gaps: orDash(p.sequence_anomalies)
    };
  }

  function select(entry, row) {
    selected = entry;
    Array.prototype.forEach.call(body.querySelectorAll("tr.selected"), function (r) { r.classList.remove("selected"); });
    if (row) row.classList.add("selected");

    var bytes = frameBytes(entry);
    elHex.textContent = hexDump(bytes);
    elNote.textContent = bytes.length + " bytes: src, dst, seq (u32 LE), type, ttl" +
      (typeof entry.checksum === "number" ? ", checksum" : "") + (typeof entry.payload === "string" ? ", payload" : "") +
      ". Rebuilt from the gateway JSON.";
    elJson.textContent = JSON.stringify(jsonView(entry), null, 2);

    var analysis = sequenceAnalysis(entry);
    elSeq.className = "seq-note " + analysis.cls;
    elSeq.textContent = analysis.text;
    detail.hidden = false;
  }

  function buildRow(entry) {
    var tr = document.createElement("tr");
    tr.className = "clickable" + (selected === entry ? " selected" : "");
    tr.appendChild(cell(entry.n));
    tr.appendChild(cell(clock(entry.timestamp)));
    tr.appendChild(statusCell(entry.direction || "RX", "tag-" + (entry.direction || "RX").toLowerCase()));
    tr.appendChild(cell("N" + entry.source));
    tr.appendChild(cell("N" + entry.destination));
    tr.appendChild(cell(entry.type));
    tr.appendChild(cell(orDash(entry.action)));
    tr.appendChild(cell(orDash(entry.ttl)));
    tr.appendChild(cell(entry.hop ? "N" + entry.hop : "–"));
    tr.appendChild(cell(orDash(entry.rssi_instant)));
    tr.appendChild(cell(orDash(entry.sequence_number)));
    tr.appendChild(statusCell(entry.packet_status));
    tr.addEventListener("click", function () { select(entry, tr); });
    return tr;
  }

  function renderEmpty() {
    body.textContent = "";
    var tr = document.createElement("tr");
    tr.className = "empty";
    var td = cell("Waiting for packets…");
    td.colSpan = 12;
    tr.appendChild(td);
    body.appendChild(tr);
  }

  function renderTail() {
    body.textContent = "";
    if (!buffer.length) { renderEmpty(); return; }
    buffer.slice(-MAX_ROWS).forEach(function (entry) { body.appendChild(buildRow(entry)); });
    wrap.scrollTop = wrap.scrollHeight;
  }

  function updateCount() {
    elCount.textContent = buffer.length + " / " + MAX_BUFFER + " buffered" + (paused ? " (paused)" : "");
  }

  function add(packet) {
    var entry = {};
    for (var key in packet) entry[key] = packet[key];
    entry.n = ++counter;
    buffer.push(entry);
    if (buffer.length > MAX_BUFFER) buffer.shift();
    updateCount();
    if (paused) return;

    var stick = wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 24;
    var empty = body.querySelector("tr.empty");
    if (empty) body.removeChild(empty);
    body.appendChild(buildRow(entry));
    while (body.children.length > MAX_ROWS) body.removeChild(body.firstChild);
    if (stick) wrap.scrollTop = wrap.scrollHeight;
  }

  function init() {
    body = document.getElementById("pktBody");
    wrap = body.closest(".table-wrap");
    detail = document.getElementById("pktDetail");
    elHex = document.getElementById("inspHex");
    elJson = document.getElementById("inspJson");
    elSeq = document.getElementById("inspSeq");
    elNote = document.getElementById("inspNote");
    elCount = document.getElementById("pktCount");
    btnPause = document.getElementById("pktPause");

    btnPause.addEventListener("click", function () {
      paused = !paused;
      btnPause.textContent = paused ? "Resume" : "Pause";
      updateCount();
      if (!paused) renderTail();
    });
    document.getElementById("pktClear").addEventListener("click", function () {
      buffer = [];
      selected = null;
      detail.hidden = true;
      renderEmpty();
      updateCount();
    });

    renderEmpty();
    updateCount();
  }

  return { init: init, add: add };
})();
