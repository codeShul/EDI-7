/* Multi-tier incident log: security alerts, self-healing/routing, system events.
 * Server-side entries are derived from GET /api/events; dashboard-side entries
 * (connection changes) are kept for the session only. */
var Logs = (function () {
  "use strict";

  var MAX = 200;
  var CATEGORIES = ["security", "healing", "system"];
  var serverEntries = [], sessionEntries = [];
  var tab = "security", query = "";
  var body, search;

  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function clock(ms) {
    var d = new Date(ms);
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function pct(c) { return c === null || c === undefined ? "n/a" : Math.round(c * 100) + "%"; }
  function nodeName(id) { return String(id) === "0" ? "System" : "Node " + id; }
  function parseJson(text) { try { return JSON.parse(text); } catch (e) { return null; } }

  function fromEvent(e) {
    var t = e.timestamp * 1000;
    var route = parseJson(e.recovery_route);
    var links = route && route.active_links !== undefined
      ? "mesh recalculated, " + route.active_links + "/" + route.total_links + " links healthy" : "";

    switch (e.event_type) {
      case "ATTACK_DETECTED":
        return [
          { time: t, level: "CRIT", source: nodeName(e.node_id), category: "security", action: "ISOLATE",
            message: "[" + e.attack_type + "] " + (e.detail || "Attack detected") + " (confidence " + pct(e.confidence) + ")" },
          { time: t, level: "HEAL", source: "Gateway", category: "healing", action: "Isolate + reroute",
            message: "Node " + e.node_id + " isolated" + (links ? "; " + links : "") }
        ];
      case "MANUAL_ISOLATE":
        return [{ time: t, level: "INFO", source: "Operator", category: "healing", action: "ISOLATE",
          message: "Node " + e.node_id + " isolated manually" + (links ? "; " + links : "") }];
      case "MANUAL_RESTORE":
        return [{ time: t, level: "HEAL", source: "Operator", category: "healing", action: "RESTORE",
          message: "Node " + e.node_id + " restored to the mesh" + (links ? "; " + links : "") }];
      case "SIM_ATTACK":
        return [{ time: t, level: "WARN", source: "Simulator", category: "system", action: "Injected",
          message: e.detail || "Attack injected" }];
      default:
        return [{ time: t, level: "INFO", source: e.event_type === "SIM_RESET" ? "Simulator" : "Gateway",
          category: "system", action: e.action || "–", message: e.detail || e.event_type }];
    }
  }

  function all() {
    return serverEntries.concat(sessionEntries).sort(function (a, b) { return b.time - a.time; });
  }

  function cell(text, className) {
    var td = document.createElement("td");
    td.textContent = text;
    if (className) td.className = className;
    return td;
  }

  function render() {
    var entries = all();
    var counts = { security: 0, healing: 0, system: 0 };
    entries.forEach(function (e) { counts[e.category]++; });
    CATEGORIES.forEach(function (c) {
      document.getElementById("cnt" + c.charAt(0).toUpperCase() + c.slice(1)).textContent = counts[c];
    });

    var needle = query.toLowerCase();
    var shown = entries.filter(function (e) {
      return e.category === tab &&
        (!needle || (e.source + " " + e.message + " " + e.action).toLowerCase().indexOf(needle) !== -1);
    }).slice(0, MAX);

    body.textContent = "";
    if (!shown.length) {
      var tr = document.createElement("tr");
      tr.className = "empty";
      var td = cell("No entries in this category yet.");
      td.colSpan = 5;
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    shown.forEach(function (e) {
      var row = document.createElement("tr");
      row.appendChild(cell(clock(e.time)));
      var level = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "lvl lvl-" + e.level;
      badge.textContent = e.level;
      level.appendChild(badge);
      row.appendChild(level);
      row.appendChild(cell(e.source));
      row.appendChild(cell(e.message, "wrap"));
      row.appendChild(cell(e.action));
      body.appendChild(row);
    });
  }

  function setEvents(events) {
    serverEntries = [];
    events.forEach(function (e) { Array.prototype.push.apply(serverEntries, fromEvent(e)); });
    render();
  }

  function addSystem(message, level) {
    sessionEntries.push({ time: Date.now(), level: level || "INFO", source: "Dashboard", category: "system",
      action: "–", message: message });
    if (sessionEntries.length > MAX) sessionEntries.shift();
    render();
  }

  function download(name, mime, text) {
    var url = URL.createObjectURL(new Blob([text], { type: mime }));
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function csvField(v) { return '"' + String(v).replace(/"/g, '""') + '"'; }

  function exportLogs(format) {
    var entries = all().slice(0, MAX * 3);
    if (format === "csv") {
      var lines = ["time,level,source,category,action,message"].concat(entries.map(function (e) {
        return [new Date(e.time).toISOString(), e.level, e.source, e.category, e.action, e.message].map(csvField).join(",");
      }));
      download("securemesh_logs.csv", "text/csv", lines.join("\n"));
    } else {
      download("securemesh_logs.json", "application/json", JSON.stringify(entries.map(function (e) {
        return { time: new Date(e.time).toISOString(), level: e.level, source: e.source,
          category: e.category, action: e.action, message: e.message };
      }), null, 2));
    }
  }

  function init() {
    body = document.getElementById("logBody");
    search = document.getElementById("logSearch");

    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (btn) {
      btn.addEventListener("click", function () {
        tab = btn.getAttribute("data-tab");
        Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (b) {
          var active = b === btn;
          b.classList.toggle("active", active);
          b.setAttribute("aria-selected", active ? "true" : "false");
        });
        render();
      });
    });
    search.addEventListener("input", function () { query = search.value.trim(); render(); });
    document.getElementById("logCsv").addEventListener("click", function () { exportLogs("csv"); });
    document.getElementById("logJson").addEventListener("click", function () { exportLogs("json"); });
    render();
  }

  return { init: init, setEvents: setEvents, addSystem: addSystem };
})();
