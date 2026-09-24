/* Animated SVG topology: nodes on a ring, one line per mesh link (10 for 5 nodes).
 * Packets are shown as pulses travelling along the link (requestAnimationFrame). */
var Topology = (function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var CX = 200, CY = 195, RING = 128, NODE_R = 22, LABEL_R = 46;
  var MAX_PULSES = 50, PULSE_MS = 650;

  var svg, linkLayer, pulseLayer, nodeLayer, onSelect;
  var pos = {}, linkEls = {}, nodeEls = {}, linkState = {}, nodeState = {};
  var selected = null;
  var pulses = [], rafId = 0;
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function make(name, attrs, parent) {
    var el = document.createElementNS(NS, name);
    for (var key in attrs) el.setAttribute(key, attrs[key]);
    if (parent) parent.appendChild(el);
    return el;
  }

  function linkKey(a, b) { return Math.min(a, b) + "-" + Math.max(a, b); }

  function init(svgEl, selectCallback) {
    svg = svgEl;
    onSelect = selectCallback;
    linkLayer = make("g", {}, svg);
    pulseLayer = make("g", {}, svg);
    nodeLayer = make("g", {}, svg);
  }

  function build(ids) {
    linkLayer.textContent = "";
    nodeLayer.textContent = "";
    pos = {}; linkEls = {}; nodeEls = {};

    ids.forEach(function (id, i) {
      var angle = -Math.PI / 2 + (i * 2 * Math.PI) / ids.length;
      pos[id] = { x: CX + RING * Math.cos(angle), y: CY + RING * Math.sin(angle), angle: angle };
    });

    for (var i = 0; i < ids.length; i++) {
      for (var j = i + 1; j < ids.length; j++) {
        var a = pos[ids[i]], b = pos[ids[j]];
        var line = make("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, "class": "link" }, linkLayer);
        make("title", {}, line);
        linkEls[linkKey(ids[i], ids[j])] = line;
      }
    }

    ids.forEach(function (id) {
      var p = pos[id];
      var g = make("g", {
        "class": "node", tabindex: "0", role: "button",
        transform: "translate(" + p.x.toFixed(1) + "," + p.y.toFixed(1) + ")"
      }, nodeLayer);
      make("title", {}, g);
      make("circle", { r: NODE_R }, g);
      make("line", { "class": "iso-mark", x1: -14, y1: -14, x2: 14, y2: 14 }, g);
      make("line", { "class": "iso-mark", x1: -14, y1: 14, x2: 14, y2: -14 }, g);
      var nodeNames = {
        1: "1 (68:09)",
        2: "2 (1c:c3)",
        3: "3 (Gateway)",
        4: "4 (Attacker)",
        5: "5 (Offline)"
      };
      label.textContent = nodeNames[id] || ("N" + id);
      var status = make("text", {
        "class": "node-status",
        x: (Math.cos(p.angle) * LABEL_R).toFixed(1),
        y: (Math.sin(p.angle) * LABEL_R + 3).toFixed(1)
      }, g);
      status.textContent = "OK";

      g.addEventListener("click", function () { toggle(id, true); });
      g.addEventListener("keydown", function (evt) {
        if (evt.key === "Enter" || evt.key === " ") { evt.preventDefault(); toggle(id, true); }
      });
      nodeEls[id] = { g: g, status: status };
    });
  }

  function paint() {
    Object.keys(linkEls).forEach(function (key) {
      var state = (linkState[key] || "ACTIVE").toLowerCase();
      var parts = key.split("-");
      var related = selected !== null && (Number(parts[0]) === selected || Number(parts[1]) === selected);
      linkEls[key].setAttribute("class", "link " + state + (related ? " hl" : ""));
      linkEls[key].firstChild.textContent = "Link N" + parts[0] + " ↔ N" + parts[1] + ": " + state;
    });

    Object.keys(nodeEls).forEach(function (id) {
      var status = nodeState[id] || "HEALTHY";
      var el = nodeEls[id];
      var isRelated = selected !== null && Number(id) !== selected &&
        linkState[linkKey(Number(id), selected)] === "ACTIVE";
      el.g.setAttribute("class", "node " + status.toLowerCase() +
        (Number(id) === selected ? " selected" : "") + (isRelated ? " related" : ""));
      el.status.textContent = status === "HEALTHY" ? "OK" : status;
      el.g.setAttribute("aria-label", "Node " + id + ", " + status.toLowerCase());
      el.g.firstChild.textContent = "Node N" + id + " — " + status;
    });

    svg.classList.toggle("has-selection", selected !== null);
  }

  /* topology: GET /api/topology; nodes: GET /api/nodes rows */
  function update(topology, nodes) {
    if (Object.keys(nodeEls).length !== topology.nodes.length) build(topology.nodes);

    linkState = {};
    topology.links.forEach(function (l) { linkState[linkKey(l.source, l.destination)] = l.status; });

    nodeState = {};
    (nodes || []).forEach(function (n) { nodeState[Number(n.node_id)] = n.status; });
    topology.isolated.forEach(function (id) { nodeState[id] = "ISOLATED"; });

    paint();
  }

  function toggle(id, notify) {
    selected = selected === id ? null : id;
    paint();
    if (notify && onSelect) onSelect(selected);
  }

  function select(id) {
    selected = id;
    paint();
  }

  function pulse(src, dst, kind) {
    if (reduceMotion || document.hidden || !pos[src] || !pos[dst] || pulses.length >= MAX_PULSES) return;
    var dot = make("circle", { r: 4, "class": "pulse " + kind, cx: pos[src].x, cy: pos[src].y }, pulseLayer);
    pulses.push({ el: dot, from: pos[src], to: pos[dst], start: performance.now() });
    if (!rafId) rafId = requestAnimationFrame(tick);
  }

  function tick(now) {
    for (var i = pulses.length - 1; i >= 0; i--) {
      var p = pulses[i];
      var t = (now - p.start) / PULSE_MS;
      if (t >= 1) {
        pulseLayer.removeChild(p.el);
        pulses.splice(i, 1);
      } else {
        p.el.setAttribute("cx", p.from.x + (p.to.x - p.from.x) * t);
        p.el.setAttribute("cy", p.from.y + (p.to.y - p.from.y) * t);
      }
    }
    rafId = pulses.length ? requestAnimationFrame(tick) : 0;
  }

  return { init: init, update: update, select: select, pulse: pulse };
})();
