/* luvre workstation UI — call graph: hierarchical layout + canvas drawing */
"use strict";

/* ═══════════════════════ call graph (Ghidra-style Sugiyama layout) ═══════════════════════
   Layout model borrowed from Ghidra's GraphServices (jungrapht):
   hierarchical ranks (callers above, callees below), barycenter ordering to
   minimize edge crossings, orthogonal-ish edges with arrowheads, and
   incremental expansion by double-clicking a node. */

const GRAPH_LAYER_H = 118;
const GRAPH_GAP = 26;
const GRAPH_MAX_NODES = 400;

const G = {
  rawNodes: new Map(),   // addr -> name
  rawEdges: new Set(),   // "callerAddr>calleeAddr"
  center: 0,
  nodes: [],             // laid out: {addr,name,rank,kind,x,y,w,h}
  byId: new Map(),
  edges: [],             // {from,to,fromNode,toNode}
  scale: 1, tx: 0, ty: 0,
  hover: null, selected: null,
  panning: false, dragging: null, down: null, moved: false,
  canvas: null, ctx: null, raf: 0,
};

function resetGraph(centerAddr) {
  G.rawNodes = new Map();
  G.rawEdges = new Set();
  G.center = centerAddr;
  G.selected = centerAddr;
  G.hover = null;
  G.scale = 1;
  G.tx = 0;
  G.ty = 0;
}

function mergeGraphPiece(g) {
  for (const n of g.nodes) if (!G.rawNodes.has(n.addr)) G.rawNodes.set(n.addr, n.name);
  for (const [a, b] of g.edges) G.rawEdges.add(`${a}>${b}`);
}

async function showGraph(addr) {
  resetGraph(addr);
  $("#graph-info").innerHTML = t("graph.building", { addr: hexpad(addr) });
  try {
    const depth = Number($("#graph-depth").value || 2);
    mergeGraphPiece(await api(`function/${addr}/callgraph?depth=${depth}&max=${GRAPH_MAX_NODES}`));
    layoutGraph();
    fitGraph();
    updateGraphStats();
    pokeGraph();
  } catch (e) {
    $("#graph-info").textContent = t("graph.fail", { err: e.message });
  }
}

async function expandGraphNode(node) {
  if (G.rawNodes.size >= GRAPH_MAX_NODES) {
    toast(t("toast.graph_limit", { n: GRAPH_MAX_NODES }), "info");
    return;
  }
  try {
    const g = await api(`function/${node.addr}/callgraph?depth=1&max=120`);
    const beforeN = G.rawNodes.size, beforeE = G.rawEdges.size;
    mergeGraphPiece(g);
    if (G.rawNodes.size === beforeN && G.rawEdges.size === beforeE) {
      toast(t("toast.no_new"), "info", 1600);
      return;
    }
    layoutGraph();
    fitGraph();
    updateGraphStats();
    pokeGraph();
    logLine(`graph: expanded ${node.name} (${G.rawNodes.size} nodes)`, "hi");
  } catch (e) {
    toast("expand failed: " + e.message, "error");
  }
}

function updateGraphStats() {
  $("#graph-info").innerHTML = `<b>${esc(t("graph.center_addr", { addr: hexpad(G.center) }))}</b>`;
  $("#graph-stats").textContent = `${t("graph.stats", { n: G.rawNodes.size, m: G.rawEdges.size })} · ${t("graph.hint")}`;
}

/* ---------------- rank computation: callers negative, callees positive ---------------- */

function computeRanks() {
  const ranks = new Map([[G.center, 0]]);
  const adj = new Map();
  const touch = (a) => { if (!adj.has(a)) adj.set(a, []); };
  for (const key of G.rawEdges) {
    const [a, b] = key.split(">").map(Number);
    touch(a); touch(b);
    adj.get(a).push({ next: b, delta: 1 });   // a calls b
    adj.get(b).push({ next: a, delta: -1 });  // a is a caller of b
  }
  const queue = [G.center];
  while (queue.length) {
    const cur = queue.shift();
    const r = ranks.get(cur);
    for (const { next, delta } of adj.get(cur) || []) {
      if (!ranks.has(next)) {
        ranks.set(next, Math.max(-3, Math.min(3, r + delta)));
        queue.push(next);
      }
    }
  }
  for (const addr of G.rawNodes.keys()) if (!ranks.has(addr)) ranks.set(addr, 0);
  return ranks;
}

/* ---------------- layout: layers + barycenter ordering ---------------- */

function layoutGraph() {
  const ctx = G.ctx;
  const FONT = "12px 'JetBrains Mono', Consolas, monospace";
  ctx.font = FONT;
  const ranks = computeRanks();

  const nodes = [];
  const byId = new Map();
  for (const [addr, name] of G.rawNodes) {
    const tw = ctx.measureText(name).width;
    const n = {
      addr, name,
      rank: ranks.get(addr),
      w: Math.max(110, Math.min(300, tw + 34)),
      h: 42, x: 0, y: 0, kind: "same",
    };
    nodes.push(n);
    byId.set(addr, n);
  }
  for (const n of nodes) {
    n.kind = n.addr === G.center ? "center"
      : n.rank < 0 ? "caller"
      : n.rank > 0 ? "callee" : "same";
  }

  const edges = [];
  for (const key of G.rawEdges) {
    const [a, b] = key.split(">").map(Number);
    const fa = byId.get(a), fb = byId.get(b);
    if (fa && fb) edges.push({ from: a, to: b, fromNode: fa, toNode: fb });
  }

  const layers = new Map();
  for (const n of nodes) {
    if (!layers.has(n.rank)) layers.set(n.rank, []);
    layers.get(n.rank).push(n);
  }
  const sortedRanks = [...layers.keys()].sort((a, b) => a - b);

  // seed order: center first in its layer, then by address for stability
  for (const r of sortedRanks) {
    layers.get(r).sort((a, b) =>
      (a.addr === G.center ? -1 : b.addr === G.center ? 1 : a.addr - b.addr));
  }

  // barycenter sweeps to reduce crossings
  const neighbors = new Map();
  for (const e of edges) {
    if (!neighbors.has(e.from)) neighbors.set(e.from, []);
    if (!neighbors.has(e.to)) neighbors.set(e.to, []);
    neighbors.get(e.from).push(e.to);
    neighbors.get(e.to).push(e.from);
  }
  for (let pass = 0; pass < 4; pass++) {
    const pos = new Map();
    for (const r of sortedRanks) layers.get(r).forEach((n, i) => pos.set(n.addr, i));
    for (const r of sortedRanks) {
      const layer = layers.get(r);
      const bary = new Map();
      for (const n of layer) {
        const others = (neighbors.get(n.addr) || []).filter((a) => {
          const m = byId.get(a);
          return m && m.rank !== r;
        });
        bary.set(n.addr, others.length
          ? others.reduce((s, a) => s + (pos.get(a) ?? 0), 0) / others.length
          : pos.get(n.addr));
      }
      layer.sort((a, b) => (bary.get(a.addr) - bary.get(b.addr)) || (a.addr - b.addr));
    }
  }

  // pack each layer horizontally, y by rank
  for (const r of sortedRanks) {
    const layer = layers.get(r);
    const total = layer.reduce((s, n) => s + n.w, 0) + GRAPH_GAP * (layer.length - 1);
    let x = -total / 2;
    for (const n of layer) {
      n.x = x + n.w / 2;
      n.y = r * GRAPH_LAYER_H;
      x += n.w + GRAPH_GAP;
    }
  }
  const cNode = byId.get(G.center);
  if (cNode) {
    const dx = -cNode.x;
    for (const n of nodes) n.x += dx;
  }

  G.nodes = nodes;
  G.byId = byId;
  G.edges = edges;
}

function fitGraph() {
  if (!G.nodes.length) return;
  const c = G.canvas;
  const host = c.parentElement;
  let W = host ? host.clientWidth : 0;
  let H = host ? host.clientHeight : 0;
  if (!W || !H || W > 8000 || H > 8000) { W = 800; H = 500; }
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of G.nodes) {
    minX = Math.min(minX, n.x - n.w / 2); maxX = Math.max(maxX, n.x + n.w / 2);
    minY = Math.min(minY, n.y - n.h / 2); maxY = Math.max(maxY, n.y + n.h / 2);
  }
  const pad = 46;
  const gw = Math.max(1, maxX - minX + pad * 2);
  const gh = Math.max(1, maxY - minY + pad * 2);
  const fit = Math.min(W / gw, H / gh);
  // Keep labels readable: never zoom below 0.6; when the graph is wider than
  // the viewport, anchor the center node instead of the bounding box.
  G.scale = Math.max(0.6, Math.min(1.5, fit));
  const anchor = (fit < 0.6 && G.byId?.get(G.center)) || null;
  if (anchor) {
    G.tx = W / 2 - anchor.x * G.scale;
    G.ty = H / 2 - anchor.y * G.scale;
  } else {
    G.tx = W / 2 - ((minX + maxX) / 2) * G.scale;
    G.ty = H / 2 - ((minY + maxY) / 2) * G.scale;
  }
}

/* ---------------- drawing ---------------- */

function rrPath(ctx, x, y, w, h, r) {
  if (ctx.roundRect) { ctx.beginPath(); ctx.roundRect(x, y, w, h, r); return; }
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function arrowHead(ctx, x, y, angle) {
  const s = 7;
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x - s * Math.cos(angle - 0.42), y - s * Math.sin(angle - 0.42));
  ctx.lineTo(x - s * Math.cos(angle + 0.42), y - s * Math.sin(angle + 0.42));
  ctx.closePath();
  ctx.fill();
}

function clipText(ctx, text, maxW) {
  if (ctx.measureText(text).width <= maxW) return text;
  let lo = 0, hi = text.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ctx.measureText(text.slice(0, mid) + "…").width <= maxW) lo = mid;
    else hi = mid - 1;
  }
  return text.slice(0, lo) + "…";
}

function pokeGraph() {
  if (G.raf) return;
  G.raf = requestAnimationFrame(() => { G.raf = 0; drawGraph(); });
}

function drawGraph() {
  const c = G.canvas, ctx = G.ctx;
  if (!c || !ctx) return;
  // Guard against a layout feedback loop: never let the canvas attribute
  // size drive its own CSS size. Measure the parent instead.
  const host = c.parentElement;
  let W = host ? host.clientWidth : 0;
  let H = host ? host.clientHeight : 0;
  if (!W || !H) { W = c.clientWidth; H = c.clientHeight; }
  if (!W || !H) return;
  if (W > 8000 || H > 8000) return;   // runaway layout: refuse to draw
  const dpr = window.devicePixelRatio || 1;
  const wantW = Math.round(W * dpr), wantH = Math.round(H * dpr);
  if (c.width !== wantW || c.height !== wantH) {
    c.width = wantW;
    c.height = wantH;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  // theme-aware palette (task: light default + graphite&rose dark)
  const P = graphPalette();
  if (P.bg) c.style.background = P.bg;
  ctx.save();
  ctx.translate(G.tx, G.ty);
  ctx.scale(G.scale, G.scale);

  const hot = G.hover;
  // ---- edges (call direction: caller -> callee) ----
  for (const e of G.edges) {
    const a = e.fromNode, b = e.toNode;
    if (!a || !b) continue;
    const lit = hot != null && (e.from === hot || e.to === hot);
    ctx.strokeStyle = lit ? P.edgeHi : P.edge;
    ctx.fillStyle = ctx.strokeStyle;
    ctx.lineWidth = lit ? 1.6 : 1.1;

    if (b.y > a.y) {
      // normal downward call edge
      const x1 = a.x, y1 = a.y + a.h / 2;
      const x2 = b.x, y2 = b.y - b.h / 2;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
      arrowHead(ctx, x2, y2, Math.atan2(y2 - y1, x2 - x1));
    } else if (b.y < a.y) {
      // cycle / backward edge: dashed
      const x1 = a.x, y1 = a.y - a.h / 2;
      const x2 = b.x, y2 = b.y + b.h / 2;
      ctx.setLineDash([5, 4]);
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
      ctx.setLineDash([]);
      arrowHead(ctx, x2, y2, Math.atan2(y2 - y1, x2 - x1));
    } else {
      // same rank: arc above
      const dir = a.x <= b.x ? 1 : -1;
      const x1 = a.x + dir * a.w / 2, y1 = a.y - a.h / 4;
      const x2 = b.x - dir * b.w / 2, y2 = b.y - b.h / 4;
      const mx = (x1 + x2) / 2, my = Math.min(y1, y2) - 40;
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.quadraticCurveTo(mx, my, x2, y2); ctx.stroke();
      arrowHead(ctx, x2, y2, Math.atan2(y2 - my, x2 - mx));
    }
  }

  // ---- nodes ----
  for (const n of G.nodes) {
    const isCenter = n.addr === G.center;
    const isSel = n.addr === G.selected;
    const isHover = n.addr === G.hover;
    const x = n.x - n.w / 2, y = n.y - n.h / 2;

    rrPath(ctx, x, y, n.w, n.h, 6);
    ctx.fillStyle = isCenter
      ? `rgba(${P.roseRgb || "255,93,143"},.13)`
      : isHover ? P.fillHover : P.fill;
    ctx.fill();
    ctx.strokeStyle = isCenter ? P.rose
      : isSel ? P.cyan : P.stroke;
    ctx.lineWidth = isCenter || isSel ? 1.8 : 1;
    ctx.stroke();

    // left kind stripe
    const stripe = n.kind === "caller" ? P.caller
      : n.kind === "callee" ? P.callee
      : n.kind === "center" ? P.rose : P.amber;
    ctx.fillStyle = stripe;
    rrPath(ctx, x + 1.5, y + 1.5, 3.5, n.h - 3, 1.75);
    ctx.fill();

    ctx.textAlign = "left";
    ctx.font = "10px 'JetBrains Mono', Consolas, monospace";
    ctx.fillStyle = P.addr;
    ctx.fillText(hexpad(n.addr), x + 13, y + 15);

    ctx.font = "12px 'JetBrains Mono', Consolas, monospace";
    ctx.fillStyle = isCenter ? P.rose : P.text;
    ctx.fillText(clipText(ctx, n.name, n.w - 22), x + 13, y + 32);
  }

  ctx.restore();
}

function graphHit(mx, my) {
  const x = (mx - G.tx) / G.scale;
  const y = (my - G.ty) / G.scale;
  for (let i = G.nodes.length - 1; i >= 0; i--) {
    const n = G.nodes[i];
    if (Math.abs(x - n.x) <= n.w / 2 + 2 && Math.abs(y - n.y) <= n.h / 2 + 2) return n;
  }
  return null;
}

/* ---------------- interactions ---------------- */

function wireGraph() {
  const c = $("#graph-canvas");
  G.canvas = c;
  G.ctx = c.getContext("2d");
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => pokeGraph()).observe(c.parentElement);
  }

  c.addEventListener("mousedown", (e) => {
    const r = c.getBoundingClientRect();
    const hit = graphHit(e.clientX - r.left, e.clientY - r.top);
    G.down = hit;
    G.moved = false;
    if (hit) {
      G.dragging = hit;
    } else {
      G.panning = true;
      c.classList.add("grabbing");
    }
    e.preventDefault();
  });

  window.addEventListener("mousemove", (e) => {
    const r = c.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    if (G.dragging) {
      G.moved = true;
      G.dragging.x = (mx - G.tx) / G.scale;
      G.dragging.y = (my - G.ty) / G.scale;
      pokeGraph();
      return;
    }
    if (G.panning) {
      if (Math.abs(e.movementX) + Math.abs(e.movementY) > 2) G.moved = true;
      G.tx += e.movementX;
      G.ty += e.movementY;
      pokeGraph();
      return;
    }
    const hit = graphHit(mx, my);
    const next = hit ? hit.addr : null;
    if (next !== G.hover) {
      G.hover = next;
      c.classList.toggle("nodehover", !!hit);
      pokeGraph();
    }
  });

  window.addEventListener("mouseup", () => {
    if (G.dragging && !G.moved) {
      // plain click: select, keep whichever tab is open
      const n = G.dragging;
      G.selected = n.addr;
      S.currentFunc = { addr: n.addr, name: n.name };
      loadXrefs(n.addr);
      pokeGraph();
    }
    G.dragging = null;
    G.panning = false;
    c.classList.remove("grabbing");
  });

  c.addEventListener("dblclick", (e) => {
    const r = c.getBoundingClientRect();
    const hit = graphHit(e.clientX - r.left, e.clientY - r.top);
    if (hit) expandGraphNode(hit);
  });

  c.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = c.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const k = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    const ns = Math.max(0.15, Math.min(3.5, G.scale * k));
    G.tx = mx - ((mx - G.tx) / G.scale) * ns;
    G.ty = my - ((my - G.ty) / G.scale) * ns;
    G.scale = ns;
    pokeGraph();
  }, { passive: false });

  $("#graph-refresh").onclick = () => {
    if (S.currentFunc) showGraph(S.currentFunc.addr);
  };
  $("#graph-fit").onclick = () => { fitGraph(); pokeGraph(); };
  $("#graph-depth").onchange = () => {
    if (S.currentFunc) showGraph(S.currentFunc.addr);
  };
}
