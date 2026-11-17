
"use strict";

/* luvre workstation UI — core: helpers, modals, decoder hand-off, context menu, global state */

/* ═══════════════════════ tiny helpers ═══════════════════════ */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hexa = (n) => "0x" + Number(n).toString(16);
const hexpad = (n, w = 8) => "0x" + Number(n).toString(16).padStart(w, "0");
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const bytesToB64 = (u8) => btoa(String.fromCharCode(...u8));

function funcNameByAddr(addr) {
  for (const [name, a] of S.funcMap) if (a === addr) return name;
  return null;
}

async function api(path, opts = {}) {
  const res = await fetch("/api/" + path, opts);
  let body = null;
  try { body = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
  return body;
}

function toast(msg, cls = "info", ms = 4200) {
  const el = document.createElement("div");
  el.className = `toast ${cls}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function logLine(msg, cls = "") {
  const v = $("#logview");
  const t = new Date().toLocaleTimeString();
  v.innerHTML += `<div><span class="t">${t}</span> ${cls ? `<span class="${cls}">` : ""}${esc(msg)}${cls ? "</span>" : ""}</div>`;
  while (v.childElementCount > 600) v.firstChild.remove();
  v.scrollTop = v.scrollHeight;
}

/* theme-aware canvas colors: read once per draw from CSS custom props */
function graphPalette() {
  const cs = getComputedStyle(document.documentElement);
  const g = (n) => cs.getPropertyValue(n).trim();
  return {
    bg: g("--graph-bg"), edge: g("--graph-edge"), edgeHi: g("--graph-edge-hi"),
    text: g("--graph-text"), addr: g("--graph-addr"),
    fill: g("--graph-node-fill"), fillHover: g("--graph-node-hover"),
    stroke: g("--graph-node-stroke"), caller: g("--graph-caller"), callee: g("--graph-callee"),
    rose: g("--rose"), cyan: g("--cyan"), amber: g("--amber"),
    roseRgb: g("--rose-rgb"),
  };
}

/* ── modals ── */
function openModal(sel) { $(sel).classList.remove("hidden"); }
function closeModal(sel) { $(sel).classList.add("hidden"); }

let askResolve = null;
function askText(title, initial) {
  return new Promise((resolve) => {
    askResolve = resolve;
    $("#ask-title").textContent = title;
    $("#ask-input").value = initial || "";
    openModal("#modal-ask");
    $("#ask-input").focus();
    $("#ask-input").select();
  });
}
function closeAsk(value) {
  closeModal("#modal-ask");
  if (askResolve) { const r = askResolve; askResolve = null; r(value); }
}

/* ── F3: one-click send to the decoder lab ── */
function sendToDecoder(text, mode = "text") {
  $("#dec-input").value = text;
  const radio = document.querySelector(`input[name="dec-mode"][value="${mode}"]`);
  if (radio) radio.checked = true;
  // update the input size label right away (it used to stay stale until a run)
  const nbytes = mode === "hex"
    ? (text.match(/[0-9a-fA-F]/g) || []).length / 2
    : mode === "b64" ? Math.floor(text.replace(/\s/g, "").length * 3 / 4)
    : new TextEncoder().encode(text).length;
  $("#dec-in-size").textContent = `(${nbytes} bytes)`;
  $("#drawer").classList.remove("closed");
  $("#drawer").classList.add("open"); // keep the two state classes mutually exclusive
  $("#drawer-toggle").textContent = t("drawer.hide");
  $$("#drawer-tabs .tab").forEach((tb) => tb.classList.toggle("active", tb.dataset.tab === "decoder"));
  $$("#drawer-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === "decoder"));
  toast(t("toast.sent"), "info", 1800);
}

function fmtSize(n) {
  n = Number(n);
  if (!Number.isFinite(n)) return "—";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

/* ── X2: right-click context menu ── */

function openCtxMenu(x, y, items) {
  const m = $("#ctx-menu");
  m.innerHTML = items.map((it, i) =>
    it === "-" ? `<div class="menu-sep"></div>`
      : `<div class="menu-item" data-i="${i}"${it.title ? ` title="${esc(it.title)}"` : ""}>${it.icon ? `<span class="mi-icon">${it.icon}</span>` : ""}<span class="mi-name">${esc(it.label)}</span></div>`).join("");
  m.classList.remove("hidden");
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 8)) + "px";
  m.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 8)) + "px";
  m.querySelectorAll(".menu-item").forEach((el) =>
    el.onclick = () => { m.classList.add("hidden"); items[Number(el.dataset.i)].run(); });
}

function closeCtxMenu() {
  const m = $("#ctx-menu");
  if (m) m.classList.add("hidden");
}

/* IDA-style: jump to a string's first referencing function, highlight the line */
async function jumpStringRef(sAddr) {
  try {
    const res = await api(`xrefs/${sAddr}`);
    const refs = res.to.filter((r) => r.function_addr != null);
    if (refs.length) {
      const r0 = refs[0];
      selectFunction(r0.function_addr, r0.function || hexpad(r0.function_addr), {
        highlightAddr: r0.addr,
        highlightTarget: sAddr,
      });
    } else toast(t("toast.no_refs"), "info");
  } catch (e) { toast(e.message, "error"); }
}

document.addEventListener("contextmenu", (e) => {
  closeCtxMenu();

  // ── symbol in decompiled C (function name / address)
  const sym = e.target.closest("#code-decompile .a, #code-decompile .f");
  if (sym && sym.dataset.addr) {
    e.preventDefault();
    const addr = parseInt(sym.dataset.addr, 16);
    const name = sym.dataset.name || sym.textContent;
    const items = [
      { icon: "⌖", label: t("ctx.jump"), run: () => navigateAddr(addr, name) },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(addr, { focus: true }) },
    ];
    if (S.funcMap.has(name))
      items.push({ icon: "◈", label: t("ctx.graph"), run: () => { switchCenter("graph"); showGraph(addr); } });
    items.push("-",
      { icon: "⧉", label: t("ctx.copy_name"), run: () => navigator.clipboard.writeText(name) },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(addr)) });
    openCtxMenu(e.clientX, e.clientY, items);
    return;
  }

  // ── text selection anywhere in code / hex → decoder
  const selText = String(window.getSelection ? getSelection() : "").trim();
  if (selText && (e.target.closest("#code-decompile") || e.target.closest("#code-hex"))) {
    e.preventDefault();
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⚗", label: t("ctx.decode_text"), title: t("ctx.decode.title"), run: () => sendToDecoder(selText, "text") },
      { icon: "⚗", label: t("ctx.decode_hex"), title: t("ctx.decode.title"), run: () => sendToDecoder(selText.replace(/[^0-9a-fA-F]/g, ""), "hex") },
      "-",
      { icon: "⧉", label: t("ctx.copy"), run: () => navigator.clipboard.writeText(selText) },
    ]);
    return;
  }

  // ── xref row (inspector): jump / copy
  const xrow = e.target.closest("#xrefs-info .xref-row");
  if (xrow && xrow.dataset.addr) {
    e.preventDefault();
    const target = parseInt(xrow.dataset.addr, 16);
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.jump"), run: () => {
          if (xrow.dataset.faddr) {
            const fa = Number(xrow.dataset.faddr);
            selectFunction(fa, xrow.dataset.fname || funcNameByAddr(fa) || hexpad(fa), { highlightAddr: target });
          } else {
            const fn = funcNameByAddr(target);
            if (fn) selectFunction(target, fn);
            else showDisasm(target);
          }
        } },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(target)) },
    ]);
    return;
  }

  // ── crypto-constant hit: refs / disasm / copy
  const crow = e.target.closest("#constants-info .xref-row");
  if (crow && crow.dataset.addr) {
    e.preventDefault();
    const a = parseInt(crow.dataset.addr, 16);
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      { icon: "⌗", label: t("ctx.disasm"), run: () => showDisasm(a) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    ]);
    return;
  }

  // ── function-list row: decompile / graph / rename / note / copy
  const frow = e.target.closest("#list-functions .row");
  if (frow && frow.dataset.addr) {
    e.preventDefault();
    const fa = Number(frow.dataset.addr);
    const fname = (frow.querySelector(".name") || {}).textContent || funcNameByAddr(fa) || hexpad(fa);
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.decompile"), run: () => selectFunction(fa, fname) },
      { icon: "◈", label: t("ctx.graph"), run: () => { switchCenter("graph"); showGraph(fa); } },
      "-",
      { icon: "✎", label: t("ctx.rename"), run: () => selectFunction(fa, fname).then(renameCurrentFn) },
      { icon: "✚", label: t("ctx.note"), run: () => selectFunction(fa, fname).then(noteCurrentFn) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(fa)) },
    ]);
    return;
  }

  // ── string row: jump-to-ref / refs / decode / copy
  const srow = e.target.closest("#list-strings .row");
  if (srow && srow.dataset.addr != null) {
    e.preventDefault();
    const sAddr = Number(srow.dataset.addr);
    const lit = srow.querySelector(".lit");
    const sVal = lit ? lit.textContent : "";
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.jump_ref"), title: t("ctx.jump_ref.title"), run: () => jumpStringRef(sAddr) },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(sAddr, { focus: true }) },
      { icon: "⚗", label: t("ctx.decode"), run: () => sendToDecoder(sVal, "text") },
      "-",
      { icon: "⧉", label: t("ctx.copy"), run: () => navigator.clipboard.writeText(sVal) },
    ]);
    return;
  }

  // ── import row: callers / copy
  const irow = e.target.closest("#list-imports .row");
  if (irow && irow.dataset.addr) {
    e.preventDefault();
    const a = Number(irow.dataset.addr);
    const nm = irow.dataset.name || (irow.querySelector(".name") || {}).textContent || "";
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌕", label: t("ctx.callers"), title: t("ctx.callers.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_name"), run: () => navigator.clipboard.writeText(nm) },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    ]);
    return;
  }

  // ── export row: jump / refs / copy
  const erow = e.target.closest("#list-exports .row");
  if (erow && erow.dataset.addr) {
    e.preventDefault();
    const a = Number(erow.dataset.addr);
    const nm = erow.dataset.name || (erow.querySelector(".name") || {}).textContent || "";
    openCtxMenu(e.clientX, e.clientY, [
      { icon: "⌖", label: t("ctx.jump"), run: () => {
          const fn = funcNameByAddr(a);
          if (fn) selectFunction(a, fn);
          else showDisasm(a);
        } },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_name"), run: () => navigator.clipboard.writeText(nm) },
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    ]);
    return;
  }

  // ── search-result row: depends on which index it came from
  const qrow = e.target.closest("#search-results .row");
  if (qrow && qrow.dataset.addr) {
    e.preventDefault();
    const a = parseInt(qrow.dataset.addr, 16);
    const items = [];
    if (qrow.dataset.kind === "string") {
      const lit = qrow.querySelector(".name");
      items.push(
        { icon: "⌖", label: t("ctx.jump_ref"), title: t("ctx.jump_ref.title"), run: () => jumpStringRef(a) },
        { icon: "⚗", label: t("ctx.decode"), run: () => sendToDecoder(lit ? lit.textContent : "", "text") },
        "-",
      );
    } else if (qrow.dataset.kind === "function") {
      items.push(
        { icon: "⌖", label: t("ctx.decompile"), run: () => selectFunction(a, qrow.dataset.fname) },
        { icon: "◈", label: t("ctx.graph"), run: () => { switchCenter("graph"); showGraph(a); } },
        "-",
      );
    }
    items.push(
      { icon: "⌗", label: t("ctx.disasm"), run: () => showDisasm(a) },
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) },
    );
    openCtxMenu(e.clientX, e.clientY, items);
    return;
  }

  // ── disassembly row: follow call target / refs / copy
  const drow = e.target.closest("#code-disasm .disasm-row");
  if (drow && drow.dataset.addr) {
    e.preventDefault();
    const a = parseInt(drow.dataset.addr, 16);
    const tgt = drow.querySelector(".disasm-target");
    const items = [];
    if (tgt)
      items.push({ icon: "⌖", label: t("ctx.follow"), run: () => {
        const ta = parseInt(tgt.dataset.addr, 16);
        const fn = funcNameByAddr(ta);
        if (fn) selectFunction(ta, fn);
        else showDisasm(ta);
      } });
    items.push(
      { icon: "⌕", label: t("ctx.refs"), title: t("ctx.refs.title"), run: () => loadXrefs(a, { focus: true }) },
      "-",
      { icon: "⧉", label: t("ctx.copy_addr"), run: () => navigator.clipboard.writeText(hexpad(a)) });
    openCtxMenu(e.clientX, e.clientY, items);
    return;
  }
});

/* ═══════════════════════ global state ═══════════════════════ */

const S = {
  program: null,
  triage: null,
  funcMap: new Map(),      // name -> addr
  functionsLoaded: 0,
  functionsTotal: 0,
  functionsQuery: "",
  stringsQuery: "",
  currentFunc: null,       // {addr, name}
  disasmCache: new Map(),  // addr -> rendered? (skip cache, cheap)
  blocks: [],
  hexBlock: null,
  hexOffset: 0,
  hexChunk: 4096,
  hexBytes: null,          // last-read chunk (F3: send to decoder)
  decOutBytes: null,       // last decoder-lab output (encoding switch re-render)
  selectedString: null,
  ops: [],
};
