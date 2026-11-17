/* luvre workstation UI — workstation panels: listings, code, inspector, hex */
"use strict";

/* ── X3: DIE-style packer verdict (查壳结论) ── */

const PACKER_SECTION_SIGS = [
  [/^upx/i, "UPX"], [/^\.?vmp[0-9]/i, "VMProtect"], [/themida|winlice/i, "Themida"],
  [/^\.?aspack|^\.?adata/i, "ASPack"], [/petite/i, "Petite"], [/^\.?mpress/i, "MPRESS"],
  [/^\.fsg|^fsg/i, "FSG"], [/nspack|^\.?nsp[0-9]/i, "NsPack"],
  [/pecompact|^\.?pec[0-9]/i, "PECompact"], [/enigma/i, "Enigma"],
  [/^\.?mew/i, "MEW"], [/^\.?upack/i, "UPack"],
];

function renderVerdict() {
  const box = $("#verdict-info");
  const tri = S.triage;
  if (!tri) { box.innerHTML = `<div class="insp-empty">${esc(t("insp.nothing"))}</div>`; return; }
  const secs = tri.sections || [];
  const ent = Number(tri.max_entropy || 0);
  const hits = [];
  for (const sec of secs)
    for (const [re, name] of PACKER_SECTION_SIGS)
      if (re.test(String(sec.name || ""))) hits.push(`${name} · ${sec.name}`);
  let cls, main, hint;
  if (hits.length) {
    cls = "v-bad";
    main = t("verdict.packed", { n: [...new Set(hits)].join(", ") });
    hint = t("verdict.packed.hint");
  } else if (ent >= 7.5) {
    // high entropy outranks a bare overlay — a compressed payload IS packing
    cls = "v-bad";
    main = t("verdict.high_entropy", { e: ent.toFixed(2) });
    hint = t("verdict.high_entropy.hint");
  } else if (tri.overlay_present) {
    cls = "v-warn";
    main = t("verdict.overlay");
    hint = t("verdict.overlay.hint");
  } else if (ent >= 6.5) {
    cls = "v-warn";
    main = t("verdict.mid_entropy", { e: ent.toFixed(2) });
    hint = t("verdict.mid_entropy.hint");
  } else {
    cls = "v-ok";
    main = t("verdict.clean");
    hint = t("verdict.clean.hint");
  }
  box.innerHTML = `<div class="verdict ${cls}"><div class="verdict-main">${esc(main)}</div><div class="verdict-hint">${esc(hint)}</div></div>`;
}

/* ═══════════════════════ tabs (generic) ═══════════════════════ */

function wireTabs(barSel, bodySel, onChange) {
  const bar = $(barSel);
  bar.addEventListener("click", (e) => {
    const btn = e.target.closest(".tab[data-tab]");
    if (!btn) return;
    $$(barSel + " .tab").forEach((t) => t.classList.toggle("active", t === btn));
    const name = btn.dataset.tab;
    $$(bodySel + " > .tabpane").forEach((p) =>
      p.classList.toggle("active", p.dataset.pane === name));
    if (onChange) onChange(name);
  });
}
const activeTab = (barSel) => $(barSel + " .tab.active")?.dataset.tab;

/* ═══════════════════════ engine status ═══════════════════════ */

function engineState(mode) {
  const dot = $("#engine-dot");
  dot.className = `engine-dot ${mode}`;
  dot.querySelector(".dot-label").textContent =
    t(mode === "busy" ? "engine.analyzing" : mode === "ready" ? "engine.ready" : mode === "error" ? "engine.error" : "engine.idle");
  const st = $("#st-engine");
  st.textContent = t(mode === "busy" ? "engine.st.analyzing" : mode === "ready" ? "engine.st.ready" : mode === "error" ? "engine.st.error" : "engine.st.idle");
  st.className = mode;
}

function setBusy(b, jobLabel = "") {
  engineState(b ? "busy" : (S.program ? "ready" : "idle"));
  $("#st-job").textContent = b ? jobLabel : "";
}

/* ═══════════════════════ opening binaries ═══════════════════════ */

async function openByPath(path) {
  if (!path) return;
  // wipe every panel FIRST — during the (potentially long) open the UI must
  // never keep showing the previous project's strings/functions/xrefs
  resetWorkspace(t("st.opening"));
  setBusy(true, t("job.opening"));
  logLine(`open ${path}`, "hi");
  try {
    const { job } = await api("open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    await pollJob(job, (j) => {
      $("#st-job").textContent = j.progress || t("job.opening");
    });
    logLine(t("log.analysis_done"), "ok");
    await loadProgram();
    gdbStaleTargetCheck();
  } catch (e) {
    toast(t("toast.open_fail", { err: e.message }), "error");
    logLine(`open failed: ${e.message}`, "err");
    await recoverAfterOpenFail();
  } finally {
    setBusy(false);
  }
}

/* A failed open must not leave the workspace showing a phantom project.
   Re-sync with what the server actually holds: if it still has a program,
   rebuild from it; if not, back to the clean empty state. */
async function recoverAfterOpenFail() {
  try {
    await api("program");
    await loadProgram();
  } catch {
    resetWorkspace();
  }
}

async function uploadAndOpen(file) {
  setBusy(true, t("job.uploading"));
  logLine(`upload ${file.name} (${file.size} bytes)`, "hi");
  try {
    const buf = await file.arrayBuffer();
    const res = await fetch(`/api/upload?name=${encodeURIComponent(file.name)}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: buf,
    });
    if (!res.ok) throw new Error(`upload failed: HTTP ${res.status}`);
    const { path } = await res.json();
    $("#path-input").value = path;
    // uploads are copies (the browser never reveals the original path) — say
    // so, and point at the path bar for in-place analysis
    logLine(`${t("toast.upload_copied")} ${path}`, "hi");
    toast(t("toast.upload_copied"), "info", 5200);
    await openByPath(path);
  } catch (e) {
    toast(e.message, "error");
    setBusy(false);
  }
}

function pollJob(id, onTick) {
  return new Promise((resolve, reject) => {
    let lastLog = "";
    const timer = setInterval(async () => {
      try {
        const j = await api(`job/${id}`);
        if (onTick) onTick(j);
        if (j.log.length) {
          const last = j.log[j.log.length - 1];
          if (last !== lastLog) { lastLog = last; logLine(last); }
        }
        if (j.status === "done") { clearInterval(timer); resolve(j); }
        if (j.status === "error") { clearInterval(timer); reject(new Error(j.error)); }
      } catch (e) { clearInterval(timer); reject(e); }
    }, 500);
  });
}

/* Wipe every panel so no project's data ever leaks into another's view
   (the "opening shows the previous project's strings" complaint). Used at
   open start, on open failure recovery, and before loadProgram rebuilds. */
function resetWorkspace(statusMsg) {
  S.program = null;
  S.triage = null;
  S.currentFunc = null;
  S.selectedString = null;
  S.ops = [];
  renderOps();
  $("#hero").classList.add("hidden");
  $("#st-program").textContent = statusMsg || t("st.noprogram");
  renderVerdict();   // handles S.triage == null → "nothing loaded"
  $("#decompile-title").textContent = t("decompile.title.none");
  $("#code-decompile").innerHTML = `<div class="code-empty">${esc(t("code.empty.noprogram"))}</div>`;
  $("#disasm-title").textContent = t("code.title.none");
  $("#code-disasm").innerHTML = `<div class="code-empty">${esc(t("disasm.empty.noprogram"))}</div>`;
  for (const id of ["btn-copy-code", "btn-download-code", "btn-rename-fn", "btn-note-fn"])
    $(`#${id}`).classList.add("hidden");
  $("#xrefs-target").textContent = "—";
  $("#xrefs-target").removeAttribute("data-addr");
  $("#xrefs-info").innerHTML = `<div class="insp-empty">${esc(t("insp.select"))}</div>`;
  // unified search: a new program must start with a clean slate (stale
  // keywords made old-program results look like they belonged to the new one)
  const sq = $("#search-q");
  if (sq) sq.value = "";
  const sr = $("#search-results");
  if (sr) sr.innerHTML = `<div class="code-empty">${esc(t("search.hint"))}</div>`;
  $("#constants-info").innerHTML = `<div class="insp-empty">${esc(t("insp.constants.hint"))}</div>`;
  $("#count-constants").textContent = "";
  $("#program-info").innerHTML = `<div class="insp-empty">${esc(t("insp.nothing"))}</div>`;
  $("#sections-info").innerHTML = "";
  $("#overlay-info").innerHTML = "";
  $("#graph-info").textContent = t("graph.info.none");
  $("#graph-stats").textContent = "";
  const rawBox = $("#code-raw");
  if (rawBox) rawBox.innerHTML = `<div class="code-empty">${esc(t("raw.empty"))}</div>`;
  const rawInfo = $("#raw-info");
  if (rawInfo) rawInfo.textContent = "";
  G.rawNodes = new Map(); G.rawEdges = new Set();
  G.nodes = []; G.edges = []; G.byId = new Map();
  G.center = 0; G.selected = null; G.hover = null;
  pokeGraph();
  S.functionsLoaded = 0; S.funcMap.clear();
  $("#list-functions").innerHTML = "";
  $("#count-functions").textContent = "";
  $("#st-fn").textContent = "";
  $("#list-strings").innerHTML = "";
  $("#count-strings").textContent = "";
  $("#st-str").textContent = "";
  $("#search-results").innerHTML = `<div class="code-empty">${esc(t("search.hint"))}</div>`;
  $("#search-info").textContent = "";
}

async function loadProgram() {
  // fetch first, wipe second: resetWorkspace() nulls S.program/S.triage, so
  // the freshly fetched data must be re-installed AFTER the wipe or every
  // load dies with "Cannot read properties of null" and the workspace stays
  // stuck on the empty state (regression caught by the open-path E2E)
  const prog = await api("program");
  const tri = await api("triage");
  resetWorkspace();
  // a filter left over from the previous program hides every function of the
  // new one as "无匹配项" (found while switching ch12 → ch13 during a solve)
  $("#filter-functions").value = "";
  $("#filter-strings").value = "";
  S.program = prog;
  S.triage = tri;
  engineState("ready");
  $("#st-program").textContent = prog.name;
  // resetWorkspace() installed the pre-open "open a binary first" hints;
  // with a program loaded the center must say what to do NEXT instead
  // (found while solving a keygenme: pane kept saying open-a-binary)
  $("#code-decompile").innerHTML = `<div class="code-empty">${esc(t("code.empty.dec"))}</div>`;
  $("#code-disasm").innerHTML = `<div class="code-empty">${esc(t("disasm.empty"))}</div>`;
  renderVerdict();
  renderProgramInfo();
  renderSections();
  renderOverlay();
  await loadFunctions(false);
  loadStrings();
  loadImportsExports();
  loadBlocks();
  loadConstants();
  toast(t("toast.analyzed", { name: S.program.name, n: S.program.function_count }), "info");
}

/* ═══════════════════════ left: functions ═══════════════════════ */

const PAGE = 400;

let _fnLoadInFlight = false;
async function loadFunctions(append) {
  const list = $("#list-functions");
  // fast scrolling fires the scroll handler repeatedly — never let two
  // appends race (that would duplicate rows)
  if (append && _fnLoadInFlight) return;
  if (!append) { S.functionsLoaded = 0; _fnLoadInFlight = false; list.innerHTML = `<div class="loading">${esc(t("list.loading.fn"))}</div>`; }
  const offset = S.functionsLoaded;
  _fnLoadInFlight = true;
  try {
    const data = await api(`functions?q=${encodeURIComponent(S.functionsQuery)}&offset=${offset}&limit=${PAGE}`);
    if (!append) list.innerHTML = "";
    S.functionsTotal = data.total;
    $("#count-functions").textContent = data.total;
    $("#st-fn").textContent = t("st.fn", { n: data.total });
    for (const f of data.items) addFuncRow(list, f);
    S.functionsLoaded += data.items.length;
    if (!data.items.length && !append)
      list.innerHTML = `<div class="code-empty">${esc(t("list.no_match"))}</div>`;
  } catch (e) {
    if (!append) list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`;
    else logLine("functions append failed: " + e.message, "err");  // appends used to fail silently
  } finally {
    _fnLoadInFlight = false;
  }
}

function addFuncRow(list, f) {
  S.funcMap.set(f.name, f.addr);
  const row = document.createElement("div");
  row.className = "row";
  row.tabIndex = 0;
  row.dataset.addr = f.addr;
  row.innerHTML = `<span class="addr">${hexpad(f.addr)}</span><span class="name">${esc(f.name)}</span><span class="meta">${f.size}</span>`;
  row.onclick = () => selectFunction(f.addr, f.name);
  list.appendChild(row);
}

async function selectFunction(addr, name, opts = {}) {
  S.currentFunc = { addr, name };
  $$("#list-functions .row").forEach((r) =>
    r.classList.toggle("active", Number(r.dataset.addr) === addr));
  $("#decompile-title").innerHTML = `<b>${esc(name)}</b> · ${hexpad(addr)}`;
  for (const id of ["btn-copy-code", "btn-download-code", "btn-rename-fn", "btn-note-fn"])
    $(`#${id}`).classList.remove("hidden");
  const code = $("#code-decompile");
  code.innerHTML = `<div class="loading">${esc(t("dec.decompiling", { name }))}</div>`;
  try {
    const res = await api(`function/${addr}/decompile`);
    renderCode(res.code, {
      addrLines: res.addr_lines,
      addrLinesHi: res.addr_lines_hi,
      addrData: res.addr_data,
      highlightAddr: opts.highlightAddr,
      highlightTarget: opts.highlightTarget,
    });
    if (activeTab("#center-tabs") !== "decompile" && !opts.keepTab && activeTab("#center-tabs") !== "graph")
      switchCenter("decompile");
  } catch (e) {
    code.innerHTML = `<div class="code-empty">${esc(t("dec.fail", { err: e.message }))}</div>`;
  }
  loadXrefs(addr);
}

/* F1: rename / note the current function */
async function renameCurrentFn() {
  if (!S.currentFunc) { toast(t("toast.select_fn"), "info"); return; }
  const { addr, name } = S.currentFunc;
  const next = await askText(t("rename.prompt", { old: name }), name);
  if (next == null) return;
  const clean = next.trim();
  if (!clean || clean === name) return;
  try {
    await api(`function/${addr}/rename`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: clean }),
    });
    S.funcMap.delete(name);
    S.funcMap.set(clean, addr);
    S.currentFunc = { addr, name: clean };
    $("#decompile-title").innerHTML = `<b>${esc(clean)}</b> · ${hexpad(addr)}`;
    const row = $(`#list-functions .row[data-addr="${addr}"] .name`);
    if (row) row.textContent = clean;
    if (G.rawNodes.has(addr)) { G.rawNodes.set(addr, clean); layoutGraph(); pokeGraph(); }
    // the open pseudocode still shows the old name — re-decompile it
    if (activeTab("#center-tabs") === "decompile") {
      const res = await api(`function/${addr}/decompile`);
      renderCode(res.code);
    }
    toast(t("toast.renamed", { name: clean }), "ok");
    logLine(`rename ${hexpad(addr)}: ${name} → ${clean}`, "hi");
  } catch (e) { toast(e.message, "error"); }
}

async function noteCurrentFn() {
  if (!S.currentFunc) { toast(t("toast.select_fn"), "info"); return; }
  const { addr, name } = S.currentFunc;
  let cur = "";
  try {
    const r = await api(`function/${addr}/comment`);
    cur = r.comment || "";
  } catch { /* first note */ }
  const text = await askText(t("note.prompt", { name }), cur);
  if (text == null) return;
  try {
    await api(`function/${addr}/comment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    toast(t("toast.note"), "ok");
    logLine(`note ${hexpad(addr)}: ${text ? text.slice(0, 60) : "(cleared)"}`, "hi");
  } catch (e) { toast(e.message, "error"); }
}

function switchCenter(tab) {
  $$("#center-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  $$("#center-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === tab));
}

/* ═══════════════════════ C syntax highlight ═══════════════════════ */

const C_TOKEN = new RegExp([
  "(\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)",                                    // 1 comment
  "(\"(?:[^\"\\\\]|\\\\.)*\")",                                                 // 2 string
  "('(?:[^'\\\\]|\\\\.)*')",                                                    // 3 char
  "(\\b0x[0-9a-fA-F]{4,}\\b)",                                                  // 4 hex
  "(\\b(?:FUN_|SUB_|DAT_|s_|u_|_)[-\\w]{4,}\\b)",                               // 5 ghidra syms
  "\\b(int|char|void|long|short|unsigned|signed|float|double|bool|undefined\\d?|uint|u?long\\s?long|byte|word|dword|qword|if|else|for|while|do|return|switch|case|default|break|continue|sizeof|struct|union|enum|const|static|true|false|null|NULL)\\b", // 6 kw
  "\\b(\\d+)\\b",                                                               // 7 dec
  "([A-Za-z_]\\w*)(?=\\s*\\()",                                                 // 8 call
].join("|"), "g");

function addrFromSym(sym) {
  const m = sym.match(/([0-9a-fA-F]{6,16})$/);
  return m ? parseInt(m[1], 16) : null;
}

function highlightC(code) {
  let out = "", last = 0, m;
  C_TOKEN.lastIndex = 0;
  while ((m = C_TOKEN.exec(code))) {
    out += esc(code.slice(last, m.index));
    const [tok, comment, str, chr, hexnum, ghsym, kw, dec, call] = m;
    if (comment) out += `<span class="c">${esc(comment)}</span>`;
    else if (str || chr) out += `<span class="s">${esc(str || chr)}</span>`;
    else if (hexnum) out += `<span class="n">${esc(hexnum)}</span>`;
    else if (ghsym) {
      const addr = addrFromSym(ghsym);
      // B1: data-addr carries HEX digits everywhere; readers use parseInt(…, 16)
      out += `<span class="a" data-addr="${addr != null ? addr.toString(16) : ""}" data-name="${esc(ghsym)}">${esc(ghsym)}</span>`;
    }
    else if (kw) out += `<span class="k">${esc(kw)}</span>`;
    else if (dec) out += `<span class="n">${esc(dec)}</span>`;
    else if (call) {
      const known = S.funcMap.get(call);
      out += `<span class="f${known != null ? " a" : ""}"${known != null ? ` data-addr="${known.toString(16)}" data-name="${esc(call)}"` : ""}>${esc(call)}</span>`;
    }
    last = m.index + tok.length;
  }
  out += esc(code.slice(last));
  return out;
}

function renderCode(codeText, opts = {}) {
  const box = $("#code-decompile");
  const lines = codeText.replace(/\n$/, "").split("\n");
  box.innerHTML = lines.map((line, i) =>
    `<div class="codeline"><span class="ln">${i + 1}</span><span>${highlightC(line)}</span></div>`
  ).join("");
  box.onclick = (e) => {
    const t = e.target.closest(".a");
    if (!t) return;
    if (t.dataset.addr) navigateAddr(parseInt(t.dataset.addr, 16), t.dataset.name);
    else if (t.dataset.name) {
      const addr = S.funcMap.get(t.dataset.name);
      if (addr != null) selectFunction(addr, t.dataset.name);
    }
  };
  // X1: highlight the decompiled line that references the xref target.
  // Rules (in order): exact data-address match on the target (string/const
  // literal tokens carry their own data address), containment of the ref
  // instruction in a line's code range, nearest following code line
  // (argument-setup instructions precede the call they feed → gaps belong
  // to the NEXT line), fallback to the last line starting at/below the ref.
  if (opts.highlightAddr != null && opts.addrLines) {
    const H = opts.highlightAddr;
    const T = opts.highlightTarget != null ? Number(opts.highlightTarget) : null;
    const lnos = Object.keys(opts.addrLines).map(Number).sort((a, b) => a - b);
    let lineNo = null;
    if (T != null && opts.addrData) {
      for (const ln of lnos) if (Number(opts.addrData[ln]) === T) { lineNo = ln; break; }
    }
    if (lineNo == null) {
      for (const ln of lnos) {
        const lo = Number(opts.addrLines[ln]);
        const hi = opts.addrLinesHi && opts.addrLinesHi[ln] != null ? Number(opts.addrLinesHi[ln]) : lo;
        if (lo <= H && H <= hi) { lineNo = ln; break; }
      }
    }
    if (lineNo == null) for (const ln of lnos) if (Number(opts.addrLines[ln]) > H) { lineNo = ln; break; }
    if (lineNo == null) for (const ln of lnos) if (Number(opts.addrLines[ln]) <= H) lineNo = ln;
    const el = lineNo ? box.querySelector(`.codeline:nth-child(${lineNo})`) : null;
    if (el) {
      el.classList.add("hl");
      setTimeout(() => el.scrollIntoView({ block: "center" }), 60);
    }
  }
}

function navigateAddr(addr, name) {
  const known = S.funcMap.get(name);
  if (known != null) { selectFunction(known, name); return; }
  // try containing function via disasm, then decompile it
  showDisasm(addr, true);
}

/* ═══════════════════════ disassembly ═══════════════════════ */

async function showDisasm(addr, alsoSelect) {
  switchCenter("disasm");
  const box = $("#code-disasm");
  $("#disasm-title").textContent = `${hexpad(addr)} …`;
  try {
    const res = await api(`function/${addr}/disasm`);
    $("#disasm-title").innerHTML = `<b>${esc(res.function || "?")}</b> · ${hexpad(res.function_addr ?? addr)}`;
    box.innerHTML = res.instructions.map((ins) => {
      const parts = ins.text.split(/\s+/);
      const mn = parts[0] || "";
      const rest = ins.text.slice(mn.length);
      const ref = ins.refs && ins.refs.length ? ins.refs[0] : null;
      const alreadyShown = ref != null && ins.text.toLowerCase().includes(ref.toString(16));
      const target = ref != null && !alreadyShown
        ? ` <span class="disasm-target" data-addr="${ref.toString(16)}">${hexpad(ref)}</span>`
        : "";
      return `<div class="disasm-row" data-addr="${ins.addr.toString(16)}">
        <span class="disasm-addr">${hexpad(ins.addr)}</span>
        <span class="disasm-bytes">${esc(ins.bytes)}</span>
        <span class="disasm-text"><span class="disasm-mnemonic">${esc(mn)}</span>${esc(rest)}${target}</span>
      </div>`;
    }).join("");
    box.querySelectorAll(".disasm-target").forEach((t) =>
      t.onclick = () => {
        const a = parseInt(t.dataset.addr, 16);
        const fn = funcNameByAddr(a);
        if (fn) selectFunction(a, fn);
        else showDisasm(a);
      });
    // mark current row
    const cur = box.querySelector(`.disasm-row[data-addr="${addr.toString(16)}"]`);
    if (cur) cur.classList.add("cur"), cur.scrollIntoView({ block: "center" });
    if (alsoSelect && res.function_addr != null) {
      S.currentFunc = { addr: res.function_addr, name: res.function };
      loadXrefs(res.function_addr);
    }
  } catch (e) {
    box.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`;
  }
}

/* ═══════════════════════ strings / imports / exports ═══════════════════════ */

async function loadStrings(append = false) {
  const list = $("#list-strings");
  if (!append) list.innerHTML = `<div class="loading">${esc(t("list.loading.str"))}</div>`;
  try {
    const data = await api(`strings?q=${encodeURIComponent(S.stringsQuery)}&limit=400`);
    if (!append) list.innerHTML = "";
    $("#count-strings").textContent = data.total;
    $("#st-str").textContent = t("st.strings", { n: data.total });
    if (!data.items.length) { list.innerHTML = `<div class="code-empty">${esc(t("list.no_match"))}</div>`; return; }
    for (const s of data.items) {
      const row = document.createElement("div");
      row.className = "row";
      row.tabIndex = 0;
      row.dataset.addr = s.addr;
      row.innerHTML = `<span class="addr">${hexpad(s.addr)}</span><span class="val"><span class="lit">${esc(s.value)}</span></span><span class="meta">${s.length}</span><button class="row-btn" title="${esc(t("hex.send.title"))}">⚗</button>`;
      row.onclick = () => {
        S.selectedString = s.value;
        $$("#list-strings .row").forEach((r) => r.classList.toggle("active", r === row));
        loadXrefs(s.addr, { focus: true });
      };
      // IDA reflex: double-click a string → jump straight into the code using it
      row.ondblclick = () => jumpStringRef(s.addr);
      row.querySelector(".row-btn").onclick = (e) => {
        e.stopPropagation();
        S.selectedString = s.value;
        sendToDecoder(s.value, "text");
      };
      list.appendChild(row);
    }
  } catch (e) { if (!append) list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

async function loadImportsExports() {
  for (const [which, sel] of [["imports", "#list-imports"], ["exports", "#list-exports"]]) {
    const list = $(sel);
    list.innerHTML = `<div class="loading">…</div>`;
    try {
      const data = await api(which);
      list.innerHTML = "";
      if (!data.items.length) { list.innerHTML = `<div class="code-empty">${esc(t("list.none"))}</div>`; continue; }
      for (const it of data.items) {
        const row = document.createElement("div");
        row.className = "row";
        row.tabIndex = 0;
        row.dataset.name = it.name;
        if (it.addr != null) row.dataset.addr = it.addr;
        row.innerHTML = which === "imports"
          ? `<span class="name">${esc(it.name)}</span><span class="meta">${esc(it.library || "")}</span>`
          : `<span class="addr">${hexpad(it.addr)}</span><span class="name">${esc(it.name)}</span>`;
        // X1: click an import → who calls it (via its thunk function)
        if (which === "imports" && it.addr != null) {
          row.title = t("imports.xref.title");
          row.onclick = () => loadXrefs(it.addr, { focus: true });
        }
        list.appendChild(row);
      }
    } catch (e) { list.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
  }
}

/* ═══════════════════════ inspector ═══════════════════════ */

function renderProgramInfo() {
  const p = S.program;
  $("#program-info").innerHTML = `<dl class="kv">
    <dt>${esc(t("label.name"))}</dt><dd class="long">${esc(p.name)}</dd>
    <dt>${esc(t("label.format"))}</dt><dd>${esc(p.format)}</dd>
    <dt>${esc(t("label.language"))}</dt><dd>${esc(p.language_id)}</dd>
    <dt>${esc(t("label.compiler"))}</dt><dd>${esc(p.compiler)}</dd>
    <dt>${esc(t("label.base"))}</dt><dd class="mono-addr">${hexpad(parseInt(p.image_base, 16))}</dd>
    <dt>${esc(t("label.size"))}</dt><dd>${Number(p.size).toLocaleString()}</dd>
    <dt>${esc(t("label.functions"))}</dt><dd>${p.function_count}</dd>
    <dt>${esc(t("label.project"))}</dt><dd class="long" title="${esc(p.project_dir || "")}">${esc(p.project_dir || "—")}</dd>
  </dl>`;
}

function renderSections() {
  const box = $("#sections-info");
  const secs = S.triage.sections || [];
  if (!secs.length) { box.innerHTML = `<div class="insp-empty">${esc(t("list.none"))}</div>`; return; }
  box.innerHTML = secs.map((s) => {
    const ent = s.entropy != null ? s.entropy.toFixed(2) : "—";
    const w = s.entropy != null ? Math.min(100, s.entropy / 8 * 100) : 0;
    const packed = s.entropy > 7.2 ? ` <span style="color:var(--rose)">· ${esc(t("sec.packed"))}</span>` : "";
    // B4: malformed section tables must not print NaN
    const sz = Number(s.raw_size ?? s.size);
    const off = s.raw_offset ?? s.offset;
    const szText = Number.isFinite(sz) && sz >= 0 ? sz.toLocaleString() : "—";
    const offText = off != null && Number.isFinite(Number(off)) ? hexa(Number(off)) : "—";
    return `<div class="sec-row">
      <div class="sec-line1"><span class="sec-name">${esc(s.name || ("#" + s.index))}</span><span class="sec-ent">H=${ent}${packed}</span></div>
      <div class="sec-bar"><i style="width:${w}%"></i></div>
      <div class="sec-meta">${szText} B @ ${offText}</div>
    </div>`;
  }).join("");
}

function renderOverlay() {
  const box = $("#overlay-info");
  const tri = S.triage;
  if (tri.overlay_present) {
    box.innerHTML = `<div class="overlay-box">
      <div class="overlay-title">${esc(t("ov.detected"))}</div>
      <div class="sec-meta">${t("ov.size")}: ${Number(tri.overlay_size).toLocaleString()} B · ${t("ov.offset")}: ${hexa(tri.overlay_offset)}</div>
      <div class="sec-meta">${esc(t("ov.hint"))}</div>
    </div>`;
  } else {
    const coff = Number(tri.coff_symbols || 0);
    box.innerHTML = `<div class="overlay-box clean"><div class="overlay-title clean">${esc(t("ov.clean"))}</div>` +
      (coff > 0 ? `<div class="sec-meta">${esc(t("ov.coff", { n: coff.toLocaleString() }))}</div>` : "") +
      `</div>`;
  }
}

function shortRefType(t) {
  /* Ghidra ref types get long (UNCONDITIONAL_CALL, COMPUTED_CALL_INDIRECT...)
   * and blow past the fixed 6ch column — normalize to short labels. */
  let s = String(t);
  s = s.replace(/^UNCONDITIONAL_/, "").replace(/^CONDITIONAL_/, "").replace(/^COMPUTED_/, "");
  if (s === "INDIRECTION") s = "PTR";
  if (s.endsWith("_INDIRECT")) s = "I" + s.slice(0, -9);
  return s;
}

async function loadXrefs(addr, opts = {}) {
  $("#xrefs-target").textContent = hexa(addr);
  $("#xrefs-target").dataset.addr = addr;
  const box = $("#xrefs-info");
  box.innerHTML = `<div class="loading">${esc(t("list.loading.refs"))}</div>`;
  try {
    const res = await api(`xrefs/${addr}`);
    let html = "";
    if (res.to.length) {
      html += `<div class="xref-label">${esc(t("xrefs.to"))} (${res.to.length})</div>`;
      html += res.to.slice(0, 40).map((r) =>
        `<div class="xref-row" tabindex="0" data-addr="${Number(r.addr).toString(16)}"${r.function_addr != null ? ` data-faddr="${Number(r.function_addr)}" data-fname="${esc(r.function || "")}"` : ""}><span class="xref-type" title="${esc(r.type)}">${esc(shortRefType(r.type))}</span><span class="xref-addr">${hexpad(r.addr)}</span><span class="xref-name">${esc(r.function || "")}</span></div>`).join("");
    } else html += `<div class="insp-empty">${esc(t("xrefs.none"))}</div>`;
    if (res.from.length) {
      html += `<div class="xref-label">${esc(t("xrefs.from"))} (${res.from.length})</div>`;
      html += res.from.slice(0, 40).map((r) =>
        `<div class="xref-row" tabindex="0" data-addr="${Number(r.to).toString(16)}"><span class="xref-type" title="${esc(r.type)}">${esc(shortRefType(r.type))}</span><span class="xref-addr">${hexpad(r.to)}</span></div>`).join("");
    }
    box.innerHTML = html;
    box.querySelectorAll(".xref-row").forEach((row) =>
      row.onclick = () => {
        const target = parseInt(row.dataset.addr, 16);
        // X1: prefer the containing function — jump into decompiled C, not raw asm
        if (row.dataset.faddr) {
          const fa = Number(row.dataset.faddr);
          selectFunction(fa, row.dataset.fname || funcNameByAddr(fa) || hexpad(fa), {
            highlightAddr: target,
            highlightTarget: Number($("#xrefs-target").dataset.addr),
          });
        } else {
          const fn = funcNameByAddr(target);
          if (fn) selectFunction(target, fn);
          else showDisasm(target);
        }
      });
    if (opts.focus) {
      const g = $("#insp-xrefs");
      g.scrollIntoView({ block: "nearest", behavior: "smooth" });
      g.classList.remove("flash");
      void g.offsetWidth; // restart the flash animation
      g.classList.add("flash");
    }
  } catch (e) { box.innerHTML = `<div class="insp-empty">${esc(e.message)}</div>`; }
}

async function loadConstants() {
  const box = $("#constants-info");
  box.innerHTML = `<div class="loading">${esc(t("list.loading.const"))}</div>`;
  try {
    const res = await api("constants");
    $("#count-constants").textContent = res.items.length;
    if (!res.items.length) {
      box.innerHTML = `<div class="insp-empty">${esc(t("const.none"))}</div>`;
      return;
    }
    box.innerHTML = res.items.map((h) =>
      `<div class="xref-row" tabindex="0" data-addr="${Number(h.addr).toString(16)}" title="${esc(h.note || "")}">
        <span class="xref-addr">${hexpad(h.addr)}</span>
        <span class="xref-name">${esc(h.name)}</span>
        <span class="chip c-${h.category === "hash" ? "hash" : h.category === "ecc" ? "ecc" : h.category === "encoding" ? "encoding" : "crypto"}">${esc(h.function || h.block || "")}</span>
      </div>`).join("");
    box.querySelectorAll(".xref-row").forEach((row) =>
      row.onclick = () => showDisasm(parseInt(row.dataset.addr, 16)));
    toast(t("const.hits", { n: res.items.length }), "info");
  } catch (e) { box.innerHTML = `<div class="insp-empty">${esc(e.message)}</div>`; }
}

/* ═══════════════════════ memory hex ═══════════════════════ */

async function loadBlocks() {
  try {
    const res = await api("memory/blocks");
    S.blocks = res.items;
    const sel = $("#hex-block");
    sel.innerHTML = S.blocks.map((b) =>
      `<option value="${esc(b.name)}">${esc(b.name)} (${hexa(b.start)}, ${Number(b.size).toLocaleString()})</option>`).join("");
    S.hexBlock = S.blocks[0]?.name || null;
    S.hexOffset = 0;
    if (S.hexBlock) readHex();
  } catch (e) { /* ignore */ }
}

async function readHex() {
  const box = $("#code-hex");
  if (!S.hexBlock) { box.innerHTML = `<div class="code-empty">${esc(t("hex.empty"))}</div>`; return; }
  box.innerHTML = `<div class="loading">${esc(t("list.loading.mem"))}</div>`;
  try {
    const res = await api(`memory/read?block=${encodeURIComponent(S.hexBlock)}&offset=${S.hexOffset}&len=${S.hexChunk}`);
    const bytes = b64ToBytes(res.data_b64);
    S.hexBytes = bytes;   // F3: keep for "send to decoder"
    // true vaddr = block start + block-relative offset (labels used to show
    // block-relative numbers, which read as wrong addresses)
    S.hexBase = (S.blocks.find((b) => b.name === S.hexBlock) || {}).start || 0;
    $("#hex-info").textContent = `${S.hexBlock} @ ${hexpad(S.hexBase + S.hexOffset)}`;
    let html = "";
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const addr = S.hexBase + S.hexOffset + i;
      let hx = "", asc = "";
      for (const b of chunk) {
        hx += `<span class="hexbyte${b === 0 ? " zero" : ""}">${b.toString(16).padStart(2, "0")}</span> `;
        asc += (b >= 0x20 && b < 0x7f) ? `<span class="hexascii">${esc(String.fromCharCode(b))}</span>` : `<span class="hexbyte">·</span>`;
      }
      html += `<div class="hexgrid"><span class="hexaddr">${hexpad(addr)}</span>  ${hx} <span class="hexaddr">|</span>${asc}<span class="hexaddr">|</span></div>`;
    }
    box.innerHTML = html;
  } catch (e) { box.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

/* ═══════════════════════ raw disasm (obfuscation lifeline) ═══════════════════════ */

async function showRawDisasm(addr) {
  if (!S.program || addr == null || Number.isNaN(addr)) return;
  addr = Number(addr);
  switchCenter("raw");
  $("#raw-addr").value = "0x" + addr.toString(16);
  const box = $("#code-raw");
  box.innerHTML = `<div class="loading">${esc(t("dec.decompiling", { name: hexpad(addr) }))}</div>`;
  try {
    const res = await api(`disasm-raw?addr=${addr}`);
    S.rawBase = res.base;
    const STOP = { end: "raw.stop.end", ret: "raw.stop.ret", trap: "raw.stop.trap",
                   invalid: "raw.stop.invalid", loop: "raw.stop.loop",
                   indirect: "raw.stop.indirect", limit: "raw.stop.limit" };
    let html = "";
    for (const it of res.items) {
      if (it.resume) {
        html += `<div class="codeline raw-sep"><span class="ln">…</span>${esc(t("raw.resume", { addr: hexpad(it.addr) }))}</div>`;
      } else if (it.dead) {
        html += `<div class="codeline raw-dead"><span class="ln">·</span>${esc(t("raw.dead", { addr: hexpad(it.addr) }))}</div>`;
      } else {
        // make direct jump/call targets clickable — one click re-decodes there
        const mm = it.text.match(/^(\S+\s+)(0x[0-9a-f]+)$/i);
        const body = mm
          ? `${esc(mm[1])}<span class="a raw-target" data-addr="${parseInt(mm[2], 16).toString(16)}">${esc(mm[2])}</span>`
          : esc(it.text);
        const flowMark = it.flow === "jmp" ? `<span class="raw-flow">↝</span>` : "";
        html += `<div class="codeline"><span class="ln">${hexpad(it.addr)}</span>${flowMark}<span class="raw-bytes">${esc(it.bytes)}</span><span class="raw-insn${it.invalid ? " bad" : ""}">${body}</span></div>`;
      }
    }
    if (STOP[res.stop]) html += `<div class="codeline raw-sep"><span class="ln">∎</span>${esc(t(STOP[res.stop]))}</div>`;
    box.innerHTML = html;
    const rec = res.recovered ? ` · ${t("raw.recovered", { n: res.recovered })}` : "";
    $("#raw-info").textContent = `${res.block || ""} · ${res.items.length} insns${rec}`;
    logLine(`raw disasm ${hexpad(res.base)}: ${res.items.length} insns, stop=${res.stop}`, "hi");
  } catch (e) { box.innerHTML = `<div class="code-empty">${esc(e.message)}</div>`; }
}

/* ═══════════════════════ search ═══════════════════════
   One box, three indexes: a plain query searches STRING LITERALS and
   FUNCTION NAMES (the RE anchors), an even-length hex pattern additionally
   searches raw memory bytes. Results are grouped; clearing the box restores
   the empty state (it used to stick with the last hits). */

function looksLikeHexPat(s) {
  const t = s.replace(/0x/gi, "").replace(/[\s,:-]/g, "");
  return /^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0;
}

function searchGroup(title, rowsHtml) {
  if (!rowsHtml) return "";
  return `<div class="search-group"><div class="search-group-label">${esc(title)}</div>${rowsHtml}</div>`;
}

async function runSearch() {
  const pat = $("#search-q").value.trim();
  const box = $("#search-results");
  if (!pat) {                       // cleared input → restore the empty state
    box.innerHTML = `<div class="code-empty">${esc(t("search.hint"))}</div>`;
    $("#search-info").textContent = "";
    return;
  }
  box.innerHTML = `<div class="loading">${esc(t("list.loading.search"))}</div>`;
  $("#search-info").textContent = "";

  const hexMode = looksLikeHexPat(pat);
  // strings + function names are useful even for a hex-looking query
  const strP = api(`strings?q=${encodeURIComponent(pat)}&limit=200`)
    .catch(() => ({ items: [], total: 0 }));
  const fnP = api(`functions?q=${encodeURIComponent(pat)}&offset=0&limit=100`)
    .catch(() => ({ items: [], total: 0 }));
  const memP = hexMode
    ? api(`search?hex=${encodeURIComponent(pat)}&limit=200`).catch(() => ({ items: [] }))
    : Promise.resolve({ items: [] });
  const [strRes, fnRes, memRes] = await Promise.all([strP, fnP, memP]);

  let html = "";
  // strings — the anchor of the solving chain: click → xrefs, dblclick → jump
  let rows = "";
  for (const s of strRes.items) {
    rows += `<div class="row" tabindex="0" data-kind="string" data-addr="${s.addr.toString(16)}">
      <span class="addr">${hexpad(s.addr)}</span><span class="name lit">${esc(s.value)}</span><span class="meta">${s.length}</span>
    </div>`;
  }
  html += searchGroup(t("search.group.strings", { n: strRes.total ?? strRes.items.length }), rows);

  // function names — click → decompile; when the match came from the
  // signature (not the name), surface the signature so the hit is explainable
  rows = "";
  for (const f of fnRes.items) {
    const q = pat.toLowerCase();
    const inName = f.name.toLowerCase().includes(q);
    const sig = inName ? "" : (f.signature || "");
    const sigHtml = sig
      ? `<div class="row-sub">${esc(sig.length > 90 ? sig.slice(0, 90) + "…" : sig)}</div>`
      : "";
    rows += `<div class="row" tabindex="0" data-kind="function" data-addr="${f.addr.toString(16)}" data-fname="${esc(f.name)}">
      <span class="addr">${hexpad(f.addr)}</span><span class="name">${esc(f.name)}</span><span class="meta">${f.size}</span>${sigHtml}
    </div>`;
  }
  html += searchGroup(t("search.group.functions", { n: fnRes.total ?? fnRes.items.length }), rows);

  // raw memory bytes (only for a hex-shaped pattern)
  rows = "";
  for (const h of memRes.items || []) {
    rows += `<div class="row" tabindex="0" data-kind="mem" data-addr="${h.addr.toString(16)}">
      <span class="addr">${hexpad(h.addr)}</span><span class="name">${esc(h.block)}</span><span class="meta">${esc(h.function || "")}</span>
    </div>`;
  }
  html += searchGroup(t("search.group.mem", { n: (memRes.items || []).length }), rows);

  if (!html) {
    box.innerHTML = `<div class="code-empty">${esc(t("search.nohits"))}</div>`;
    $("#search-info").textContent = t("search.hits.none");
    return;
  }
  box.innerHTML = html;
  const nAll = (strRes.total ?? strRes.items.length) + (fnRes.total ?? fnRes.items.length) + (memRes.items || []).length;
  $("#search-info").textContent = t("search.hits", { n: nAll });

  box.querySelectorAll('.row[data-kind="string"]').forEach((row) => {
    const a = parseInt(row.dataset.addr, 16);
    row.onclick = () => loadXrefs(a, { focus: true });
    row.ondblclick = () => jumpStringRef(a);
  });
  box.querySelectorAll('.row[data-kind="function"]').forEach((row) => {
    const a = parseInt(row.dataset.addr, 16);
    row.onclick = () => selectFunction(a, row.dataset.fname);
  });
  box.querySelectorAll('.row[data-kind="mem"]').forEach((row) => {
    const a = parseInt(row.dataset.addr, 16);
    row.onclick = () => showDisasm(a);
  });
}

/* ═══════════════════════ decompile-all ═══════════════════════ */

async function decompileAll() {
  setBusy(true, t("job.decompiling"));
  logLine(t("log.batch"), "hi");
  try {
    const { job } = await api("export/decompile-all", { method: "POST" });
    await pollJob(job, (j) => {
      $("#st-job").textContent = j.progress || t("job.decompiling");
      if (j.log.length) logLine(j.log[j.log.length - 1]);
    });
    toast(t("toast.zip"), "ok");
    logLine(t("log.batch_done"), "ok");
    window.location = `/api/download/decompile-all.zip?job=${job}`;
  } catch (e) {
    toast(t("log.batch_fail", { err: e.message }), "error");
    logLine(`batch failed: ${e.message}`, "err");
  } finally { setBusy(false); }
}

/* ═══════════════════════ goto ═══════════════════════ */

async function gotoInput() {
  const v = $("#goto-input").value.trim();
  if (!v) return;
  if (/^0x[0-9a-f]+$/i.test(v) || /^\d+$/.test(v)) {
    const addr = v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
    showDisasm(addr, true);
  } else {
    // exact known function name → jump straight into its decompile
    // (typing "FUN_08048f50" used to only filter the list, which read
    // as "nothing happened" — caught while driving the keygenme solve)
    const known = S.funcMap.get(v);
    if (known != null) { selectFunction(known, v); return; }
    S.functionsQuery = v;
    $("#filter-functions").value = v;
    $$("#left-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === "functions"));
    $$("#left-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === "functions"));
    await loadFunctions(false);
    // B6: zero hits used to fail silently
    if (!S.functionsTotal) toast(t("goto.none", { q: v }), "info");
    else if (S.functionsTotal === 1) {
      // unambiguous filter hit → navigate there too (funcMap may not hold
      // the name yet: rows load in pages, so read it off the row)
      const row = $("#list-functions .row");
      const nameEl = row && row.querySelector(".name");
      if (row && nameEl) selectFunction(Number(row.dataset.addr), nameEl.textContent);
    }
  }
}

/* ═══════════════════════ layout: resizers & drawer ═══════════════════════ */

function wireResizer(sel, cssVar, min, max) {
  const el = $(sel);
  let dragging = false;
  el.addEventListener("mousedown", (e) => { dragging = true; e.preventDefault(); });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    if (cssVar === "--left-w") {
      const w = Math.min(max, Math.max(min, e.clientX));
      document.documentElement.style.setProperty(cssVar, w + "px");
    } else {
      const w = Math.min(max, Math.max(min, window.innerWidth - e.clientX));
      document.documentElement.style.setProperty(cssVar, w + "px");
    }
  });
  window.addEventListener("mouseup", () => (dragging = false));
}

/* ═══════════════════════ F2: recent files ═══════════════════════ */

async function toggleRecentMenu() {
  const menu = $("#recent-menu");
  if (!menu.classList.contains("hidden")) { menu.classList.add("hidden"); return; }
  menu.innerHTML = `<div class="menu-empty">…</div>`;
  menu.classList.remove("hidden");
  try {
    const { items } = await api("recent");
    if (!items.length) { menu.innerHTML = `<div class="menu-empty">${esc(t("recent.none"))}</div>`; return; }
    menu.innerHTML = items.map((it) =>
      `<button class="menu-item" data-path="${esc(it.path)}">
        <span class="mi-name">${esc(it.name)}</span>
        <span class="mi-meta">${fmtSize(it.size)} · ${new Date(it.ts * 1000).toLocaleString()}</span>
      </button>`).join("");
    menu.querySelectorAll(".menu-item").forEach((b) =>
      b.onclick = () => {
        menu.classList.add("hidden");
        $("#path-input").value = b.dataset.path;
        openByPath(b.dataset.path);
      });
  } catch { menu.innerHTML = `<div class="menu-empty">—</div>`; }
}

/* ═══════════════════════ F5: PyInstaller unpack modal ═══════════════════════ */

let unpackJob = null;      // job id of the running/finished unpack
let unpackOutdir = "";     // server-side output dir (for "send to Ghidra")
let unpackPreviewName = "";

function looksBinary(bytes, name = "") {
  if (/\.pyc$/i.test(name)) return true;
  const n = Math.min(bytes.length, 800);
  if (!n) return false;
  let odd = 0;
  for (let i = 0; i < n; i++) {
    const b = bytes[i];
    if (b === 0 || (b < 0x09) || (b > 0x0d && b < 0x20)) odd++;
  }
  return odd / n > 0.08;
}

/* Only PE / ELF images can be imported by Ghidra — gating the button on the
   magic bytes prevents the "send a .manifest/.pyc to Ghidra" dead end that
   used to fail the open AND empty the engine. */
function isExecImage(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return true;                    // MZ → PE
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return true; // ELF
  return false;
}

async function openUnpackModal() {
  openModal("#modal-unpack");
  $("#unpack-ghidra").classList.add("hidden");
  const meta = $("#unpack-meta"), list = $("#unpack-list"), prev = $("#unpack-preview");
  meta.textContent = "…";
  list.innerHTML = "";
  prev.textContent = "";
  const curPath = (S.program && S.program.source_path) || $("#path-input").value || "";
  const isApk = /\.apk$/i.test(curPath) || (S.triage?.sniff?.format === "ZIP" && /\.apk$/i.test(S.sourcePath || ""));
  const route = isApk ? "unpack/apk" : "unpack/pyinstaller";
  $("#unpack-kind").textContent = isApk ? "解包 APK" : "解包 PyInstaller";
  try {
    const { job } = await api(route, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),   // server uses the currently open binary
    });
    unpackJob = job;
    const j = await pollJob(job, (jj) => { meta.textContent = jj.progress || "…"; });
    renderUnpackResult(j.result);
  } catch (e) {
    if (/NotPyInstaller|not a pyinstaller/i.test(e.message)) meta.textContent = t("unpack.notpy");
    else meta.textContent = t("unpack.failed", { err: e.message });
  }
}

function renderUnpackResult(m) {
  if (!m || !m.outdir) { $("#unpack-meta").textContent = t("unpack.notpy"); return; }
  unpackOutdir = m.outdir;
  if (m.apk) { renderUnpackApk(m); return; }
  const bits = [m.pyinstaller || "PyInstaller", `Python ${m.python || "?"}`,
    `${m.total} ${t("unpack.entries")}`];
  if (m.pyz_modules) bits.push(`PYZ ${m.pyz_modules}`);
  if (m.warnings && m.warnings.length) bits.push(`⚠ ${m.warnings.length}`);
  $("#unpack-meta").textContent = bits.join(" · ");
  const entries = (m.entries || []).slice()
    .sort((a, b) => ((b.type === "s") - (a.type === "s")) || a.name.localeCompare(b.name));
  $("#unpack-list").innerHTML = entries.map((en) =>
    `<div class="row" tabindex="0" data-name="${esc(en.name)}">
      <span class="addr">${en.type === "s" ? "★" : esc(en.type)}</span>
      <span class="name">${esc(en.name)}</span>
      <span class="meta">${fmtSize(en.size)}</span>
    </div>`).join("");
  $("#unpack-preview").textContent = t("unpack.pick");
  $$("#unpack-list .row").forEach((row) =>
    row.onclick = () => previewUnpackedFile(row.dataset.name));
}

function renderUnpackApk(m) {
  const bits = [`APK`, `${m.entries.length} ${t("unpack.entries")}`];
  const dexes = Object.keys(m.dex || {});
  if (dexes.length) bits.push(`${dexes.length} dex`);
  $("#unpack-meta").textContent = bits.join(" · ");
  const typeChip = (t) => t === "dex" ? "★" : t === "manifest" ? "M" : t === "native" ? "so" : "·";
  $("#unpack-list").innerHTML = m.entries.map((en) =>
    `<div class="row" tabindex="0" data-name="${esc(en.name)}" data-kind="${esc(en.type)}">
      <span class="addr">${typeChip(en.type)}</span>
      <span class="name">${esc(en.name)}</span>
      <span class="meta">${fmtSize(en.size)}</span>
    </div>`).join("");
  $("#unpack-preview").textContent = t("unpack.pick");
  $$("#unpack-list .row").forEach((row) =>
    row.onclick = () => {
      const name = row.dataset.name;
      if (row.dataset.kind === "dex" && (m.dex_strings || {})[name]) {
        const strs = m.dex_strings[name] || [];
        const full = (unpackOutdir ? unpackOutdir.replace(/[\/]+$/, "") + "\\" : "") + name;
        const NL = String.fromCharCode(10);
        $("#unpack-preview").innerHTML =
          `<div class="dec-label">${esc(name)} — ${strs.length} strings <span class="spring"></span>
             <button class="btn btn-xs" id="apk-copy-strs">⧉ ${esc(t("apk.copy_all"))}</button>
             <button class="btn btn-ghost btn-xs" id="apk-to-lab">⚗ ${esc(t("dec.send_str"))}</button></div>
           <div class="prev-path"><code>${esc(full)}</code></div>
           <div class="apk-strings">${strs.map((x) => esc(x)).join(NL)}</div>`;
        $("#apk-copy-strs").onclick = () =>
          navigator.clipboard.writeText(strs.join(NL)).then(() => toast(t("toast.copied"), "ok", 1500));
        $("#apk-to-lab").onclick = () => sendToDecoder(strs.join(NL), "text");
      } else {
        previewUnpackedFile(name);
      }
    });
}

async function previewUnpackedFile(name) {
  unpackPreviewName = name;
  const prev = $("#unpack-preview");
  const ghidraBtn = $("#unpack-ghidra");
  prev.textContent = "…";
  ghidraBtn.classList.add("hidden");
  try {
    const res = await api(`unpack/file?job=${encodeURIComponent(unpackJob)}&name=${encodeURIComponent(name)}`);
    const bytes = b64ToBytes(res.data_b64);
    if (isExecImage(bytes)) {
      if (looksBinary(bytes, name)) prev.textContent = t("unpack.bin");
      else prev.textContent = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      ghidraBtn.classList.remove("hidden");
      return;
    }
    // not an executable image: preview text if readable, otherwise explain —
    // but never offer "send to Ghidra" for it
    if (looksBinary(bytes, name)) {
      // the natural next step for a .pyc/.data is grabbing the file on disk —
      // show where it landed + a one-click path copy
      const full = (unpackOutdir ? unpackOutdir.replace(/[\/]+$/, "") + "\\" : "") + name;
      prev.innerHTML = `<div class="prev-warn">${esc(t("unpack.bin.noexec"))}</div>
        <div class="prev-path"><code>${esc(full)}</code>
        <button class="btn btn-xs" id="unpack-copy-path">⧉ ${esc(t("unpack.copy_path"))}</button></div>`;
      const cp = document.getElementById("unpack-copy-path");
      if (cp) cp.onclick = () => { navigator.clipboard.writeText(full).then(() => toast(t("toast.copied"), "ok", 1500)); };
      return;
    }
    prev.textContent = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch (e) { prev.textContent = e.message; }
}

/* ═══════════════════════ F4: keyboard shortcuts ═══════════════════════ */

function switchLeft(tab) {
  $$("#left-tabs .tab").forEach((tb) => tb.classList.toggle("active", tb.dataset.tab === tab));
  $$("#left-body > .tabpane").forEach((p) => p.classList.toggle("active", p.dataset.pane === tab));
}

function handleShortcut(e) {
  // Esc closes the topmost surface, always
  if (e.key === "Escape") {
    const open = $$(".modal-backdrop:not(.hidden)");
    if (open.length) {
      open.forEach((m) => m.classList.add("hidden"));
      if (askResolve) { const r = askResolve; askResolve = null; r(null); }
    }
    document.body.classList.remove("insp-open");
    closeCtxMenu();
    $("#recent-menu").classList.add("hidden");
    return;
  }
  const tag = document.activeElement ? document.activeElement.tagName : "";
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "?") { openModal("#modal-keys"); return; }
  if (e.key === "g") { $("#goto-input").focus(); $("#goto-input").select(); return; }
  if (e.key === "/") { e.preventDefault(); switchLeft("functions"); $("#filter-functions").focus(); return; }
  if (e.key >= "1" && e.key <= "4") { switchLeft(["functions", "strings", "imports", "exports"][Number(e.key) - 1]); return; }
  if (e.key === "n") { renameCurrentFn(); return; }
  if (e.key === "m") { noteCurrentFn(); return; }
}

/* B7: lists are clickable divs — give keyboard users the same affordance */
function handleRowKeys(e) {
  if (e.key !== "Enter" && e.key !== " ") return;
  const row = e.target.closest(".row, .xref-row, .xor-row, .menu-item");
  if (!row || row.tagName === "BUTTON" || row.tagName === "A") return;
  e.preventDefault();
  row.click();
}
