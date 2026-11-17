/* luvre workstation UI — gdb bridge: sessions, breakpoints, patching */
"use strict";

/* ═══════════════════════ gdb bridge (dynamic debugging) ═══════════════════════ */

const GD = { poll: 0, memBytes: null, pc: null, pendingBps: [], staleHintFor: null,
             patchHistory: [],   // [{addr, written, prev}] — undo + file export
             runtimeInfo: null };

function gdbBadge(mode, label) {
  const b = $("#gdb-badge");
  b.className = `engine-dot ${mode}`;
  b.querySelector(".dot-label").textContent = label;
}

const GDB_STOP_I18N = [
  [/^breakpoint-hit/, "gdb.stop.bp"],
  [/^end-stepping-range/, "gdb.stop.step"],
  [/^function-finished/, "gdb.stop.finish"],
  [/^exited-normally/, "gdb.stop.exit0"],
  [/^exited/, "gdb.stop.exit"],
  [/^signal/, "gdb.stop.signal"],
];

function gdbStopText(reason) {
  for (const [re, key] of GDB_STOP_I18N)
    if (re.test(reason || "")) return t(key);
  return reason || "";
}

async function gdbApi(path, opts) {
  return api("gdb/" + path, opts);
}

function gdbRenderStatus(st) {
  const empty = !st.loaded && !st.dead && !st.running && !st.stop;
  if (st.dead) gdbBadge("error", t("gdb.badge.dead"));
  else if (st.exited) gdbBadge("ready", t("gdb.badge.exited"));
  else if (st.running) gdbBadge("busy", t("gdb.badge.running"));
  else if (st.stop) gdbBadge("ready", t("gdb.badge.stopped"));
  else if (st.loaded) gdbBadge("ready", t("gdb.badge.loaded"));
  else gdbBadge("idle", t("gdb.badge.idle"));

  const si = $("#gdb-stopinfo");
  const stop = st.stop;
  if (stop && stop.reason && !st.exited) {
    const addrHex = stop.addr ? String(stop.addr).replace(/^0x/, "") : null;
    si.innerHTML = `<span class="gdb-stop-hit">${esc(gdbStopText(stop.reason))}</span>` +
      (stop.func ? ` @ <b>${esc(stop.func)}</b>` : "") +
      (addrHex ? ` · <span class="a" data-pc="${addrHex}">${hexpad(parseInt(addrHex, 16))}</span>` : "");
    const link = si.querySelector(".a");
    if (link) link.onclick = () => showDisasm(parseInt(link.dataset.pc, 16));
    $("#gdb-pc").textContent = "";
  } else if (st.exited) {
    si.innerHTML = `<span class="gdb-stop-hit">${esc(t("gdb.stop.exit0"))}</span>`;
    $("#gdb-pc").textContent = "";
  } else if (st.running) {
    si.textContent = t("gdb.stop.running");
    $("#gdb-pc").textContent = "";
  } else {
    si.textContent = "";
    $("#gdb-pc").textContent = "";
  }
  $("#gdb-target").textContent = st.program ? "⇲ " + st.program.split(/[\\/]/).pop() : "";
  $("#gdb-exit-btn").classList.remove("hidden");
  $("#gdb-start").classList.add("hidden");
  gdbHintIfStaleTarget(st.program);
}

function gdbHintIfStaleTarget(sessionProg) {
  /* A live session pointing at a DIFFERENT sample than the workspace must
     not hide the start button — the backend auto-restarts onto the current
     sample when clicked.  Runs from BOTH the poll render and openByPath:
     a page reload with a stale live session used to leave the start button
     hidden with zero explanation (real-sample catch). */
  const cur = S.program && S.program.source_path;
  if (!sessionProg || !cur) return;
  const norm = (p) => String(p).replace(/[\\/]+/g, "\\").toLowerCase();
  if (norm(sessionProg) === norm(cur)) { GD.staleHintFor = null; return; }
  $("#gdb-start").classList.remove("hidden");
  if (GD.staleHintFor === sessionProg) return;   // surface once per target
  GD.staleHintFor = sessionProg;
  const oldName = sessionProg.split(/[\\/]/).pop();
  logLine(t("gdb.stale_target", { old: oldName }), "hi");
  toast(t("gdb.stale_target", { old: oldName }), "info", 6000);
}

async function gdbStaleTargetCheck() {
  /* fetch-based variant for openByPath (no status payload in hand yet) */
  try {
    const res = await fetch("/api/gdb/state");
    const st = await res.json();
    if (st.active && st.status) gdbHintIfStaleTarget(st.status.program);
  } catch { /* gdb info unavailable — not fatal */ }
}

function gdbRenderBreaks(items) {
  const box = $("#gdb-breaks");
  if (!items.length && !GD.pendingBps.length) {
    box.innerHTML = `<div class="insp-empty">${esc(t("gdb.no_bp"))}</div>`;
    return;
  }
  if (GD.pendingBps.length && !items.length) {
    box.innerHTML = GD.pendingBps.map((bp, i) =>
      `<div class="row" data-pending="${i}"><span class="addr">⏳</span><span class="name">${esc(bp.loc)}${bp.cond ? `<span class="bp-cond">${esc(bp.cond)}</span>` : ""}</span><span class="meta">pending</span></div>`).join("");
    return;
  }
  box.innerHTML = items.filter((b) => b.func || b.orig_loc || b.addr).map((b) => {
    const a = b.addr ? String(b.addr).replace(/^0x/, "") : "";
    const meta = b.ignore ? `skip ${esc(b.ignore)}` : "";
    return `<div class="row" data-num="${esc(b.number)}" data-addr="${a}">
      <span class="addr">#${esc(b.number)}</span>
      <span class="name">${esc(b.func || b.orig_loc || b.addr || "")}${b.cond ? `<span class="bp-cond editable" data-num="${esc(b.number)}" title="${esc(t("gdb.cond.edit.title", { num: b.number }))}">${esc(b.cond)}</span>` : ""}</span>
      <span class="meta">${meta}</span>
      <button class="op-rm" data-del="${esc(b.number)}" title="✕">✕</button>
    </div>`;
  }).join("");
  // 条件 chip 可点击编辑（清空 = 清除条件）——比删了重加快
  box.querySelectorAll(".bp-cond.editable").forEach((el) =>
    el.onclick = async (e) => {
      e.stopPropagation();
      const num = el.dataset.num;
      const next = await askText(t("gdb.cond.edit.title", { num }), el.textContent);
      if (next == null) return;
      try {
        await gdbApi("break/cond", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ number: num, cond: next.trim() }) });
        toast(t("gdb.toast.cond_set", { num }), "ok", 1600);
        gdbRefreshLists();
      } catch (err) { toast("gdb: " + err.message, "error"); }
    });
  box.querySelectorAll("[data-del]").forEach((btn) =>
    btn.onclick = async (e) => {
      e.stopPropagation();
      await gdbApi("break/delete", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ number: btn.dataset.del }) });
      gdbRefreshLists();
    });
  box.querySelectorAll(".row").forEach((row) =>
    row.onclick = (e) => {
      if (e.target.closest("[data-del]")) return;
      const a = row.dataset.addr && parseInt(row.dataset.addr, 16);
      if (a) showDisasm(a);
    });
}

const GDB_GPR = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
                 "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"];

async function gdbSetExpr(expr) {
  if (!expr) return;
  try {
    await gdbApi("set", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expr }) });
    toast(t("gdb.toast.set", { expr }), "ok", 1600);
    await gdbPoll();
  } catch (e) { toast("gdb: " + e.message, "error"); }
}

/* memory patching: NOP fill (x86 0x90) or raw hex bytes.  The original
   bytes are captured BEFORE each write — that's the undo credential and,
   converted static, the payload for "write back to a file copy".  After
   the write the patched region is re-read through the memory panel. */
async function gdbPatch(kind) {
  const addr = $("#gdb-patch-addr").value.trim();
  if (!addr) { toast(t("gdb.patch.need_addr"), "info"); return; }
  let body, count;
  if (kind === "nop") {
    count = parseInt($("#gdb-patch-len").value, 10) || 1;
    body = { addr, nop_len: count };
  } else {
    const bytes = $("#gdb-patch-bytes").value.trim();
    if (!bytes) { toast(t("gdb.patch.need_bytes"), "info"); return; }
    count = bytes.replace(/0x|\s/gi, "").length / 2;
    body = { addr, bytes };
  }
  try {
    const pre = await gdbApi(`memory?expr=${encodeURIComponent(addr)}&len=${count}`);
    const prev = [...b64ToBytes(pre.data_b64)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const res = await gdbApi("patch", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    GD.patchHistory.push({ addr: res.addr, written: res.bytes, prev });
    logLine(`patch ${res.addr}: ${res.count} B [${res.bytes}]`, "hi");
    toast(t("gdb.toast.patched", { addr: res.addr, n: res.count }), "ok", 2400);
    const rd = await gdbApi(`memory?expr=${encodeURIComponent(res.addr)}&len=${Math.max(res.count, 16)}`);
    gdbRenderMem(b64ToBytes(rd.data_b64), gdbMemBase(res.addr));
  } catch (e) { toast("gdb: " + e.message, "error", 6000); }
}

async function gdbPatchUndo() {
  const last = GD.patchHistory.pop();
  if (!last) { toast(t("gdb.undo.none"), "info"); return; }
  try {
    const res = await gdbApi("patch", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ addr: last.addr, bytes: last.prev }),
    });
    logLine(`undo patch ${res.addr} ← ${res.bytes}`, "hi");
    toast(t("gdb.toast.undo", { addr: res.addr }), "ok", 2200);
    const rd = await gdbApi(`memory?expr=${encodeURIComponent(res.addr)}&len=${Math.max(res.count ?? 16, 16)}`);
    gdbRenderMem(b64ToBytes(rd.data_b64), gdbMemBase(res.addr));
  } catch (e) {
    GD.patchHistory.push(last);   // 还原失败塞回去，凭据不丢
    toast("gdb: " + e.message, "error", 6000);
  }
}

/* runtime → static conversion for the file patch export (ASLR targets) */
function gdbRuntimeDelta() {
  /* delta = runtime − static for the debugee module, from whichever source
     /api/gdb/base landed: "mappings" (Linux: base vs image base) or
     "sections" (mingw: a runtime section range vs the static section table) */
  if (!GD.runtimeInfo || !S.program || !S.program.image_base) return null;
  const img = parseInt(S.program.image_base, 16);
  if (GD.runtimeInfo.kind === "mappings") return GD.runtimeInfo.base - img;
  const secs = (S.triage && S.triage.sections) || [];
  for (const rsec of GD.runtimeInfo.sections) {
    const s = secs.find((x) => (x.name || "") === rsec.name);
    if (!s) continue;
    const staticStart = S.triage.format === "PE"
      ? img + Number(s.virtual_address || 0)
      : Number(s.addr || 0);
    if (staticStart) return rsec.start - staticStart;
  }
  return null;
}

async function gdbPatchExport() {
  if (!GD.patchHistory.length) { toast(t("gdb.patch.none_export"), "info"); return; }
  const patches = GD.patchHistory.map((p) => {
    const a = typeof p.addr === "string" ? (p.addr.startsWith("0x") ? parseInt(p.addr, 16) : Number(p.addr)) : Number(p.addr);
    const delta = gdbRuntimeDelta();
    const staticAddr = delta != null && a >= delta + parseInt(S.program.image_base, 16) ? a - delta : a;
    return { addr: staticAddr, bytes: p.written };
  });
  try {
    const res = await api("gdb/patch/export", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ patches }),
    });
    logLine(`patched copy: ${res.path} (${res.applied}/${res.total}${res.unmapped.length ? ", unmapped " + res.unmapped.join(",") : ""})`, "ok");
    toast(t("gdb.toast.exported", { path: res.path }), "ok", 9000);
  } catch (e) { toast(e.message, "error", 8000); }
}

/* ── ASLR static ↔ runtime address converter ──
   relocation info comes from /api/gdb/base (`info proc mappings` on Linux
   gdb, `info files` section ranges on mingw); the static side pairs the
   image base / section table from the loaded program.  Direction is
   auto-detected: subtracting the delta landing inside the image means the
   input was runtime, otherwise it was static. */
async function gdbLoadBase() {
  try {
    const res = await gdbApi("base");
    GD.runtimeInfo = res;
    logLine(`runtime ${res.kind}: ${res.kind === "mappings" ? "base " + hexpad(res.base) : res.sections.length + " sections"}`, "hi");
    gdbConvert();
  } catch (e) { toast("gdb: " + e.message, "error", 6000); }
}

function gdbConvert() {
  const out = $("#gdb-cvt-out");
  if (!out) return;
  if (!GD.runtimeInfo) { out.textContent = ""; return; }
  const img = S.program && S.program.image_base ? parseInt(S.program.image_base, 16) : null;
  const delta = gdbRuntimeDelta();
  const v = $("#gdb-cvt-addr").value.trim();
  if (delta == null || !img || !v) {
    out.textContent = delta == null
      ? `${t("gdb.cvt.base")}: ${GD.runtimeInfo.kind === "mappings" ? hexpad(GD.runtimeInfo.base) : GD.runtimeInfo.sections.map((s) => s.name).join(", ")}`
      : `${t("gdb.cvt.base")}: ${hexpad(img + delta)}`;
    return;
  }
  const a = v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10);
  if (!Number.isFinite(a)) { out.textContent = "?"; return; }
  const imgEnd = img + Number(S.program.size || 0x100000);
  let st, rt;
  if (a - delta >= img && a - delta < imgEnd) { rt = a; st = a - delta; }
  else { st = a; rt = a + delta; }
  out.innerHTML = `<span class="cvt-res" title="${esc(t("gdb.cvt.fill.title"))}">${esc(t("gdb.cvt.rt"))} ${hexpad(rt)} · ${esc(t("gdb.cvt.st"))} ${hexpad(st)}</span>`;
  out.querySelector(".cvt-res").onclick = () => {
    $("#gdb-patch-addr").value = hexpad(rt);
    toast(t("gdb.toast.filled"), "ok", 1500);
  };
}

/* ── threads (multi-threaded targets) ── */
function gdbRenderThreads(data) {
  const box = $("#gdb-threads");
  if (!data || !data.threads || !data.threads.length) {
    box.innerHTML = `<div class="insp-empty">${esc(t("gdb.threads.none"))}</div>`;
    return;
  }
  box.innerHTML = data.threads.map((th) => {
    const fn = th.frame && th.frame.func ? " · " + th.frame.func : "";
    return `<span class="gdb-thread${String(th.id) === data.current ? " cur" : ""}" data-id="${esc(th.id)}" title="${esc(th.details || th.name || "")}">T${esc(th.id)}${fn}</span>`;
  }).join("");
  box.querySelectorAll(".gdb-thread").forEach((el) =>
    el.onclick = async () => {
      try {
        await gdbApi("thread/select", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: el.dataset.id }) });
        toast(t("gdb.toast.thread", { id: el.dataset.id }), "ok", 1500);
        await gdbPoll();
      } catch (e) { toast("gdb: " + e.message, "error"); }
    });
}

function gdbRenderRegs(regs) {
  const box = $("#gdb-regs");
  const keys = Object.keys(regs);
  if (!keys.length) { box.innerHTML = `<div class="insp-empty">${esc(t("gdb.stopped_only"))}</div>`; return; }
  const ordered = [...GDB_GPR.filter((k) => keys.includes(k)), ...keys.filter((k) => !GDB_GPR.includes(k))];
  const pcName = keys.includes("rip") ? "rip" : (keys.includes("eip") ? "eip" : null);
  box.innerHTML = ordered.map((k) =>
    `<span class="gdb-reg${k === pcName ? " pc" : ""}" title="${esc(t("toast.copied"))}"><b>${esc(k)}</b> ${esc(regs[k])}</span>`).join("");
  box.querySelectorAll(".gdb-reg").forEach((el) =>
    el.onclick = () => {
      navigator.clipboard.writeText(el.textContent.replace(/^\S+\s+/, "")).then(() => toast(t("toast.copied"), "ok", 1200));
    });
  if (pcName) {
    const pcv = parseInt(regs[pcName], 16);
    if (pcv) { GD.pc = pcv; $("#gdb-pc").textContent = "PC " + hexpad(pcv); }
  }
}

function gdbRenderStack(items) {
  const box = $("#gdb-stack");
  if (!items.length) { box.innerHTML = `<div class="insp-empty">${esc(t("gdb.stopped_only"))}</div>`; return; }
  box.innerHTML = items.map((f) =>
    `<div class="row" data-addr="${String(f.addr || "").replace(/^0x/, "")}">
      <span class="addr">#${esc(f.level ?? "?")}</span>
      <span class="name">${esc(f.func || "?")}</span>
      <span class="meta">${esc(String(f.addr || ""))}</span>
    </div>`).join("");
  box.querySelectorAll(".row").forEach((row) =>
    row.onclick = () => {
      const a = row.dataset.addr && parseInt(row.dataset.addr, 16);
      if (a) showDisasm(a);
    });
}

/* display base for the gdb memory panel: a plain hex expr shows REAL
   addresses (the patch readback used to start at 0x00000000, which reads
   as "wrote to address 0"); symbolic exprs ($rsp) keep relative numbering */
function gdbMemBase(expr) {
  const m = /^0x([0-9a-f]{4,16})$/i.exec(String(expr || "").trim());
  return m ? parseInt(m[1], 16) : 0;
}

function gdbRenderMem(data, baseAddr = 0) {
  GD.memBytes = data;
  const box = $("#gdb-mem");
  let html = "";
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.slice(i, i + 16);
    const hx = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = [...chunk].map((b) => (b >= 0x20 && b < 0x7f) ? esc(String.fromCharCode(b)) : "·").join("");
    html += `<div class="hexgrid"><span class="hexaddr">${hexpad(baseAddr + i)}</span>  ${hx}  <span class="hexaddr">|</span><span class="hexascii">${asc}</span><span class="hexaddr">|</span></div>`;
  }
  box.innerHTML = html || `<div class="insp-empty">—</div>`;
  const send = $("#gdb-mem-send");
  send.classList.remove("hidden");
  send.onclick = () => {
    const hexText = [...data].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    sendToDecoder(hexText, "hex");
  };
}

function gdbRenderConsole(items) {
  const box = $("#gdb-console");
  box.textContent = items.join("\n");
  box.scrollTop = box.scrollHeight;
}

async function gdbRefreshLists() {
  if (!GD.poll) return;
  const [bps, stack, log, threads] = await Promise.all([
    gdbApi("breaks").catch(() => null),
    gdbApi("stack").catch(() => null),
    gdbApi("log").catch(() => null),
    gdbApi("threads").catch(() => null),
  ]);
  if (bps) gdbRenderBreaks(bps.items);
  if (stack) gdbRenderStack(stack.items);
  if (log) gdbRenderConsole(log.items);
  gdbRenderThreads(threads);
}

async function gdbPoll() {
  let data;
  try {
    data = await gdbApi("state");
  } catch { return; }
  if (!data.active) {
    if (GD.poll) { clearInterval(GD.poll); GD.poll = 0; }
    gdbBadge("idle", t("gdb.badge.idle"));
    $("#gdb-exit-btn").classList.add("hidden");
    $("#gdb-start").classList.remove("hidden");
    return;
  }
  const st = data.status;
  gdbRenderStatus(st);
  if (st.stop && !st.running && !st.exited) {
    try {
      const regs = (await gdbApi("registers")).registers;
      gdbRenderRegs(regs);
    } catch { /* target running again */ }
    await gdbRefreshLists();
  } else if (st.running) {
    $("#gdb-regs").innerHTML = `<div class="insp-empty">${esc(t("gdb.running_hint"))}</div>`;
    $("#gdb-stack").innerHTML = "";
  } else if (st.exited) {
    // the console keeps streaming after exit (program stdout flushes at exit) —
    // without this the UI shows the stale pre-run view forever
    await gdbRefreshLists();
  }
}

async function gdbEnsurePolling() {
  if (GD.poll) return;
  GD.poll = setInterval(gdbPoll, 1200);
  await gdbPoll();
}


let GDB_ENV_DONE = false;

async function gdbAdaptTransports() {
  /* Host-adaptive transport menu.  /api/gdb/env reports the host platform
     and whether WSL / a native gdb actually exists.  On a POSIX host the
     WSL option is dead weight (the backend refuses it, and the distro box
     is meaningless), and "Windows 本机 gdb" is just plain gdb on PATH —
     so drop the WSL option, hide the distro input, relabel the local one
     and default to it.  Also covers Windows machines without WSL.  Runs
     once per page load; while the backend probe is in flight, poll. */
  if (GDB_ENV_DONE) return;
  let env = null;
  try {
    for (let i = 0; i < 8; i++) {
      env = await (await fetch("/api/gdb/env")).json();
      if (!env.probing) break;
      await new Promise((r) => setTimeout(r, 4000));
    }
  } catch { return; }  // env unavailable — leave the default menu untouched
  if (!env || env.probing) return;
  GDB_ENV_DONE = true;
  const posix = env.platform && env.platform !== "nt";
  const wslOpt = document.querySelector('#gdb-transport option[value="wsl"]');
  const localOpt = document.querySelector('#gdb-transport option[value="local"]');
  if (posix || env.wsl_ok === false) {
    wslOpt.remove();
    $("#gdb-distro").classList.add("hidden");
    if ($("#gdb-transport").value === "wsl") $("#gdb-transport").value = "local";
    if (posix) {
      localOpt.removeAttribute("data-i18n");   // not "Windows 本机 gdb" here
      localOpt.textContent = t("gdb.transport.local.posix");
    }
  }
}

async function gdbStart() {
  const transport = $("#gdb-transport").value;
  const distro = $("#gdb-distro").value.trim() || "Ubuntu-22.04";
  const args = $("#gdb-args").value.trim();
  const stdinText = $("#gdb-stdin").value;
  const envText = $("#gdb-env").value.trim();
  setBusy(true, "gdb");
  logLine(`gdb session starting (${transport})`, "hi");
  try {
    const res = await gdbApi("start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transport, distro, args, stdin: stdinText, env: envText }),
    });
    gdbRenderStatus(res.status);
    await gdbEnsurePolling();
    // replay breakpoints placed before the session existed
    for (const bp of GD.pendingBps.splice(0)) {
      try {
        const r = await gdbApi("break", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ loc: bp.loc, cond: bp.cond || "" }) });
        if (bp.skip > 0 && r.bkpt && r.bkpt.number) {
          await gdbApi("break/after", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ number: r.bkpt.number, count: bp.skip }) });
        }
        logLine(`pending breakpoint planted: ${bp.loc}${bp.cond ? " if " + bp.cond : ""}${bp.skip ? ` (skip ${bp.skip})` : ""}`, "hi");
      } catch (e) { toast(`gdb: ${e.message}`, "error"); }
    }
    gdbRefreshLists();
    toast(t("gdb.toast.started"), "ok", 2000);
    logLine(`gdb session active (${transport}, ${res.info.program})`, "ok");
  } catch (e) {
    toast("gdb: " + e.message, "error", 6000);
    logLine("gdb start failed: " + e.message, "err");
  } finally { setBusy(false); }
}

async function gdbExec(action) {
  try {
    await gdbApi("exec", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    await gdbPoll();
  } catch (e) { toast("gdb: " + e.message, "error"); }
}

function gdbExit() {
  gdbApi("exit", { method: "POST" }).catch(() => {});
  clearInterval(GD.poll); GD.poll = 0;
  gdbBadge("idle", t("gdb.badge.idle"));
  $("#gdb-stopinfo").textContent = "";
  $("#gdb-pc").textContent = "";
  $("#gdb-target").textContent = "";
  $("#gdb-start").classList.remove("hidden");
  $("#gdb-exit-btn").classList.add("hidden");
  $("#gdb-args").disabled = false;
  $("#gdb-stdin").disabled = false;
  $("#gdb-env").disabled = false;
  GD.pendingBps = [];
  GD.patchHistory = [];   // 会话死了，补丁凭据也失效（内存随进程消失）
  GD.runtimeInfo = null;  // 新会话重新读基址
  const cvt = $("#gdb-cvt-out");
  if (cvt) cvt.textContent = "";
  $("#gdb-interrupt").classList.add("hidden");
  ["#gdb-breaks", "#gdb-regs", "#gdb-stack", "#gdb-mem", "#gdb-console", "#gdb-threads"].forEach(
    (id) => { const el = $(id); if (el) el.innerHTML = `<div class="insp-empty">—</div>`; });
  GD.memBytes = null;
  logLine("gdb session closed", "hi");
}

function wireGdb() {
  gdbAdaptTransports();
  // remember the transport across reloads — silently falling back to the
  // first option made a reload start a WSL session on a local-gdb workflow
  const tSel = $("#gdb-transport");
  try {
    const saved = localStorage.getItem("lv.gdb.transport");
    if (saved && tSel.querySelector(`option[value="${saved}"]`)) tSel.value = saved;
  } catch { /* private mode */ }
  tSel.addEventListener("change", () => {
    try { localStorage.setItem("lv.gdb.transport", tSel.value); } catch { /* ignore */ }
  });
  $("#gdb-start").onclick = gdbStart;
  $("#gdb-exit-btn").onclick = gdbExit;
  $("#gdb-run").onclick = () => gdbExec("run");
  $("#gdb-continue").onclick = () => gdbExec("continue");
  $("#gdb-next").onclick = () => gdbExec("next");
  $("#gdb-step").onclick = () => gdbExec("step");
  $("#gdb-nexti").onclick = () => gdbExec("nexti");
  $("#gdb-stepi").onclick = () => gdbExec("stepi");
  $("#gdb-finish").onclick = () => gdbExec("finish");
  $("#gdb-interrupt").onclick = () => gdbExec("interrupt");
  $("#gdb-cmd-send").onclick = async () => {
    const cmd = $("#gdb-cmd").value.trim();
    if (!cmd) return;
    try {
      await gdbApi("exec", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "console", cmd }) });
      $("#gdb-cmd").value = "";
      await gdbPoll();
    } catch (e) { toast("gdb: " + e.message, "error"); }
  };
  $("#gdb-cmd").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#gdb-cmd-send").click(); }
  });
  $("#gdb-bp-add").onclick = async () => {
    const loc = $("#gdb-bp-input").value.trim();
    const cond = $("#gdb-bp-cond").value.trim();
    const skip = parseInt($("#gdb-bp-skip").value, 10) || 0;
    if (!loc) return;
    $("#gdb-bp-input").value = "";
    $("#gdb-bp-cond").value = "";   // a leftover condition must not leak into the NEXT breakpoint
    $("#gdb-bp-skip").value = "";
    if (!GD.poll) {
      // no live session yet — queue it; gdbStart replays pending breakpoints
      // (standard debugger behavior: place breakpoints before launching)
      GD.pendingBps.push({ loc, cond, skip });
      gdbRenderBreaks([]);
      return;
    }
    try {
      const res = await gdbApi("break", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ loc, cond }) });
      if (skip > 0 && res.bkpt && res.bkpt.number) {
        await gdbApi("break/after", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ number: res.bkpt.number, count: skip }) });
      }
      gdbRefreshLists();
    } catch (e) { toast("gdb: " + e.message, "error"); }
  };
  $("#gdb-bp-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#gdb-bp-add").click(); }
  });
  $("#gdb-set-btn").onclick = () => gdbSetExpr($("#gdb-set-input").value.trim());
  $("#gdb-set-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#gdb-set-btn").click(); }
  });
  $("#gdb-mem-read").onclick = async () => {
    const expr = $("#gdb-mem-expr").value.trim();
    const len = parseInt($("#gdb-mem-len").value, 10) || 128;
    if (!expr) return;
    try {
      const res = await gdbApi(`memory?expr=${encodeURIComponent(expr)}&len=${len}`);
      gdbRenderMem(b64ToBytes(res.data_b64), gdbMemBase(expr));
    } catch (e) { toast("gdb: " + e.message, "error"); }
  };
  $("#gdb-mem-expr").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#gdb-mem-read").click(); }
  });
  $("#gdb-patch-nop").onclick = () => gdbPatch("nop");
  $("#gdb-patch-write").onclick = () => gdbPatch("write");
  $("#gdb-patch-bytes").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); $("#gdb-patch-write").click(); }
  });
  $("#gdb-patch-undo").onclick = gdbPatchUndo;
  $("#gdb-patch-export").onclick = gdbPatchExport;
  $("#gdb-cvt-load").onclick = gdbLoadBase;
  $("#gdb-cvt-addr").addEventListener("input", () => { if (GD.runtimeInfo) gdbConvert(); });
  $("#gdb-cvt-addr").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); if (!GD.runtimeInfo) gdbLoadBase(); else gdbConvert(); }
  });
}
