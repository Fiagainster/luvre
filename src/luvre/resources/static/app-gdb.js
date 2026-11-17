/* luvre workstation UI — gdb bridge: sessions, breakpoints, patching */
"use strict";

/* ═══════════════════════ gdb bridge (dynamic debugging) ═══════════════════════ */

const GD = { poll: 0, memBytes: null, pc: null, pendingBps: [], staleHintFor: null };

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
  box.innerHTML = items.map((b) => {
    const a = b.addr ? String(b.addr).replace(/^0x/, "") : "";
    return `<div class="row" data-num="${esc(b.number)}" data-addr="${a}">
      <span class="addr">#${esc(b.number)}</span>
      <span class="name">${esc(b.func || b.orig_loc || b.addr || "")}${b.cond ? `<span class="bp-cond" title="${esc(b.cond)}">${esc(b.cond)}</span>` : ""}</span>
      <button class="op-rm" data-del="${esc(b.number)}" title="✕">✕</button>
    </div>`;
  }).join("");
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

/* memory patching: NOP fill (x86 0x90) or raw hex bytes.  After the write
   the patched region is re-read through the memory panel — the visual
   confirm doubles as a "did gdb actually take the write" check. */
async function gdbPatch(kind) {
  const addr = $("#gdb-patch-addr").value.trim();
  if (!addr) { toast(t("gdb.patch.need_addr"), "info"); return; }
  let body;
  if (kind === "nop") {
    const n = parseInt($("#gdb-patch-len").value, 10) || 1;
    body = { addr, nop_len: n };
  } else {
    const bytes = $("#gdb-patch-bytes").value.trim();
    if (!bytes) { toast(t("gdb.patch.need_bytes"), "info"); return; }
    body = { addr, bytes };
  }
  try {
    const res = await gdbApi("patch", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    logLine(`patch ${res.addr}: ${res.count} B [${res.bytes}]`, "hi");
    toast(t("gdb.toast.patched", { addr: res.addr, n: res.count }), "ok", 2400);
    const rd = await gdbApi(`memory?expr=${encodeURIComponent(res.addr)}&len=${Math.max(res.count, 16)}`);
    gdbRenderMem(b64ToBytes(rd.data_b64), gdbMemBase(res.addr));
  } catch (e) { toast("gdb: " + e.message, "error", 6000); }
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
  const [bps, stack, log] = await Promise.all([
    gdbApi("breaks").catch(() => null),
    gdbApi("stack").catch(() => null),
    gdbApi("log").catch(() => null),
  ]);
  if (bps) gdbRenderBreaks(bps.items);
  if (stack) gdbRenderStack(stack.items);
  if (log) gdbRenderConsole(log.items);
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
        await gdbApi("break", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ loc: bp.loc, cond: bp.cond || "" }) });
        logLine(`pending breakpoint planted: ${bp.loc}${bp.cond ? " if " + bp.cond : ""}`, "hi");
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
  $("#gdb-interrupt").classList.add("hidden");
  ["#gdb-breaks", "#gdb-regs", "#gdb-stack", "#gdb-mem", "#gdb-console"].forEach(
    (id) => { $(id).innerHTML = `<div class="insp-empty">—</div>`; });
  GD.memBytes = null;
  logLine("gdb session closed", "hi");
}

function wireGdb() {
  gdbAdaptTransports();
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
    if (!loc) return;
    $("#gdb-bp-input").value = "";
    $("#gdb-bp-cond").value = "";   // a leftover condition must not leak into the NEXT breakpoint
    if (!GD.poll) {
      // no live session yet — queue it; gdbStart replays pending breakpoints
      // (standard debugger behavior: place breakpoints before launching)
      GD.pendingBps.push({ loc, cond });
      gdbRenderBreaks([]);
      return;
    }
    try {
      await gdbApi("break", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ loc, cond }) });
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
}
