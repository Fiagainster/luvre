/* luvre workstation UI — boot: element wiring + startup status */
"use strict";

/* ═══════════════════════ boot ═══════════════════════ */

window.addEventListener("DOMContentLoaded", async () => {
  applyI18n();
  renderOpSelect();
  wireTabs("#left-tabs", "#left-body");
  wireTabs("#center-tabs", "#center-body", (tab) => {
    if (tab === "hex" && S.hexBlock && !$("#code-hex .hexgrid")) readHex();
    if (tab === "disasm" && S.currentFunc) showDisasm(S.currentFunc.addr);
    if (tab === "graph" && S.currentFunc && G.center !== S.currentFunc.addr) {
      showGraph(S.currentFunc.addr);
    } else if (tab === "graph") {
      fitGraph();
      pokeGraph();
    }
    if (tab === "gdb") gdbEnsurePolling();
  });
  wireTabs("#drawer-tabs", "#drawer-body");
  wireResizer('[data-resize="left"]', "--left-w", 180, 520);
  wireResizer('[data-resize="right"]', "--right-w", 200, 560);
  wireGraph();
  wireGdb();
  $("#btn-show-graph").onclick = () => {
    if (S.currentFunc) {
      switchCenter("graph");
      showGraph(S.currentFunc.addr);
    } else toast(t("toast.select_fn"), "info");
  };

  // ── modals (settings / ask / keys / unpack) ──
  document.querySelectorAll(".modal-backdrop").forEach((m) => {
    m.addEventListener("mousedown", (e) => {
      if (e.target === m || e.target.closest("[data-close]")) {
        m.classList.add("hidden");
        if (m.id === "modal-ask" && askResolve) { const r = askResolve; askResolve = null; r(null); }
      }
    });
  });
  $("#btn-settings").onclick = () => {
    $("#set-lang").value = LV_LANG;
    $("#set-theme").value = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
    openModal("#modal-settings");
  };
  $("#set-lang").onchange = (e) => setLang(e.target.value);
  $("#set-theme").onchange = (e) => {
    const th = e.target.value === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", th);
    try { localStorage.setItem("lv.theme", th); } catch { /* private mode */ }
    pokeGraph();
  };
  $("#btn-keys").onclick = () => { closeModal("#modal-settings"); openModal("#modal-keys"); };
  $("#ask-ok").onclick = () => closeAsk($("#ask-input").value);
  $("#ask-clear").onclick = () => { $("#ask-input").value = ""; $("#ask-input").focus(); };
  $("#ask-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") closeAsk($("#ask-input").value);
  });

  // F1: rename / note
  $("#btn-rename-fn").onclick = renameCurrentFn;
  $("#btn-note-fn").onclick = noteCurrentFn;

  // F2: recent
  $("#btn-recent").onclick = toggleRecentMenu;
  document.addEventListener("mousedown", (e) => {
    if (!e.target.closest(".recent-wrap")) $("#recent-menu").classList.add("hidden");
    if (!e.target.closest("#ctx-menu")) closeCtxMenu();
  });

  // F5: unpack
  $("#btn-unpack").onclick = openUnpackModal;
  $("#unpack-ghidra").onclick = () => {
    if (unpackOutdir && unpackPreviewName) {
      closeModal("#modal-unpack");
      openByPath(unpackOutdir + "/" + unpackPreviewName);
    }
  };

  // F6: narrow-screen inspector drawer
  $("#btn-inspector").onclick = () => document.body.classList.toggle("insp-open");

  // F4: shortcuts + B7 row keys
  document.addEventListener("keydown", handleShortcut);
  document.addEventListener("keydown", handleRowKeys);

  // re-render translated dynamic text when the language flips
  document.addEventListener("lv:langchange", () => {
    renderOpSelect();   // op names follow the UI language
    renderOps();
    if (S.program) {
      renderProgramInfo();
      renderVerdict();
      renderSections();
      renderOverlay();
      loadConstants();
    }
    updateGraphStats();
  });

  // boot status (B2: show progress while auto-analysis is still running)
  try {
    const st = await api("status");
    $("#st-version").textContent = "luvre v" + st.version;
    if (st.analyzing) {
      engineState("busy");
      $("#st-job").textContent = st.progress || t("engine.analyzing");
      const timer = setInterval(async () => {
        try {
          const s2 = await api("status");
          $("#st-job").textContent = s2.progress || t("engine.analyzing");
          if (!s2.analyzing) {
            clearInterval(timer);
            $("#st-job").textContent = "";
            await loadProgram();
          }
        } catch { clearInterval(timer); engineState("error"); }
      }, 900);
    } else {
      engineState("idle");
      if (st.program_loaded) await loadProgram();  // server still holds a program (e.g. page refresh)
    }
  } catch (e) {
    engineState("error");
  }

  // open binary — three ways
  $("#btn-open").onclick = () => $("#file-input").click();
  $("#hero-open").onclick = () => $("#file-input").click();
  $("#file-input").onchange = (e) => { if (e.target.files[0]) uploadAndOpen(e.target.files[0]); };
  $("#path-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") openByPath(e.target.value.trim());
  });
  window.addEventListener("dragover", (e) => { e.preventDefault(); document.body.classList.add("dragging"); });
  window.addEventListener("dragleave", (e) => { if (!e.relatedTarget) document.body.classList.remove("dragging"); });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    document.body.classList.remove("dragging");
    if (e.dataTransfer.files[0]) uploadAndOpen(e.dataTransfer.files[0]);
  });

  // goto
  $("#goto-input").addEventListener("keydown", (e) => { if (e.key === "Enter") gotoInput(); });

  // filters (debounced)
  let ftimer;
  $("#filter-functions").addEventListener("input", (e) => {
    clearTimeout(ftimer);
    ftimer = setTimeout(() => { S.functionsQuery = e.target.value; loadFunctions(false); }, 250);
  });
  let stimer;
  $("#filter-strings").addEventListener("input", (e) => {
    clearTimeout(stimer);
    stimer = setTimeout(() => { S.stringsQuery = e.target.value; loadStrings(false); }, 250);
  });

  // infinite scroll on function list
  $("#list-functions").addEventListener("scroll", (e) => {
    const el = e.target;
    if (el.scrollTop + el.clientHeight > el.scrollHeight - 80 && S.functionsLoaded < S.functionsTotal) {
      loadFunctions(true);
    }
  });

  // center actions
  $("#btn-copy-code").onclick = () => {
    navigator.clipboard.writeText($("#code-decompile").innerText).then(() => toast(t("toast.copied"), "ok", 1800));
  };
  $("#btn-download-code").onclick = () => {
    if (S.currentFunc) window.location = `/api/download/decompile/${S.currentFunc.addr}.c`;
  };
  $("#btn-decompile-all").onclick = decompileAll;

  // hex controls
  $("#hex-block").onchange = (e) => { S.hexBlock = e.target.value; S.hexOffset = 0; readHex(); };
  $("#hex-prev").onclick = () => { S.hexOffset = Math.max(0, S.hexOffset - S.hexChunk); readHex(); };
  $("#hex-next").onclick = () => { S.hexOffset += S.hexChunk; readHex(); };
  $("#hex-go").onclick = () => {
    const v = $("#hex-offset").value.trim();
    if (!v) return;
    let off = v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10) || 0;
    if (!Number.isFinite(off)) return;
    // accept a full virtual address too — locate the containing block and
    // switch to it (typing 0x8048e90 while on the ELF-header block used to
    // read past the block and fail)
    const hit = S.blocks.find(
      (b) => Number(b.start) !== 0 && off >= Number(b.start) && off < Number(b.start) + Number(b.size),
    );
    if (hit) {
      if (S.hexBlock !== hit.name) {
        S.hexBlock = hit.name;
        $("#hex-block").value = hit.name;
      }
      off -= Number(hit.start);
    } else {
      // address inside no block: small numbers are block-relative offsets
      // (keep that), but address-sized values used to be sent raw and got
      // added to the current block's base — a doubled address and a baffling
      // "Unable to read bytes" error.  Show the mapped ranges instead.
      const starts = S.blocks.map((b) => Number(b.start)).filter((x) => x > 0);
      const minStart = starts.length ? Math.min(...starts) : 0;
      if (off >= minStart) {
        const ranges = S.blocks.map((b) => `${b.name} 0x${Number(b.start).toString(16)}–0x${(Number(b.start) + Number(b.size)).toString(16)}`).join(", ");
        toast(t("hex.unmapped", { addr: off.toString(16), ranges }), "error", 6000);
        return;
      }
    }
    S.hexOffset = Math.max(0, off);
    readHex();
  };
  $("#hex-copy").onclick = () => {
    if (!S.hexBytes || !S.hexBytes.length) { toast(t("hex.empty"), "info"); return; }
    const blk = S.blocks.find((b) => b.name === S.hexBlock);
    const base = (blk ? Number(blk.start) : 0) + S.hexOffset;
    let s = "";
    for (let i = 0; i < S.hexBytes.length; i += 16) {
      const chunk = S.hexBytes.slice(i, i + 16);
      const hx = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const asc = [...chunk].map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
      s += "0x" + (base + i).toString(16).padStart(8, "0") + "  " + hx.padEnd(48) + " |" + asc + "|\n";
    }
    navigator.clipboard.writeText(s).then(() => toast(t("toast.copied"), "ok", 1800))
      .catch((err) => toast("clipboard: " + err.message, "error", 3000));
  };
  $("#hex-offset").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#hex-go").onclick(); });
  $("#hex-send").onclick = async (e) => {
    if (!S.hexBytes || !S.hexBytes.length) { toast(t("hex.empty"), "info"); return; }
    if (!e.shiftKey) {
      const hexText = [...S.hexBytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      sendToDecoder(hexText, "hex");
      return;
    }
    // Shift-click: the lab used to receive only the current 4096B page —
    // big regions (VM memories, string tables) needed manual page-flipping.
    // Pull up to 8 pages (32 KB) from the current offset and send them all.
    try {
      setBusy(true, "hex");
      let all = [...S.hexBytes];
      let off = S.hexOffset + S.hexBytes.length;
      for (let k = 0; k < 7 && S.hexBytes.length === S.hexChunk; k++) {
        const res = await api(`memory/read?block=${encodeURIComponent(S.hexBlock)}&offset=${off}&len=${S.hexChunk}`);
        const more = b64ToBytes(res.data_b64);
        if (!more.length) break;
        all.push(...more);
        off += more.length;
        if (more.length < S.hexChunk) break;
      }
      const hexText = all.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      sendToDecoder(hexText, "hex");
      toast(t("hex.sent.pages", { n: all.length }), "ok", 2500);
    } catch (err) { toast(err.message, "error"); }
    finally { setBusy(false); }
  };
  $("#hex-disasm").onclick = () => {
    if (!S.hexBlock) return;
    const blk = S.blocks.find((b) => b.name === S.hexBlock);
    if (!blk) return;
    showRawDisasm(Number(blk.start) + S.hexOffset);
  };

  // raw disasm
  $("#raw-go").onclick = () => {
    const v = $("#raw-addr").value.trim();
    if (!v) return;
    showRawDisasm(v.startsWith("0x") ? parseInt(v, 16) : parseInt(v, 10));
  };
  $("#raw-addr").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#raw-go").onclick(); });
  $("#code-raw").addEventListener("click", (e) => {
    const a = e.target.closest(".raw-target[data-addr]");
    if (a) showRawDisasm(parseInt(a.dataset.addr, 16));
  });

  // decoder lab
  $("#btn-op-add").onclick = () => {
    const spec = OPS[Number($("#op-select").value)];
    const args = {};
    for (const [name, type, def] of spec.args) if (type !== "bool") args[name] = def ?? "";
    S.ops.push({ op: spec.op, args });
    renderOps();
  };
  $("#btn-decode").onclick = runChain;
  $("#dec-show-hex").onchange = () => {
    const out = $("#dec-output").value;
    if (out) runChain();
  };
  $("#dec-enc").onchange = () => {
    if (S.decOutBytes && S.decOutBytes.length) renderDecOutput(S.decOutBytes);
  };
  $("#btn-dec-copy").onclick = () => {
    navigator.clipboard.writeText($("#dec-output").value).then(() => toast(t("toast.copied"), "ok", 1500));
  };
  $("#btn-dec-paste-string").onclick = () => {
    if (S.selectedString == null) { toast(t("toast.no_string"), "info"); return; }
    sendToDecoder(S.selectedString, "text");
  };
  $("#btn-xor-brute").onclick = xorBrute;
  // ✕ 关闭：清空结果并收起结果区（之前没有任何关闭手段）
  $("#xor-close").onclick = () => {
    $("#xor-results").classList.remove("show");
    const rows = $("#xor-rows");
    if (rows) rows.innerHTML = "";
    const count = $("#xor-count");
    if (count) count.textContent = "";
  };
  $("#btn-xor-derive").onclick = xorDerive;
  $("#dec-presets").addEventListener("click", (e) => {
    const b = e.target.closest("[data-preset]");
    if (!b) return;
    // xorbrute is a brute-force action, not a chain recipe — route it to xorBrute()
    if (b.dataset.preset === "xorbrute") { xorBrute(); return; }
    applyPreset(b.dataset.preset);
  });

  // search
  $("#btn-search").onclick = runSearch;
  $("#search-q").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });

  // drawer toggle — `open`/`closed` are mutually exclusive (the hero's
  // body:has(#drawer.open) rule relies on it; stale `.open` used to keep the
  // empty-state hero hidden forever after collapsing)
  $("#drawer-toggle").onclick = () => {
    const d = $("#drawer");
    const closed = d.classList.toggle("closed");
    d.classList.toggle("open", !closed);
    $("#drawer-toggle").textContent = closed ? t("drawer.show") : t("drawer.hide");
  };

  logLine(t("log.welcome"), "ok");
});

// boot 自检：boot 是一条长异步流，中途抛异常时后续接线全部静默跳过，
// 表现为"按钮点了没反应"。这个检查独立于 boot 存活（顶层 setTimeout），
// 接线死了也能弹出来。
setTimeout(() => {
  const must = ["#btn-show-graph", "#hex-send", "#raw-go", "#btn-xor-brute", "#btn-search", "#drawer-toggle"];
  const dead = must.filter((sel) => {
    const el = $(sel);
    return el && typeof el.onclick !== "function";
  });
  if (dead.length) {
    console.error("boot wiring incomplete:", dead);
    toast(t("boot.incomplete", { items: dead.join(" ") }), "error", 12000);
  }
}, 2500);
