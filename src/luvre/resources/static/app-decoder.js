/* luvre workstation UI — decoder lab: chained ops, XOR toolbox */
"use strict";

/* ═══════════════════════ decoder lab ═══════════════════════ */

const OPS = [
  { op: "to_hex", label: "Hex → encode", zh: "Hex 编码", args: [["sep", "str", "e.g. ' '"], ["upper", "bool"]] },
  { op: "from_hex", label: "Hex → decode", zh: "Hex 解码", args: [] },
  { op: "to_base64", label: "Base64 → encode", zh: "Base64 编码", args: [["urlsafe", "bool"]] },
  { op: "from_base64", label: "Base64 → decode", zh: "Base64 解码", args: [] },
  { op: "to_base32", label: "Base32 → encode", zh: "Base32 编码", args: [] },
  { op: "from_base32", label: "Base32 → decode", zh: "Base32 解码", args: [] },
  { op: "to_ascii85", label: "Ascii85 → encode", zh: "Ascii85 编码", args: [] },
  { op: "from_ascii85", label: "Ascii85 → decode", zh: "Ascii85 解码", args: [] },
  { op: "url_encode", label: "URL → encode", zh: "URL 编码", args: [] },
  { op: "url_decode", label: "URL → decode", zh: "URL 解码", args: [] },
  { op: "rot", label: "ROT-n", zh: "ROT-n 移位", args: [["n", "int", 13]] },
  { op: "rot47", label: "ROT47", zh: "ROT47 移位", args: [["n", "int", 47]] },
  { op: "xor", label: "XOR repeating key", zh: "XOR 重复密钥", args: [["key", "str", "ATRI"], ["hex", "bool"]] },
  { op: "xor_pos", label: "XOR with offset", zh: "XOR 位置偏移", args: [["key", "str", "00"], ["offset", "int", 0], ["hex", "bool"]] },
  { op: "rc4", label: "RC4", zh: "RC4", args: [["key", "str", "secret"]] },
  { op: "reverse", label: "Reverse bytes", zh: "字节反转", args: [] },
  { op: "bit_not", label: "NOT bits", zh: "按位取反", args: [] },
  { op: "c_escape", label: "C escape", zh: "C 转义", args: [] },
  { op: "c_unescape", label: "C unescape", zh: "C 反转义", args: [] },
  { op: "hexdump", label: "Hexdump", zh: "Hexdump 视图", args: [] },
  { op: "gzip_decompress", label: "GZip decompress", zh: "GZip 解压", args: [] },
  { op: "gzip_compress", label: "GZip compress", zh: "GZip 压缩", args: [] },
  { op: "zlib_decompress", label: "Zlib decompress", zh: "Zlib 解压", args: [] },
  { op: "zlib_compress", label: "Zlib compress", zh: "Zlib 压缩", args: [] },
  { op: "raw_inflate", label: "Raw inflate", zh: "Raw inflate 解压", args: [] },
  { op: "md5", label: "MD5", zh: "MD5", args: [] },
  { op: "sha1", label: "SHA-1", zh: "SHA-1", args: [] },
  { op: "sha256", label: "SHA-256", zh: "SHA-256", args: [] },
];

/* op names follow the UI language (zh labels added 2026-11: "decoding lab confusing" feedback) */
function opLabel(spec) {
  return (LV_LANG === "zh" && spec.zh) ? spec.zh : spec.label;
}

/* one-click recipes — the "how do I even use this" answer.
   b64 keeps mode text (the base64 characters ARE the input), hex preset only
   flips the input mode — from_hex on top of hex-mode input would decode twice. */
const DEC_PRESETS = {
  b64:     { ops: [{ op: "from_base64", args: {} }], mode: "text" },
  hex:     { ops: [], mode: "hex" },
  rot13:   { ops: [{ op: "rot", args: { n: "13" } }], mode: "text" },
  reverse: { ops: [{ op: "reverse", args: {} }], mode: "text" },
};

function applyPreset(key) {
  const p = DEC_PRESETS[key];
  if (!p) return;
  S.ops = p.ops.map((o) => ({ op: o.op, args: { ...o.args } }));
  renderOps();
  const radio = document.querySelector(`input[name="dec-mode"][value="${p.mode}"]`);
  if (radio) radio.checked = true;
  runChain();
}

function renderOpSelect() {
  $("#op-select").innerHTML = OPS.map((o, i) =>
    `<option value="${i}">${esc(opLabel(o))}</option>`).join("");
}

function renderOps() {
  const list = $("#op-list");
  if (!S.ops.length) { list.innerHTML = `<div class="insp-empty">${esc(t("dec.noops"))}</div>`; return; }
  list.innerHTML = S.ops.map((o, i) => {
    const spec = OPS.find((s) => s.op === o.op);
    const args = spec.args.map(([name, type, def]) => {
      const v = o.args[name] ?? def ?? "";
      if (type === "bool") return `<label class="chk"><input type="checkbox" data-i="${i}" data-arg="${name}" ${v ? "checked" : ""}>${name}</label>`;
      return `<span class="op-arg">${name}<input data-i="${i}" data-arg="${name}" value="${esc(String(v))}"></span>`;
    }).join("");
    return `<div class="op-item">
      <span class="op-arrow">${i + 1}.</span><span class="op-name">${esc(opLabel(spec))}</span>
      <span class="op-args">${args}</span>
      <span class="spring"></span>
      <button class="op-rm" data-rm="${i}" title="remove">✕</button>
    </div>`;
  }).join("");
  list.querySelectorAll("input[data-arg]").forEach((inp) => {
    const sync = () => {
      const i = Number(inp.dataset.i), arg = inp.dataset.arg;
      S.ops[i].args[arg] = inp.type === "checkbox" ? inp.checked : inp.value;
    };
    inp.addEventListener("input", sync);   // every keystroke — no reliance on blur ordering
    inp.addEventListener("change", sync);  // checkbox toggles & paste-commit
    if (inp.type === "checkbox") inp.addEventListener("click", sync);
  });
  list.querySelectorAll("[data-rm]").forEach((b) =>
    b.onclick = () => { S.ops.splice(Number(b.dataset.rm), 1); renderOps(); });
}

function decInputBytes() {
  const mode = document.querySelector('input[name="dec-mode"]:checked').value;
  const raw = $("#dec-input").value;
  if (mode === "hex") return Uint8Array.from(raw.trim().replace(/0x|[\s,:-]/g, "").match(/.{1,2}/g)?.map((h) => parseInt(h, 16)) || []);
  if (mode === "b64") return b64ToBytes(raw.trim());
  return new TextEncoder().encode(raw);
}

async function runChain() {
  const input = decInputBytes();
  $("#dec-in-size").textContent = `(${input.length} bytes)`;
  const declog = $("#dec-log");
  declog.innerHTML = "";
  try {
    const res = await api("decode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_b64: bytesToB64(input), recipe: S.ops.map((o) => ({ op: o.op, args: o.args })) }),
    });
    const out = b64ToBytes(res.result_b64);
    $("#dec-out-size").textContent = `(${out.length} bytes)`;
    renderDecOutput(out);
    declog.innerHTML = res.log.map((l) => `<div>${esc(l)}</div>`).join("");
  } catch (e) {
    declog.innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}

function renderDecOutput(bytes) {
  S.decOutBytes = bytes;   // kept so switching the text encoding re-renders
  const showHex = $("#dec-show-hex").checked;
  const ta = $("#dec-output");
  if (showHex) {
    let s = "";
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hx = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const asc = [...chunk].map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
      s += i.toString(16).padStart(8, "0") + "  " + hx.padEnd(48) + " |" + asc + "|\n";
    }
    ta.value = s;
  } else {
    // utf-8 replaces invalid bytes with U+FFFD — fine for real text, lossy
    // for ciphertext; latin-1 maps every byte 1:1, gbk serves 中文 samples
    const enc = $("#dec-enc").value;
    if (enc === "latin1") {
      let s = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      ta.value = s;
    } else {
      ta.value = new TextDecoder(enc, { fatal: false }).decode(bytes);
    }
  }
}

async function xorBrute() {
  const input = decInputBytes();
  const box = $("#xor-results");
  const rowsBox = $("#xor-rows") || box;
  try {
    const res = await api("xor/brute", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_b64: bytesToB64(input) }),
    });
    box.classList.add("show");
    const count = $("#xor-count");
    if (count) count.textContent = res.items.length || "";
    rowsBox.innerHTML = res.items.length
      ? res.items.map((r) =>
          `<div class="xor-row" tabindex="0" data-key="${r.key}"><span class="xor-key">${esc(r.key_hex)}</span><span class="xor-score">${r.score}</span><span class="xor-preview">${esc(r.preview)}</span></div>`).join("")
      : `<div class="insp-empty">${esc(t("xor.none.brute"))}</div>`;
    rowsBox.querySelectorAll(".xor-row").forEach((row) =>
      row.onclick = () => {
        // dataset carries the decimal key; feed the xor op its hex form (B5 radix)
        S.ops = [{ op: "xor", args: { key: Number(row.dataset.key).toString(16), hex: true } }];
        renderOps(); runChain();
      });
    box.scrollIntoView({ block: "nearest" }); // 矮抽屉里结果区在折叠线下方，自动带过来
  } catch (e) { toast(e.message, "error"); }
}

async function xorDerive() {
  const prefix = $("#dec-prefix").value;
  if (!prefix) { toast(t("toast.prefix"), "info"); return; }
  const input = decInputBytes();
  const box = $("#xor-results");
  const rowsBox = $("#xor-rows") || box;
  try {
    const res = await api("xor/derive", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input_b64: bytesToB64(input), prefix }),
    });
    box.classList.add("show");
    const count = $("#xor-count");
    if (count) count.textContent = res.items.length || "";
    rowsBox.innerHTML = res.items.length
      ? res.items.map((r) =>
          `<div class="xor-row" tabindex="0"><span class="xor-key">len ${r.length}</span><span class="xor-score">${r.key_ascii ? "ascii" : "hex"}</span><span class="xor-preview">${esc(r.key_display)}</span></div>`).join("")
      : `<div class="insp-empty">${esc(t("xor.none.derive"))}</div>`;
    rowsBox.querySelectorAll(".xor-row").forEach((row, i) =>
      row.onclick = () => {
        const r = res.items[i];
        // key_bytes is always the hex encoding; prefer the readable ascii form
        S.ops = [{ op: "xor", args: r.key_ascii ? { key: r.key_ascii } : { key: r.key_bytes, hex: true } }];
        renderOps(); runChain();
      });
    box.scrollIntoView({ block: "nearest" });
  } catch (e) { toast(e.message, "error"); }
}
