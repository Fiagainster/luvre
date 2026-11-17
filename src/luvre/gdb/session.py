"""GdbSession: one gdb process in MI mode, driven over subprocess pipes.

Two transports:
  * "wsl"   — `wsl -d <distro> -- gdb --interpreter=mi2`  (Linux ELF targets;
              Windows paths auto-convert to /mnt/<drive>/...)
  * "local" — `<mingw>\\gdb.exe --interpreter=mi2`        (Windows PE targets)

Threading model: a reader thread parses MI lines as they arrive.  Result
records (token-matched) resolve pending command futures; exec-async records
(*running / *stopped) update the session state that the UI polls.  A lock
serializes stdin writes.  Non-MI noise (the wsl.exe localhost-proxy warning)
arrives on stderr and never reaches the parser; anything odd on stdout is
classified as noise and logged.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from luvre.gdb.mi import (
    format_register_values,
    parse_breakpoint_table,
    parse_mi_line,
    parse_stopped,
)

DEFAULT_TIMEOUT = 25.0


class GdbError(RuntimeError):
    pass


class GdbTimeout(GdbError):
    pass


def to_wsl_path(path: str) -> str:
    """D:\\a\\b → /mnt/d/a/b  (already-posix paths pass through)."""
    p = path.replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    if p.startswith("/"):
        return p
    raise GdbError(f"cannot convert path for WSL: {path!r}")


def find_local_gdb() -> str | None:
    """Locate a Windows gdb.exe (PATH first, then common mingw homes)."""
    exe = "gdb.exe" if os.name == "nt" else "gdb"
    for d in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(d) / exe
        if cand.is_file():
            return str(cand)
    for base in ("D:/System/mingw64/bin", "C:/mingw64/bin", "C:/msys64/mingw64/bin"):
        cand = Path(base) / exe
        if cand.is_file():
            return str(cand)
    return None


def parse_env_text(text: str) -> list[tuple[str, str]]:
    """Parse ``KEY=VALUE`` pairs separated by commas or newlines.

    GUI samples need ``DISPLAY`` (GTK won't boot without it) — the debugee
    environment is set through gdb's ``set env`` so both transports behave
    the same.  Blank lines and ``#`` comments are ignored.
    """
    pairs: list[tuple[str, str]] = []
    for chunk in re.split(r"[\n,]+", text or ""):
        chunk = chunk.strip()
        if not chunk or chunk.startswith("#"):
            continue
        if "=" not in chunk:
            raise GdbError(f"bad env entry (want KEY=VALUE): {chunk!r}")
        key, _, val = chunk.partition("=")
        key, val = key.strip(), val.strip()
        if not key or re.search(r"\s", key):
            raise GdbError(f"bad env key: {chunk!r}")
        pairs.append((key, val))
    return pairs


class GdbSession:
    """One live gdb MI session.  Use start() — the constructor is internal."""

    def __init__(
        self,
        transport: str,
        *,
        distro: str = "Ubuntu-22.04",
        local_gdb: str | None = None,
        argv_override: list[str] | None = None,
        on_console: Callable[[str], None] | None = None,
    ):
        self.transport = transport
        self.distro = distro
        self.local_gdb = local_gdb or (find_local_gdb() if transport == "local" else None)
        self.argv_override = argv_override  # test seam: full command line instead of gdb
        # Windows gdb speaks the ANSI codepage (GBK here) on its stdio —
        # UTF-8 bytes for 网安训练 arrive as mojibake and its own echoes
        # come back the same way.  Linux gdb is plain UTF-8.  mbcs is a
        # Windows-only codec name — POSIX must never select it (CI caught
        # this: ubuntu runners ship a real gdb, so the local transport is
        # reachable there and .encode("mbcs") blew up in the reader path).
        self.io_encoding = "utf-8" if (transport == "wsl" or os.name != "nt") else "mbcs"
        self.on_console = on_console

        self.proc: subprocess.Popen | None = None
        self._stdout_lock = threading.Lock()
        self._pending: dict[str, dict[str, Any]] = {}  # token -> {"event": Event, "record": ...}
        self._state_lock = threading.Lock()
        self.state: dict[str, Any] = {
            "running": False,
            "exited": False,
            "stop": None,       # normalized *stopped payload or None
            "program": None,
            "loaded": False,
            "dead": None,       # error string if the gdb process died
        }
        self.console: list[str] = []      # ring of console/log lines
        self.exited_code: int | None = None
        self._boot_prompt = threading.Event()
        self._cmd_seq = 0

    # ------------------------------------------------------------------ boot

    def start(self, program_path: str | None = None) -> None:
        """Launch gdb.  The program rides on gdb's COMMAND LINE — Python
        passes Unicode argv via CreateProcessW, which works for both mingw
        gdb and wsl.exe.  (MI stdin mangles non-ASCII paths: Windows gdb
        decodes them in the ANSI codepage, and copying the sample to %TEMP%
        gets it eaten by Defender — see dev-notes.)"""
        if self.argv_override:
            argv = list(self.argv_override)
        elif self.transport == "wsl":
            argv = ["wsl", "-d", self.distro, "--", "gdb", "--interpreter=mi2", "-q", "-nx"]
            if program_path:
                argv.append(to_wsl_path(program_path))
        elif self.transport == "local":
            if not self.local_gdb or not Path(self.local_gdb).is_file():
                raise GdbError(f"gdb.exe not found (looked in PATH and common mingw dirs)")
            argv = [self.local_gdb, "--interpreter=mi2", "-q", "-nx"]
        else:
            raise GdbError(f"unknown transport {self.transport!r}")

        env = dict(os.environ, WSL_UTF8="1")
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env,
        )
        threading.Thread(target=self._reader_stdout, daemon=True).start()
        threading.Thread(target=self._reader_stderr, daemon=True).start()
        if not self._boot_prompt.wait(timeout=30):
            raise GdbTimeout("gdb did not print its first MI prompt within 30s")
        # quiet down confirmations that would block non-interactive flows
        try:
            self.cmd("-gdb-set confirm off")
            self.cmd("-gdb-set pagination off")
        except GdbError:
            pass

    # ------------------------------------------------------------------- io

    def _send_line(self, line: str) -> None:
        if self.proc is None or self.proc.stdin is None:
            raise GdbError("gdb process is not running")
        with self._stdout_lock:
            self.proc.stdin.write((line + "\n").encode(self.io_encoding))
            self.proc.stdin.flush()

    def _reader_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        for raw in iter(self.proc.stdout.readline, b""):
            # latin-1 = byte-transparent view: gdb MIXES raw high bytes with
            # \xHH/\NNN escapes in one MI string, so decoding here (utf-8 or
            # mbcs) would shred multi-byte sequences before the parser can
            # reassemble them.  parse_mi_line + _unescape_c collect bytes and
            # decode once with the transport encoding.
            line = raw.decode("latin-1")
            rec = parse_mi_line(line, self.io_encoding)
            if rec is None:
                continue
            kind = rec["kind"]
            if kind == "prompt":
                self._boot_prompt.set()
                continue
            if kind == "console":
                self._push_console(rec["payload"])
                continue
            if kind in ("log", "target"):
                self._push_console("[log] " + rec["payload"])
                continue
            if kind == "noise":
                # stdout lines that don't parse as MI are almost always the
                # inferior's raw stdout interleaved between MI records (it
                # writes to the same pipe) — show them as plain program output
                self._push_console(str(rec["payload"]))
                continue
            token = rec["token"]
            if kind == "result" and token and token in self._pending:
                entry = self._pending.pop(token)
                entry["record"] = rec
                entry["event"].set()
                # `-exec-run/continue/...` report `^running` as a RESULT record —
                # mingw gdb (sync mode) never emits the async *running twin, so
                # the running transition must happen here or the UI never sees
                # the target go live.
                if rec["class"] == "running":
                    self._on_exec({"kind": "exec", "class": "running",
                                   "token": None, "payload": {}})
                continue
            if kind == "exec":
                self._on_exec(rec)
                continue
            if kind == "notify":
                # e.g. =breakpoint-created — keep a compact trace
                cls = rec["class"] or ""
                if "breakpoint" in cls:
                    self._push_console("[notify] " + cls)
                continue

    def _reader_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for raw in iter(self.proc.stderr.readline, b""):
            line = raw.decode(self.io_encoding, "replace").rstrip()
            if line:
                self._push_console("[stderr] " + line)
        # EOF on stderr means the process is gone
        self._mark_dead()

    def _push_console(self, text: str) -> None:
        self.console.append(text)
        if len(self.console) > 1000:
            del self.console[: len(self.console) - 1000]
        if self.on_console:
            try:
                self.on_console(text)
            except Exception:  # noqa: BLE001
                pass

    def _on_exec(self, rec: dict[str, Any]) -> None:
        cls = rec["class"] or ""
        with self._state_lock:
            if cls == "running":
                self.state["running"] = True
                self.state["stop"] = None
                if self.state["exited"]:
                    # rerun after a normal exit (confirm off + second -exec-run):
                    # ^running means the target is live again — keeping the old
                    # exited flag made every later stop render as "正常退出"
                    # (real-sample catch: ch20 conditional bp hit invisible)
                    self.state["exited"] = False
            elif cls == "stopped":
                self.state["running"] = False
                self.state["stop"] = parse_stopped(rec["payload"])
                if self.state["stop"]["reason"].startswith("exited"):
                    self.state["exited"] = True
            elif cls.startswith("exited"):
                self.state["running"] = False
                self.state["exited"] = True

    def _mark_dead(self) -> None:
        with self._state_lock:
            if not self.state["exited"]:
                self.state["dead"] = "gdb process terminated unexpectedly"
            self.state["running"] = False

    # ------------------------------------------------------------ commands

    def cmd(self, mi_cmd: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
        """Send one MI command, wait for its result record. Raises on ^error."""
        if self.proc is None or self.proc.poll() is not None:
            raise GdbError("gdb session is not alive")
        with self._state_lock:
            dead = self.state["dead"]
        if dead:
            raise GdbError(dead)
        self._cmd_seq += 1
        token = str(self._cmd_seq)
        entry: dict[str, Any] = {"event": threading.Event(), "record": None}
        self._pending[token] = entry
        try:
            self._send_line(f"{token}{mi_cmd}")
        except Exception:
            self._pending.pop(token, None)
            raise
        if not entry["event"].wait(timeout):
            self._pending.pop(token, None)
            raise GdbTimeout(f"no response to {mi_cmd!r} within {timeout}s")
        rec = entry["record"]
        assert rec is not None
        if rec["class"] == "error":
            msg = rec["payload"].get("msg", rec["payload"])
            raise GdbError(str(msg))
        return rec["payload"]

    # ------------------------------------------------------------- lifecycle

    def load(self, program_path: str, args: str = "", stdin_text: str = "",
             env_text: str = "") -> dict[str, Any]:
        """Point gdb at the binary (local transport: the path rides MI stdin,
        encoded in the ANSI codepage so 中文 paths survive) and prepare run
        arguments / stdin redirection / debugee environment."""
        if self.transport == "local":
            fwd = program_path.replace("\\", "/")
            self.cmd(f'-file-exec-and-symbols "{fwd}"')
        for key, val in parse_env_text(env_text):
            v = f'"{val}"' if re.search(r"\s", val) else val
            self.cmd(f"-gdb-set env {key} {v}")
        parts = []
        if args:
            parts.append(args)
        if stdin_text:
            stdin_file = self._stage_stdin(stdin_text)
            parts.append(f'< "{stdin_file}"')
        if parts:
            self.cmd("-gdb-set args " + " ".join(parts))
        with self._state_lock:
            self.state["program"] = program_path
            self.state["loaded"] = True
            self.state["exited"] = False
            self.state["stop"] = None
        return {"program": program_path}

    def _stage_stdin(self, text: str) -> str:
        data = text.encode("utf-8")
        if self.transport == "wsl":
            name = f"/tmp/lvr_stdin_{uuid.uuid4().hex[:8]}"
            p = subprocess.Popen(
                ["wsl", "-d", self.distro, "--", "sh", "-c", f"cat > '{name}'"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=dict(os.environ, WSL_UTF8="1"),
            )
            p.communicate(data)
            return name
        tmp = Path(os.environ.get("TEMP", ".")) / f"lvr_stdin_{uuid.uuid4().hex[:8]}.txt"
        tmp.write_bytes(data)
        return str(tmp).replace("\\", "/")

    def exit(self, timeout: float = 5.0) -> None:
        try:
            self._send_line("-gdb-exit")
        except Exception:  # noqa: BLE001
            pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # a target blocked on stdin keeps sync-mode gdb busy — kill hard
                self.proc.kill()
            for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                try:
                    pipe.close()   # reader threads hit EOF and finish cleanly
                except Exception:  # noqa: BLE001
                    pass
        with self._state_lock:
            self.state["running"] = False
            self.state["dead"] = self.state["dead"] or "session closed"

    # ------------------------------------------------------------- features

    def insert_break(self, loc: str, condition: str | None = None) -> dict[str, Any]:
        """loc: function name, file:line, or *0xADDR.

        condition: optional gdb expression — the breakpoint only fires while
        it holds (``-break-insert -c``; e.g. "$eax==5" or "$rsp<0xffffd000").
        Double quotes are rejected because the condition rides inside quotes.
        """
        loc = loc.strip()
        if not loc:
            raise GdbError("empty breakpoint location")
        quoted_loc = shlex.quote(loc) if not loc.startswith("*") else loc
        if condition:
            condition = condition.strip()
            if '"' in condition:
                raise GdbError("condition must not contain double quotes")
            payload = self.cmd(f'-break-insert -c "{condition}" {quoted_loc}')
        else:
            payload = self.cmd(f"-break-insert {quoted_loc}")
        bk = payload.get("bkpt") or {}
        if isinstance(bk, list):
            bk = bk[0]
        return bk

    def set_break_condition(self, number: str, condition: str) -> dict[str, Any]:
        """Attach / replace a condition on an existing breakpoint; an empty
        condition clears it (``-break-condition N`` with no expr)."""
        number = str(number).strip()
        if not number:
            raise GdbError("breakpoint number required")
        condition = (condition or "").strip()
        if '"' in condition:
            raise GdbError("condition must not contain double quotes")
        if condition:
            self.cmd(f'-break-condition {number} "{condition}"')
        else:
            self.cmd(f"-break-condition {number}")
        return {"number": number, "condition": condition}

    def delete_break(self, number: str) -> None:
        self.cmd(f"-break-delete {number}")

    def list_breaks(self) -> list[dict[str, Any]]:
        # MI blocks on commands while the target runs (sync-mode gdb) — fail
        # fast instead of hanging the frontend poll for the full timeout.
        self._require_stopped("listing breakpoints")
        return parse_breakpoint_table(self.cmd("-break-list"))

    def _require_stopped(self, what: str) -> None:
        with self._state_lock:
            if self.state["running"]:
                raise GdbError(f"target is running — stop it before {what}")
            if self.state["dead"]:
                raise GdbError(self.state["dead"])

    def run(self) -> dict[str, Any]:
        self.cmd("-exec-run")
        return {"running": True}

    def continue_(self) -> dict[str, Any]:
        self.cmd("-exec-continue")
        return {"running": True}

    def next_(self) -> dict[str, Any]:
        self._require_stopped("stepping")
        self.cmd("-exec-next")
        return {"running": True}

    def step_(self) -> dict[str, Any]:
        self._require_stopped("stepping")
        self.cmd("-exec-step")
        return {"running": True}

    def stepi_(self) -> dict[str, Any]:
        # Line-level step needs function bounds — on stripped samples gdb
        # answers "Cannot find bounds of current function"; instruction-level
        # stepping always works.
        self._require_stopped("stepping")
        self.cmd("-exec-stepi")
        return {"running": True}

    def nexti_(self) -> dict[str, Any]:
        self._require_stopped("stepping")
        self.cmd("-exec-nexti")
        return {"running": True}

    def finish(self) -> dict[str, Any]:
        self._require_stopped("stepping")
        self.cmd("-exec-finish")
        return {"running": True}

    def interrupt(self) -> dict[str, Any]:
        """Stop a running target (Ctrl-C equivalent).  In sync-mode gdb this
        goes through the console escape, which Linux native handles even
        while the target runs."""
        try:
            self._send_line("-exec-interrupt")
        except GdbError:
            raise
        return {"stopping": True}

    def console_cmd(self, text: str) -> dict[str, Any]:
        """Run a raw gdb CLI command through MI's console escape
        (``-interpreter-exec console``).  This reaches everything the MI
        dialect hides — ``handle SIGTRAP nostop pass`` (self-int3 samples
        whose own signal handlers must receive their traps), ``info proc
        mappings``, ``x/16xw``…  Output arrives through the regular console
        stream and is shown in the gdb console box."""
        self.console_output(text)
        return {"command": text.strip()}

    def console_output(self, text: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
        """Run one gdb CLI command and RETURN the console lines it produced.

        In sync-mode gdb the command's console output is emitted before its
        ^done record and the reader thread processes them in order, so by the
        time cmd() unblocks the lines are already in the ring — slice from
        the pre-command length.  Used for parsing `info proc mappings`.
        """
        text = text.strip()
        if not text:
            raise GdbError("empty command")
        self._require_stopped("running console commands")
        # MI wants a C-string, not shlex quoting (single quotes confuse gdb)
        quoted = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        start = len(self.console)
        self.cmd(f"-interpreter-exec console {quoted}", timeout)
        return list(self.console[start:])

    def runtime_base(self) -> dict[str, Any]:
        """Runtime relocation info of the debugee's own module, for the UI's
        static↔runtime address conversion on ASLR targets.

        Two sources, by availability:
          * ``info proc mappings`` — Linux gdb.  base = (first mapping owned
            by the program).start − offset (ELF maps headers at base, offset
            0; PE at base with the .text row at file offset 0x1000).
          * ``info files`` — mingw gdb refuses `info proc mappings` with
            "Not supported on this target", but its section ranges
            (``0xRUNTIME - 0xRUNTIME is .text``) carry the same delta; the
            frontend pairs a section name with the static section table.
        Returns {kind: "mappings"|"sections", ...}; the frontend computes
        delta = runtime − static for whichever landed.
        """
        self._require_stopped("reading module mappings")
        try:
            lines = self.console_output("info proc mappings")
        except GdbError:
            lines = []
        rows = []
        for ln in lines:
            m = re.match(
                r"\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s*(\S+)?",
                ln,
            )
            if m:
                rows.append({
                    "start": int(m.group(1), 16), "end": int(m.group(2), 16),
                    "size": int(m.group(3), 16), "offset": int(m.group(4), 16),
                    "obj": (m.group(5) or "").replace("\\", "/").lower(),
                })
        prog_name = str(self.state.get("program") or "").replace("\\", "/").split("/")[-1].lower()
        candidates = [r for r in rows if prog_name and r["obj"].endswith(prog_name)]
        if rows:
            # name match preferred; first row is the fallback (both Linux and
            # Windows listings put the main module first)
            first = (candidates or rows)[0]
            return {"kind": "mappings", "base": first["start"] - first["offset"],
                    "rows": rows[:8]}
        # mingw path: `info files` section ranges of the exec file
        lines = self.console_output("info files")
        sections = []
        in_exec = False
        for ln in lines:
            if "Local exec file" in ln:
                in_exec = True
                continue
            if not in_exec:
                continue
            if " is " in ln and " in " in ln:
                break  # DLL section rows follow the exec file's own sections
            m = re.match(r"\s*(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s+is\s+(\S+)", ln)
            if m:
                sections.append({"name": m.group(3),
                                 "start": int(m.group(1), 16),
                                 "end": int(m.group(2), 16)})
        if not sections:
            raise GdbError("could not derive runtime relocation info from "
                           "`info proc mappings` or `info files`")
        return {"kind": "sections", "sections": sections[:12]}

    def set_break_ignore(self, number: str, count: int) -> dict[str, Any]:
        """Ignore the first ``count`` hits of a breakpoint (-break-after)."""
        number = str(number).strip()
        if not number:
            raise GdbError("breakpoint number required")
        count = max(0, int(count))
        self.cmd(f"-break-after {number} {count}")
        return {"number": number, "ignore": count}

    def threads(self) -> dict[str, Any]:
        """All threads of a stopped target (-thread-info)."""
        self._require_stopped("listing threads")
        payload = self.cmd("-thread-info", timeout=15)
        out = []
        for t in payload.get("threads") or []:
            if not isinstance(t, dict):
                continue
            out.append({
                "id": str(t.get("id", "")),
                "name": str(t.get("name", "")) if t.get("name") else "",
                "details": str(t.get("details", "")) if t.get("details") else "",
                "frame": (t.get("frame") or {}) if isinstance(t.get("frame"), dict) else {},
            })
        return {"threads": out, "current": str(payload.get("current-thread-id", ""))}

    def thread_select(self, thread_id: str) -> dict[str, Any]:
        """Make another thread current (-thread-select); subsequent stepping
        and frame commands act on it."""
        self._require_stopped("switching threads")
        tid = str(thread_id).strip()
        if not tid.isdigit():
            raise GdbError("thread id must be a number")
        self.cmd(f"-thread-select {tid}", timeout=15)
        return {"current": tid}

    def wait_stop(self, timeout: float = 10.0) -> dict[str, Any] | None:
        """Poll helper: wait until the target reports a stop."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._state_lock:
                if not self.state["running"]:
                    return self.state["stop"]
                if self.state["dead"] or self.state["exited"]:
                    return self.state["stop"] or {"reason": "exited"}
            time.sleep(0.1)
        return None

    def registers(self) -> dict[str, str]:
        self._require_stopped("reading registers")
        names = self.cmd("-data-list-register-names").get("register-names") or []
        values = self.cmd("-data-list-register-values x")
        return format_register_values(names if isinstance(names, list) else [], values)

    @staticmethod
    def _addr_expr(expr: str) -> str:
        """Normalize a memory ADDRESS expression.

        ``-data-read/write-memory-bytes`` evaluate ADDRESS as an EXPRESSION —
        the ``*`` prefix is breakpoint syntax and means DEREFERENCE here, so
        ``*0x080480d9`` silently became "contents of 0x080480d9 used as an
        address" (garbage like 0x75491b75, real-sample catch).  Users paste
        breakpoint-style stars everywhere, so strip a leading one.
        """
        expr = str(expr).strip()
        if expr.startswith("*"):
            expr = expr[1:].strip()
        if not expr:
            raise GdbError("empty address expression")
        return expr

    def read_memory(self, expr: str, count: int) -> bytes:
        self._require_stopped("reading memory")
        expr = self._addr_expr(expr)
        count = max(1, min(int(count), 1 << 20))
        payload = self.cmd(f'-data-read-memory-bytes "{expr}" {count}')
        chunks = payload.get("memory") or []
        data = bytearray()
        for c in chunks:
            if isinstance(c, dict) and "contents" in c:
                data.extend(bytes.fromhex(str(c["contents"])))
        return bytes(data)

    def write_bytes(self, addr_expr: str, hex_bytes: str) -> dict[str, Any]:
        """Patch target memory at ``addr_expr`` with raw bytes (hex string).

        ``-data-write-memory-bytes`` goes through gdb, so breakpoint traps and
        the instruction cache stay coherent — NOPing out a comparison
        mid-session just works on the next resume.  Requires a stopped target.
        """
        self._require_stopped("patching memory")
        addr_expr = self._addr_expr(addr_expr)
        clean = re.sub(r"0x|\s+", "", str(hex_bytes), flags=re.IGNORECASE).lower()
        if not clean or len(clean) % 2 or not re.fullmatch(r"[0-9a-f]+", clean):
            raise GdbError("bad hex bytes (want even-length hex, e.g. 9090c3)")
        if len(clean) // 2 > 4096:
            raise GdbError("patch too large (max 4096 bytes)")
        self.cmd(f'-data-write-memory-bytes "{addr_expr}" {clean}')
        return {"addr": addr_expr, "count": len(clean) // 2, "bytes": clean}

    def nop_fill(self, addr_expr: str, length: int) -> dict[str, Any]:
        """Fill ``length`` bytes with x86 NOPs (0x90) — the classic patch.

        One 0x90 per byte keeps it length-exact; smarter multi-byte NOPs are
        irrelevant for skipping code (the skipped bytes simply execute as
        no-ops).  ARM/other architectures: write explicit bytes instead.
        """
        length = max(1, min(int(length), 4096))
        return self.write_bytes(addr_expr, "90" * length)

    def stack(self) -> list[dict[str, Any]]:
        self._require_stopped("reading the stack")
        payload = self.cmd("-stack-list-frames")
        frames = payload.get("stack") or []
        return [f.get("frame", f) if isinstance(f, dict) else f for f in frames] if isinstance(frames, list) else []

    def evaluate(self, expr: str) -> str:
        self._require_stopped("evaluating expressions")
        payload = self.cmd(f'-data-evaluate-expression "{expr}"')
        return str(payload.get("value", ""))

    def status(self) -> dict[str, Any]:
        with self._state_lock:
            st = dict(self.state)
        st["transport"] = self.transport
        st["distro"] = self.distro if self.transport == "wsl" else None
        st["console_tail"] = self.console[-40:]
        return st
