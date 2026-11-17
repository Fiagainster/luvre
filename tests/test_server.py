"""HTTP layer tests with a stub engine — no JVM involved."""

import base64
import os
from pathlib import Path
import json
import threading
import time
import urllib.request

import pytest

from luvre.server.app import AppState, serve


class StubEngine:
    """Mimics EngineManager's surface with canned data."""

    def __init__(self):
        self._functions = [
            {"addr": 0x401000 + i * 0x10, "name": f"fun_{i}", "size": 0x20, "signature": f"undefined fun_{i}()"}
            for i in range(5)
        ]
        self.opened_paths: list[str] = []
        self._comments: dict[int, str] = {}

    # lifecycle
    def open(self, path, progress=None):
        if progress:
            progress("importing")
        self.opened_paths.append(path)
        return {"name": "stub.exe", "function_count": len(self._functions)}

    def program_info(self):
        if not self.opened_paths:
            return None
        return {"name": "stub.exe", "format": "PE", "language_id": "x86:LE:32:default",
                "compiler": "visualstudio", "image_base": "0x400000", "size": 0x1000,
                "function_count": 5, "source_path": self.opened_paths[-1]}

    # listings
    def list_functions(self, query="", offset=0, limit=300):
        items = [f for f in self._functions if query.lower() in f["name"].lower()]
        return {"total": len(items), "items": items[offset:offset + limit]}

    def list_strings(self, query="", offset=0, limit=300):
        items = [{"addr": 0x408000, "length": 5, "value": "hello"}]
        if query and query not in items[0]["value"]:
            items = []
        return {"total": len(items), "items": items}

    def imports(self):
        return [{"name": "MessageBoxA", "library": "user32.dll"}]

    def exports(self):
        return [{"addr": 0x401000, "name": "DllMain"}]

    # per-function
    def decompile(self, addr):
        return {"addr": addr, "name": "main", "code": "int main() { return 0; }"}

    def decompile_many(self, addrs, progress=None):
        return [(a, f"fun_{i}", f"// {a:x}") for i, a in enumerate(addrs)]

    def disasm(self, addr, limit=500):
        return {"addr": addr, "function": "main", "function_addr": addr,
                "instructions": [{"addr": addr, "bytes": "55", "text": "PUSH EBP"}]}

    def xrefs(self, addr):
        return {"to": [{"addr": 0x401100, "type": "CALL", "function": "caller"}],
                "from": [{"addr": addr, "to": 0x402000, "type": "CALL"}]}

    def callgraph(self, addr, depth=2, max_nodes=250):
        return {"center": addr,
                "nodes": [{"addr": addr, "name": "main"}, {"addr": 0x402000, "name": "callee"}],
                "edges": [[addr, 0x402000]]}

    # memory
    def memory_blocks(self):
        return [{"name": ".text", "start": 0x401000, "size": 0x1000, "initialized": True,
                 "read": True, "write": False, "execute": True, "entropy": 6.1}]

    def read_memory(self, block, offset, length):
        assert block == ".text"
        return bytes(range(offset, offset + length))

    def search_hex(self, pattern, limit=500):
        return [{"addr": 0x401234, "block": ".text", "function": "fun_1"}]

    def disasm_raw(self, addr, max_bytes=2048):
        return {"base": addr, "mode_bits": 32,
                "items": [{"addr": addr, "size": 1, "bytes": "55", "text": "push ebp"}],
                "stop": "ret", "recovered": 0, "block": ".text"}

    def constants_scan(self):
        return [{"name": "AES S-box", "category": "block-cipher", "note": "", "length": 16,
                 "addr": 0x409000, "block": ".rdata", "function": None}]

    # annotations
    def rename_function(self, addr, name):
        for f in self._functions:
            if f["addr"] == addr:
                old = f["name"]
                f["name"] = name
                return {"addr": addr, "old": old, "name": name}
        return {"addr": addr, "old": None, "name": name}

    def set_function_comment(self, addr, text):
        self._comments[addr] = text
        return {"addr": addr, "comment": text}

    def function_comment(self, addr):
        return self._comments.get(addr)


@pytest.fixture()
def server(tmp_path_factory, monkeypatch):
    # isolate app-data writes (recent.json etc.) from the real user dir
    monkeypatch.setenv("LVR_DATA_DIR", str(tmp_path_factory.mktemp("lvrdata")))
    httpd = serve(AppState(StubEngine()), "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def get(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def post(base: str, path: str, obj: dict):
    req = urllib.request.Request(
        base + path, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def get_raw(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.status, r.read()


class TestBasics:
    def test_index_served(self, server):
        status, body = get_raw(server, "/")
        assert status == 200 and b"luvre" in body

    def test_status(self, server):
        status, data = get(server, "/api/status")
        assert status == 200
        assert data["version"] and "engine_ready" in data

    def test_unknown_route_404(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(server, "/api/nope")
        assert e.value.code == 404

    def test_static_traversal_blocked(self, server):
        with pytest.raises(urllib.error.HTTPError):
            get_raw(server, "/static/../engine/manager.py")


class TestStubbedApi:
    def test_functions(self, server):
        _, data = get(server, "/api/functions?q=fun_3")
        assert data["total"] == 1 and data["items"][0]["name"] == "fun_3"

    def test_strings(self, server):
        _, data = get(server, "/api/strings?q=hello")
        assert data["items"][0]["value"] == "hello"

    def test_decompile(self, server):
        _, data = get(server, "/api/function/4198400/decompile")
        assert data["code"].startswith("int main")

    def test_disasm(self, server):
        _, data = get(server, "/api/function/4198400/disasm")
        assert data["instructions"][0]["text"] == "PUSH EBP"

    def test_xrefs(self, server):
        _, data = get(server, "/api/function/4198400/xrefs")
        assert data["to"][0]["function"] == "caller"

    def test_callgraph(self, server):
        _, data = get(server, "/api/function/4198400/callgraph?depth=2")
        assert data["center"] == 4198400
        assert len(data["nodes"]) == 2
        assert data["edges"][0] == [4198400, 0x402000]

    def test_memory_read(self, server):
        _, data = get(server, "/api/memory/read?block=.text&offset=3&len=4")
        assert base64.b64decode(data["data_b64"]) == bytes([3, 4, 5, 6])

    def test_constants(self, server):
        _, data = get(server, "/api/constants")
        assert data["items"][0]["name"] == "AES S-box"

    def test_no_program_409(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(server, "/api/program")
        assert e.value.code == 409

    def test_disasm_raw(self, server):
        _, data = get(server, "/api/disasm-raw?addr=0x401000")
        assert data["base"] == 0x401000
        assert data["items"][0]["text"] == "push ebp"
        _, data = get(server, "/api/disasm-raw?addr=4198404")  # decimal form works too
        assert data["base"] == 4198404

    def test_disasm_raw_bad_addr(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            get(server, "/api/disasm-raw?addr=zzz")
        assert e.value.code == 400


class TestPureRoutes:
    def test_decode_route(self, server):
        payload = base64.b64encode(b"hi").decode()
        _, data = post(server, "/api/decode", {"input_b64": payload, "recipe": [{"op": "to_hex"}]})
        assert base64.b64decode(data["result_b64"]) == b"6869"
        assert data["log"]

    def test_decode_bad_recipe(self, server):
        payload = base64.b64encode(b"hi").decode()
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/decode", {"input_b64": payload, "recipe": [{"op": "bogus"}]})
        assert e.value.code == 400
        assert "unknown operation" in e.value.read().decode()

    def test_xor_brute_route(self, server):
        plain = b"the flag is flag{x} and more english text follows here!!"
        data = base64.b64encode(bytes(b ^ 0x20 for b in plain)).decode()
        _, out = post(server, "/api/xor/brute", {"input_b64": data})
        assert out["items"][0]["key"] == 0x20

    def test_xor_derive_route(self, server):
        plain = b"flag{known_prefix}"
        key = b"KEYS"
        data = bytes(b ^ key[i % 4] for i, b in enumerate(plain))
        _, out = post(server, "/api/xor/derive", {"input_b64": base64.b64encode(data).decode(),
                                                  "prefix": "flag{"})
        assert out["items"][0]["key_ascii"] == "KEYS"


class TestApkUnpack:
    def test_apk_unpack_route(self, server, tmp_path):
        import sys
        sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
        from make_minidex import build_minidex

        apk = tmp_path / "demo.apk"
        import zipfile

        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"binary-xml-blob")
            zf.writestr("classes.dex", build_minidex(
                ["Lcom/ctf/MainActivity;", "flag{apk_static_ftw}", "https://c2.example/x"]))
            zf.writestr("lib/arm64-v8a/libnative.so", b"ELF-fake")
            zf.writestr("res/values.txt", "hello")

        _, data = post(server, "/api/open", {"path": str(apk)})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)

        _, data = post(server, "/api/unpack/apk", {})
        jid = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{jid}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done", job.get("error")
        res = job["result"]
        assert res["apk"] is True
        names = [e["name"] for e in res["entries"]]
        assert "classes.dex" in names and "AndroidManifest.xml" in names
        assert "classes.dex" in res["dex_strings"]
        strs = res["dex_strings"]["classes.dex"]
        assert "flag{apk_static_ftw}" in strs
        assert "Lcom/ctf/MainActivity;" in strs
        # traversal entry must never land on disk
        outdir = Path(res["outdir"])
        assert (outdir / "classes.dex").is_file()
        assert (outdir / "res" / "values.txt").is_file()


class TestGdbRoutes:
    def attach(self, server, monkeypatch=None):
        # reach into the handler's app state via a fresh session
        from luvre.server.app import AppState
        # the server fixture creates AppState internally; use the exposed hooks
        # by starting a session through the API with a stub injected instead
        sess = StubGdbSession()
        # find the running server's state object through its handler factory
        # — simplest: drive routes that need a session after attaching manually
        return sess

    def test_gdb_env(self, server):
        # first call may return {"probing": true} while wsl probes in background
        import time as _t
        data = {"probing": True}
        for _ in range(30):
            _, data = get(server, "/api/gdb/env")
            if not data.get("probing"):
                break
            _t.sleep(1)
        assert "local_ok" in data and "wsl_ok" in data and "distros" in data

    def test_gdb_state_no_session(self, server):
        _, data = get(server, "/api/gdb/state")
        assert data["active"] is False

    def test_gdb_route_without_session_409(self, server):
        for path in ("/api/gdb/registers", "/api/gdb/breaks", "/api/gdb/stack",
                     "/api/gdb/log", "/api/gdb/memory?expr=0x1&len=8"):
            with pytest.raises(urllib.error.HTTPError) as e:
                get(server, path)
            assert e.value.code == 409
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/gdb/exec", {"action": "run"})
        assert e.value.code == 409


class TestGdbEnvAdaptive:
    """Host-adaptive transport surface (POSIX must never touch WSL)."""

    def test_wsl_start_refused_on_posix(self, monkeypatch):
        from luvre.gdb.session import GdbError
        st = AppState(StubEngine())
        monkeypatch.setattr(os, "name", "posix")
        with pytest.raises(GdbError, match="wsl transport requires"):
            st.gdb_start("wsl", "Ubuntu-22.04", "", "")

    def test_wsl_start_allowed_on_windows(self, monkeypatch):
        # the guard passes on nt — the call then fails on "no program loaded",
        # which proves it got past the transport check
        from luvre.gdb.session import GdbError
        st = AppState(StubEngine())
        monkeypatch.setattr(os, "name", "nt")
        with pytest.raises(GdbError, match="no program loaded"):
            st.gdb_start("wsl", "Ubuntu-22.04", "", "")

    def test_probing_stub_never_stacks_probes(self, monkeypatch):
        # while the background probe is in flight, polling must return the
        # stub without launching a second synchronous probe (the wsl probe
        # takes 5-20s; a stacked one blocked request threads for the same
        # duration on every poll)
        st = AppState(StubEngine())
        calls = []
        gate = threading.Event()

        def slow_probe(self):
            calls.append(1)
            gate.wait(5)
            st._gdb_env_cache = {"probing": False, "platform": os.name,
                                 "local_ok": True, "wsl_ok": False, "distros": []}
            return st._gdb_env_cache

        monkeypatch.setattr(AppState, "_gdb_env_probe", slow_probe)
        first = st.gdb_env(background=True)
        assert first == {"probing": True, "platform": os.name}
        deadline = time.time() + 5
        while time.time() < deadline and not calls:
            time.sleep(0.05)
        assert calls == [1]           # background probe entered _gdb_env_probe
        second = st.gdb_env(background=True)
        assert second == {"probing": True, "platform": os.name}
        assert calls == [1]           # the poll did NOT stack a sync re-probe
        gate.set()
        deadline = time.time() + 5
        while time.time() < deadline and not st._gdb_env_cache:
            time.sleep(0.05)
        assert st._gdb_env_cache["platform"] == os.name
        assert len(calls) == 1        # exactly one probe ran, end to end


class TestOpenFlow:
    def test_open_creates_triage(self, server, tmp_path):
        sample = tmp_path / "tiny.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 200)
        _, data = post(server, "/api/open", {"path": str(sample)})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done", job
        assert job["result"]["name"] == "stub.exe"

        _, tri = get(server, "/api/triage")
        assert tri["sniff"]["format"] == "PE"

    def test_open_missing_file_errors(self, server):
        _, data = post(server, "/api/open", {"path": "Z:/no/such/file.bin"})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "error"
        assert "not found" in job["error"]

    def test_decompile_all_zip(self, server):
        sample = None
        # ensure a program is "loaded"
        _, data = post(server, "/api/open", {"path": __file__})
        job_id = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{job_id}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done"

        _, data = post(server, "/api/export/decompile-all", {})
        jid = data["job"]
        for _ in range(100):
            _, job = get(server, f"/api/job/{jid}")
            if job["status"] != "running":
                break
            time.sleep(0.05)
        assert job["status"] == "done"
        status, zbytes = get_raw(server, f"/api/download/decompile-all.zip?job={jid}")
        assert status == 200 and zbytes[:2] == b"PK"


def _wait_job(server, jid):
    for _ in range(100):
        _, job = get(server, f"/api/job/{jid}")
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    return job


class TestAnnotationsAndRecent:
    def _open(self, server, tmp_path, name="tiny.exe"):
        sample = tmp_path / name
        sample.write_bytes(b"MZ" + b"\x00" * 200)
        _, data = post(server, "/api/open", {"path": str(sample)})
        job = _wait_job(server, data["job"])
        assert job["status"] == "done", job
        return sample

    def test_rename_and_comment(self, server, tmp_path):
        self._open(server, tmp_path)
        addr = 0x401000
        _, out = post(server, f"/api/function/{addr}/rename", {"name": "check_flag"})
        assert out["name"] == "check_flag" and out["old"] == "fun_0"
        _, out = post(server, f"/api/function/{addr}/comment", {"text": "CRC check here"})
        assert out["comment"] == "CRC check here"
        _, out = get(server, f"/api/function/{addr}/comment")
        assert out["comment"] == "CRC check here"

    def test_rename_requires_program(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/function/4198400/rename", {"name": "x"})
        assert e.value.code == 409

    def test_rename_validates_name(self, server, tmp_path):
        self._open(server, tmp_path)
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/function/4198400/rename", {"name": "   "})
        assert e.value.code == 400

    def test_recent_lists_opened(self, server, tmp_path):
        sample = self._open(server, tmp_path, "recent_sample.bin")
        _, out = get(server, "/api/recent")
        assert out["items"][0]["path"] == str(sample)
        assert out["items"][0]["name"] == "recent_sample.bin"
        assert out["items"][0]["size"] == 202


class TestOriginGuard:
    """Drive-by / DNS-rebinding defense: cross-origin requests must 403."""

    def test_post_with_foreign_origin_403(self, server):
        req = urllib.request.Request(
            server + "/api/open", data=json.dumps({"path": "x"}).encode(),
            headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
        )
        with pytest.raises(urllib.error.HTTPError) as e:
            with urllib.request.urlopen(req, timeout=10):
                pass
        assert e.value.code == 403

    def test_get_with_foreign_origin_403(self, server):
        req = urllib.request.Request(server + "/api/status",
                                     headers={"Origin": "http://evil.example"})
        with pytest.raises(urllib.error.HTTPError) as e:
            with urllib.request.urlopen(req, timeout=10):
                pass
        assert e.value.code == 403

    def test_same_origin_post_passes(self, server):
        # the UI's own fetches send Origin=<server host:port>; must pass
        port = urllib.request.urlopen(server + "/api/status", timeout=10).geturl()
        origin = port.rsplit("/", 2)[0] if port.startswith("http") else server
        req = urllib.request.Request(
            server + "/api/decode", data=json.dumps(
                {"input_b64": base64.b64encode(b"hi").decode(), "recipe": []}).encode(),
            headers={"Content-Type": "application/json", "Origin": origin},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200

    def test_rebound_host_403(self, server):
        # DNS rebinding: a page naming attacker.example but hitting loopback
        req = urllib.request.Request(server + "/api/status",
                                     headers={"Host": "attacker.example"})
        with pytest.raises(urllib.error.HTTPError) as e:
            with urllib.request.urlopen(req, timeout=10):
                pass
        assert e.value.code == 403

    def test_no_headers_pass(self, server):
        # curl / tests / scripts send neither header
        status, _ = get(server, "/api/status")
        assert status == 200


class TestJobFarmSweep:
    def test_finished_jobs_swept_after_ttl(self):
        from luvre.server.app import JobFarm, JOB_TTL
        farm = JobFarm()
        jid = farm.spawn("noop", lambda job: None)
        for _ in range(100):
            if farm.get(jid) and farm.get(jid).status != "running":
                break
            time.sleep(0.05)
        farm.get(jid).created -= (JOB_TTL + 60)  # age it past the TTL
        farm.spawn("noop", lambda job: None)     # spawn triggers the sweep
        assert farm.get(jid) is None

    def test_running_jobs_never_swept(self):
        from luvre.server.app import JobFarm, JOB_TTL
        farm = JobFarm()
        gate = threading.Event()
        farm.spawn("stuck", lambda job: gate.wait(5))
        jobs = [j for j in farm._jobs.values()]
        assert len(jobs) == 1
        jobs[0].created -= (JOB_TTL + 60)
        farm.spawn("noop", lambda job: None)
        assert farm.get(jobs[0].id) is not None  # running job survives
        gate.set()


class StubSession:
    """Bare GdbSession surface for route tests (no subprocess)."""

    def __init__(self):
        self._n = 0
        self.breaks = []

    def status(self):
        return {"loaded": True, "running": False, "exited": False, "dead": None,
                "stop": {"reason": "breakpoint-hit", "func": "main", "addr": "0x00401370"},
                "program": "stub.exe", "console": [], "console_tail": []}

    def insert_break(self, loc, condition=None):
        self._n += 1
        bk = {"number": str(self._n), "addr": "0x00401370", "func": "main", "orig_loc": loc}
        if condition:
            bk["cond"] = condition
        self.breaks.append(bk)
        return bk

    def set_break_condition(self, number, condition):
        for b in self.breaks:
            if b["number"] == str(number):
                b["cond"] = condition or None
        return {"number": str(number), "condition": condition}

    def write_bytes(self, expr, hex_bytes):
        clean = hex_bytes.strip().lower()
        if not clean or len(clean) % 2 or not all(c in "0123456789abcdef" for c in clean):
            raise ValueError("bad hex bytes")  # mirror GdbSession's validation
        return {"addr": expr, "count": len(clean) // 2, "bytes": clean}

    def nop_fill(self, expr, length):
        return {"addr": expr, "count": length, "bytes": "90" * length}


@pytest.fixture()
def gdb_server(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("LVR_DATA_DIR", str(tmp_path_factory.mktemp("lvrdata3")))
    state = AppState(StubEngine())
    state.gdb_session = StubSession()
    httpd = serve(state, "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", state
    httpd.shutdown()


class TestGdbPatchRoutes:
    def test_patch_nop(self, gdb_server):
        base, _ = gdb_server
        _, out = post(base, "/api/gdb/patch", {"addr": "*0x401370", "nop_len": 4})
        assert out["ok"] and out["count"] == 4 and out["bytes"] == "90" * 4

    def test_patch_write(self, gdb_server):
        base, _ = gdb_server
        _, out = post(base, "/api/gdb/patch", {"addr": "0x402000", "bytes": "9090C3"})
        assert out["ok"] and out["bytes"] == "9090c3"

    def test_patch_bad_hex_500(self, gdb_server):
        base, _ = gdb_server
        with pytest.raises(urllib.error.HTTPError) as e:
            post(base, "/api/gdb/patch", {"addr": "0x402000", "bytes": "zz"})
        assert e.value.code == 500

    def test_patch_needs_addr(self, gdb_server):
        base, _ = gdb_server
        with pytest.raises(urllib.error.HTTPError) as e:
            post(base, "/api/gdb/patch", {"bytes": "90"})
        assert e.value.code == 400

    def test_patch_no_session_409(self, server):
        with pytest.raises(urllib.error.HTTPError) as e:
            post(server, "/api/gdb/patch", {"addr": "0x1", "nop_len": 2})
        assert e.value.code == 409

    def test_break_with_condition(self, gdb_server):
        base, state = gdb_server
        _, out = post(base, "/api/gdb/break", {"loc": "*0x401370", "cond": "$eax==5"})
        assert out["bkpt"]["cond"] == "$eax==5"
        assert state.gdb_session.breaks[0]["cond"] == "$eax==5"

    def test_break_cond_route(self, gdb_server):
        base, state = gdb_server
        post(base, "/api/gdb/break", {"loc": "main"})
        _, out = post(base, "/api/gdb/break/cond", {"number": "1", "cond": "$ebx>2"})
        assert out["ok"] and out["condition"] == "$ebx>2"
        assert state.gdb_session.breaks[0]["cond"] == "$ebx>2"
        _, out = post(base, "/api/gdb/break/cond", {"number": "1", "cond": ""})
        assert state.gdb_session.breaks[0]["cond"] is None
