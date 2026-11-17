"""Session-layer tests against a fake gdb (no WSL / no real binary needed)."""

import sys
from pathlib import Path

import time

import pytest

from luvre.gdb.session import GdbSession, GdbError, parse_env_text, to_wsl_path

FAKE = Path(__file__).parent / "fake_gdb.py"


def test_parse_env_text():
    assert parse_env_text("DISPLAY=:99") == [("DISPLAY", ":99")]
    assert parse_env_text("DISPLAY=:99, LANG=C.UTF-8") == [
        ("DISPLAY", ":99"), ("LANG", "C.UTF-8")]
    assert parse_env_text("A=1\nB=2\n# comment\n\nC=3") == [
        ("A", "1"), ("B", "2"), ("C", "3")]
    assert parse_env_text("") == []
    assert parse_env_text("KEY = spaced value") == [("KEY", "spaced value")]
    with pytest.raises(GdbError):
        parse_env_text("NOEQUALS")
    with pytest.raises(GdbError):
        parse_env_text("HAS SPACE=1")


@pytest.fixture()
def session():
    s = GdbSession("local", argv_override=[sys.executable, str(FAKE)])
    s.start()
    yield s
    s.exit()


def test_wsl_path_conversion():
    assert to_wsl_path(r"D:\Project\网安训练\MazE") == "/mnt/d/Project/网安训练/MazE"
    assert to_wsl_path("C:/x/y.exe") == "/mnt/c/x/y.exe"
    assert to_wsl_path("/usr/bin/gdb") == "/usr/bin/gdb"
    with pytest.raises(GdbError):
        to_wsl_path("relative/path")


class TestSessionFlow:
    def test_boot_and_load(self, session):
        info = session.load("C:\\fake\\target.exe", args="--demo")
        assert info["program"] == "C:\\fake\\target.exe"
        st = session.status()
        assert st["loaded"] and st["program"] == "C:\\fake\\target.exe"

    def test_load_emits_env_commands(self, session, monkeypatch):
        sent = []
        real = session.cmd

        def spy(mi_cmd, timeout=25.0):
            sent.append(mi_cmd)
            return real(mi_cmd, timeout)

        monkeypatch.setattr(session, "cmd", spy)
        session.load("C:\\fake\\target.exe", env_text="DISPLAY=:99, FOO=a b")
        env_cmds = [c for c in sent if c.startswith("-gdb-set env")]
        assert env_cmds == ['-gdb-set env DISPLAY :99', '-gdb-set env FOO "a b"']

    def test_break_insert_list_delete(self, session):
        bk = session.insert_break("*0x00401370")
        assert bk["number"] == "1"
        bk2 = session.insert_break("main")
        assert bk2["number"] == "2"
        bps = session.list_breaks()
        assert len(bps) == 2
        session.delete_break("1")
        bps = session.list_breaks()
        assert len(bps) == 2  # fake gdb doesn't really delete; router works though

    def test_run_until_breakpoint(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "breakpoint-hit"
        assert stop["func"] == "main"
        st = session.status()
        assert not st["running"]

    def test_registers(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        regs = session.registers()
        assert regs["rax"] == "0x11" and regs["rcx"] == "0x33"

    def test_memory(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        data = session.read_memory("$rsp", 4)
        assert data == b"ABCD"

    def test_stack(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        frames = session.stack()
        assert frames[0]["func"] == "main"
        assert frames[1]["func"] == "__start"

    def test_evaluate(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        assert session.evaluate("$rax") == "42"

    def test_next_then_stop(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.next_()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "end-stepping-range"

    def test_stepi_nexti(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        for act in (session.stepi_, session.nexti_):
            act()
            stop = session.wait_stop(timeout=5)
            assert stop is not None and stop["reason"] == "end-stepping-range"

    def test_list_breaks_while_running_raises(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.state["running"] = True  # simulate live target (MI would block)
        with pytest.raises(GdbError, match="running"):
            session.list_breaks()
        session.state["running"] = False

    def test_continue_after_stop(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.continue_()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "breakpoint-hit"

    def test_error_command_raises(self, session):
        session.load("C:\\fake\\target.exe")
        with pytest.raises(GdbError):
            session.cmd("-frobnicate")  # unknown → fake replies ^error

    def test_console_cmd(self, session):
        session.load("C:\\fake\\target.exe")
        res = session.console_cmd("handle SIGTRAP nostop noprint pass")
        assert res["command"] == "handle SIGTRAP nostop noprint pass"
        deadline = time.time() + 3
        while time.time() < deadline:
            if any("handle SIGTRAP" in line for line in session.console):
                break
            time.sleep(0.1)
        assert any("handle SIGTRAP" in line for line in session.console)

    def test_console_cmd_empty_raises(self, session):
        with pytest.raises(GdbError):
            session.console_cmd("   ")

    def test_console_cmd_while_running_raises(self, session):
        session.load("C:\\fake\\target.exe")
        session.insert_break("*0x00401370")
        session.run()
        session.wait_stop(timeout=5)
        session.state["running"] = True  # sync-mode MI would block
        with pytest.raises(GdbError, match="running"):
            session.console_cmd("info proc mappings")
        session.state["running"] = False

    def test_console_capture(self, session):
        session.load("C:\fake\target.exe")
        # the ~console line arrives asynchronously — poll briefly
        deadline = time.time() + 3
        while time.time() < deadline:
            if any("Reading symbols" in line for line in session.console):
                return
            time.sleep(0.1)
        assert any("Reading symbols" in line for line in session.console)
        assert any("Reading symbols" in line for line in session.console)


class TestPatch:
    def test_write_bytes_roundtrip(self, session):
        session.load("C:\fake\target.exe")
        res = session.write_bytes("0x00402000", "9090C3")
        assert res["count"] == 3 and res["bytes"] == "9090c3"
        assert session.read_memory("0x00402000", 3) == bytes.fromhex("9090c3")

    def test_write_bytes_accepts_0x_prefix_and_spaces(self, session):
        session.load("C:\fake\target.exe")
        session.write_bytes("0x00402000", "0x 90 90")
        assert session.read_memory("0x00402000", 2) == b"\x90\x90"

    def test_write_bytes_bad_hex_raises(self, session):
        session.load("C:\fake\target.exe")
        with pytest.raises(GdbError):
            session.write_bytes("0x00402000", "zz")
        with pytest.raises(GdbError):
            session.write_bytes("0x00402000", "909")  # odd length
        with pytest.raises(GdbError):
            session.write_bytes("0x00402000", "")

    def test_write_bytes_running_target_raises(self, session):
        session.load("C:\fake\target.exe")
        session.state["running"] = True
        with pytest.raises(GdbError, match="running"):
            session.write_bytes("0x00402000", "90")
        session.state["running"] = False

    def test_nop_fill(self, session):
        session.load("C:\fake\target.exe")
        res = session.nop_fill("*0x00403000", 4)
        assert res["count"] == 4
        assert session.read_memory("*0x00403000", 4) == b"\x90" * 4

    def test_nop_fill_clamps(self, session):
        session.load("C:\fake\target.exe")
        res = session.nop_fill("0x00403000", 99999)
        assert res["count"] == 4096


class TestConditionalBreak:
    def test_insert_with_condition(self, session):
        bk = session.insert_break("*0x00401370", condition="$eax==5")
        assert bk["number"] == "1"
        assert bk["cond"] == "$eax==5"
        bps = session.list_breaks()
        assert bps[0]["cond"] == "$eax==5"

    def test_insert_without_condition_has_none(self, session):
        bk = session.insert_break("main")
        assert "cond" not in bk

    def test_condition_with_quote_raises(self, session):
        with pytest.raises(GdbError, match="quote"):
            session.insert_break("main", condition='$rax=="x"')

    def test_set_break_condition(self, session):
        bk = session.insert_break("*0x00401370")
        res = session.set_break_condition(bk["number"], "$ebx>3")
        assert res["condition"] == "$ebx>3"
        bps = session.list_breaks()
        assert bps[0]["cond"] == "$ebx>3"

    def test_clear_break_condition(self, session):
        bk = session.insert_break("*0x00401370", condition="$eax==1")
        session.set_break_condition(bk["number"], "")
        bps = session.list_breaks()
        assert not bps[0].get("cond")

    def test_set_condition_unknown_bp_errors(self, session):
        with pytest.raises(GdbError):
            session.set_break_condition("99", "$rax>0")

    def test_rerun_after_exit_clears_exited(self, session):
        # ch20 real-sample catch: after a normal exit, a second -exec-run must
        # resurrect the target — a stale exited flag rendered every later
        # breakpoint stop as "正常退出" and hid the registers panel
        session.load("C:\fake\target.exe")
        session.insert_break("*0x00401370")
        session.state["exited"] = True   # pretend a previous run ended normally
        session.run()
        stop = session.wait_stop(timeout=5)
        assert stop is not None and stop["reason"] == "breakpoint-hit"
        st = session.status()
        assert st["running"] is False
        assert st["exited"] is False

    def test_write_accepts_breakpoint_star(self, session):
        # the '*' prefix is breakpoint syntax; in an ADDRESS expression it
        # means dereference and silently wrote to garbage (ch20 real catch)
        session.load("C:\fake\target.exe")
        session.write_bytes("*0x00402000", "9090")
        assert session.read_memory("0x00402000", 2) == b"\x90\x90"

    def test_read_accepts_breakpoint_star(self, session):
        session.load("C:\fake\target.exe")
        session.write_bytes("0x00402000", "4142")
        assert session.read_memory("*0x00402000", 2) == b"AB"

    def test_write_empty_addr_raises(self, session):
        session.load("C:\fake\target.exe")
        with pytest.raises(GdbError):
            session.write_bytes("*", "90")


class TestBreakIgnore:
    def test_set_and_list(self, session):
        bk = session.insert_break("*0x00401370")
        session.set_break_ignore(bk["number"], 3)
        bps = session.list_breaks()
        assert bps[0].get("ignore") == "3"

    def test_zero_count_clears(self, session):
        bk = session.insert_break("*0x00401370")
        session.set_break_ignore(bk["number"], 3)
        session.set_break_ignore(bk["number"], 0)
        bps = session.list_breaks()
        assert "ignore" not in bps[0]

    def test_unknown_bp_errors(self, session):
        with pytest.raises(GdbError):
            session.set_break_ignore("99", 1)


class TestRuntimeBase:
    def test_parse_mappings_offset_zero(self, session):
        session.load("C:\fake\target.exe")
        res = session.runtime_base()
        assert res["base"] == 0x400000   # first row start 0x400000 - offset 0
        assert len(res["rows"]) == 2

    def test_running_target_raises(self, session):
        session.load("C:\fake\target.exe")
        session.state["running"] = True
        with pytest.raises(GdbError, match="running"):
            session.runtime_base()
        session.state["running"] = False


class TestThreads:
    def test_list(self, session):
        session.load("C:\fake\target.exe")
        res = session.threads()
        assert res["threads"][0]["id"] == "1"
        assert res["threads"][0]["frame"]["func"] == "main"
        assert res["current"] == "1"

    def test_select_and_switch(self, session):
        session.load("C:\fake\target.exe")
        res = session.thread_select("2")
        assert res["current"] == "2"
        res = session.threads()
        assert res["current"] == "2"

    def test_select_bad_id(self, session):
        session.load("C:\fake\target.exe")
        with pytest.raises(GdbError, match="number"):
            session.thread_select("x")

    def test_runtime_base_falls_back_to_info_files(self, session, monkeypatch):
        # mingw gdb refuses `info proc mappings` ("Not supported on this
        # target") — the `info files` section ranges carry the same delta
        session.load("C:\fake\target.exe")

        def fake_out(text, timeout=25.0):
            if "proc mappings" in text:
                raise GdbError("Not supported on this target.")
            return ["Local exec file:\n",
                    "\t`C:\fake\target.exe', file type pei-x86-64.",
                    "\tEntry point: 0x00401125",
                    "\t0x00401000 - 0x00401200 is .text",
                    "\t0x00402000 - 0x00402130 is .data",
                    "\t0x00403000 - 0x00403100 is .text in C:\WINDOWS\ntdll.dll"]
        monkeypatch.setattr(session, "console_output", fake_out)
        res = session.runtime_base()
        assert res["kind"] == "sections"
        assert [s["name"] for s in res["sections"]] == [".text", ".data"]
        assert res["sections"][0]["start"] == 0x401000
