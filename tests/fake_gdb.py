"""A minimal fake gdb: speaks just enough MI over stdio for session tests."""
import re
import sys
import time

w = sys.stdout

def out(s):
    w.write(s + "\n")
    w.flush()

def out2(s):
    w.write(s)
    w.flush()

out2("=thread-group-added,id=\"i1\"\n")
out2("(gdb)\n")

state = {"bp": 0}
bps = {}    # number -> {"loc": str, "cond": str|None}
mem = {}    # address string -> bytes (patch roundtrip)


def read_hex(expr):
    """Bytes to report for a read: patched contents win over the default."""
    key = expr.strip().strip('"').lstrip("*")
    if key in mem:
        return mem[key].hex()
    return "41424344"


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    token = ""
    while line and line[0].isdigit():
        token += line[0]
        line = line[1:]
    if line in ("-gdb-set confirm off", "-gdb-set pagination off"):
        out(f"{token}^done")
    elif line.startswith("-file-exec-and-symbols"):
        out(f'{token}^done')
        out('~"Reading symbols from fake.\\n"')
    elif line.startswith("-gdb-set args"):
        out(f"{token}^done")
    elif line.startswith("-gdb-set env"):
        out(f"{token}^done")
    elif line.startswith("-break-insert"):
        m = re.match(r'-break-insert -c "([^"]*)" (.+)$', line)
        if m:
            cond, loc = m.group(1), m.group(2)
        else:
            cond, loc = None, line[len("-break-insert "):]
        state["bp"] += 1
        n = state["bp"]
        bps[n] = {"loc": loc, "cond": cond}
        cond_part = f',cond="{cond}"' if cond else ""
        out(f'{token}=breakpoint-created,bkpt={{number="{n}",addr="0x00401370"{cond_part}}}')
        out(f'{token}^done,bkpt={{number="{n}",type="breakpoint",addr="0x00401370"{cond_part}}}')
    elif line.startswith("-break-condition"):
        m = re.match(r'-break-condition\s+(\d+)\s+"([^"]*)"$', line)
        n = int(m.group(1)) if m else None
        if m and n in bps:
            bps[n]["cond"] = m.group(2) or None
            out(f"{token}^done")
        elif re.match(r'-break-condition\s+(\d+)\s*$', line):
            n = int(re.match(r'-break-condition\s+(\d+)\s*$', line).group(1))
            if n in bps:
                bps[n]["cond"] = None
            out(f"{token}^done")
        else:
            out(f'{token}^error,msg="No breakpoint number {n}."')
    elif line == "-break-list":
        entries = []
        for i in range(1, state["bp"] + 1):
            bp = bps.get(i, {})
            cond_part = f',cond="{bp["cond"]}"' if bp.get("cond") else ""
            entries.append(f'{{number="{i}",addr="0x00401370"{cond_part}}}')
        out(f'{token}^done,BreakpointTable={{body={{bkpt=[{",".join(entries)}]}}}}')
    elif line.startswith("-break-delete"):
        out(f"{token}^done")
    elif line == "-data-write-memory-bytes" or line.startswith("-data-write-memory-bytes"):
        m = re.match(r'-data-write-memory-bytes\s+"([^"]+)"\s+([0-9a-fA-F]+)\s*$', line)
        if m:
            mem[m.group(1).strip().lstrip("*")] = bytes.fromhex(m.group(2))
            out(f"{token}^done")
        else:
            out(f'{token}^error,msg="bad write"')
    elif line in ("-exec-run", "-exec-continue"):
        out(f"{token}^running")
        time.sleep(0.3)
        out('*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",frame={addr="0x00401370",func="main",args=[]},thread-id="1"')
    elif line in ("-exec-next", "-exec-step", "-exec-nexti", "-exec-stepi"):
        out(f"{token}^running")
        time.sleep(0.2)
        out('*stopped,reason="end-stepping-range",frame={addr="0x00401375",func="main",args=[]},thread-id="1"')
    elif line == "-data-list-register-names":
        out(f'{token}^done,register-names=["rax","rbx","rcx"]')
    elif line == "-data-list-register-values x":
        out(f'{token}^done,register-values=[{{number="0",value="0x11"}},{{number="1",value="0x22"}},{{number="2",value="0x33"}}]')
    elif line.startswith("-data-read-memory-bytes"):
        m = re.search(r'"([^"]+)"', line)
        hexdata = read_hex(m.group(1)) if m else "41424344"
        out(f'{token}^done,memory=[{{begin="0x0",contents="{hexdata}",size="{len(hexdata)//2}"}}]')
    elif line == "-stack-list-frames":
        out(f'{token}^done,stack=[frame={{level="0",func="main",addr="0x00401370"}},frame={{level="1",func="__start",addr="0x00401000"}}]')
    elif line.startswith("-data-evaluate-expression"):
        out(f'{token}^done,value="42"')
    elif line.startswith("-interpreter-exec console"):
        # console escape: echo the command back through the ~console stream
        out(f'~"console: {line[len("-interpreter-exec console "):].strip(chr(34))}\\n"')
        out(f"{token}^done")
    elif line == "-gdb-exit":
        out(f"{token}^exit")
        break
    else:
        out(f'{token}^error,msg="unhandled: {line[:40]}"')
    out2("(gdb)\n")
