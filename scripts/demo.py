#!/usr/bin/env python3
"""Demo for the README: real moat in front of @modelcontextprotocol/server-filesystem.

Needs Node.js (npx). Usage: cargo build --release --bin moat && python scripts/demo.py
The GIF in docs/images was recorded from this script with asciinema and agg."""
import json, os, queue, random, shutil, string, subprocess, sys, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOAT = os.environ.get("MOAT", str(ROOT / "target" / "release" / ("moat.exe" if os.name == "nt" else "moat")))
WORK = Path(tempfile.mkdtemp(prefix="moat-demo-"))
P = WORK / "project"; (WORK / ".ssh").mkdir(parents=True); P.mkdir()
random.seed(7)
key = "sk-proj-" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(40))
(P / "notes.md").write_text(f"# notes\nOPENAI_API_KEY={key}\nDEBUG=1\n")
(WORK / ".ssh" / "id_ed25519").write_text("dummy-private-key-for-demo\n")
LOG = WORK / "audit.jsonl"
os.chdir(WORK)

DIM, GRN, RED, CY, B, R = "\x1b[2m", "\x1b[32m", "\x1b[31m", "\x1b[36m", "\x1b[1m", "\x1b[0m"
def out(s=""): print(s, flush=True)
def pause(t): time.sleep(t)

cmd = [MOAT, "wrap", "--no-prompt", "--allow", str(P), "--audit-log", str(LOG), "--",
       "npx", "-y", "@modelcontextprotocol/server-filesystem", str(P)]
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
q = queue.Queue()
threading.Thread(target=lambda: [q.put(l) for l in proc.stdout] , daemon=True).start()
def send(m): proc.stdin.write(json.dumps(m) + "\n"); proc.stdin.flush()
def recv(i, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try: m = json.loads(q.get(timeout=1))
        except (queue.Empty, ValueError): continue
        if m.get("id") == i: return m
    raise SystemExit("timeout")
def text(m):
    r = m.get("result", {})
    t = " ".join(c.get("text", "") for c in r.get("content", []) if isinstance(c, dict))
    return t or m.get("error", {}).get("message", json.dumps(m))

ver = subprocess.run([MOAT, "--version"], capture_output=True, text=True).stdout.strip().replace("moat ", "mcp-moat ")
out(f"{B}{ver}{R} {DIM}in front of @modelcontextprotocol/server-filesystem{R}")
out(f"{CY}${R} moat wrap --no-prompt --allow ./project --audit-log audit.jsonl \\")
out("    -- npx -y @modelcontextprotocol/server-filesystem ./project")
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1"}}})
recv(1); send({"jsonrpc": "2.0", "method": "notifications/initialized"})
n = [10]
def call(comment, shown, name, args, expect_secret=False):
    out(); out(f"{DIM}# {comment}{R}"); pause(0.8)
    out(f"{B}>{R} {shown}"); pause(0.6)
    n[0] += 1
    send({"jsonrpc": "2.0", "id": n[0], "method": "tools/call", "params": {"name": name, "arguments": args}})
    m = recv(n[0]); r = m.get("result", {}); t = text(m)
    blocked = bool(r.get("isError")) or "error" in m
    if blocked:
        ls = [l.strip() for l in t.splitlines() if l.strip()]
        head = ls[0].strip("[]")
        why = ls[1].replace("Action blocked: ", "").replace(str(WORK) + "/", "")
        out(f"  {RED}BLOCKED{R} {head}"); import textwrap
        for w in textwrap.wrap(why, 86): out(f"          {DIM}{w}{R}")
    else:
        for line in t.splitlines():
            if "KEY" in line or "REDACTED" in line: out(f"  {GRN}OK{R}      {line}")
    pause(1.5)
    return t, blocked

t, _ = call("1. the agent reads a file that holds a secret", 'read_file("project/notes.md")', "read_file", {"path": str(P / "notes.md")})
assert key not in t
call("2. the agent reaches outside the allowed folder", 'read_file("../.ssh/id_ed25519")', "read_file", {"path": str(WORK / ".ssh" / "id_ed25519")})
call("3. the agent writes a protected file (--no-prompt: no operator, so deny)", 'write_file("project/.env", "X=1")', "write_file", {"path": str(P / ".env"), "content": "X=1"})
print(f".env created: {(P/'.env').exists()}", file=sys.stderr)
proc.stdin.close(); proc.wait(timeout=20)
out(); out(f"{DIM}# 4. the audit log is a hash chain{R}"); pause(0.8)
out(f"{CY}${R} moat audit verify audit.jsonl"); pause(0.6)
v = subprocess.run([MOAT, "audit", "verify", str(LOG)], capture_output=True, text=True)
for line in (v.stdout + v.stderr).splitlines():
    if line.strip(): out(f"  {line.replace(str(LOG), 'audit.jsonl')}")
pause(2)
