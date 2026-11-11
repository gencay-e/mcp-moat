#!/usr/bin/env python3
"""Demo for the README: real moat in front of @modelcontextprotocol/server-filesystem.

Nothing is mocked. Needs Node.js (npx).
Usage: cargo build --release --bin moat && python scripts/demo.py
Record: asciinema rec --idle-time-limit 1 -c "python scripts/demo.py" demo.cast
        agg --font-size 19 --last-frame-duration 3 demo.cast moat-demo.gif
The terminal is meant to be 80 columns wide. Commands are typed char by char
with small random delays; output is printed as soon as moat returns it."""
import json, os, queue, random, shutil, string, subprocess, tempfile, textwrap, threading, time
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

GRY, GRN, RED, CY, B, R = "\x1b[90m", "\x1b[32m", "\x1b[31m", "\x1b[36m", "\x1b[1m", "\x1b[0m"
WIDTH = 74
rng = random.Random(3)

def out(s=""): print(s, flush=True)
def pause(t): time.sleep(t)
def typed(prefix, s):
    """Print prefix instantly, then type s at ~25-40 ms per character."""
    print(prefix, end="", flush=True)
    for ch in s:
        print(ch, end="", flush=True)
        time.sleep(rng.uniform(0.022, 0.042) + (0.05 if ch == " " and rng.random() < 0.1 else 0))
    time.sleep(0.12)
    print(flush=True)

cmd = [MOAT, "wrap", "--no-prompt", "--allow", str(P), "--audit-log", str(LOG), "--",
       "npx", "-y", "@modelcontextprotocol/server-filesystem", str(P)]
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
q = queue.Queue()
threading.Thread(target=lambda: [q.put(l) for l in proc.stdout], daemon=True).start()
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

# The server was started above (as the first command would start it); the
# initialize handshake runs while the first command is being typed.
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1"}}})
typed(f"{CY}${R} ", "moat wrap --no-prompt --allow ./project --audit-log audit.jsonl \\")
typed("    ", "-- npx -y @modelcontextprotocol/server-filesystem ./project")
recv(1); send({"jsonrpc": "2.0", "method": "notifications/initialized"})
pause(0.5)
n = [10]
def call(comment, shown, name, args):
    out(f"{GRY}# {comment}{R}")
    typed(f"{B}>{R} ", shown)
    n[0] += 1
    send({"jsonrpc": "2.0", "id": n[0], "method": "tools/call", "params": {"name": name, "arguments": args}})
    m = recv(n[0]); r = m.get("result", {}); t = text(m)
    blocked = bool(r.get("isError")) or "error" in m
    if blocked:
        ls = [l.strip() for l in t.splitlines() if l.strip()]
        head = ls[0].strip("[]")
        why = ls[1].replace("Action blocked: ", "").replace(str(WORK) + "/", "")
        out(f"  {RED}BLOCKED{R} {head}")
        for w in textwrap.wrap(why, WIDTH, initial_indent="  ", subsequent_indent="  "): out(f"{GRY}{w}{R}")
    else:
        for line in t.splitlines():
            if "KEY" in line or "REDACTED" in line: out(f"  {GRN}OK{R}  {line}")
    pause(rng.uniform(0.5, 0.7))
    return t, blocked

t, _ = call("1. the agent reads a file that holds a secret", 'read_file("project/notes.md")', "read_file", {"path": str(P / "notes.md")})
assert key not in t
call("2. it reaches outside the allowed folder", 'read_file("../.ssh/id_ed25519")', "read_file", {"path": str(WORK / ".ssh" / "id_ed25519")})
call("3. it writes a protected file (--no-prompt: no operator, so deny)", 'write_file("project/.env", "X=1")', "write_file", {"path": str(P / ".env"), "content": "X=1"})
assert not (P / ".env").exists()
proc.stdin.close(); proc.wait(timeout=20)
out(f"{GRY}# 4. the audit log is a hash chain{R}")
typed(f"{CY}${R} ", "moat audit verify audit.jsonl")
v = subprocess.run([MOAT, "audit", "verify", str(LOG)], capture_output=True, text=True)
for line in (v.stdout + v.stderr).splitlines():
    if line.strip(): out(f"  {line.replace(str(LOG), 'audit.jsonl')}")
pause(0.6)
shutil.rmtree(WORK, ignore_errors=True)
