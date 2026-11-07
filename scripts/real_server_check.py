#!/usr/bin/env python3
"""Run mcp-moat in front of real MCP servers and check the result.

Servers: @modelcontextprotocol/server-filesystem and @modelcontextprotocol/server-everything (Node.js,
npx) and mcp-server-git (Python; `pip install mcp-server-git` or uvx).

Usage: python scripts/real_server_check.py [path to moat binary]

Needs Node.js (npx) and access to the npm and PyPI registries. The binary defaults to
target/release/moat. Everything happens in a temporary folder. Exit code 0 = all checks passed,
1 = a check failed. Symlink checks are skipped on Windows. The git part is skipped (and said so)
if the git server is not available.
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOAT = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target" / "release" / ("moat.exe" if os.name == "nt" else "moat"))
SERVER = [shutil.which("npx") or "npx", "-y", "@modelcontextprotocol/server-filesystem"]
FAILED: list[str] = []


def session(cmd: list[str], calls: list[tuple[str, str, dict]], timeout: int = 90, env: dict | None = None) -> tuple[dict, str]:
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            bufsize=1, env=env)
    lines: queue.Queue = queue.Queue()

    def pump() -> None:
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()

    def send(message: dict) -> None:
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

    def receive(wanted: int) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                continue
            if line is None:
                return {"error": {"message": "stream closed"}}
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("id") == wanted:
                return message
        return {"error": {"message": "timeout"}}

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "check", "version": "1"}}})
    results = {"init": receive(1)}
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    results["tools"] = receive(2)
    for index, (label, name, arguments) in enumerate(calls, start=10):
        send({"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        results[label] = receive(index)
    proc.stdin.close()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    return results, proc.stderr.read()


def text_of(message: dict) -> str:
    result = message.get("result", {})
    return " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict)) or json.dumps(message)


def is_blocked(message: dict) -> bool:
    return bool(message.get("result", {}).get("isError")) and "MCP-MOAT" in text_of(message)


def check(condition: bool, label: str, detail: str = "") -> None:
    print(("ok    " if condition else "FAIL  ") + label + ("" if condition else f"  -> {detail[:160]}"))
    if not condition:
        FAILED.append(label)


def git_command() -> list[str] | None:
    probe = subprocess.run([sys.executable, "-c", "import mcp_server_git"], capture_output=True)
    if probe.returncode == 0:
        return [sys.executable, "-m", "mcp_server_git"]
    uvx = shutil.which("uvx")
    return [uvx, "mcp-server-git"] if uvx else None


def git_server() -> None:
    print("== git server (mcp-server-git)")
    server = git_command()
    git = shutil.which("git")
    if not server or not git:
        print("skip  the git server or git is not available")
        return
    work = Path(tempfile.mkdtemp(prefix="moat-git-"))
    jail, outside = (work / "jail").resolve(), (work / "outside").resolve()
    for folder in (jail / "repo", outside / "repo"):
        folder.mkdir(parents=True)
        for command in (["init", "-q", "."], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
            subprocess.run([git, *command], cwd=folder, check=True)
        (folder / "f.txt").write_text(f"data {folder}\n")
        subprocess.run([git, "add", "."], cwd=folder, check=True)
        subprocess.run([git, "commit", "-qm", "init"], cwd=folder, check=True)
    (jail / "repo" / "new.txt").write_text("new\n")
    repo, other = str(jail / "repo"), str(outside / "repo")
    calls = [
        ("status_inside", "git_status", {"repo_path": repo}),
        ("log_inside", "git_log", {"repo_path": repo, "max_count": 1}),
        ("diff_head", "git_diff", {"repo_path": repo, "target": "HEAD"}),
        ("diff_tilde", "git_diff", {"repo_path": repo, "target": "HEAD~1"}),
        ("add_inside", "git_add", {"repo_path": repo, "files": ["new.txt"]}),
        ("status_outside", "git_status", {"repo_path": other}),
        ("log_outside", "git_log", {"repo_path": other}),
        ("show_outside", "git_show", {"repo_path": other, "revision": "HEAD"}),
        ("diff_outside", "git_diff", {"repo_path": other, "target": "HEAD"}),
        ("traversal", "git_status", {"repo_path": f"{repo}/../../outside/repo"}),
        ("add_traversal", "git_add", {"repo_path": repo, "files": ["../../outside/repo/f.txt"]}),
        ("add_absolute", "git_add", {"repo_path": repo, "files": [f"{other}/f.txt"]}),
        ("branch_outside", "git_create_branch", {"repo_path": other, "branch_name": "evil"}),
        ("checkout_outside", "git_checkout", {"repo_path": other, "branch_name": "evil"}),
    ]
    res, _ = session([MOAT, "wrap", "--preset", "git", "--allow", str(jail), "--no-prompt", "--"] + server, calls)
    for label in ("status_inside", "log_inside", "diff_head"):
        check(not is_blocked(res[label]) and not res[label].get("result", {}).get("isError"), f"git: {label} works", text_of(res[label]))
    check(not is_blocked(res["diff_tilde"]), "git: a revision with ~ (HEAD~1) is not mistaken for a path", text_of(res["diff_tilde"]))
    check("staged" in text_of(res["add_inside"]).lower(), "git: git_add of a relative file inside the repo works", text_of(res["add_inside"]))
    for label in ("status_outside", "log_outside", "show_outside", "diff_outside", "traversal", "add_traversal",
                  "add_absolute", "branch_outside", "checkout_outside"):
        check(is_blocked(res[label]), f"git: {label} is blocked", text_of(res[label]))
    branches = subprocess.run([git, "branch", "--list"], cwd=outside / "repo", capture_output=True, text=True).stdout
    check("evil" not in branches, "git: no branch was created in the repository outside the jail", branches)
    shutil.rmtree(work, ignore_errors=True)


def everything_server(work: Path) -> None:
    print("== reference server (server-everything)")
    config = work / "everything.toml"
    config.write_text('always_allow_tools = ["echo", "get-env", "get-sum"]\nnon_file_tools = ["get-sum"]\n')
    env = {**os.environ, "OPENAI_API_KEY": "abcdefgh12345678", "DB_PASSWORD": "hunter2hunter2",
           "GROQ_KEY": "gsk_A1b2C3d4E5f6G7h8I9j0K1l2", "GITHUB_TOKEN": "ghp_" + "A" * 36}
    calls = [("echo", "echo", {"message": "hello"}), ("sum", "get-sum", {"a": 2, "b": 3}), ("env", "get-env", {}),
             ("unknown", "trigger-long-running-operation", {"duration": 1, "steps": 1})]
    server = [shutil.which("npx") or "npx", "-y", "@modelcontextprotocol/server-everything"]
    res, _ = session([MOAT, "wrap", "--no-prompt", "--config", str(config), "--"] + server, calls, timeout=120, env=env)
    check("hello" in text_of(res["echo"]) and not is_blocked(res["echo"]), "everything: an allowed tool works", text_of(res["echo"]))
    check("5" in text_of(res["sum"]) and not is_blocked(res["sum"]), "everything: non_file_tools lets get-sum run", text_of(res["sum"]))
    check(is_blocked(res["unknown"]) and "not whitelisted" in text_of(res["unknown"]), "everything: a tool that is not listed is blocked", text_of(res["unknown"]))
    dump = text_of(res["env"])
    for secret in ("abcdefgh12345678", "hunter2hunter2", "gsk_A1b2C3d4E5f6G7h8I9j0K1l2", "ghp_" + "A" * 36):
        check(secret not in dump, f"everything: environment dump hides {secret[:6]}...", dump[:100])
    check('"OPENAI_API_KEY": "[MCP-MOAT-REDACTED-SECRET]"' in dump, "everything: the key name and the quotes stay in the dump", dump[:200])


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="moat-real-"))
    jail, outside = (work / "jail").resolve(), (work / "outside").resolve()
    (jail / "sub").mkdir(parents=True)
    (jail / ".ssh").mkdir()
    outside.mkdir()
    (jail / "a.txt").write_text("hello from inside\n")
    (jail / "secrets.env").write_text(
        "GROQ=gsk_A1b2C3d4E5f6G7h8I9j0K1l2\nOPENAI_API_KEY=abcdefgh12345678\nDB_PASSWORD=hunter2hunter2\nDEBUG=1\n")
    (jail / ".ssh" / "id_rsa").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n")
    (outside / "o.txt").write_text("TOP SECRET OUTSIDE\n")
    symlinks = os.name != "nt"
    if symlinks:
        os.symlink(outside, jail / "link_out")
        os.symlink(outside / "o.txt", jail / "link_file")

    J, O = str(jail), str(outside)
    calls = [
        ("read_inside", "read_text_file", {"path": f"{J}/a.txt"}),
        ("read_secrets", "read_text_file", {"path": f"{J}/secrets.env"}),
        ("read_ssh", "read_text_file", {"path": f"{J}/.ssh/id_rsa"}),
        ("read_outside", "read_text_file", {"path": f"{O}/o.txt"}),
        ("read_traversal", "read_text_file", {"path": f"{J}/../outside/o.txt"}),
        ("read_multi_mixed", "read_multiple_files", {"paths": [f"{J}/a.txt", f"{O}/o.txt"]}),
        ("list_outside", "list_directory", {"path": O}),
        ("media_outside", "read_media_file", {"path": f"{O}/o.txt"}),
        ("tree_inside", "directory_tree", {"path": J}),
        ("info_inside", "get_file_info", {"path": f"{J}/a.txt"}),
        ("write_outside", "write_file", {"path": f"{O}/new.txt", "content": "x"}),
        ("move_out", "move_file", {"source": f"{J}/a.txt", "destination": f"{O}/moved.txt"}),
        ("write_protected", "write_file", {"path": f"{J}/moat.toml", "content": "evil"}),
        ("write_inside", "write_file", {"path": f"{J}/new.txt", "content": "x"}),
        ("edit_inside", "edit_file", {"path": f"{J}/a.txt", "edits": [{"oldText": "hello", "newText": "bye"}]}),
        ("mkdir_inside", "create_directory", {"path": f"{J}/newdir"}),
    ]
    if symlinks:
        calls += [
            ("read_symlink_file", "read_text_file", {"path": f"{J}/link_file"}),
            ("read_symlink_dir", "read_text_file", {"path": f"{J}/link_out/o.txt"}),
        ]

    audit = work / "audit.jsonl"
    base = [MOAT, "wrap", "--preset", "filesystem", "--allow", J, "--no-prompt"]

    print(f"== normal mode (jail {J})")
    res, err = session(base + ["--audit-log", str(audit), "--"] + SERVER + [J], calls)
    check(len(res["tools"].get("result", {}).get("tools", [])) >= 10, "tools/list passes through", text_of(res["tools"]))
    check("hello from inside" in text_of(res["read_inside"]) and not is_blocked(res["read_inside"]), "read inside the jail works", text_of(res["read_inside"]))
    secrets = text_of(res["read_secrets"])
    check("gsk_A1b2" not in secrets, "Groq key is masked", secrets)
    check("abcdefgh12345678" not in secrets, "OPENAI_API_KEY value is masked", secrets)
    check("hunter2hunter2" not in secrets, "DB_PASSWORD value is masked", secrets)
    check("DEBUG=1" in secrets, "harmless lines stay readable", secrets)
    check("BEGIN OPENSSH" not in text_of(res["read_ssh"]), "private key block is masked", text_of(res["read_ssh"]))
    for label in ("read_outside", "read_traversal", "read_multi_mixed", "list_outside", "media_outside",
                  "write_outside", "move_out", "write_protected"):
        check(is_blocked(res[label]), f"{label} is blocked", text_of(res[label]))
    if symlinks:
        for label in ("read_symlink_file", "read_symlink_dir"):
            check(is_blocked(res[label]), f"{label} is blocked", text_of(res[label]))
    check(not is_blocked(res["tree_inside"]) and "children" in text_of(res["tree_inside"]), "directory_tree works", text_of(res["tree_inside"]))
    check(not is_blocked(res["info_inside"]), "get_file_info works", text_of(res["info_inside"]))
    check(not is_blocked(res["write_inside"]) and (jail / "new.txt").exists(), "write inside the jail works")
    check(not (outside / "new.txt").exists() and not (outside / "moved.txt").exists(), "nothing was written outside the jail")
    check(not (jail / "moat.toml").exists(), "moat.toml was not created")
    verify = subprocess.run([MOAT, "audit", "verify", str(audit)], capture_output=True, text=True)
    report = verify.stdout + verify.stderr  # the report is written to stderr
    check(verify.returncode == 0 and "INTACT" in report, "audit chain verifies", report)
    records = report.split("Verified Records:")[1].split()[0] if "Verified Records:" in report else "0"
    check(records.isdigit() and int(records) >= len(calls), "audit log has a record for every call", report)

    print("== read-only mode")
    for leftover in ("new.txt", "newdir"):
        target = jail / leftover
        shutil.rmtree(target) if target.is_dir() else target.unlink(missing_ok=True)
    (jail / "a.txt").write_text("hello from inside\n")
    res, _ = session(base + ["--read-only", "--"] + SERVER + [J], calls)
    for label in ("write_inside", "edit_inside", "mkdir_inside", "move_out", "write_protected"):
        check(is_blocked(res[label]), f"{label} is blocked", text_of(res[label]))
    check(not (jail / "new.txt").exists() and not (jail / "newdir").exists(), "read-only mode created nothing")
    check((jail / "a.txt").read_text() == "hello from inside\n", "read-only mode changed nothing")
    check(not is_blocked(res["read_inside"]), "reading still works in read-only mode", text_of(res["read_inside"]))
    check(not is_blocked(res["tree_inside"]), "directory_tree works in read-only mode", text_of(res["tree_inside"]))

    git_server()
    everything_server(work)

    shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'all checks passed' if not FAILED else str(len(FAILED)) + ' check(s) failed: ' + ', '.join(FAILED)}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
