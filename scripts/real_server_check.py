#!/usr/bin/env python3
"""Run mcp-moat in front of real MCP servers and check the result.

Servers: filesystem, everything, memory, PostgreSQL and Playwright (Node.js/npx),
plus git, sqlite and fetch (Python/uvx). Server versions are pinned below.

Usage: python scripts/real_server_check.py [path to moat binary]

Needs Node.js (npx) and access to the npm and PyPI registries. The binary defaults to
target/release/moat. Everything happens in a temporary folder. Exit code 0 = all checks passed,
1 = a check failed. Windows directory junctions are tested without administrator privileges.
The separate Windows console check covers prompts and Ctrl+C in an isolated pseudoconsole.
PostgreSQL needs running Docker; Playwright needs an installed browser.
"""
from __future__ import annotations

import base64
from collections import deque
import json
import http.server
import os
import queue
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOAT = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else str(ROOT / "target" / "release" / ("moat.exe" if os.name == "nt" else "moat"))
# Pinned server versions: a new upstream release must not change the result of this check.
FILESYSTEM_SERVER = "@modelcontextprotocol/server-filesystem@2.3.0"
EVERYTHING_SERVER = "@modelcontextprotocol/server-everything@2.3.0"
GIT_SERVER_VERSION = "2026.11.11"
MEMORY_SERVER = "@modelcontextprotocol/server-memory@2.1.1"
SQLITE_SERVER_VERSION = "2025.4.25"
# The archived SQLite server uses SDK 1.x decorators removed in SDK 2.x.
SQLITE_MCP_VERSION = "1.26.0"
FETCH_SERVER_VERSION = "2026.11.11"
POSTGRES_SERVER = "@modelcontextprotocol/server-postgres@0.6.2"
POSTGRES_IMAGE = "postgres:17.6-alpine"
PLAYWRIGHT_SERVER = "@playwright/mcp@0.0.85"
NODE = shutil.which("node") or "node"
NPX = ([NODE, str(Path(NODE).resolve().parent / "node_modules" / "npm" / "bin" / "npx-cli.js")]
       if os.name == "nt" else [shutil.which("npx") or "npx"])
SERVER = [*NPX, "-y", FILESYSTEM_SERVER]
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
    stderr_chunks: deque[str] = deque(maxlen=64)

    def drain_stderr() -> None:
        for chunk in iter(lambda: proc.stderr.read(4096), ""):
            stderr_chunks.append(chunk)

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()

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

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "check", "version": "1"}}})
        results = {"init": receive(1)}
        if results["init"].get("error"):
            code = results["init"]["error"].get("code", "unknown")
            raise RuntimeError(f"server initialization failed (JSON-RPC error {code})")
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
            check(False, "session: proxy exits after input closes")
            proc.kill()
            proc.wait(timeout=10)
        check(proc.returncode == 0, "session: proxy exits successfully")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        stderr_thread.join(timeout=5)
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
    return results, "".join(stderr_chunks)


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
    return [uvx, f"mcp-server-git=={GIT_SERVER_VERSION}"] if uvx else None


def git_server() -> None:
    print("== git server (mcp-server-git)")
    server = git_command()
    git = shutil.which("git")
    if not server or not git:
        check(False, "git: git and a server launcher are installed")
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
    config.write_text('always_allow_tools = ["echo", "get-env", "get-sum", "get-tiny-image"]\n'
                      'non_file_tools = ["get-env", "get-sum", "get-tiny-image"]\n')
    env = {**os.environ, "OPENAI_API_KEY": "abcdefgh12345678", "DB_PASSWORD": "hunter2hunter2",
           "GROQ_KEY": "gsk_A1b2C3d4E5f6G7h8I9j0K1l2", "GITHUB_TOKEN": "ghp_" + "A" * 36,
           "MOAT_AUDIT_KEY": "audit-key-for-environment-test", "CLIENT_SECRET_VALUE": "secret-value",
           "PUBLIC_VALUE": "public-sentinel"}
    calls = [("echo", "echo", {"message": "hello"}), ("sum", "get-sum", {"a": 2, "b": 3}), ("env", "get-env", {}),
             ("unknown", "trigger-long-running-operation", {"duration": 1, "steps": 1}),
             ("image", "get-tiny-image", {})]
    server = [*NPX, "-y", EVERYTHING_SERVER]
    res, _ = session([MOAT, "wrap", "--no-prompt", "--config", str(config), "--"] + server, calls, timeout=120, env=env)
    check("hello" in text_of(res["echo"]) and not is_blocked(res["echo"]), "everything: an allowed tool works", text_of(res["echo"]))
    check("5" in text_of(res["sum"]) and not is_blocked(res["sum"]), "everything: non_file_tools lets get-sum run", text_of(res["sum"]))
    check(is_blocked(res["unknown"]) and "not whitelisted" in text_of(res["unknown"]), "everything: a tool that is not listed is blocked", text_of(res["unknown"]))
    images = [c for c in res["image"].get("result", {}).get("content", []) if c.get("type") == "image"]
    png = base64.b64decode(images[0].get("data", "")) if images else b""
    check(png.startswith(b"\x89PNG"), "everything: image data passes unchanged (valid PNG)", str(res["image"])[:200])
    dump = text_of(res["env"])
    for name in ("OPENAI_API_KEY", "DB_PASSWORD", "GITHUB_TOKEN", "MOAT_AUDIT_KEY", "CLIENT_SECRET_VALUE"):
        check(f'"{name}"' not in dump, f"everything: {name} is absent in the child")
    check("gsk_A1b2C3d4E5f6G7h8I9j0K1l2" not in dump, "everything: DLP masks an inherited secret")
    check("public-sentinel" in dump, "everything: ordinary environment survives scrubbing")
    for strict in (False, True):
        config.write_text('always_allow_tools = ["get-env"]\nnon_file_tools = ["get-env"]\n'
                          'pass_env = ["GITHUB_TOKEN", "MOAT_AUDIT_KEY"]\n'
                          f'clear_env = {str(strict).lower()}\n')
        forwarded, _ = session([MOAT, "wrap", "--no-prompt", "--config", str(config), "--"] + server,
                               [("env", "get-env", {})], timeout=120, env=env)
        child_env = text_of(forwarded["env"])
        check('"GITHUB_TOKEN"' in child_env, f"everything: pass_env survives clear_env={strict}")
        check('"MOAT_AUDIT_KEY"' not in child_env, f"everything: audit key stays private with clear_env={strict}")
        check(("public-sentinel" not in child_env) == strict, f"everything: clear_env={strict} applies")


def memory_server(work: Path) -> None:
    print("== memory server")
    storage = work / "memory.jsonl"
    storage.write_text(json.dumps({"type": "entity", "name": "fixture", "entityType": "test",
                                   "observations": ["memory-sentinel"]}) + "\n", encoding="utf-8")
    original = storage.read_bytes()
    calls = [("read", "read_graph", {}),
             ("write", "create_entities", {"entities": [{"name": "forbidden", "entityType": "test", "observations": []}]})]
    res, _ = session([MOAT, "wrap", "--preset", "memory", "--no-prompt", "--",
                      *NPX, "-y", MEMORY_SERVER], calls,
                     env={**os.environ, "MEMORY_FILE_PATH": str(storage)})
    check("memory-sentinel" in text_of(res["read"]), "memory: graph can be read")
    check(is_blocked(res["write"]), "memory: unattended writes require approval")
    check(storage.read_bytes() == original, "memory: denied write leaves storage unchanged")


def sqlite_server(work: Path) -> None:
    print("== sqlite server")
    uvx = shutil.which("uvx")
    if not uvx:
        check(False, "sqlite: uvx is installed")
        return
    database = work / "fixture.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE fixture (value TEXT)")
        connection.execute("INSERT INTO fixture VALUES ('sqlite-sentinel')")
    calls = [("tables", "list_tables", {}), ("schema", "describe_table", {"table_name": "fixture"}),
             ("read", "read_query", {"query": "SELECT * FROM fixture"}),
             ("write", "write_query", {"query": "INSERT INTO fixture VALUES ('forbidden')"})]
    res, _ = session([MOAT, "wrap", "--preset", "sqlite", "--no-prompt", "--", uvx,
                      "--with", f"mcp=={SQLITE_MCP_VERSION}",
                      f"mcp-server-sqlite=={SQLITE_SERVER_VERSION}", "--db-path", str(database)], calls, timeout=180)
    check("fixture" in text_of(res["tables"]), "sqlite: schema tables can be listed")
    check("value" in text_of(res["schema"]), "sqlite: table schema can be read")
    check("sqlite-sentinel" in text_of(res["read"]), "sqlite: SELECT works")
    check(is_blocked(res["write"]), "sqlite: unattended writes require approval")
    with sqlite3.connect(database) as connection:
        check(connection.execute("SELECT COUNT(*) FROM fixture").fetchone()[0] == 1,
              "sqlite: denied write leaves database unchanged")


def fetch_server(work: Path) -> None:
    print("== fetch server")
    uvx = shutil.which("uvx")
    if not uvx:
        check(False, "fetch: uvx is installed")
        return

    class Fixture(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"User-agent: *\nAllow: /\n" if self.path == "/robots.txt" else b"fetch-sentinel"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/fixture"
        res, _ = session([MOAT, "wrap", "--preset", "fetch", "--no-prompt", "--", uvx,
                          f"mcp-server-fetch=={FETCH_SERVER_VERSION}", "--allow-private-ips"],
                         [("read", "fetch", {"url": url}), ("write", "http_post", {"url": url})], timeout=180)
        check("fetch-sentinel" in text_of(res["read"]), "fetch: local HTTP fixture can be read")
        check(is_blocked(res["write"]), "fetch: write tools are blocked")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def postgres_server(work: Path) -> None:
    print("== PostgreSQL server")
    docker = shutil.which("docker")
    if not docker:
        check(False, "postgres: Docker is installed and running")
        return

    name = f"moat-postgres-check-{os.getpid()}"
    password = "moat-fixture-only"
    database = "moat_acceptance"
    try:
        container = subprocess.run(
            [docker, "run", "--detach", "--rm", "--name", name,
             "--env", f"POSTGRES_PASSWORD={password}", "--env", "POSTGRES_USER=moat",
             "--env", f"POSTGRES_DB={database}", "--publish", "127.0.0.1::5432", POSTGRES_IMAGE],
            capture_output=True, text=True, timeout=180,
        )
        if container.returncode:
            check(False, f"postgres: disposable {POSTGRES_IMAGE} fixture starts", container.stderr)
            return

        container_id = container.stdout.strip()
        port = subprocess.run([docker, "port", container_id, "5432/tcp"],
                              capture_output=True, text=True, timeout=15)
        host_port = port.stdout.strip().rsplit(":", 1)[-1]
        if port.returncode or not host_port.isdigit():
            check(False, "postgres: Docker publishes an ephemeral loopback port", port.stderr or port.stdout)
            return
        connection = f"postgresql://moat:{password}@127.0.0.1:{host_port}/{database}"
        ready = False
        deadline = time.time() + 60
        while time.time() < deadline:
            probe = subprocess.run(
                [docker, "exec", container_id, "pg_isready", "-U", "moat", "-d", database],
                capture_output=True, text=True, timeout=10,
            )
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(1)
        check(ready, "postgres: fixture accepts connections", probe.stderr or probe.stdout)
        if not ready:
            return
        seed = subprocess.run(
            [docker, "exec", container_id, "psql", "-U", "moat", "-d", database, "-v", "ON_ERROR_STOP=1",
             "-c", "CREATE TABLE fixture (value text); INSERT INTO fixture VALUES ('postgres-sentinel');"],
            capture_output=True, text=True, timeout=20,
        )
        check(seed.returncode == 0, "postgres: fixture table is seeded", seed.stderr)
        if seed.returncode:
            return

        direct, _ = session([*NPX, "-y", POSTGRES_SERVER, connection],
                            [("read", "query", {"sql": "SELECT value FROM fixture"})], timeout=180)
        listed = direct["tools"].get("result", {}).get("tools", [])
        check(any(tool.get("name") == "query" for tool in listed),
              "postgres: pinned server advertises its query tool", json.dumps(listed)[:400])
        check("postgres-sentinel" in text_of(direct["read"]),
              "postgres: pinned server successfully reads the fixture", text_of(direct["read"]))

        wrapped, _ = session(
            [MOAT, "wrap", "--preset", "postgres", "--no-prompt", "--", *NPX, "-y", POSTGRES_SERVER, connection],
            [("read", "query", {"sql": "SELECT value FROM fixture"}),
             ("write", "query", {"sql": "INSERT INTO fixture VALUES ('forbidden')"})], timeout=180,
        )
        check(is_blocked(wrapped["read"]),
              "postgres: preset blocks generic query pending approval (server tool is query)", text_of(wrapped["read"]))
        check(is_blocked(wrapped["write"]), "postgres: unattended INSERT is blocked", text_of(wrapped["write"]))
        verify = subprocess.run(
            [docker, "exec", container_id, "psql", "-U", "moat", "-d", database, "-Atqc",
             "SELECT count(*) || ':' || min(value) FROM fixture"],
            capture_output=True, text=True, timeout=20,
        )
        check(verify.returncode == 0 and verify.stdout.strip() == "1:postgres-sentinel",
              "postgres: blocked INSERT leaves database unchanged", verify.stderr or verify.stdout)
    finally:
        subprocess.run([docker, "rm", "--force", name], capture_output=True, text=True, timeout=30)


def playwright_server(work: Path) -> None:
    print("== Playwright server")

    class Fixture(http.server.BaseHTTPRequestHandler):
        posts = 0

        def do_GET(self) -> None:
            body = b"<!doctype html><title>moat-playwright-fixture</title><button>Modify</button>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            type(self).posts += 1
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        browser_dir = work / "playwright-profile"
        chrome = Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe"
        edge_root = os.environ.get("PROGRAMFILES(X86)") or os.environ.get("PROGRAMFILES", "C:/Program Files")
        edge = Path(edge_root) / "Microsoft/Edge/Application/msedge.exe"
        installed_browser = ("chrome", chrome) if chrome.is_file() else ("msedge", edge) if edge.is_file() else ("chromium", None)
        if os.name != "nt":
            for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
                if executable := shutil.which(name):
                    installed_browser = ("chromium", executable)
                    break
        command = [*NPX, "-y", PLAYWRIGHT_SERVER, "--headless", "--browser", installed_browser[0],
                   "--allowed-hosts", "127.0.0.1", "--user-data-dir", str(browser_dir),
                   "--output-dir", str(work / "playwright-output")]
        if installed_browser[1]:
            command.extend(["--executable-path", str(installed_browser[1])])
        res, _ = session(
            [MOAT, "wrap", "--preset", "playwright", "--no-prompt", "--", *command],
            [("navigate", "browser_navigate", {"url": url}),
             ("snapshot", "browser_snapshot", {})],
            timeout=180,
        )
        tools = res["tools"].get("result", {}).get("tools", [])
        available = {tool.get("name") for tool in tools}
        for name in ("browser_evaluate", "browser_file_upload"):
            check(name in available, f"playwright: pinned server advertises {name}", json.dumps(tools)[:400])
        check(not is_blocked(res["navigate"]) and "moat-playwright-fixture" in text_of(res["navigate"]),
              "playwright: preset allows navigation to the local fixture", text_of(res["navigate"]))
        check(not is_blocked(res["snapshot"]) and "Modify" in text_of(res["snapshot"]),
              "playwright: preset allows reading the page snapshot", text_of(res["snapshot"]))
        denied_calls = [
            ("evaluate", "browser_evaluate", {"function": "async () => { await fetch('/modify', { method: 'POST' }); return 'posted'; }"}),
            ("upload", "browser_file_upload", {"paths": [str(work / "missing-upload.txt")]})]
        if "browser_download" in available:
            denied_calls.append(("download", "browser_download", {"url": url}))
        denied, _ = session(
            [MOAT, "wrap", "--preset", "playwright", "--no-prompt", "--", *command],
            denied_calls, timeout=180,
        )
        for label in ("evaluate", "upload", *( ["download"] if "browser_download" in available else [])):
            check(is_blocked(denied[label]), f"playwright: preset blocks {label}", text_of(denied[label]))
        check(Fixture.posts == 0, "playwright: blocked evaluation caused no HTTP POST", str(Fixture.posts))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="moat-real-"))
    jail, outside = (work / "jail").resolve(), (work / "outside").resolve()
    (jail / "sub").mkdir(parents=True)
    (jail / ".ssh").mkdir()
    outside.mkdir()
    (jail / "a.txt").write_text("hello from inside\n")
    (jail / "secrets.env").write_text(
        "GROQ=gsk_A1b2C3d4E5f6G7h8I9j0K1l2\nOPENAI_API_KEY=abcdefgh12345678\nDB_PASSWORD=hunter2hunter2\nDEBUG=1\n")
    (jail / "base64_secret.txt").write_text(
        "API_KEY=dGVzdERMT1dTU0VDUkVULWJhc2U2NA==\n")
    (jail / ".ssh" / "id_rsa").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n")
    (outside / "o.txt").write_text("TOP SECRET OUTSIDE\n")
    symlinks = os.name != "nt"
    if symlinks:
        os.symlink(outside, jail / "link_out")
        os.symlink(outside / "o.txt", jail / "link_file")
    else:
        subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "mklink", "/J",
                        str(jail / "link_out"), str(outside)], check=True, capture_output=True)

    J, O = str(jail), str(outside)
    calls = [
        ("read_inside", "read_text_file", {"path": f"{J}/a.txt"}),
        ("read_secrets", "read_text_file", {"path": f"{J}/secrets.env"}),
        ("read_ssh", "read_text_file", {"path": f"{J}/.ssh/id_rsa"}),
        ("read_base64_secret", "read_text_file", {"path": f"{J}/base64_secret.txt"}),
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
    else:
        calls.append(("read_junction", "read_text_file", {"path": f"{J}/link_out/o.txt"}))

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
    check("dGVzdERMT1dTU0VDUkVULWJhc2U2NA==" not in secrets, "Base64-encoded secret is masked", secrets)
    check("DEBUG=1" in secrets, "harmless lines stay readable", secrets)
    check("BEGIN OPENSSH" not in text_of(res["read_ssh"]), "private key block is masked", text_of(res["read_ssh"]))
    for label in ("read_outside", "read_traversal", "read_multi_mixed", "list_outside", "media_outside",
                  "write_outside", "move_out", "write_protected"):
        check(is_blocked(res[label]), f"{label} is blocked", text_of(res[label]))
    if symlinks:
        for label in ("read_symlink_file", "read_symlink_dir"):
            check(is_blocked(res[label]), f"{label} is blocked", text_of(res[label]))
    else:
        check(is_blocked(res["read_junction"]), "Windows directory junction escape is blocked")
    check(not is_blocked(res["tree_inside"]) and "children" in text_of(res["tree_inside"]), "directory_tree works", text_of(res["tree_inside"]))
    check(not is_blocked(res["info_inside"]), "get_file_info works", text_of(res["info_inside"]))
    check(not is_blocked(res["write_inside"]) and (jail / "new.txt").exists(), "write inside the jail works")
    check(not (outside / "new.txt").exists() and not (outside / "moved.txt").exists(), "nothing was written outside the jail")
    check(not (jail / "moat.toml").exists(), "moat.toml was not created")
    verify = subprocess.run([MOAT, "audit", "verify", "--require-seal", str(audit)], capture_output=True, text=True)
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
    memory_server(work)
    sqlite_server(work)
    fetch_server(work)
    postgres_server(work)
    playwright_server(work)

    shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'all checks passed' if not FAILED else str(len(FAILED)) + ' check(s) failed: ' + ', '.join(FAILED)}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
