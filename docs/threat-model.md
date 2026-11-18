# Threat model

moat sits between an MCP client (an AI agent) and an MCP server on stdio. It checks tool calls going to the server and results coming back. It does not isolate the server process. The server keeps the rights of your user.

## Who is assumed to be the attacker

A confused or manipulated agent, for example through a prompt injection in a web page or file. The agent may ask the server for files outside the project, for secrets, or for changes to its own safety configuration. The operator, the machine and the moat binary are trusted.

## What moat checks

| Attack | What moat does | Where it is tested |
|---|---|---|
| Read or write outside the allowed folder (`/etc/passwd`, `..` segments, absolute paths) | Path jail: the request is rejected | `crates/mcp-moat-core/tests`, `scripts/real_server_check.py` (server-filesystem) |
| Symlink or hardlinked ancestor crossing the boundary | Existing path components are checked; Unix and Windows hardlink checks are implemented | Windows junction and NT namespace tests pass; real symlink test remains open after privilege error 1314; native Ubuntu/WSL link checks pass; macOS acceptance is open |
| Changing the configuration (`moat.toml`) through the agent | Writes to protected files need operator approval (denied with `--no-prompt`) | `crates/mcp-moat-core/tests` |
| Secrets in server output (API keys, tokens, `key=value` lines, JSON text) | Known formats are replaced by `[MCP-MOAT-REDACTED-SECRET]` | `real_server_findings.rs`, `real_server_check.py` |
| Destructive shell commands | Tokenized command filter, then operator prompt | `crates/mcp-moat-core/tests`; the filter is not a shell parser |
| Altering the log afterwards | Hash chain over audit lines, checked by `moat audit verify` | `crates/mcp-moat-core/tests` |

## What moat does not do

* It does not sandbox the server. A server can read a file in a way moat does not see as a path argument.
* It does not stop time-of-check to time-of-use changes of a path.
* It does not find secrets in unknown formats or in encoded form.
* The command filter checks blocked rules and regexes against command segments and recognized wrappers, including `sh`/`bash`/`zsh -c`, `cmd /c`, PowerShell `-c`, and process wrappers such as `env`, `nohup`, `nice`, `timeout`, and `xargs`. It is not a full shell parser: variable expansion, aliases, unquoted `eval` payloads and arbitrary scripts remain outside its analysis.
* Without `MOAT_AUDIT_KEY`, an attacker with write access can recompute the whole chain. With a key, HMAC-SHA256 authenticates entries; `--require-seal` requires a final `session_end` for every session. Neither setting detects whole-file or whole-session deletion without an external record.
* Windows junction and NT namespace tests pass, but a real symlink test is open after Windows returned privilege error 1314. The ConPTY approval and Ctrl+C test passed, including termination of the child and grandchild. The native Ubuntu/WSL workspace matrix passed (298 tests), including Unix link checks; Clippy and formatting passed. Native macOS acceptance is open because no macOS host was available.
* Real PostgreSQL baseline reads and denied writes pass, but its generic query tool still requires approval for SELECT. Playwright navigation/snapshot and denied evaluate/upload checks pass with Chrome; download acceptance remains open because the pinned server does not advertise browser_download.

## Findings from tests against real servers

Running moat in front of the real servers (`@modelcontextprotocol/server-filesystem`, `mcp-server-git`, `server-everything`) found problems that mock servers did not show. All are fixed and have a regression test:

* Secrets in `.env` lines and in JSON text were not masked.
* The tool `directory_tree` was not treated as a file tool.
* git arguments such as `target` or `revision` were read as paths and blocked legitimate calls.
* A list of relative file names was not resolved against the repository path.
* Windows 8.3 short names could bypass the path comparison.

Run the check yourself: `python scripts/real_server_check.py` (needs Node.js, Python and `mcp-server-git`).
