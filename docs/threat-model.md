# Threat model

moat sits between an MCP client (an AI agent) and an MCP server on stdio. It checks tool calls going to the server and results coming back. It does not isolate the server process. The server keeps the rights of your user.

## Who is assumed to be the attacker

A confused or manipulated agent, for example through a prompt injection in a web page or file. The agent may ask the server for files outside the project, for secrets, or for changes to its own safety configuration. The operator, the machine and the moat binary are trusted.

## What moat checks

| Attack | What moat does | Where it is tested |
|---|---|---|
| Read or write outside the allowed folder (`/etc/passwd`, `..` segments, absolute paths) | Path jail: the request is rejected | `crates/mcp-moat-core/tests`, `scripts/real_server_check.py` (server-filesystem) |
| Symlink pointing out of the folder | Symlinks are resolved and checked | `scripts/real_server_check.py` on Linux; not on macOS or Windows |
| Changing the configuration (`moat.toml`) through the agent | Writes to protected files need operator approval (denied with `--no-prompt`) | `crates/mcp-moat-core/tests` |
| Secrets in server output (API keys, tokens, `key=value` lines, JSON text) | Known formats are replaced by `[MCP-MOAT-REDACTED-SECRET]` | `real_server_findings.rs`, `real_server_check.py` |
| Destructive shell commands | Tokenized command filter, then operator prompt | `crates/mcp-moat-core/tests`; the filter is not a shell parser |
| Altering the log afterwards | Hash chain over audit lines, checked by `moat audit verify` | `crates/mcp-moat-core/tests` |

## What moat does not do

* It does not sandbox the server. A server can read a file in a way moat does not see as a path argument.
* It does not stop time-of-check to time-of-use changes of a path.
* It does not find secrets in unknown formats or in encoded form.
* The command filter tokenizes the command line, collapses whitespace, resolves path prefixes to the program name and compares flags, so `rm  -rf /`, `rm -r -f /`, `/bin/rm -fr /` and `sudo rm -rf /` are blocked. It is not a full shell parser: variable expansion, aliases, unquoted `eval` payloads, wrapper scripts and encoded commands other than the PowerShell pattern are not resolved. Those commands go to the operator prompt (or are denied with `--no-prompt`).
* The audit hash is not keyed. Someone with write access can rebuild a whole log.
* Windows and macOS behaviour is tested in CI but was not verified by hand on real systems.

## Findings from tests against real servers

Running moat in front of the real servers (`@modelcontextprotocol/server-filesystem`, `mcp-server-git`, `server-everything`) found problems that mock servers did not show. All are fixed and have a regression test:

* Secrets in `.env` lines and in JSON text were not masked.
* The tool `directory_tree` was not treated as a file tool.
* git arguments such as `target` or `revision` were read as paths and blocked legitimate calls.
* A list of relative file names was not resolved against the repository path.
* Windows 8.3 short names could bypass the path comparison.

Run the check yourself: `python scripts/real_server_check.py` (needs Node.js, Python and `mcp-server-git`).
