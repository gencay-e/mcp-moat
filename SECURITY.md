# Security

## Reporting a vulnerability

Please report vulnerabilities privately and do not open a public issue. Use GitHub's private vulnerability reporting for `gencay-e/mcp-moat` (Security tab, "Report a vulnerability").

Supported: the latest 0.1.x release.

## What mcp-moat is

A policy proxy between an MCP client and an MCP server on stdio. It reduces the damage a confused or manipulated agent can do through tool calls. It is not a sandbox and does not isolate the MCP server process. The wrapped server runs with your user's rights.

## Known limits

These are known and are not fixed in 0.1.0.

**Command filter**
* `blocked_commands` is tokenized before matching. Whitespace is collapsed, path prefixes are resolved to the program name (`/bin/rm` becomes `rm`) and combined short flags are compared as sets. `rm  -rf /`, `rm -r -f /`, `/bin/rm -fr /` and `sudo rm -rf /` match the default entries, while `rm -rf /tmp/build` does not and goes to the operator prompt.
* It is not a full shell parser. Variable expansion, aliases, unquoted `eval` payloads, wrapper scripts and encoded commands other than the PowerShell pattern are not resolved. Those commands go to the operator prompt.
* Commands that do not match are not blocked. They go to the operator prompt. With `--no-prompt` they are denied. With `--monitor` they are forwarded.
* Shell metacharacters (`|`, `&`, `;`, `$`, backticks, redirects) lead to an operator prompt, not to a block.
* Approval is only as good as the operator reading the prompt.

**Paths**
* Symlinks are resolved and checked. `scripts/real_server_check.py` tests symlinks to the outside on Linux; on macOS and Windows they are not tested.
* A path can change between the check and the use by the MCP server (time-of-check to time-of-use). This cannot be prevented from a proxy.
* Hardlink detection (link count above 1) exists on Unix only and has no automated test. On Windows there is no hardlink check.
* Reserved Windows device names are rejected on every platform. The list covers `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `CLOCK$`, `CONFIG$`, `COM1`-`COM9` and `LPT1`-`LPT9`, but not every reserved name. This also blocks real Linux and macOS directories with these names.
* Path segments that look like DOS 8.3 short names (`PROGRA~1`, `RUNNER~1`, `MOAT~1.TOM`) are rejected on every platform. This also rejects a legitimate Windows path with a short user name, and a git revision such as `HEAD~1` if it is passed in a path argument (the git preset avoids this for its own argument names).
* The UNC and NT namespace checks are text checks. Besides `\\`, `//`, `\??\`, `/??/`, `\device\` and `/device/`, they reject `\GLOBAL??\`, `\GLOBALROOT\`, `\DosDevices\`, `\SystemRoot\`, `\BaseNamedObjects\`, `\ArcName\` and `\KernelObjects\`. Separators are normalized first, so mixed forms such as `\/?\C:\` are caught. They have not been tested against a real NTLM or SMB attack on Windows.

**Secret masking**
* Only known formats and long, mixed-class Base64/Base64url blobs are masked. Other secrets, short or low-complexity Base64 values, and secrets split over several messages are not found.
* The Base64 heuristic can redact benign data that happens to look like an encoded secret.
* Masking is meant for server output. It does not stop a server from leaking data in other ways.

**Audit log**
* The hash chain detects changed, reordered or removed lines in the middle of a session.
* It does not detect removal of lines at the end, removal of a whole session, removal of the file, or a log that was rebuilt from scratch. The hash is not keyed and there is no external anchor.
* Write errors to the audit file are ignored.
* If two sessions start in the same millisecond they can get the same session id and `moat audit verify` may report a false break.

**Configuration**
* Only `moat.toml` (and the old name `fence.toml`) are protected as configuration files by name. A file given with `--config` under another name is not.

**Experimental SSE proxy and bridge** (only built with `--features experimental-sse`)
* No TLS. `https://` is rejected. Traffic to the upstream server is not encrypted.
* A POST with an unknown session id is forwarded to the upstream server with its original path.
* Lines and headers from the upstream server have no length limit.
* The path jail checks the local file system, not the remote one.
* Little test coverage.

**Platforms**
* Linux is tested in development and CI.
* macOS and Windows tests run in CI. Windows-specific behavior (UNC, device names, `CONIN$` prompts) and macOS terminal behavior were not verified by hand on real systems.
* Ctrl+C handling (child termination, exit code 130) has not been checked on every platform.

**Supply chain**
* Release archives come with a `SHA256SUMS` file. They are not signed. Dependencies are not audited with `cargo audit` or `cargo deny` yet.
