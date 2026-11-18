# Security

## Reporting a vulnerability

Please report vulnerabilities privately and do not open a public issue. Use GitHub's private vulnerability reporting for `gencay-e/mcp-moat` (Security tab, "Report a vulnerability").

Supported: the latest published release.

## What mcp-moat is

A policy proxy between an MCP client and an MCP server on stdio. It reduces the damage a confused or manipulated agent can do through tool calls. It is not a sandbox and does not isolate the MCP server process. The wrapped server runs with your user's rights.

## Known limits

**Command filter**
* `blocked_commands` is tokenized before matching. Whitespace is collapsed, path prefixes are resolved to the program name (`/bin/rm` becomes `rm`) and combined short flags are compared as sets. `rm  -rf /`, `rm -r -f /`, `/bin/rm -fr /` and `sudo rm -rf /` match the default entries, while `rm -rf /tmp/build` does not and goes to the operator prompt.
* It is not a full shell parser. Blocked-command rules and regexes are checked against command segments and recognized nested wrappers, including `sh`/`bash`/`zsh -c`, `cmd /c`, `powershell`/`pwsh -c`, and `env`, `nohup`, `nice`, `timeout` and `xargs`. Variable expansion, aliases, unquoted `eval` payloads and arbitrary wrapper scripts are not resolved. Those cases still need operator review (or are denied with `--no-prompt`).
* Commands that do not match are not blocked. They go to the operator prompt. With `--no-prompt` they are denied. With `--monitor` they are forwarded.
* `;`, `&&`, `||`, and `|` are split into command segments before blocked-command matching. Do not rely on this filter as a shell parser.
* Approval is only as good as the operator reading the prompt.

**Paths**
* The jail resolves existing path components, including symlinks and Windows junctions. Existing file components are checked for hardlinks on Unix and Windows.
* A path can change between the check and the use by the MCP server (time-of-check to time-of-use). This cannot be prevented from a proxy.
* Reserved Windows device names are rejected on every platform. The list covers `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `CLOCK$`, `CONFIG$`, `COM1`-`COM9` and `LPT1`-`LPT9`, but not every reserved name. This also blocks real Linux and macOS directories with these names.
* Path segments that look like DOS 8.3 short names (`PROGRA~1`, `RUNNER~1`, `MOAT~1.TOM`) are rejected on every platform. This also rejects a legitimate Windows path with a short user name, and a git revision such as `HEAD~1` if it is passed in a path argument (the git preset avoids this for its own argument names).
* The UNC and NT namespace checks are text checks. Besides `\\`, `//`, `\??\`, `/??/`, `\device\` and `/device/`, they reject `\GLOBAL??\`, `\GLOBALROOT\`, `\DosDevices\`, `\SystemRoot\`, `\BaseNamedObjects\`, `\ArcName\` and `\KernelObjects\`. Separators are normalized first, so mixed forms such as `\/?\C:\` are caught. They have not been tested against a real NTLM or SMB attack on Windows.

**Secret masking**
* Only known formats are masked. Other secrets, Base64-encoded secrets and secrets split over several messages are not found.
* `dlp_base64_heuristic = true` masks long mixed-class Base64 runs. It also masks benign data such as images, file paths and hashes, so it is off by default.
* Masking is meant for server output. It does not stop a server from leaking data in other ways.

**Audit log**
* The hash chain detects changed, reordered or removed lines in the middle of a session.
* Set `MOAT_AUDIT_KEY` to authenticate new entries with HMAC-SHA256; supply the same key when verifying. Without a key, hashes can be recomputed. `moat audit verify --require-seal` rejects sessions without a final `session_end` entry. It cannot detect deletion of a whole session or the entire file; keep an external record if that matters.
* If the audit file cannot be written, the action is not forwarded (fail closed).
* Session IDs use 128 bits from the operating system random number generator.

**Configuration**
* `moat.toml` (and the old name `fence.toml`) and the file given with `--config` are protected. Other configuration files that the agent should not change must be listed in `protected_files`.

**Platforms and presets**
* Unix tests cover symlinks and hardlinks. Windows tests cover directory junctions, NT namespace paths and hardlinks. The ConPTY check exercises approval input and Ctrl+C cleanup of the wrapped process tree.
* The PostgreSQL preset requires approval for the generic `query` tool exposed by `@modelcontextprotocol/server-postgres`, including `SELECT`.
* The Playwright preset allows navigation and snapshots without a filename. Evaluation, uploads, downloads, screenshots and snapshots with a filename require approval. The pinned Playwright server does not expose a download tool.

**Supply chain**
* Release archives come with a `SHA256SUMS` file. They are not signed.
* CI checks the dependencies with `cargo audit` against the RustSec advisory database.
