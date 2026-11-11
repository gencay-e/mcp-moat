# Security Model

`mcp-moat` (`moat`) is a policy-enforcing proxy between a Model Context Protocol (MCP) client and an MCP server over `stdio` (and optionally an experimental HTTP+SSE transport behind `--features experimental-sse`). It inspects JSON-RPC 2.0 requests and responses to enforce directory jails, tool allowlists, command filters, output secret masking, and hash-chained audit logging.

See also [`SECURITY.md`](../SECURITY.md) for vulnerability reporting and known limitations, and [`threat-model.md`](threat-model.md) for the short version.

## Deployment Context

* Runs locally as a wrapper binary (`crates/mcp-moat-cli/src/main.rs`) launched by an MCP host (such as Claude Desktop, Cursor, or a CLI orchestrator) in front of a child MCP server process (`crates/mcp-moat-proxy/src/engine.rs`).
* Does **not** OS-sandbox the wrapped MCP server process: the child server runs under the operator's OS user account. `mcp-moat` mediates only the MCP JSON-RPC protocol stream and operator terminal prompts (`crates/mcp-moat-tty/src/console.rs`).

## Trust Boundaries and Inputs

### Untrusted Inputs

1. **MCP Client JSON-RPC Stream (`stdin` in `crates/mcp-moat-proxy/src/engine.rs`):**
   * The MCP client (an LLM agent that may be confused or prompt-injected by untrusted files/web content) sends `tools/call`, `resources/read`, and other JSON-RPC messages. Tool names, file path arguments, URI parameters, and shell command strings are untrusted.
2. **Upstream MCP Server JSON-RPC Stream (`stdout` of child process in `crates/mcp-moat-proxy/src/engine.rs`, or HTTP+SSE upstream in `crates/mcp-moat-proxy/src/sse.rs`):**
   * Server responses (`tools/call` results, `resources/read` contents, `tools/list` schemas, and error payloads) are untrusted and may contain secrets from the local environment or prompt-injection payloads.
3. **Local HTTP Clients to Experimental SSE Proxy (`crates/mcp-moat-proxy/src/sse.rs`, only when built with `--features experimental-sse`):**
   * Browser tabs or local processes attempting cross-origin / DNS-rebinding requests against the local listener.

### Trusted Inputs

* **Operator CLI flags and policy file** (`moat.toml` loaded in `crates/mcp-moat-core/src/policy.rs`, CLI flags in `crates/mcp-moat-cli/src/main.rs`).
* **Operator interactive terminal responses** read directly from `/dev/tty` or `CONIN$` (`crates/mcp-moat-tty/src/console.rs`).
* **Local filesystem metadata** queried by `crates/mcp-moat-core/src/policy.rs` during path canonicalization.

## Security Invariants

1. **Path Jail Enforcement (`crates/mcp-moat-core/src/policy.rs`):**
   * Every path argument and `file://` URI inspected by `PolicyEngine` must resolve inside one of the canonicalized `allowed_dirs` after symlink resolution, percent-decoding, Unicode normalization, and rejection of `..` traversal, UNC/NT namespace paths (`\\`, `//`, `\\?\`), Windows reserved device names (`CON`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), and DOS 8.3 short-name segments (`~1`).
   * Writes or edits targeting `moat.toml`, `fence.toml`, the `--config` file or an entry of `protected_files` require operator approval, even inside an allowed directory, and are denied under `--no-prompt`.
2. **Default-Deny for Unknown Tools and Unverified File Tools (`crates/mcp-moat-core/src/policy.rs`):**
   * Any tool not explicitly listed in `always_allow_tools` (or enabled via `--preset`) requires operator approval (or is denied under `--no-prompt`).
   * Any tool whose name matches file-access patterns (`read_*`, `write_*`, `get_*`, etc.) and is not exempted in `non_file_tools` must supply at least one valid path argument verified against the path jail, or be blocked.
3. **Out-of-Band Operator Prompting (`crates/mcp-moat-tty/src/console.rs`):**
   * Approval prompts must read from the controlling terminal (`/dev/tty` on Unix, `CONIN$` on Windows), never from `stdin` (which carries the agent's JSON-RPC stream). If the terminal cannot be opened or `--no-prompt` is active, any action requiring approval must fail closed (`Deny`).
4. **DLP Secret Redaction on Upstream Responses (`crates/mcp-moat-core/src/dlp.rs`):**
   * Server responses and error messages forwarded to the client must pass through `DlpEngine`, replacing matched credential patterns with `[MCP-MOAT-REDACTED-SECRET]`.
5. **Audit Log Hash-Chain Integrity (`crates/mcp-moat-core/src/audit.rs`):**
   * Each JSONL audit entry records `prev_hash` and `hash = SHA-256(prev_hash || canonical_fields)`, and `moat audit verify` must reject any modified, reordered, or deleted intermediate entry within a session.

## In-Scope Vulnerability Classes

* **Path jail bypass** in `crates/mcp-moat-core/src/policy.rs` allowing `tools/call` or `resources/read` to access paths outside `allowed_dirs` or modify `moat.toml`.
* **Policy or approval bypass** in `crates/mcp-moat-proxy/src/engine.rs` or `crates/mcp-moat-core/src/policy.rs` allowing unapproved tools, write operations in `--read-only` mode, or blocked commands to execute without operator confirmation.
* **JSON-RPC framing / smuggling flaws** in `crates/mcp-moat-proxy/src/engine.rs` or `crates/mcp-moat-core/src/protocol.rs` that forward uninspected tool calls to the child server.
* **Denial of Service / panic in proxy runtime** triggered by malformed JSON-RPC messages or oversized payloads (`unwrap()`/`expect()` on untrusted input in `crates/mcp-moat-core` or `crates/mcp-moat-proxy`).
* **Audit chain verification bypass** in `crates/mcp-moat-core/src/audit.rs` where tampered mid-session entries pass `moat audit verify`.

## Out of Scope / Non-Issues

* **Direct OS syscalls made by a malicious MCP server binary** that do not pass paths through MCP tool arguments (`mcp-moat` is a protocol proxy, not an OS kernel sandbox).
* **Filesystem TOCTOU races** between `mcp-moat`'s path check and the MCP server's subsequent `open()` syscall.
* **Command filter evasions** (variable expansion, aliases, wrapper scripts) that still trigger the operator prompt (or are denied under `--no-prompt`), as documented in `SECURITY.md`.
* **Whole-file audit log deletion or full-chain recomputation** by an attacker who already has write access to the local audit file (audit hashes are unkeyed SHA-256).
* **Known limitations of `experimental-sse`** (`crates/mcp-moat-proxy/src/sse.rs`, disabled by default) already listed in `SECURITY.md` (lack of TLS, unauthenticated session IDs, unbounded upstream header/line lengths).
