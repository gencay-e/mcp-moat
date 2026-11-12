# Security Model

`mcp-moat` (`moat`) is a policy-enforcing proxy between a Model Context Protocol (MCP) client and an MCP server over `stdio`. It inspects JSON-RPC 2.0 requests and responses to enforce directory jails, tool allowlists, command filters, output secret masking, and hash-chained audit logging.

See also [`SECURITY.md`](../SECURITY.md) for vulnerability reporting and known limitations, and [`threat-model.md`](threat-model.md) for the short version.

## Deployment Context

* Runs locally as a wrapper binary (`crates/mcp-moat-cli/src/main.rs`) launched by an MCP host (such as Claude Desktop, Cursor, or a CLI orchestrator) in front of a child MCP server process (`crates/mcp-moat-proxy/src/engine.rs`).
* Does **not** sandbox the wrapped MCP server process: the child server runs under the operator's OS user account. `mcp-moat` mediates only the MCP JSON-RPC protocol stream and operator terminal prompts (`crates/mcp-moat-tty/src/console.rs`).

## Trust Boundaries and Inputs

### Untrusted Inputs

1. **MCP Client JSON-RPC Stream (`stdin` in `crates/mcp-moat-proxy/src/engine.rs`):**
   * The MCP client (an LLM agent that may be confused or prompt-injected by untrusted files/web content) sends `tools/call`, `resources/read`, and other JSON-RPC messages. Tool names, file path arguments, URI parameters, and shell command strings are untrusted.
2. **Upstream MCP Server JSON-RPC Stream (`stdout` of child process in `crates/mcp-moat-proxy/src/engine.rs`):**
   * Server responses (`tools/call` results, `resources/read` contents, `tools/list` schemas, and error payloads) are untrusted and may contain secrets from the local environment or prompt-injection payloads.

### Trusted Inputs

* **Operator CLI flags and policy file** (`moat.toml` loaded in `crates/mcp-moat-core/src/policy.rs`, CLI flags in `crates/mcp-moat-cli/src/main.rs`).
* **Operator interactive terminal responses** read directly from `/dev/tty` or `CONIN$` (`crates/mcp-moat-tty/src/console.rs`).
* **Local filesystem metadata** queried by `crates/mcp-moat-core/src/policy.rs` during path canonicalization.

## Security Invariants

1. **Path Jail Enforcement (`crates/mcp-moat-core/src/policy.rs`):**
   * The path jail is checked first. Every path argument and `file://` URI inspected by `PolicyEngine` must resolve inside one of the canonicalized `allowed_paths` after symlink resolution, percent-decoding, Unicode normalization, and rejection of `..` traversal (also percent-encoded), UNC/NT namespace paths (`\\`, `//`, `\\?\`), Windows reserved device names (`CON`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), and DOS 8.3 short-name segments (`~1`). One path that is invalid or outside the jail blocks the whole call, whatever the tool name, the allow lists, the read-only setting or the other arguments (`command`, `url`, `query`, `content`) are. A call with a command argument and a path outside the jail is blocked, not sent to the operator.
   * Only local paths and `file://` URIs are filesystem paths. An `http://` or `https://` URL in a URL argument (`url`, `uri`, `href`, `*_url`) is not a path and is not jail-checked; a tool that fetches URLs still has to be authorized (listed or enabled by a preset). The same URL in a path argument (`path`, `file`, ...) is rejected. A `file://` URL or a bare path in a URL argument is jail-checked.
   * Writes or edits targeting `moat.toml`, `fence.toml`, the `--config` file or an entry of `protected_files` require operator approval, even inside an allowed directory, and are denied under `--no-prompt`.
2. **Default-Deny for Unknown Tools and Unverified File Tools (`crates/mcp-moat-core/src/policy.rs`):**
   * Order of checks. The first match wins:

     | # | Check | Result |
     |---|---|---|
     | 1 | tool is in `hidden_tools`, or `arguments` is not a JSON object | Block |
     | 2 | any path-like argument is invalid or outside the jail | Block |
     | 3 | file tool (by name) without any path argument, and not in `non_file_tools` | Block |
     | 4 | modifying tool and `read_only` | Block |
     | 5 | tool is not authorized and does not modify | Block |
     | 6 | command argument matches `blocked_commands` or a blocked regex | Block |
     | 7 | any other command argument (metacharacters or not) | AskOperator |
     | 8 | modifying tool, and: a path is a protected file, or `require_approval_on_write` is set (with or without a path), or the tool is not authorized | AskOperator |
     | 9 | none of the above | Allow |

     AskOperator is a denial under `--no-prompt` and when no terminal is available. Step 5 comes before step 7, so a `command` argument never turns an unknown, non-modifying tool into a prompt. Step 8 applies to every modifying tool, also one that takes no path (`create_entities`, `write_query`). The protected-file test needs a path; `require_approval_on_write` does not.
   * Method allowlist. Before any of these checks, the proxy forwards only the standard MCP client-to-server methods: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`, `prompts/list`, `prompts/get`, `completion/complete`, `logging/setLevel`, and the notifications `notifications/initialized`, `notifications/cancelled`, `notifications/progress` and `notifications/roots/list_changed`. Replies to server requests (no `method`, for example `roots/list`, `sampling/createMessage`, elicitation) are forwarded. Any other method is not forwarded: a request gets `-32601` ("Method '...' is not allowed by mcp-moat policy"), a notification is dropped, and both are audited as blocked. `allowed_methods` in `moat.toml` adds exact method names for server extensions. Under `--monitor` the method is forwarded and the category is logged.
   * Audit failure. If the audit log cannot be written, nothing further is forwarded; each request with an id gets `-32603` ("Request not forwarded: the audit log could not be written"), notifications get no response.
   * Authorization (used in steps 5 and 8) comes only from: `always_allow_tools`, `custom_always_allow_tools` (presets fill these lists), or the exact name of a tool of `@modelcontextprotocol/server-filesystem` (`read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`, `write_file`, `edit_file`, `append_file`, `copy_file`, `create_directory`, `list_directory`, `list_directory_with_sizes`, `directory_tree`, `move_file`, `search_files`, `get_file_info`, `list_allowed_directories`). A modifying standard tool authorizes only when the call has a path (a `write_file` call without a path, exempted by `non_file_tools`, needs approval). The default `always_allow_tools` lists `list_directory`, `read_file`, `search_files` and `grep`. A name that only matches a generic pattern (`read_*`, `write_*`, `get_*`, `*_file`) or a look-alike (`rm`, `cat`, `shred`, `wipe`, `purge_dir`, `delete_file`) never authorizes a tool.
   * Classification is separate from authorization. `custom_modifying_tools` and the built-in name rules only classify a tool as modifying (read-only mode blocks it, it counts as a write). An unlisted modifying tool with its paths inside the jail, or without a path, needs operator approval (denied under `--no-prompt`), an unlisted tool that does not modify is blocked.
   * `ignore_path_keys` in `moat.toml` exempts argument keys from the path check for every tool (operator decision). Keys ignored by a preset apply only to the tools of that preset.
   * A command argument is never allowed automatically: for a tool that is authorized or modifying, a blocked command is blocked and any other command needs operator approval (denied under `--no-prompt`). A tool that is neither authorized nor modifying is blocked whatever its arguments are.
   * Any tool whose name matches file-access patterns and is not in `non_file_tools` must supply at least one valid path argument verified against the path jail, or be blocked. This includes calls with no arguments, empty arguments or `null`. `list_allowed_directories` is exempt. `non_file_tools` only removes the path requirement; paths that are present are always checked, and it never authorizes a tool.
   * `require_approval_on_write` makes every authorized modifying tool ask, also a listed pathless one such as `create_entities` in the `memory` preset.
   * Presets list their pathless tools in `non_file_tools`: `sqlite` (`read_query`, `list_tables`, `describe_table`, `show_schema`, `write_query`, `execute_query`, `create_table`, `drop_table`), `memory` (`read_graph`, `search_nodes`, `open_nodes`, `create_entities`, `create_relations`, `delete_entities`, `delete_relations`, `add_observations`) and `fetch` (`fetch`, `http_get`, `web_search`, `read_url`). Without the preset, these names are unknown tools. Read tools of a preset are allowed, modifying tools of `sqlite` and `memory` need operator approval, modifying tools of `fetch` are blocked (the preset sets `read_only`), and `git_add`, `git_commit`, `git_create_branch` and `git_checkout` are allowed while `git_push`, `git_reset` and `git_merge` need operator approval.
3. **Out-of-Band Operator Prompting (`crates/mcp-moat-tty/src/console.rs`):**
   * Approval prompts must read from the controlling terminal (`/dev/tty` on Unix, `CONIN$` on Windows), never from `stdin` (which carries the agent's JSON-RPC stream). If the terminal cannot be opened or `--no-prompt` is active, any action requiring approval must fail closed (`Deny`). `--monitor` is the exception by design: it forwards everything and only logs.
4. **DLP Secret Redaction on Upstream Responses (`crates/mcp-moat-core/src/dlp.rs`):**
   * Server responses and error messages forwarded to the client must pass through `DlpEngine`, replacing matched credential patterns with `[MCP-MOAT-REDACTED-SECRET]`.
   * Log output (any `RUST_LOG` level) contains method names, ids, byte lengths, tool names and decisions, never request lines, arguments, responses, malformed input or the environment. The `--monitor` diagnostic on stderr names the tool (sanitized, length-capped) and a fixed category, never the block reason, path or URI of the request. Tested in `crates/mcp-moat-cli/tests/cli_test.rs` with `RUST_LOG=trace`, also with `--monitor`. The approval prompt and `moat audit` output replace control characters in request-derived text; the prompt may show the target path.
5. **Audit Log Hash-Chain Integrity (`crates/mcp-moat-core/src/audit.rs`):**
   * Each JSONL audit entry records `prev_hash` and `hash = SHA-256(prev_hash || canonical_fields)`, and `moat audit verify` must reject any modified, reordered, or deleted intermediate entry within a session.

## In-Scope Vulnerability Classes

* **Path jail bypass** in `crates/mcp-moat-core/src/policy.rs` allowing `tools/call` or `resources/read` to access paths outside `allowed_paths` or modify `moat.toml`.
* **Policy or approval bypass** in `crates/mcp-moat-proxy/src/engine.rs` or `crates/mcp-moat-core/src/policy.rs` allowing unapproved tools, write operations in `--read-only` mode, or blocked commands to execute without operator confirmation.
* **JSON-RPC framing / smuggling flaws** in `crates/mcp-moat-proxy/src/engine.rs` or `crates/mcp-moat-core/src/protocol.rs` that forward uninspected tool calls to the child server.
* **Denial of Service / panic in proxy runtime** triggered by malformed JSON-RPC messages or oversized payloads (`unwrap()`/`expect()` on untrusted input in `crates/mcp-moat-core` or `crates/mcp-moat-proxy`).
* **Audit chain verification bypass** in `crates/mcp-moat-core/src/audit.rs` where tampered mid-session entries pass `moat audit verify`.

## Out of Scope / Non-Issues

* **Direct OS syscalls made by a malicious MCP server binary** that do not pass paths through MCP tool arguments (`mcp-moat` is a protocol proxy, not an OS kernel sandbox).
* **Filesystem TOCTOU races** between `mcp-moat`'s path check and the MCP server's subsequent `open()` syscall.
* **Command filter evasions** (variable expansion, aliases, wrapper scripts) that still trigger the operator prompt (or are denied under `--no-prompt`), as documented in `SECURITY.md`.
* **Whole-file audit log deletion or full-chain recomputation** by an attacker who already has write access to the local audit file (audit hashes are unkeyed SHA-256).

## Tests

The invariants above are tested in `crates/mcp-moat-core/tests/invariants.rs` (one section per invariant, a decision table for every preset, deterministic property checks: an outside path is always `Block`, an unauthorized tool is never `Allow`, and a decision matrix of 1840 cases over authorization, classification, path, command argument, `require_approval_on_write` and `read_only` that must equal the table above, written as an independent rule function in `crates/mcp-moat-core/tests/common/mod.rs`) and `crates/mcp-moat-proxy/tests/no_prompt.rs` (no approval is granted without a console; the same matrix runs through the proxy).
