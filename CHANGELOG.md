# Changelog

## 0.3.0 (2026-11-13)

### Behavior changes (breaking: calls that 0.2.x allowed can now be blocked or need approval)

* **The path jail is checked first.** All path arguments are extracted and checked before commands, approval, presets or allow lists are looked at. 0.2.x asked the operator for a call such as `write_file {"path": "/etc/passwd", "command": "echo hi"}`; it is now blocked. A path outside the jail is a block for every tool name and every other argument. A relative `cwd` or an absolute `cwd` outside the jail is now checked as a path as well.
* **A tool is only allowed by a list, a preset or its exact standard name.** A name that matches a file pattern (`read_*`, `write_*`, `get_*`, `*_file`) is no longer allowed because its path is inside the jail. An unlisted tool that modifies needs operator approval (denied with `--no-prompt`), any other unlisted tool is blocked. To keep using such a tool, add it to `always_allow_tools` or `custom_always_allow_tools`.
* **`custom_modifying_tools` only classifies.** In 0.2.x a tool in this list with a path in the jail was allowed. Now `--read-only` blocks it and it counts as a write, but it needs approval (or an entry in `always_allow_tools`) to run. This changes the built-in presets too:
  * `filesystem`: `delete_file` needs approval.
  * `git`: `git_add`, `git_commit`, `git_create_branch` and `git_checkout` are in the allow list and still run without a prompt. `git_push`, `git_reset` and `git_merge` now need approval.
  * `sqlite`: `write_query`, `execute_query`, `create_table` and `drop_table` need approval.
  * `memory`: `create_entities`, `create_relations`, `delete_entities`, `delete_relations` and `add_observations` need approval.
  To allow one of them without a prompt, list it in `always_allow_tools`.
* **The standard tool names are the exact tools of `@modelcontextprotocol/server-filesystem`** (`read_file`, `read_text_file`, `read_media_file`, `read_multiple_files`, `write_file`, `edit_file`, `append_file`, `copy_file`, `create_directory`, `list_directory`, `list_directory_with_sizes`, `directory_tree`, `move_file`, `search_files`, `get_file_info`, `list_allowed_directories`). The match is exact. `rm`, `cp`, `mv`, `cat`, `shred`, `wipe`, `purge_dir`, `delete_file`, `create_file` and similar names are no longer allowed automatically (they are still treated as file tools, and the modifying ones as writes). Different case or `-` instead of `_` (`READ_FILE`, `read-file`) is no longer the standard name.
* **A file tool without a path is blocked** ("Path argument could not be verified for file tool"), also with no arguments, `{}` or `null`, unless it is listed in `non_file_tools`. Only `list_allowed_directories` is exempt. `list_tables`, `show_schema` and `read_graph` are no longer exempt by name; the `sqlite`, `memory` and `fetch` presets now set `non_file_tools` for their own tools (`read_query`, `describe_table`, `search_nodes`, `open_nodes`, `read_url` and the rest). A tool that is allowed by name but takes no path (`get-env`) needs `non_file_tools`. `non_file_tools` does not allow a tool.
* **`http://` and `https://` URLs are not paths.** A URL in `url`, `uri`, `href` or a `*_url` argument is not checked against the jail. In 0.2.x the `fetch` preset rejected `https://example.com/` as a path. `file://` URLs and bare paths in a URL argument are still jail-checked, and an `http(s)` URL in a path argument (`path`, `file`) is still rejected. The tool that fetches the URL must still be authorized.
* **`require_approval_on_write` applies to every modifying tool**, also one that takes no path (`create_entities`, `write_query`).
* **An unlisted tool that does not modify is blocked even with a `command` argument.** It was sent to the operator before. An unlisted modifying tool still asks.
* Percent-encoded traversal in plain paths (`%2e%2e/`, `..%2f`, double-encoded) is rejected.
* Preset `ignore_path_keys` apply only to the tools of that preset (git: `target`, `revision`, `branch_name` and similar; memory: `from`, `to`). Before, they were merged into the global list and disabled path checks for those keys on every tool. `ignore_path_keys` in `moat.toml` stays global, as an operator decision.
* **Unknown JSON-RPC methods are refused (breaking).** Until 0.2.x every method other than `tools/call` and `resources/read`/`subscribe` was forwarded. Now only the standard MCP client-to-server methods are forwarded (`initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`, `prompts/list`, `prompts/get`, `completion/complete`, `logging/setLevel`, `notifications/initialized`, `notifications/cancelled`, `notifications/progress`, `notifications/roots/list_changed`), and replies to server requests. Any other request gets `-32601`, any other notification is dropped, and both are audited as blocked. If your server needs an extension method, add it to `allowed_methods` in `moat.toml`. `--monitor` still forwards and logs the category.
* **A failed audit write answers the client.** A request with an id that is not forwarded because the audit log could not be written now gets `-32603` ("Request not forwarded: the audit log could not be written") instead of no response. Notifications get none. `resources/read` and the generic forward path are now held back on audit failure like `tools/call`.
* **The `--monitor` diagnostic no longer prints the block reason.** It names the tool (control characters replaced, length-capped) and a fixed category such as "path outside allowed folder", "unknown tool", "blocked command" or "read-only", never the path or URI from the request. The approval prompt and `moat audit` output replace control characters in request-derived text.
* The block message for policy violations says "external MCP protocol policy proxy" instead of "OS-level security proxy". The path error says "allowed root" instead of "sandbox root". Some code comments no longer say "Zero-Trust firewall".

### Removed

* `moat sse-proxy`, `moat sse-bridge` and the `experimental-sse` feature. They were removed because their audit and secret-masking guarantees did not match the stdio proxy. They may return in a later release.

### Added

* `PresetConfig.non_file_tools`: a preset can list its pathless tools.
* `crates/mcp-moat-core/tests/invariants.rs`: one test section per invariant in `docs/security-model.md`, a decision table for every built-in preset and tool, a decision matrix over authorization, classification, path, command argument, `require_approval_on_write` and `read_only` (also run through the proxy without a console) that must equal an independent rule function, and deterministic property checks (fixed seed): a path outside the jail is always a block, and a tool that nothing authorizes is never allowed. `crates/mcp-moat-proxy/tests/no_prompt.rs` checks that nothing that needs approval is forwarded with `--no-prompt`.

### Logging

* Log output never contains request lines, arguments, server responses, malformed input or environment values, at any `RUST_LOG` level. `debug` logs method, id and byte length; the log lines for blocked calls no longer include the reason or the URI. A test runs `moat wrap` with `RUST_LOG=trace` and checks that test secrets do not appear.

### CI and scripts

* A release build fails if the tag (`vX.Y.Z`) does not match `workspace.package.version`.
* A release requires the `cargo audit` job to pass.
* The Intel macOS binary is executed on the ARM runner under Rosetta (`--version`). Before, its smoke test was skipped.
* The CI jobs run clippy and the tests once; there is no feature matrix any more.
* The real-server servers are pinned: `@modelcontextprotocol/server-filesystem@2.3.0`, `@modelcontextprotocol/server-everything@2.3.0`, `mcp-server-git==2026.11.11` (`scripts/real_server_check.py`, `scripts/demo.py`, CI).

### Documentation

* `SECURITY.md`: the supported version is the latest published release.
* `docs/security-model.md` and the README describe the order of checks, the authorization sources, classification versus authorization, pathless preset tools and URLs versus paths. The model document used the key name `allowed_dirs`; the key is `allowed_paths`.
* `moat.toml`: the header and the `read_only` comment no longer overstate what moat does.
* The README demo output comes from a real run of `scripts/demo.py`. The text calls the client a scripted MCP client.

## 0.2.3 (2026-11-12)

No change to how moat behaves.

* The README now states that audit write failures fail closed: the call is not forwarded.
* The crate pages on crates.io link the homepage and the documentation.
* Comments and output of the red-team script are in English only.

## 0.2.2 (2026-11-11)

* With `--no-prompt`, a call that needs approval was blocked with "Action was rejected by operator in prompt", although nobody was asked. The block message now says: "Approval required (protected file or unlisted tool), but --no-prompt is set, so the call was denied".
* If no terminal is available for the approval prompt (or it cannot be read), the block message now says so instead of blaming the operator.
* "Action was rejected by operator in prompt" is only used when the operator answered "no". The same three messages apply to the SSE proxy and bridge, including the JSON-RPC error for non-tool requests.
* The audit log is unchanged: all denied approvals are still recorded with the operator decision `Deny`.
* The README example for `moat audit verify` now shows the real output, including the `Path` line.
* The README has a short terminal recording of a real run (`scripts/demo.py`).

## 0.2.1 (2026-11-11)

No change to how moat behaves.

* The Linux binary is built on Ubuntu 22.04 and runs on systems with glibc 2.35 or newer. 0.2.0 needed glibc 2.39.
* The images and links in the README work on crates.io. They used paths that crates.io resolved against the wrong folder.
* CI checks the dependencies with `cargo audit`. Release notes are taken from this file.
* Test names and comments were cleaned up, and a test that depended on the order of other tests creates its own folder.
* The security model moved to `docs/security-model.md` and was corrected: `--config` and `protected_files` are protected, audit write errors stop the call.

## 0.2.0 (2026-11-11)

### Added
* `moat check` validates a configuration without starting a server: TOML syntax, `allowed_paths` (must exist and be directories), the audit log path and the `blocked_commands_regex` entries.
* `moat completion bash|zsh|fish|powershell` prints shell completions.
* Secret masking knows more formats: OpenAI `sk-proj-`, `sk-svcacct-` and `sk-admin-` keys, DeepSeek, Mistral and Cohere (with context), Perplexity, Voyage AI, AWS temporary session keys (`ASIA...`) and AWS secret access keys next to `aws` or `secret`.
* `dlp_base64_heuristic` in `moat.toml` (default `false`). When on, long Base64 and Base64url runs with upper case, lower case and digits are masked as possible secrets. It is off by default because it also masks image and audio data, file paths, lockfile hashes, long identifiers and public keys.
* `protected_files` in `moat.toml`. The file passed to `--config` is added automatically, so an agent cannot rewrite the policy that guards it.
* The crates are published on crates.io (`cargo install --locked mcp-moat`).

### Changed
* `blocked_commands` entries are tokenized before matching: whitespace is collapsed, path prefixes such as `/bin/rm` are reduced to the program name, combined short flags are compared as sets, and `sudo` is skipped. `rm  -rf /`, `rm -r -f /`, `/bin/rm -fr /` and `sudo rm -rf /` now match `rm -rf /`. `rm -rf /tmp/build` does not match and goes to the operator prompt.
* The UNC and NT path check also rejects `\GLOBAL??\`, `\GLOBALROOT\`, `\DosDevices\`, `\SystemRoot\`, `\BaseNamedObjects\`, `\ArcName\` and `\KernelObjects\`, and normalizes separators first.

### Fixed
* **Audit writes fail closed.** If the audit log cannot be created, opened, written or flushed, the action is not forwarded. Before, the error was logged and the call went through without an audit entry. The experimental SSE bridge stops forwarding events in the same case.
* Audit error messages no longer contain the session id.
* `moat check` no longer rejects a `--config` file or `protected_files` entry whose path has an 8.3-style segment, such as the Windows temp folder `C:\Users\RUNNER~1\...`. The 8.3 rule is meant for paths in tool calls.

## 0.1.0 (2026-11-07)

First release.

### Added
* `scripts/real_server_check.py` runs mcp-moat in front of three real MCP servers (`server-filesystem`, `mcp-server-git`, `server-everything`) and makes 56 checks: jail, traversal, symlinks, protected files, read-only mode, secret masking, audit chain. It runs in CI.
* Config options `non_file_tools` and `ignore_path_keys`.

### Changed
* License is MIT only. `LICENSE-APACHE` and `LICENSE-MIT` were removed; `LICENSE` stays.
* `sse-proxy` and `sse-bridge` are experimental and only built with `--features experimental-sse`.
* `FenceError` in `mcp-moat-core` is now `MoatError`.
* The crates are marked `publish = false`. Nothing is published to crates.io yet.
* `moat --version` now reads the version from `Cargo.toml`. The help text no longer promises protection it does not give.
* Release archives are built for Linux x86_64, macOS aarch64, macOS x86_64 and Windows x86_64 and come with `SHA256SUMS`.
* The README no longer lists unverified numbers or guarantees. Known limits are in `SECURITY.md`.

### Fixed
* **Secret masking missed ordinary `.env` lines.** The generic pattern only matched when the key name started at a word boundary, so `OPENAI_API_KEY=...`, `GITHUB_TOKEN=...`, `DB_PASSWORD=...`, `STRIPE_SECRET=...` and `x-api-key: ...` were passed through unmasked unless the value had a known prefix. Names with a prefix are matched now. The name stays, the value is masked. Found by running mcp-moat in front of the real filesystem MCP server.
* Secrets in JSON text were not masked when the key name was followed by a closing quote (`"OPENAI_API_KEY": "..."`), which is what an environment dump looks like. Quotes and spacing are kept now: `"OPENAI_API_KEY": "[MCP-MOAT-REDACTED-SECRET]"`.
* Relative paths next to `repo_path`, `cwd` and similar keys (`files: ["src/main.rs"]` of `git_add`) were checked against the working directory of mcp-moat and a legitimate call was blocked. They are joined with the base directory and then checked. Absolute paths and `..` are still blocked.
* The git preset treated revisions and branch names (`target: "HEAD~1"`) as paths. It knows the tools `git_add`, `git_create_branch`, `git_diff_staged` and `git_diff_unstaged` now.
* The 8.3 short name rule rejected every path with a `~`. It now rejects names of the form `PROGRA~1`, `RUNNER~1`, `MOAT~1.TOM` (up to six characters, a tilde, digits, an optional short extension). Names such as `iCloud~md~obsidian` and `report~final.docx` are accepted.
* Groq keys (`gsk_...`) were not masked.
* `directory_tree`, a read tool of the official filesystem server, was blocked as "unrecognized tool". It is now treated as a read tool and checked against the jail.
* SSE proxy: the upstream endpoint is always replaced by a proxy URL. Before, an absolute URL or a different query parameter name was passed to the client unchanged, so the client could post to the upstream server directly.
* SSE proxy: `data:` and `event:` lines without a space after the colon are handled.
* SSE proxy: `https://` URLs are rejected. They were accepted but sent without TLS.
* SSE proxy: `Access-Control-Allow-Origin: *` was removed. Requests with an `Origin` header, and on loopback binds requests with a non-loopback `Host` header, are rejected.
* Removed `unwrap()` / `expect()` calls that could panic in `PolicyEngine::new` and the proxy engine.
* Tests no longer write files into the source tree.
* Four tests that assumed Windows paths now run correctly on Linux and macOS.
* `cargo fmt` and `cargo clippy -D warnings` pass.

### Removed
* `install.sh` and `install.ps1` were removed. Download a release and check `SHA256SUMS`.
