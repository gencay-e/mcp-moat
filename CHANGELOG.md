# Changelog

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
