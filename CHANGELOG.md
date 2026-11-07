# Changelog

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
