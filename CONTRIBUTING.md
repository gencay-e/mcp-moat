# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first so we can agree on the approach.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Tests against real MCP servers need Node.js, Python and `mcp-server-git`:

```bash
cargo build --release -p mcp-moat-cli
python scripts/real_server_check.py
```

## Rules

* Keep a change small and focused. Add a test that fails without it.
* Do not weaken a check to make a test pass. If a rule blocks something legitimate, say so in the issue.
* Do not commit secrets, `.env` files or real tokens. Test secrets must be fake.
* Security problems: see [SECURITY.md](SECURITY.md), do not open a public issue.

## Release

1. Raise `version` in `Cargo.toml` and the `version` of the path dependencies in `crates/*/Cargo.toml`, add a `CHANGELOG.md` entry, run `cargo test --workspace --all-features` and `python scripts/real_server_check.py`.
2. Tag `v<version>` on GitHub. The CI builds the release archives and `SHA256SUMS`.
3. Publish the crates in dependency order, each after the previous one is visible on crates.io:
   ```bash
   cargo publish -p mcp-moat-core
   cargo publish -p mcp-moat-tty
   cargo publish -p mcp-moat-proxy
   cargo publish -p mcp-moat
   ```
