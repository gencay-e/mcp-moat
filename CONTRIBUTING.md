# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first so we can agree on the approach.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The experimental SSE proxy is behind a feature: add `--features experimental-sse` (or `--all-features`).

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
