//! Tests for the invariants listed in docs/security-model.md, one section per invariant.
//!
//! Sections 1 and 2 also contain a decision table for every built-in preset and two
//! deterministic property checks (fixed seed, no external dependency):
//!
//! * a path outside the jail is always `Block`, whatever the tool name and the other arguments are
//! * a tool that nothing authorizes is never `Allow`
//!
//! A decision matrix (last section) compares the policy with an independent rule function.
//!
//! The `--no-prompt` invariant is tested end to end in crates/mcp-moat-proxy/tests/no_prompt.rs.
#![allow(clippy::field_reassign_with_default)] // tests tweak single config fields

mod common;

use mcp_moat_core::audit::{verify_audit_log, AuditChain, AuditDirection};
use mcp_moat_core::dlp::DlpEngine;
use mcp_moat_core::{Decision, PolicyConfig, PolicyEngine, ToolCallParams};
use serde_json::{json, Value};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn jail() -> PathBuf {
    let p = std::env::temp_dir().join("mcp-moat-invariants-jail");
    for d in ["sub", "repo", ".git", ".ssh"] {
        std::fs::create_dir_all(p.join(d)).unwrap();
    }
    let c = p.canonicalize().unwrap();
    let s = c.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

/// A path inside the jail.
fn jp(rel: &str) -> String {
    jail().join(rel).to_string_lossy().to_string()
}

fn call(name: &str, args: Value) -> ToolCallParams {
    ToolCallParams {
        name: name.into(),
        arguments: Some(args),
    }
}

fn base_config() -> PolicyConfig {
    PolicyConfig {
        allowed_paths: vec![jail()],
        ..PolicyConfig::default()
    }
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(base_config()).unwrap()
}

fn preset_config(name: &str) -> PolicyConfig {
    let mut c = base_config();
    c.apply_preset(name).unwrap();
    // presets may reset the jail ("filesystem" sets "."); keep the test jail
    c.allowed_paths = vec![jail()];
    c
}

fn preset_engine(name: &str) -> PolicyEngine {
    PolicyEngine::new(preset_config(name)).unwrap()
}

fn is_allow(d: &Decision) -> bool {
    matches!(d, Decision::Allow)
}
fn is_block(d: &Decision) -> bool {
    matches!(d, Decision::Block(_))
}
fn is_ask(d: &Decision) -> bool {
    matches!(d, Decision::AskOperator { .. })
}

fn kind(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Block(_) => "block",
        Decision::AskOperator { .. } => "ask",
    }
}

// ---------------------------------------------------------------------------
// Invariant 1: path jail
// ---------------------------------------------------------------------------

/// Values that must never pass as a path inside the jail.
fn outside_values() -> Vec<String> {
    let sibling = format!("{}-evil/file.txt", jail().to_string_lossy());
    let mut v = vec![
        "/etc/passwd".to_string(),
        "/".to_string(),
        "../../etc/passwd".to_string(),
        "..".to_string(),
        "sub/../../../etc/passwd".to_string(),
        "..\\..\\windows\\win.ini".to_string(),
        "file:///etc/passwd".to_string(),
        "file://localhost/etc/passwd".to_string(),
        "file:///%65tc/passwd/../../x".to_string(),
        "file:///%2e%2e/%2e%2e/etc/passwd".to_string(),
        "file:///%252e%252e/etc/passwd".to_string(),
        "%2e%2e/%2e%2e/etc/passwd".to_string(),
        "..%2f..%2fetc/passwd".to_string(),
        "%252e%252e/etc/passwd".to_string(),
        "//server/share/file".to_string(),
        "\\\\server\\share\\file".to_string(),
        "\\\\?\\C:\\Windows\\win.ini".to_string(),
        "/dev/null".to_string(),
        "nul".to_string(),
        "C:foo".to_string(),
        "file.txt:stream".to_string(),
        "PROGRA~1/x".to_string(),
        "bad\0name".to_string(),
        sibling,
    ];
    v.push(format!("{}/../outside.txt", jail().to_string_lossy()));
    v
}

#[test]
fn inv1_every_outside_value_is_blocked_for_standard_tools() {
    let e = engine();
    for bad in outside_values() {
        for tool in ["read_file", "write_file", "list_directory", "move_file"] {
            let d = e.evaluate_tool_call(&call(tool, json!({ "path": bad })));
            assert!(is_block(&d), "{tool} path={bad:?} gave {d:?}");
        }
    }
}

#[test]
fn inv1_in_jail_paths_are_not_blocked() {
    let e = engine();
    for good in [jp("a.txt"), jp("sub/b.txt"), jp("c.txt")] {
        let d = e.evaluate_tool_call(&call("read_file", json!({ "path": good })));
        assert!(is_allow(&d), "{good} gave {d:?}");
    }
}

#[test]
fn inv1_path_is_checked_before_command_approval_or_allow_decisions() {
    // The review finding: a command-like argument returned AskOperator before the path check.
    let e = engine();
    let cases = [
        (
            "write_file",
            json!({"path": "/etc/passwd", "command": "echo hi", "content": "x"}),
        ),
        (
            "write_file",
            json!({"path": "/etc/passwd", "cmd": "ls; rm x", "content": "x"}),
        ),
        (
            "write_file",
            json!({"path": "../x", "args": ["--flag"], "content": "x"}),
        ),
        ("bash", json!({"command": "ls", "cwd": "/etc"})),
        (
            "run_command",
            json!({"command": "echo hi", "path": "/etc/shadow"}),
        ),
        (
            "totally_unknown",
            json!({"command": "echo hi", "dir": "../../root"}),
        ),
        (
            "shell",
            json!({"script": "echo hi", "file": "file:///etc/passwd"}),
        ),
        ("read_file", json!({"path": "/etc/passwd", "script": "x"})),
    ];
    for (tool, args) in cases {
        let d = e.evaluate_tool_call(&call(tool, args.clone()));
        assert!(is_block(&d), "{tool} {args} gave {d:?}");
    }

    // Same with approval-on-write and with the tool explicitly allowed.
    let mut c = base_config();
    c.require_approval_on_write = true;
    c.always_allow_tools.push("write_file".into());
    c.always_allow_tools.push("totally_unknown".into());
    c.custom_modifying_tools.push("totally_unknown".into());
    let e = PolicyEngine::new(c).unwrap();
    for tool in ["write_file", "totally_unknown"] {
        let d = e.evaluate_tool_call(&call(
            tool,
            json!({"path": "/etc/passwd", "command": "echo hi", "content": "x"}),
        ));
        assert!(is_block(&d), "{tool} gave {d:?}");
    }
}

#[test]
fn inv1_one_bad_path_among_many_blocks() {
    let e = engine();
    let d = e.evaluate_tool_call(&call(
        "move_file",
        json!({"source": jp("a.txt"), "destination": "/etc/cron.d/x"}),
    ));
    assert!(is_block(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call(
        "read_multiple_files",
        json!({"paths": [jp("a.txt"), jp("b.txt"), "/etc/passwd"]}),
    ));
    assert!(is_block(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call(
        "edit_file",
        json!({"path": jp("a.txt"), "options": {"nested": [{"dir": "../.."}]}}),
    ));
    assert!(is_block(&d), "{d:?}");
}

#[cfg(unix)]
#[test]
fn inv1_symlink_escape_is_blocked() {
    let link = jail().join("escape-link");
    if std::fs::symlink_metadata(&link).is_err() {
        let _ = std::os::unix::fs::symlink("/etc", &link);
    }
    let e = engine();
    for p in [
        link.join("passwd").to_string_lossy().to_string(),
        link.join("new-file").to_string_lossy().to_string(),
    ] {
        let d = e.evaluate_tool_call(&call("read_file", json!({ "path": p })));
        assert!(is_block(&d), "{p} gave {d:?}");
    }
}

#[test]
fn inv1_resource_reads_are_jailed() {
    let e = engine();
    assert!(is_block(&e.evaluate_resource_read("file:///etc/passwd")));
    assert!(is_block(
        &e.evaluate_resource_read("file:///%2e%2e/etc/passwd")
    ));
    assert!(is_block(&e.evaluate_resource_read("http://example.com/x")));
    assert!(is_allow(
        &e.evaluate_resource_read(&common::file_uri(&jp("a.txt")))
    ));
}

#[test]
fn inv1_protected_files_need_approval_even_in_jail() {
    let e = engine();
    for p in [
        "moat.toml",
        "fence.toml",
        ".git/config",
        ".env",
        ".ssh/id_rsa",
    ] {
        let d = e.evaluate_tool_call(&call("write_file", json!({"path": jp(p), "content": "x"})));
        assert!(is_ask(&d), "{p} gave {d:?}");
    }
    // The audit log and the --config file (protected_files) too.
    let mut c = base_config();
    c.protected_files = vec![jail().join("my-policy.toml")];
    let e = PolicyEngine::new(c).unwrap();
    let d = e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": jp("my-policy.toml"), "content": "x"}),
    ));
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn inv1_http_urls_are_not_paths_but_file_urls_and_paths_are() {
    let e = preset_engine("fetch");
    for url in [
        "https://example.com/",
        "http://example.com/a?b=c",
        "HTTPS://Example.com/x",
    ] {
        let d = e.evaluate_tool_call(&call("fetch", json!({ "url": url })));
        assert!(is_allow(&d), "{url} gave {d:?}");
    }
    for url in [
        "file:///etc/passwd",
        "/etc/passwd",
        "../../etc/passwd",
        "ftp://example.com/x",
        "//server/share",
    ] {
        let d = e.evaluate_tool_call(&call("fetch", json!({ "url": url })));
        assert!(is_block(&d), "{url} gave {d:?}");
    }
    // A file URL inside the jail is a jail-checked local path.
    let d = e.evaluate_tool_call(&call(
        "fetch",
        json!({"url": common::file_uri(&jp("a.txt"))}),
    ));
    assert!(is_allow(&d), "{d:?}");
    // The URL exemption applies to URL keys only: an http URL in a path key is rejected.
    let d = e.evaluate_tool_call(&call("fetch", json!({"path": "https://example.com/"})));
    assert!(is_block(&d), "{d:?}");
    let e = engine();
    let d = e.evaluate_tool_call(&call("read_file", json!({"path": "https://example.com/x"})));
    assert!(is_block(&d), "{d:?}");
}

// ---------------------------------------------------------------------------
// Invariant 2: default deny, authorization sources, classification
// ---------------------------------------------------------------------------

#[test]
fn inv2_unknown_tools_are_not_allowed() {
    let e = engine();
    for tool in [
        "frobnicate",
        "read_anything",
        "write_stuff",
        "get_secret",
        "my_special_file",
        "delete_all_the_things",
        "ReadFile",
    ] {
        for args in [
            json!({}),
            json!({"path": jp("a.txt")}),
            json!({"query": "x"}),
            json!({"path": jp("a.txt"), "content": "x"}),
        ] {
            let d = e.evaluate_tool_call(&call(tool, args.clone()));
            assert!(!is_allow(&d), "{tool} {args} gave {d:?}");
        }
    }
    // Pathless unknown, read-like: block. Pathless unknown, write-like: ask.
    assert!(is_block(
        &e.evaluate_tool_call(&call("frobnicate", json!({"x": 1})))
    ));
    assert!(is_ask(
        &e.evaluate_tool_call(&call("update_thing", json!({"x": 1})))
    ));
}

#[test]
fn inv2_custom_modifying_tools_classify_but_do_not_authorize() {
    // The review finding: custom_modifying_tools acted as an allow list.
    let mut c = base_config();
    c.custom_modifying_tools.push("deploy_site".into());
    let e = PolicyEngine::new(c.clone()).unwrap();
    let d = e.evaluate_tool_call(&call("deploy_site", json!({"path": jp("a.txt")})));
    assert!(is_ask(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call("deploy_site", json!({"name": "x"})));
    assert!(is_ask(&d), "{d:?}");

    // classification: read-only mode blocks it
    c.read_only = true;
    let e = PolicyEngine::new(c).unwrap();
    let d = e.evaluate_tool_call(&call("deploy_site", json!({"path": jp("a.txt")})));
    assert!(is_block(&d), "{d:?}");
    assert!(e.is_modifying_tool("deploy_site"));

    // authorization comes from the allow lists only
    let mut c = base_config();
    c.custom_modifying_tools.push("deploy_site".into());
    c.custom_always_allow_tools.push("deploy_site".into());
    let e = PolicyEngine::new(c).unwrap();
    let d = e.evaluate_tool_call(&call("deploy_site", json!({"path": jp("a.txt")})));
    assert!(is_allow(&d), "{d:?}");
    let mut c = base_config();
    c.always_allow_tools.push("deploy_site".into());
    let e = PolicyEngine::new(c).unwrap();
    let d = e.evaluate_tool_call(&call("deploy_site", json!({"path": jp("a.txt")})));
    assert!(is_allow(&d), "{d:?}");
}

#[test]
fn inv2_standard_authorization_is_the_exact_filesystem_server_list() {
    let e = engine();
    let standard_with_path = [
        "read_file",
        "read_text_file",
        "read_media_file",
        "list_directory",
        "list_directory_with_sizes",
        "directory_tree",
        "search_files",
        "get_file_info",
        "write_file",
        "edit_file",
        "create_directory",
        "append_file",
    ];
    for tool in standard_with_path {
        let d = e.evaluate_tool_call(&call(tool, json!({"path": jp("sub/x")})));
        assert!(is_allow(&d), "{tool} gave {d:?}");
    }
    let d = e.evaluate_tool_call(&call(
        "read_multiple_files",
        json!({"paths": [jp("a.txt"), jp("b.txt")]}),
    ));
    assert!(is_allow(&d), "{d:?}");
    for tool in ["move_file", "copy_file"] {
        let d = e.evaluate_tool_call(&call(
            tool,
            json!({"source": jp("a.txt"), "destination": jp("sub/b.txt")}),
        ));
        assert!(is_allow(&d), "{tool} gave {d:?}");
        let d = e.evaluate_tool_call(&call(
            tool,
            json!({"source": jp("a.txt"), "destination": "/etc/x"}),
        ));
        assert!(is_block(&d), "{tool} gave {d:?}");
    }
    let d = e.evaluate_tool_call(&call("list_allowed_directories", json!({})));
    assert!(is_allow(&d), "{d:?}");
}

#[test]
fn inv2_look_alike_tools_are_not_authorized() {
    let e = engine();
    for tool in [
        "rm",
        "shred",
        "wipe",
        "purge_dir",
        "overwrite",
        "unlink",
        "truncate",
        "mv",
        "cp",
        "touch",
        "mkdir",
        "rmdir",
        "delete_file",
        "remove_file",
        "create_file",
        "rename_file",
        "save_file",
        "erase",
        "clean_dir",
    ] {
        let d = e.evaluate_tool_call(&call(tool, json!({"path": jp("a.txt")})));
        assert!(!is_allow(&d), "{tool} gave {d:?}");
        assert!(
            e.is_modifying_tool(tool),
            "{tool} must stay classified as modifying"
        );
    }
    for tool in [
        "cat",
        "head",
        "tail",
        "view_file",
        "get_file",
        "open_file",
        "read_lines",
    ] {
        let d = e.evaluate_tool_call(&call(tool, json!({"path": jp("a.txt")})));
        assert!(!is_allow(&d), "{tool} gave {d:?}");
    }
    // Spelling variants of a standard name are not the standard name.
    for tool in ["READ_FILE", "Read_File", "read-file", "write-file"] {
        let d = e.evaluate_tool_call(&call(tool, json!({"path": jp("a.txt")})));
        assert!(!is_allow(&d), "{tool} gave {d:?}");
    }
    // When the user lists them, they are allowed.
    let mut c = base_config();
    c.always_allow_tools.push("cat".into());
    c.always_allow_tools.push("rm".into());
    let e = PolicyEngine::new(c).unwrap();
    assert!(is_allow(
        &e.evaluate_tool_call(&call("cat", json!({"path": jp("a.txt")})))
    ));
    assert!(is_allow(
        &e.evaluate_tool_call(&call("rm", json!({"path": jp("a.txt")})))
    ));
    // ... but never with a path outside the jail
    assert!(is_block(&e.evaluate_tool_call(&call(
        "rm",
        json!({"path": "/etc/passwd"})
    ))));
}

#[test]
fn inv2_file_tools_without_a_verifiable_path_are_blocked() {
    let e = engine();
    for args in [None, Some(json!({})), Some(Value::Null)] {
        let d = e.evaluate_tool_call(&ToolCallParams {
            name: "read_file".into(),
            arguments: args.clone(),
        });
        assert!(is_block(&d), "{args:?} gave {d:?}");
    }
    // listed pathless tool that looks like a file tool: blocked until it is a non-file tool
    let mut c = base_config();
    c.always_allow_tools.push("get-sum".into());
    let e = PolicyEngine::new(c.clone()).unwrap();
    assert!(is_block(
        &e.evaluate_tool_call(&call("get-sum", json!({"a": 1, "b": 2})))
    ));
    c.non_file_tools.push("get-sum".into());
    let e = PolicyEngine::new(c).unwrap();
    assert!(is_allow(
        &e.evaluate_tool_call(&call("get-sum", json!({"a": 1, "b": 2})))
    ));
    // non_file_tools exempts from the path requirement only; paths that are present are checked
    assert!(is_block(&e.evaluate_tool_call(&call(
        "get-sum",
        json!({"path": "/etc/passwd"})
    ))));
}

#[test]
fn inv2_read_only_blocks_modifying_tools_regardless_of_allow_lists() {
    let mut c = base_config();
    c.read_only = true;
    c.always_allow_tools.push("write_file".into());
    c.always_allow_tools.push("deploy_site".into());
    c.custom_modifying_tools.push("deploy_site".into());
    let e = PolicyEngine::new(c).unwrap();
    for tool in ["write_file", "deploy_site", "rm", "move_file", "bash"] {
        let d = e.evaluate_tool_call(&call(tool, json!({"path": jp("a.txt"), "content": "x"})));
        assert!(is_block(&d), "{tool} gave {d:?}");
    }
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a.txt")})
    ))));
}

#[test]
fn inv2_commands_never_allow() {
    let e = engine();
    for tool in ["bash", "run_command", "shell"] {
        let d = e.evaluate_tool_call(&call(tool, json!({"command": "echo hi"})));
        assert!(is_ask(&d), "{tool} gave {d:?}");
    }
    // an unknown tool that does not modify is blocked before its command is looked at
    for tool in ["frobnicate", "inspect_data"] {
        let d = e.evaluate_tool_call(&call(tool, json!({"command": "echo hi"})));
        assert!(is_block(&d), "{tool} gave {d:?}");
    }
    let d = e.evaluate_tool_call(&call("bash", json!({"command": "rm -rf /"})));
    assert!(is_block(&d), "{d:?}");
    // an allowed tool with a command argument still asks
    let d = e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a.txt"), "command": "echo hi"}),
    ));
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn inv2_require_approval_on_write_covers_pathless_modifying_tools() {
    let mut c = preset_config("memory");
    c.require_approval_on_write = true;
    c.always_allow_tools.push("create_entities".into());
    let e = PolicyEngine::new(c).unwrap();
    let d = e.evaluate_tool_call(&call(
        "create_entities",
        json!({"entities": [{"name": "a", "entityType": "t", "observations": []}]}),
    ));
    assert!(is_ask(&d), "{d:?}");
    // a read tool of the preset is not a write
    assert!(is_allow(
        &e.evaluate_tool_call(&call("read_graph", json!({})))
    ));
}

#[test]
fn inv2_hidden_tools_are_blocked() {
    let mut c = base_config();
    c.hidden_tools.push("read_file".into());
    let e = PolicyEngine::new(c).unwrap();
    assert!(is_block(&e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a")})
    ))));
}

#[test]
fn inv2_arguments_must_be_an_object() {
    let e = engine();
    for args in [json!("x"), json!(["a"]), json!(1)] {
        assert!(is_block(&e.evaluate_tool_call(&call("read_file", args))));
    }
}

// ---------------------------------------------------------------------------
// Presets: decision table
// ---------------------------------------------------------------------------

struct Row {
    tool: &'static str,
    args: Value,
    expect: &'static str,
}

fn row(tool: &'static str, args: Value, expect: &'static str) -> Row {
    Row { tool, args, expect }
}

fn table(preset: &str) -> Vec<Row> {
    match preset {
        "filesystem" => vec![
            row("read_file", json!({"path": jp("a.txt")}), "allow"),
            row("list_directory", json!({"path": jp("sub")}), "allow"),
            row(
                "search_files",
                json!({"path": jp("sub"), "pattern": "*.rs"}),
                "allow",
            ),
            row(
                "grep",
                json!({"path": jp("sub"), "pattern": "todo"}),
                "allow",
            ),
            row("get_file_info", json!({"path": jp("a.txt")}), "allow"),
            row("list_allowed_directories", json!({}), "allow"),
            row(
                "write_file",
                json!({"path": jp("sub/n.txt"), "content": "x"}),
                "allow",
            ),
            row(
                "edit_file",
                json!({"path": jp("a.txt"), "edits": [{"oldText": "a", "newText": "b"}]}),
                "allow",
            ),
            row("create_directory", json!({"path": jp("sub/new")}), "allow"),
            row(
                "move_file",
                json!({"source": jp("a.txt"), "destination": jp("sub/b.txt")}),
                "allow",
            ),
            row(
                "copy_file",
                json!({"source": jp("a.txt"), "destination": jp("sub/c.txt")}),
                "allow",
            ),
            row(
                "append_file",
                json!({"path": jp("a.txt"), "content": "x"}),
                "allow",
            ),
            // classified as modifying, not authorized: asks
            row("delete_file", json!({"path": jp("a.txt")}), "ask"),
            // protected target asks
            row(
                "write_file",
                json!({"path": jp("moat.toml"), "content": "x"}),
                "ask",
            ),
            // outside: block
            row("read_file", json!({"path": "/etc/passwd"}), "block"),
            row(
                "write_file",
                json!({"path": "../x", "content": "x"}),
                "block",
            ),
            row("read_file", json!({}), "block"),
            // not part of the preset
            row("rm", json!({"path": jp("a.txt")}), "ask"),
            row("frobnicate", json!({"path": jp("a.txt")}), "block"),
        ],
        "git" => vec![
            row("git_status", json!({"repo_path": jp("repo")}), "allow"),
            row(
                "git_diff",
                json!({"repo_path": jp("repo"), "target": "HEAD~1"}),
                "allow",
            ),
            row(
                "git_diff_unstaged",
                json!({"repo_path": jp("repo")}),
                "allow",
            ),
            row("git_diff_staged", json!({"repo_path": jp("repo")}), "allow"),
            row(
                "git_log",
                json!({"repo_path": jp("repo"), "max_count": 5}),
                "allow",
            ),
            row(
                "git_show",
                json!({"repo_path": jp("repo"), "revision": "HEAD"}),
                "allow",
            ),
            row(
                "git_branch",
                json!({"repo_path": jp("repo"), "branch_type": "local"}),
                "allow",
            ),
            row(
                "git_add",
                json!({"repo_path": jp("repo"), "files": ["a.txt"]}),
                "allow",
            ),
            row(
                "git_commit",
                json!({"repo_path": jp("repo"), "message": "msg: fix"}),
                "allow",
            ),
            row(
                "git_create_branch",
                json!({"repo_path": jp("repo"), "branch_name": "feature/x"}),
                "allow",
            ),
            row(
                "git_checkout",
                json!({"repo_path": jp("repo"), "branch_name": "main"}),
                "allow",
            ),
            // modifying, not authorized by the preset
            row("git_push", json!({"repo_path": jp("repo")}), "ask"),
            row("git_reset", json!({"repo_path": jp("repo")}), "ask"),
            row(
                "git_merge",
                json!({"repo_path": jp("repo"), "branch_name": "x"}),
                "ask",
            ),
            row("git_status", json!({"repo_path": "/etc"}), "block"),
            row(
                "git_add",
                json!({"repo_path": jp("repo"), "files": ["../../etc/passwd"]}),
                "block",
            ),
            row("git_init", json!({"repo_path": jp("repo")}), "block"),
        ],
        "fetch" => vec![
            row(
                "fetch",
                json!({"url": "https://example.com/", "max_length": 1000}),
                "allow",
            ),
            row(
                "http_get",
                json!({"url": "https://example.com/a?b=c"}),
                "allow",
            ),
            row("read_url", json!({"url": "https://example.com/"}), "allow"),
            row("web_search", json!({"query": "rust path jail"}), "allow"),
            row("fetch", json!({"url": "http://example.com/"}), "allow"),
            // read_only = true: modifying http tools are blocked
            row(
                "http_post",
                json!({"url": "https://example.com/", "body": "x"}),
                "block",
            ),
            row(
                "http_put",
                json!({"url": "https://example.com/", "body": "x"}),
                "block",
            ),
            row(
                "http_delete",
                json!({"url": "https://example.com/x"}),
                "block",
            ),
            row(
                "http_patch",
                json!({"url": "https://example.com/x", "body": "x"}),
                "block",
            ),
            // file URLs and bare paths are filesystem paths
            row("fetch", json!({"url": "file:///etc/passwd"}), "block"),
            row("fetch", json!({"url": "/etc/passwd"}), "block"),
            row("read_url", json!({"url": "file:///etc/passwd"}), "block"),
            row("http_get", json!({"url": "../../etc/passwd"}), "block"),
            row(
                "read_url",
                json!({"url": "file:///etc/passwd", "command": "x"}),
                "block",
            ),
            row("download", json!({"url": "https://example.com/"}), "block"),
        ],
        "sqlite" => vec![
            row("read_query", json!({"query": "SELECT 1"}), "allow"),
            row("list_tables", json!({}), "allow"),
            row("describe_table", json!({"table_name": "users"}), "allow"),
            row("show_schema", json!({}), "allow"),
            row(
                "write_query",
                json!({"query": "INSERT INTO t VALUES (1)"}),
                "ask",
            ),
            row(
                "execute_query",
                json!({"query": "UPDATE t SET a = 1"}),
                "ask",
            ),
            row(
                "create_table",
                json!({"query": "CREATE TABLE t (a INT)"}),
                "ask",
            ),
            row("drop_table", json!({"table_name": "t"}), "ask"),
            row(
                "read_query",
                json!({"query": "SELECT 1", "database": jp("x.db")}),
                "allow",
            ),
            row(
                "read_query",
                json!({"query": "SELECT 1", "database": "/etc/x.db"}),
                "block",
            ),
            row(
                "read_query",
                json!({"query": "SELECT 1", "db_path": "../../x.db"}),
                "block",
            ),
            row("attach_database", json!({"path": "/etc/x.db"}), "block"),
        ],
        "memory" => vec![
            row("read_graph", json!({}), "allow"),
            row("search_nodes", json!({"query": "alice"}), "allow"),
            row("open_nodes", json!({"names": ["Alice", "Bob"]}), "allow"),
            row(
                "create_entities",
                json!({"entities": [{"name": "Alice", "entityType": "person", "observations": ["likes tea"]}]}),
                "ask",
            ),
            row(
                "create_relations",
                json!({"relations": [{"from": "Alice", "to": "Bob", "relationType": "knows"}]}),
                "ask",
            ),
            row("delete_entities", json!({"entityNames": ["Alice"]}), "ask"),
            row(
                "delete_relations",
                json!({"relations": [{"from": "Alice", "to": "Bob", "relationType": "knows"}]}),
                "ask",
            ),
            row(
                "add_observations",
                json!({"observations": [{"entityName": "Alice", "contents": ["x"]}]}),
                "ask",
            ),
            row(
                "search_nodes",
                json!({"query": "x", "path": "/etc/passwd"}),
                "block",
            ),
            row("forget_everything", json!({}), "block"),
        ],
        other => panic!("no table for preset {other}"),
    }
}

#[test]
fn presets_decision_table() {
    for preset in ["filesystem", "git", "fetch", "sqlite", "memory"] {
        let e = preset_engine(preset);
        for r in table(preset) {
            let d = e.evaluate_tool_call(&call(r.tool, r.args.clone()));
            assert_eq!(
                kind(&d),
                r.expect,
                "preset {preset}: {} {} gave {d:?}",
                r.tool,
                r.args
            );
        }
    }
}

#[test]
fn presets_table_covers_every_allowed_and_modifying_tool() {
    // Every tool a built-in preset allows or classifies as modifying has a row in the table.
    for preset in ["filesystem", "git", "fetch", "sqlite", "memory"] {
        let p = PolicyConfig::get_builtin_preset(preset).unwrap();
        let rows: Vec<&str> = table(preset).iter().map(|r| r.tool).collect();
        let tools = p
            .always_allow_tools
            .iter()
            .flatten()
            .chain(p.custom_always_allow_tools.iter().flatten())
            .chain(p.custom_modifying_tools.iter().flatten());
        for t in tools {
            assert!(
                rows.contains(&t.as_str()),
                "preset {preset}: tool {t} has no table row"
            );
        }
    }
}

#[test]
fn presets_pathless_tools_are_tied_to_the_preset() {
    // Without the preset the same pathless calls are not allowed (no global name exemption).
    let e = engine();
    for (tool, args) in [
        ("read_query", json!({"query": "SELECT 1"})),
        ("describe_table", json!({"table_name": "t"})),
        ("search_nodes", json!({"query": "x"})),
        ("open_nodes", json!({"names": ["a"]})),
        ("read_graph", json!({})),
        ("list_tables", json!({})),
        ("show_schema", json!({})),
        ("read_url", json!({"url": "https://example.com/"})),
    ] {
        let d = e.evaluate_tool_call(&call(tool, args.clone()));
        assert!(!is_allow(&d), "{tool} without preset gave {d:?}");
    }
    // With one preset, the tools of another preset stay unauthorized.
    let e = preset_engine("sqlite");
    assert!(!is_allow(
        &e.evaluate_tool_call(&call("read_graph", json!({})))
    ));
    assert!(!is_allow(&e.evaluate_tool_call(&call(
        "read_url",
        json!({"url": "https://example.com/"})
    ))));
}

#[test]
fn presets_can_be_combined() {
    let mut c = base_config();
    for p in ["filesystem", "git", "sqlite", "memory"] {
        c.apply_preset(p).unwrap();
    }
    c.allowed_paths = vec![jail()];
    let e = PolicyEngine::new(c).unwrap();
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "read_query",
        json!({"query": "SELECT 1"})
    ))));
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "git_status",
        json!({"repo_path": jp("repo")})
    ))));
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": jp("sub/q"), "content": "x"})
    ))));
    assert!(is_block(&e.evaluate_tool_call(&call(
        "read_query",
        json!({"query": "x", "database": "/etc/passwd"})
    ))));
}

// ---------------------------------------------------------------------------
// Deterministic property checks
// ---------------------------------------------------------------------------

/// xorshift64*, fixed seeds: the same cases run on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const PRESETS: [&str; 5] = ["filesystem", "git", "fetch", "sqlite", "memory"];

fn all_tool_names() -> Vec<String> {
    let mut names: Vec<String> = vec![
        // standard
        "read_file",
        "read_text_file",
        "read_media_file",
        "read_multiple_files",
        "write_file",
        "edit_file",
        "create_directory",
        "list_directory",
        "list_directory_with_sizes",
        "directory_tree",
        "move_file",
        "search_files",
        "get_file_info",
        "list_allowed_directories",
        // look-alikes and patterns
        "rm",
        "shred",
        "wipe",
        "purge_dir",
        "cat",
        "grep",
        "delete_file",
        "copy_file",
        "read_anything",
        "write_stuff",
        "get_secret",
        "my_special_file",
        "update_row",
        "create_user",
        "list_things",
        "search_everything",
        "view_page",
        "READ_FILE",
        "read-file",
        // not file related
        "frobnicate",
        "bash",
        "run_command",
        "shell",
        "eval",
        "get-sum",
        "deploy",
        "echo",
        "",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for p in PRESETS {
        let cfg = PolicyConfig::get_builtin_preset(p).unwrap();
        for list in [
            cfg.always_allow_tools,
            cfg.custom_always_allow_tools,
            cfg.custom_modifying_tools,
        ]
        .into_iter()
        .flatten()
        {
            names.extend(list);
        }
    }
    names
}

fn gen_bad_path(rng: &mut Rng) -> String {
    let all = outside_values();
    // Skip a value with a NUL for JSON-key variants that would be odd; it is a valid JSON string.
    let v = rng.pick(&all).clone();
    match rng.below(4) {
        0 => v,
        1 => format!("  {v}"),
        2 => v.to_string(),
        _ => v,
    }
}

fn gen_extra_args(rng: &mut Rng, map: &mut serde_json::Map<String, Value>) {
    let extras: [(&str, Value); 14] = [
        ("command", json!("echo hi")),
        ("command", json!("ls; rm -rf x")),
        ("cmd", json!("whoami")),
        ("args", json!(["--flag", "value"])),
        ("script", json!("print(1)")),
        ("url", json!("https://example.com/")),
        ("url", json!("http://example.com/a/../b")),
        ("query", json!("SELECT 1")),
        ("content", json!("hello")),
        ("message", json!("fix: thing")),
        ("pattern", json!("*.rs")),
        ("table_name", json!("users")),
        ("names", json!(["Alice"])),
        ("max_length", json!(100)),
    ];
    for _ in 0..rng.below(4) {
        let (k, v) = rng.pick(&extras).clone();
        map.insert(k.to_string(), v);
    }
}

fn gen_path_args(rng: &mut Rng, bad: Option<&str>) -> Value {
    // Returns an argument object where `bad` (if given) is placed under a path-like key and good
    // in-jail paths may be added next to it.
    let mut map = serde_json::Map::new();
    let good = [jp("a.txt"), jp("sub/b.txt"), jp("sub")];
    if let Some(b) = bad {
        match rng.below(8) {
            0 => {
                map.insert("path".into(), json!(b));
            }
            1 => {
                map.insert("source".into(), json!(good[rng.below(3)]));
                map.insert("destination".into(), json!(b));
            }
            2 => {
                map.insert("paths".into(), json!([good[0], b, good[1]]));
            }
            3 => {
                map.insert("repo_path".into(), json!(b));
            }
            4 => {
                map.insert("file".into(), json!(b));
            }
            5 => {
                map.insert("options".into(), json!({"deep": [{"dir": b}]}));
                map.insert("path".into(), json!(good[0]));
            }
            6 => {
                map.insert("filepath".into(), json!(b));
                map.insert("content".into(), json!("x"));
            }
            _ => {
                map.insert("database".into(), json!(b));
            }
        }
    } else if rng.below(2) == 0 {
        map.insert("path".into(), json!(good[rng.below(3)]));
    }
    gen_extra_args(rng, &mut map);
    // a relative path under a base directory key must be joined with it, not trusted
    Value::Object(map)
}

fn property_configs() -> Vec<(String, PolicyConfig)> {
    let mut out = vec![("default".to_string(), base_config())];
    for p in PRESETS {
        out.push((p.to_string(), preset_config(p)));
    }
    let mut ro = base_config();
    ro.read_only = true;
    out.push(("read_only".into(), ro));
    let mut approve = base_config();
    approve.require_approval_on_write = true;
    out.push(("require_approval_on_write".into(), approve));
    out
}

#[test]
fn property_path_outside_jail_is_always_block() {
    let names = all_tool_names();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut checked = 0usize;
    for (label, base) in property_configs() {
        // Variants in which every generated tool name is listed as allowed, as non-file tool or as
        // modifying tool: no configuration may turn an outside path into anything but Block.
        let mut listed = base.clone();
        listed.always_allow_tools.extend(names.clone());
        let mut non_file = base.clone();
        non_file.non_file_tools.extend(names.clone());
        non_file.custom_always_allow_tools.extend(names.clone());
        let mut modifying = base.clone();
        modifying.custom_modifying_tools.extend(names.clone());
        let engines: Vec<PolicyEngine> = [base, listed, non_file, modifying]
            .into_iter()
            .map(|c| PolicyEngine::new(c).unwrap())
            .collect();
        for case in 0..700 {
            let tool = rng.pick(&names).clone();
            let e = &engines[case % 4];
            let bad = gen_bad_path(&mut rng);
            let args = gen_path_args(&mut rng, Some(&bad));
            let d = e.evaluate_tool_call(&call(&tool, args.clone()));
            assert!(
                is_block(&d),
                "config {label}, case {case}: tool {tool:?} args {args} gave {d:?}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 4900);
}

#[test]
fn property_unauthorized_tool_is_never_allow() {
    let allowed_somewhere: Vec<String> = {
        let mut v = Vec::new();
        for (_, c) in property_configs() {
            v.extend(c.always_allow_tools);
            v.extend(c.custom_always_allow_tools);
        }
        v.extend(
            [
                "read_file",
                "read_text_file",
                "read_media_file",
                "read_multiple_files",
                "write_file",
                "edit_file",
                "create_directory",
                "list_directory",
                "list_directory_with_sizes",
                "directory_tree",
                "move_file",
                "search_files",
                "get_file_info",
                "list_allowed_directories",
                "copy_file",
                "append_file",
            ]
            .map(String::from),
        );
        v
    };
    let mut names: Vec<String> = all_tool_names()
        .into_iter()
        .filter(|n| !allowed_somewhere.contains(n))
        .collect();
    // generated names: patterns that look like file tools, with and without separators
    let words = ["file", "dir", "data", "node", "row", "page", "item", "doc"];
    let prefixes = [
        "read_", "write_", "get_", "list_", "delete_", "edit_", "create_", "update_", "run_", "",
    ];
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..80 {
        let n = format!("{}{}", rng.pick(&prefixes), rng.pick(&words));
        if !allowed_somewhere.contains(&n) {
            names.push(n);
        }
    }
    assert!(names.len() > 60);

    let mut checked = 0usize;
    for (label, base) in property_configs() {
        // classification and the non-file exemption must never authorize
        let mut modifying = base.clone();
        modifying.custom_modifying_tools.extend(names.clone());
        let mut non_file = base.clone();
        non_file.non_file_tools.extend(names.clone());
        let engines: Vec<PolicyEngine> = [base, modifying, non_file]
            .into_iter()
            .map(|c| PolicyEngine::new(c).unwrap())
            .collect();
        for case in 0..600 {
            let tool = rng.pick(&names).clone();
            let e = &engines[case % 3];
            let bad = if rng.below(3) == 0 {
                Some(gen_bad_path(&mut rng))
            } else {
                None
            };
            let args = if rng.below(5) == 0 {
                json!({})
            } else {
                gen_path_args(&mut rng, bad.as_deref())
            };
            let d = e.evaluate_tool_call(&call(&tool, args.clone()));
            assert!(
                !is_allow(&d),
                "config {label}, case {case}: unknown tool {tool:?} args {args} gave Allow"
            );
            checked += 1;
        }
    }
    assert!(checked >= 4200);
}

#[test]
fn property_in_jail_standard_calls_are_allowed_unless_command_or_protected() {
    // Sanity for the generator: the property tests above would pass trivially if everything were
    // blocked. A well-formed call with an in-jail path must still be allowed.
    let e = engine();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for _ in 0..200 {
        let tool = *rng.pick(&[
            "read_file",
            "list_directory",
            "search_files",
            "get_file_info",
        ]);
        let p = [jp("a.txt"), jp("sub/b.txt"), jp("sub")][rng.below(3)].clone();
        let d = e.evaluate_tool_call(&call(
            tool,
            json!({"path": p, "pattern": "x", "url": "https://e.com/"}),
        ));
        assert!(is_allow(&d), "{tool} gave {d:?}");
    }
}

// ---------------------------------------------------------------------------
// Invariant 3: approval prompts (decision side)
// ---------------------------------------------------------------------------

#[test]
fn inv3_approval_is_only_requested_for_defined_cases() {
    // Every AskOperator comes from one of: command, protected target, require_approval_on_write,
    // unauthorized modifying tool. Reads and authorized calls never ask.
    let e = engine();
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a")})
    ))));
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": jp("a"), "content": "x"})
    ))));
    assert!(is_ask(
        &e.evaluate_tool_call(&call("bash", json!({"command": "ls"})))
    ));
    assert!(is_ask(&e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": jp("moat.toml"), "content": "x"})
    ))));
    assert!(is_ask(
        &e.evaluate_tool_call(&call("rm", json!({"path": jp("a")})))
    ));
    let mut c = base_config();
    c.require_approval_on_write = true;
    let e = PolicyEngine::new(c).unwrap();
    assert!(is_ask(&e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": jp("a"), "content": "x"})
    ))));
    assert!(is_allow(&e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a")})
    ))));
}

// The terminal / --no-prompt side is tested end to end in
// crates/mcp-moat-proxy/tests/no_prompt.rs (no approval is ever granted without a console).

// ---------------------------------------------------------------------------
// Invariant 4: DLP
// ---------------------------------------------------------------------------

#[test]
fn inv4_known_secret_formats_are_masked_in_responses() {
    let dlp = DlpEngine::new();
    let secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    ];
    for s in secrets {
        let mut v =
            json!({"result": {"content": [{"type": "text", "text": format!("value: {s} end")}]}});
        let n = dlp.sanitize_json_value(&mut v);
        let out = v.to_string();
        assert!(n >= 1, "{s}: nothing redacted");
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"), "{s}: {out}");
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE") && !out.contains("ghp_abcdef"),
            "{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 5: audit chain
// ---------------------------------------------------------------------------

#[test]
fn inv5_audit_chain_detects_modification_reorder_and_deletion() {
    let mut chain = AuditChain::new("inv5");
    let mut events = Vec::new();
    for i in 0..5 {
        events.push(chain.create_event(
            format!("2026-11-13T00:00:0{i}Z"),
            AuditDirection::Inbound,
            "tools/call".into(),
            Some(format!("tool{i}")),
            None,
            None,
            None,
            None,
            None,
        ));
    }
    let join = |evs: &[mcp_moat_core::audit::AuditEvent]| {
        evs.iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    };
    let ok = verify_audit_log(join(&events).as_bytes()).unwrap();
    assert!(ok.is_valid && ok.total_records == 5);

    let mut modified = events.clone();
    modified[2].tool_name = Some("other".into());
    assert!(
        !verify_audit_log(join(&modified).as_bytes())
            .unwrap()
            .is_valid
    );

    let mut deleted = events.clone();
    deleted.remove(2);
    assert!(
        !verify_audit_log(join(&deleted).as_bytes())
            .unwrap()
            .is_valid
    );

    let mut reordered = events.clone();
    reordered.swap(1, 3);
    assert!(
        !verify_audit_log(join(&reordered).as_bytes())
            .unwrap()
            .is_valid
    );
}

// ---------------------------------------------------------------------------
// Preset ignore_path_keys are scoped to the tools of the preset
// ---------------------------------------------------------------------------

#[test]
fn preset_ignore_keys_do_not_leak_to_other_tools() {
    let e = preset_engine("memory");
    let d = e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": jp("a.txt"), "content": "x", "to": "/etc/passwd"}),
    ));
    assert!(is_block(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call("frobnicate", json!({"from": "../../etc/passwd"})));
    assert!(is_block(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call(
        "move_file",
        json!({"from": "/etc/passwd", "to": jp("x")}),
    ));
    assert!(is_block(&d), "{d:?}");
    // memory tools keep their normal decision with entity names in from/to
    let d = e.evaluate_tool_call(&call(
        "create_relations",
        json!({"relations": [{"from": "Project: X", "to": "../Bob", "relationType": "knows"}]}),
    ));
    assert!(is_ask(&d), "{d:?}");

    let e = preset_engine("git");
    let d = e.evaluate_tool_call(&call(
        "git_checkout",
        json!({"repo_path": jp("repo"), "branch_name": "feature/x"}),
    ));
    assert!(is_allow(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call("frobnicate", json!({"target": "/etc/passwd"})));
    assert!(is_block(&d), "{d:?}");
    let d = e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a.txt"), "target": "/etc/passwd"}),
    ));
    assert!(is_block(&d), "{d:?}");
}

#[test]
fn operator_ignore_keys_stay_global() {
    let mut c = base_config();
    c.ignore_path_keys.push("target".into());
    let e = PolicyEngine::new(c).unwrap();
    let d = e.evaluate_tool_call(&call(
        "read_file",
        json!({"path": jp("a.txt"), "target": "HEAD~1"}),
    ));
    assert!(is_allow(&d), "{d:?}");
}

// ---------------------------------------------------------------------------
// Decision matrix
// ---------------------------------------------------------------------------

/// Every combination of authorization, classification, path, command argument,
/// `require_approval_on_write` and `read_only` must give the decision of `common::expected`,
/// which restates the order of checks of docs/security-model.md. The same cases run through the
/// proxy in crates/mcp-moat-proxy/tests/no_prompt.rs.
#[test]
fn decision_matrix_policy_equals_documented_rule() {
    use common::Exp;
    let cases = common::cases();
    let mut engines = std::collections::HashMap::new();
    let mut wrong = Vec::new();
    for case in &cases {
        let engine = engines
            .entry(case.config_key())
            .or_insert_with(|| PolicyEngine::new(case.config(&jail())).unwrap());
        let got = engine.evaluate_tool_call(&call(case.tool.name, case.arguments(&jail())));
        let got_kind = match got {
            Decision::Allow => Exp::Allow,
            Decision::Block(_) => Exp::Block,
            Decision::AskOperator { .. } => Exp::Ask,
        };
        let want = common::expected(case);
        if got_kind != want {
            wrong.push(format!("{case:?}: policy {got:?}, rule {want:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases differ:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
    // the matrix covers all three decisions
    let kinds: std::collections::HashSet<_> = cases.iter().map(common::expected).collect();
    assert_eq!(kinds.len(), 3);
}
