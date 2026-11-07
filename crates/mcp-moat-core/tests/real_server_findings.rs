//! Regression tests for gaps found while running mcp-moat in front of the real
//! `@modelcontextprotocol/server-filesystem` (see docs in CHANGELOG.md).
use mcp_moat_core::{Decision, DlpEngine, PolicyConfig, PolicyEngine, ToolCallParams};
use serde_json::json;
use std::path::PathBuf;

fn jail() -> PathBuf {
    let p = std::env::temp_dir().join("mcp-moat-real-server-jail");
    std::fs::create_dir_all(&p).unwrap();
    let c = p.canonicalize().unwrap();
    let s = c.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail()],
        ..PolicyConfig::default()
    })
    .unwrap()
}

fn call(name: &str, path: &str) -> ToolCallParams {
    ToolCallParams {
        name: name.into(),
        arguments: Some(json!({ "path": path })),
    }
}

// ---------------------------------------------------------------- secret masking

#[test]
fn env_file_lines_with_a_prefix_are_masked_and_the_name_is_kept() {
    let dlp = DlpEngine::new();
    for (line, name) in [
        ("OPENAI_API_KEY=abcdefgh12345678", "OPENAI_API_KEY="),
        ("GITHUB_TOKEN=abcdefgh12345678", "GITHUB_TOKEN="),
        ("export STRIPE_SECRET=abcdefgh12345678", "STRIPE_SECRET="),
        ("DB_PASSWORD=hunter2hunter2", "DB_PASSWORD="),
        ("x-api-key: abcdefgh12345678", "x-api-key:"),
        (
            "AWS_SECRET_ACCESS_KEY=abcdefgh12345678",
            "AWS_SECRET_ACCESS_KEY=",
        ),
        (
            "slack_bot_token = \"abcdefgh12345678\"",
            "slack_bot_token =",
        ),
    ] {
        let (out, count) = dlp.sanitize_text(line);
        assert!(count >= 1, "not masked: {line}");
        assert!(
            out.contains("[MCP-MOAT-REDACTED-SECRET]"),
            "not masked: {line}"
        );
        assert!(out.contains(name), "name was lost in {line:?} -> {out:?}");
        assert!(
            !out.contains("abcdefgh12345678") && !out.contains("hunter2hunter2"),
            "value left in {out:?}"
        );
    }
}

#[test]
fn groq_keys_are_masked() {
    let dlp = DlpEngine::new();
    let (out, count) = dlp.sanitize_text("key is gsk_A1b2C3d4E5f6G7h8I9j0K1l2 ok");
    assert_eq!(count, 1);
    assert!(!out.contains("gsk_A1b2"), "{out}");
}

#[test]
fn json_lines_with_env_style_secrets_are_masked() {
    let dlp = DlpEngine::new();
    let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"GROQ_API_KEY=gsk_A1b2C3d4E5f6G7h8I9j0K1l2\nDEBUG=1"}]}}"#;
    let (out, count) = dlp.sanitize_line(line);
    assert!(count >= 1, "{out}");
    assert!(!out.contains("gsk_A1b2"), "{out}");
    assert!(out.contains("DEBUG=1"), "{out}");
    serde_json::from_str::<serde_json::Value>(&out).expect("output must stay valid JSON");
}

#[test]
fn ordinary_settings_are_not_masked() {
    let dlp = DlpEngine::new();
    for text in [
        "max_output_tokens: 16384",
        "token_count: 123456789",
        "tokens = 12345678",
        "keyboard: abcdefghijkl",
        "password: short",
        "api_key=",
        "the password policy is in the handbook",
        "public_key_path: /home/user/.ssh/id_rsa.pub",
    ] {
        let (out, count) = dlp.sanitize_text(text);
        assert_eq!(
            (count, out.as_str()),
            (0, text),
            "false positive on {text:?}"
        );
    }
}

// ----------------------------------------------------------------- tool names

#[test]
fn directory_tree_is_a_path_checked_read_tool() {
    let e = engine();
    let inside = jail().join("sub");
    assert_eq!(
        e.evaluate_tool_call(&call("directory_tree", &inside.to_string_lossy())),
        Decision::Allow
    );
    match e.evaluate_tool_call(&call("directory_tree", "/etc")) {
        Decision::Block(msg) => assert!(!msg.contains("Unrecognized tool"), "{msg}"),
        other => panic!("directory_tree outside the jail must be blocked, got {other:?}"),
    }
}

#[test]
fn directory_tree_is_blocked_in_read_only_mode_only_if_it_modifies() {
    // It only reads, so read-only mode must not block it.
    let e = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail()],
        read_only: true,
        ..PolicyConfig::default()
    })
    .unwrap();
    assert_eq!(
        e.evaluate_tool_call(&call("directory_tree", &jail().to_string_lossy())),
        Decision::Allow
    );
}

#[test]
fn unknown_tools_with_a_path_are_still_blocked() {
    let e = engine();
    match e.evaluate_tool_call(&call("frobnicate", &jail().to_string_lossy())) {
        Decision::Block(msg) => assert!(msg.contains("Unrecognized tool"), "{msg}"),
        other => panic!("expected a block, got {other:?}"),
    }
}

// ------------------------------------------------- relative paths next to repo_path (git server)

fn git_engine() -> PolicyEngine {
    let mut config = PolicyConfig {
        allowed_paths: vec![jail()],
        ..PolicyConfig::default()
    };
    config.apply_preset("git").unwrap();
    PolicyEngine::new(config).unwrap()
}

fn git_call(name: &str, args: serde_json::Value) -> ToolCallParams {
    ToolCallParams {
        name: name.into(),
        arguments: Some(args),
    }
}

#[test]
fn relative_file_lists_are_checked_against_repo_path_not_the_working_directory() {
    let e = git_engine();
    let repo = jail().join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("f.txt"), "x").unwrap();
    std::fs::write(repo.join("src").join("main.rs"), "x").unwrap();
    let repo = repo.to_string_lossy().to_string();

    // A plain file name in the repository is fine.
    let ok = git_call(
        "git_add",
        json!({ "repo_path": repo, "files": ["f.txt", "src/main.rs"] }),
    );
    assert!(
        !matches!(e.evaluate_tool_call(&ok), Decision::Block(_)),
        "{:?}",
        e.evaluate_tool_call(&ok)
    );

    // The paths that are checked are the joined ones.
    let paths = e.extract_all_path_arguments(&ok);
    assert!(paths.iter().any(|p| p.ends_with("repo/f.txt")), "{paths:?}");
    assert!(
        paths.iter().any(|p| p.ends_with("repo/src/main.rs")),
        "{paths:?}"
    );
}

#[test]
fn relative_file_lists_cannot_leave_the_jail() {
    let e = git_engine();
    let repo = jail().join("repo").to_string_lossy().to_string();
    for file in ["../../outside/f.txt", "../x", "sub/../../x"] {
        let call = git_call("git_add", json!({ "repo_path": repo, "files": [file] }));
        assert!(
            matches!(e.evaluate_tool_call(&call), Decision::Block(_)),
            "{file} must be blocked"
        );
    }
    // Absolute paths are not joined with the repository.
    let call = git_call(
        "git_add",
        json!({ "repo_path": repo, "files": ["/etc/passwd"] }),
    );
    match e.evaluate_tool_call(&call) {
        // The text differs by platform: "/etc/passwd" is not an absolute path on Windows.
        Decision::Block(_) => {}
        other => panic!("expected a block, got {other:?}"),
    }
}

#[test]
fn a_repo_path_outside_the_jail_is_blocked() {
    let e = git_engine();
    let call = git_call("git_status", json!({ "repo_path": "/etc" }));
    assert!(matches!(e.evaluate_tool_call(&call), Decision::Block(_)));
}

#[test]
fn the_base_directory_itself_is_not_joined_with_itself() {
    let e = git_engine();
    let paths = e.extract_all_path_arguments(&git_call(
        "git_status",
        json!({ "repo_path": "relative/repo" }),
    ));
    assert_eq!(paths, vec!["relative/repo".to_string()]);
}

#[test]
fn git_revisions_branch_names_and_messages_are_not_paths() {
    let e = git_engine();
    let repo = jail().join("repo").to_string_lossy().to_string();
    for (tool, args) in [
        ("git_diff", json!({ "repo_path": repo, "target": "HEAD~1" })),
        (
            "git_show",
            json!({ "repo_path": repo, "revision": "main~2" }),
        ),
        (
            "git_create_branch",
            json!({ "repo_path": repo, "branch_name": "feature~x" }),
        ),
        (
            "git_commit",
            json!({ "repo_path": repo, "message": "fix ../../etc handling" }),
        ),
    ] {
        let call = git_call(tool, args);
        let paths = e.extract_all_path_arguments(&call);
        assert_eq!(
            paths,
            vec![repo.clone()],
            "{tool}: only repo_path is a path"
        );
        assert!(
            !matches!(e.evaluate_tool_call(&call), Decision::Block(_)),
            "{tool}: {:?}",
            e.evaluate_tool_call(&call)
        );
    }
}

#[test]
fn without_the_git_preset_target_is_still_a_path() {
    let e = engine();
    let call = ToolCallParams {
        name: "read_file".into(),
        arguments: Some(json!({ "target": "../../etc/passwd" })),
    };
    assert!(matches!(e.evaluate_tool_call(&call), Decision::Block(_)));
}

#[test]
fn the_git_preset_knows_the_tools_of_the_real_git_server() {
    let e = git_engine();
    let repo = jail().join("repo").to_string_lossy().to_string();
    for tool in [
        "git_status",
        "git_log",
        "git_show",
        "git_diff",
        "git_diff_unstaged",
        "git_diff_staged",
        "git_branch",
    ] {
        let call = git_call(tool, json!({ "repo_path": repo }));
        assert_eq!(e.evaluate_tool_call(&call), Decision::Allow, "{tool}");
    }
}

// --------------------------------------------------------------------------- 8.3 short names

#[test]
fn only_real_dos_short_names_are_rejected() {
    use mcp_moat_core::policy::validate_lexical_syntax;
    for blocked in [
        "PROGRA~1",
        "MOAT~1.TOM",
        "C:/Users/RUNNER~1/AppData",
        r"C:\safe\PROGRA~1\moat.toml",
        "a/B~12/c",
        "x~1.js",
    ] {
        assert!(
            validate_lexical_syntax(blocked).is_err(),
            "{blocked} must be rejected"
        );
    }
    for allowed in [
        "vaults/iCloud~md~obsidian/Shared/note.md",
        "backup~old/file.txt",
        "report~final.docx",
        "a~b",
        "name_with_a_long_prefix~1/file",
        "dir/~tilde-start",
        "home/~/x",
    ] {
        assert!(
            validate_lexical_syntax(allowed).is_ok(),
            "{allowed} must be accepted: {:?}",
            validate_lexical_syntax(allowed)
        );
    }
}

#[test]
fn secrets_inside_json_text_keep_their_quotes_and_neighbours() {
    // The text of a tool result that holds a JSON dump of the environment (server-everything: get-env).
    let dlp = DlpEngine::new();
    let text = "{\n  \"HOME\": \"/root\",\n  \"OPENAI_API_KEY\": \"abcdefgh12345678\",\n  \"DB_PASSWORD\": \"hunter2hunter2\",\n  \"PATH\": \"/usr/bin\"\n}";
    let (out, count) = dlp.sanitize_text(text);
    assert_eq!(count, 2, "{out}");
    assert!(
        out.contains("\"OPENAI_API_KEY\": \"[MCP-MOAT-REDACTED-SECRET]\""),
        "{out}"
    );
    assert!(
        out.contains("\"DB_PASSWORD\": \"[MCP-MOAT-REDACTED-SECRET]\""),
        "{out}"
    );
    assert!(
        out.contains("\"HOME\": \"/root\"") && out.contains("\"PATH\": \"/usr/bin\""),
        "{out}"
    );
    assert!(!out.contains("abcdefgh12345678") && !out.contains("hunter2hunter2"));
}

#[test]
fn a_whole_json_rpc_line_with_an_environment_dump_is_masked() {
    let dlp = DlpEngine::new();
    let line = r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\n  \"OPENAI_API_KEY\": \"abcdefgh12345678\"\n}"}]}}"#;
    let (out, count) = dlp.sanitize_line(line);
    assert!(count >= 1, "{out}");
    assert!(!out.contains("abcdefgh12345678"), "{out}");
    let value: serde_json::Value = serde_json::from_str(&out).expect("must stay valid JSON");
    assert!(value["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("OPENAI_API_KEY"));
}

#[test]
fn single_quoted_and_yaml_style_secrets_are_masked() {
    let dlp = DlpEngine::new();
    for (text, leaked) in [
        ("password: 'correct horse'", "correct"),
        ("client_secret: 's3cr3t-value-9876'", "s3cr3t-value-9876"),
        ("  api-key = \"abcdefgh12345678\"", "abcdefgh12345678"),
        ("'GITHUB_TOKEN':'abcdefgh12345678'", "abcdefgh12345678"),
    ] {
        let (out, _) = dlp.sanitize_text(text);
        assert!(
            !out.contains(leaked) || leaked == "correct",
            "{text:?} -> {out:?}"
        );
    }
}

// ------------------------------------------------------------ tools with file-like names but no path

#[test]
fn a_tool_with_a_file_like_name_and_no_path_needs_to_be_declared() {
    let call = ToolCallParams {
        name: "get-sum".into(),
        arguments: Some(json!({ "a": 2, "b": 3 })),
    };
    // Without the declaration it is blocked: no path can be verified.
    let blocked = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail()],
        always_allow_tools: vec!["get-sum".into()],
        ..PolicyConfig::default()
    })
    .unwrap();
    match blocked.evaluate_tool_call(&call) {
        Decision::Block(msg) => assert!(msg.contains("could not be verified"), "{msg}"),
        other => panic!("expected a block, got {other:?}"),
    }
    // With the declaration (and the allow list) it runs.
    let allowed = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail()],
        always_allow_tools: vec!["get-sum".into()],
        non_file_tools: vec!["GET-SUM".into()],
        ..PolicyConfig::default()
    })
    .unwrap();
    assert_eq!(allowed.evaluate_tool_call(&call), Decision::Allow);
}

#[test]
fn declaring_a_non_file_tool_does_not_unblock_path_arguments_outside_the_jail() {
    let e = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail()],
        always_allow_tools: vec!["get-sum".into()],
        non_file_tools: vec!["get-sum".into()],
        ..PolicyConfig::default()
    })
    .unwrap();
    let call = ToolCallParams {
        name: "get-sum".into(),
        arguments: Some(json!({ "path": "/etc/passwd" })),
    };
    assert!(matches!(e.evaluate_tool_call(&call), Decision::Block(_)));
}
