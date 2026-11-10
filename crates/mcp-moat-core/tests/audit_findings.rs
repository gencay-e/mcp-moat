use mcp_moat_core::policy::validate_lexical_syntax;
use mcp_moat_core::{Decision, DlpEngine, PolicyConfig, PolicyEngine, ToolCallParams};
use serde_json::json;
use std::path::PathBuf;

fn test_jail() -> PathBuf {
    let p = std::env::temp_dir().join("mcp-moat-test-jail");
    std::fs::create_dir_all(&p).unwrap();
    let c = p.canonicalize().unwrap();
    let s = c.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

fn clean_jail_str(jail: &std::path::Path) -> String {
    let s = jail.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).replace('\\', "/")
}

fn test_engine() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![test_jail()],
        ..PolicyConfig::default()
    })
    .unwrap()
}

fn call(name: &str, args: serde_json::Value) -> ToolCallParams {
    ToolCallParams {
        name: name.into(),
        arguments: Some(args),
    }
}

// -------------------------------------------------------------
// DLP Security Tests (Fixing f01, f02, f03)
// -------------------------------------------------------------

#[test]
fn test_f01_dlp_never_panics_on_pkcs8_private_key() {
    let dlp = DlpEngine::new();
    let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"}]}}"#;
    let (out, count) = dlp.sanitize_line(line);
    assert!(count >= 1);
    assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
}

#[test]
fn test_f02_dlp_preserves_valid_json_framing() {
    let dlp = DlpEngine::new();
    let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"password=hunter2secret"}]}}"#;
    let (out, n) = dlp.sanitize_line(line);
    assert!(n > 0);
    let parsed = serde_json::from_str::<serde_json::Value>(&out);
    assert!(
        parsed.is_ok(),
        "JSON framing must remain valid after DLP redaction: {}",
        out
    );
}

#[test]
fn test_f03_dlp_catches_unicode_escaped_secrets() {
    let dlp = DlpEngine::new();
    // JSON-escaped "\u0073\u006b-..." -> decoded to "sk-..." by AST parser and masked
    let line = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"\u0073\u006b-1234567890abcdef1234567890abcdef"}]}}"#;
    let (out, n) = dlp.sanitize_line(line);
    assert!(
        n > 0,
        "Must detect and redact unicode-escaped OpenAI secret"
    );
    assert!(!out.contains("sk-1234567890abcdef"));
    assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
}

// -------------------------------------------------------------
// Protocol & Tool Call Shape (Fixing f06)
// -------------------------------------------------------------

#[test]
fn test_f06_bad_tool_params_shape_is_blocked() {
    let call_with_string_args = ToolCallParams {
        name: "read_file".into(),
        arguments: Some(json!("not-an-object")),
    };
    let decision = test_engine().evaluate_tool_call(&call_with_string_args);
    match decision {
        Decision::Block(msg) => assert!(msg.contains("must be a JSON object")),
        _ => panic!(
            "Expected block on non-object arguments, got: {:?}",
            decision
        ),
    }
}

// -------------------------------------------------------------
// Multi-Path Extraction (Fixing f07, f08, f09)
// -------------------------------------------------------------

#[test]
fn test_f07_move_file_source_and_destination_checked() {
    let e = test_engine();
    #[cfg(windows)]
    let (source, destination) = ("C:/Windows/System32/calc.exe", "C:/Windows/Temp/target.exe");
    #[cfg(not(windows))]
    let (source, destination) = ("/etc/passwd", "/etc/mcp-moat-target");
    let d = e.evaluate_tool_call(&call(
        "move_file",
        json!({"source": source, "destination": destination}),
    ));
    match d {
        Decision::Block(msg) => {
            #[cfg(windows)]
            assert!(msg.contains("prohibited") || msg.contains("sandbox root"));
            #[cfg(not(windows))]
            assert!(
                msg.contains("outside boundary") || msg.contains("sandbox root"),
                "{}",
                msg
            );
        }
        _ => panic!(
            "Expected move_file with outside source/dest to be blocked, got: {:?}",
            d
        ),
    }
}

#[test]
fn test_f08_read_multiple_files_paths_array_checked() {
    let e = test_engine();
    let d = e.evaluate_tool_call(&call(
        "read_multiple_files",
        json!({"paths": ["C:/Windows/win.ini", "/etc/passwd"]}),
    ));
    match d {
        Decision::Block(_) => {} // Pass!
        _ => panic!(
            "Expected read_multiple_files array to be blocked, got: {:?}",
            d
        ),
    }
}

#[test]
fn test_f09_unknown_tool_fails_closed() {
    let e = test_engine();
    let d = e.evaluate_tool_call(&call("delete_everything", json!({"where": "/" })));
    assert_ne!(
        d,
        Decision::Allow,
        "Unknown tools must NEVER default to Allow!"
    );
}

// -------------------------------------------------------------
// In-Jail Self-Escalation Defense (Fixing f10)
// -------------------------------------------------------------

#[test]
fn test_f10_protected_in_jail_files_require_approval() {
    let e = test_engine();
    // Canonical path: temp_dir() can contain 8.3 short names (RUNNER~1) on Windows or a
    // symlink (/var -> /private/var) on macOS.
    let jail_dir = test_jail();

    for protected_name in [
        "moat.toml",
        "fence.toml",
        ".git/hooks/pre-commit",
        ".vscode/tasks.json",
        ".env",
    ] {
        let target = jail_dir.join(protected_name);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();

        // Strip \\?\ prefix if present on Windows so it looks like a client request
        let raw_path = target.to_string_lossy();
        let client_path = raw_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&raw_path)
            .to_string();

        let d = e.evaluate_tool_call(&call(
            "write_file",
            json!({"path": client_path, "content": "malicious config"}),
        ));

        // Must require operator approval even though it is physically inside the jail!
        match d {
            Decision::AskOperator { .. } => {} // Pass!
            _ => panic!(
                "Writing to protected file '{}' in jail must require operator approval, got {:?}",
                protected_name, d
            ),
        }
    }
}

// -------------------------------------------------------------
// Lexical Syntax Hardening (Fixing f11, f12, f13, f14)
// -------------------------------------------------------------

#[test]
fn test_f11_mixed_separator_unc_is_blocked() {
    assert!(validate_lexical_syntax(r"/\host\share\x").is_err());
    assert!(validate_lexical_syntax(r"\/host/share/x").is_err());
    assert!(validate_lexical_syntax(r"\\host\share\x").is_err());
    assert!(validate_lexical_syntax(r"//host/share/x").is_err());
}

#[test]
fn test_f13_drive_relative_and_device_names_blocked() {
    // Drive-relative without slash must fail
    assert!(validate_lexical_syntax(r"C:foo\bar").is_err());
    // Reserved DOS device names must fail
    assert!(validate_lexical_syntax(r"CONIN$").is_err());
    assert!(validate_lexical_syntax(r"CONOUT$").is_err());
    assert!(validate_lexical_syntax(r"NUL").is_err());
    assert!(validate_lexical_syntax(r"COM1").is_err());
    // Regular drive path with slash must succeed
    assert!(validate_lexical_syntax(r"C:\Projects\valid.txt").is_ok());
    assert!(validate_lexical_syntax(r"C:/Projects/valid.txt").is_ok());
}

#[test]
fn test_f14_trailing_dotdot_blocked() {
    assert!(validate_lexical_syntax(r"C:\jail\..").is_err());
    assert!(validate_lexical_syntax(r"C:/jail/..").is_err());
    assert!(validate_lexical_syntax(r"..").is_err());
    assert!(validate_lexical_syntax(r"../src").is_err());
}

// -------------------------------------------------------------
// Security Audit Regression Tests (Fixing P0, P1, P2 findings)
// -------------------------------------------------------------

#[test]
fn test_audit_p0_1_always_allow_tools_fails_closed_on_unverifiable_path() {
    let e = test_engine();

    // 1. Unverifiable file tool arguments must FAIL-CLOSED
    let d_unverifiable = e.evaluate_tool_call(&call(
        "read_file",
        json!({"unrecognized_param": "some_value"}),
    ));
    match d_unverifiable {
        Decision::Block(msg) => {
            assert!(
                msg.contains("Path argument could not be verified for file tool"),
                "Expected fail-closed path argument verification error, got: {}",
                msg
            );
        }
        _ => panic!(
            "Expected Block on unverifiable file read tool, got: {:?}",
            d_unverifiable
        ),
    }

    // 2. Expanded path keys (filename, src, nested) must be extracted and validated
    let d_outside = e.evaluate_tool_call(&call(
        "read_file",
        json!({"filename": "C:/Windows/System32/drivers/etc/hosts"}),
    ));
    assert!(
        matches!(d_outside, Decision::Block(_)),
        "Must block outside path using 'filename' key"
    );

    let jail = test_jail();
    let jail_str = clean_jail_str(&jail);
    let inside_file = format!("{}/test_inside.txt", jail_str);
    std::fs::write(&inside_file, "hello").unwrap();

    let d_inside = e.evaluate_tool_call(&call("read_file", json!({"src": inside_file})));
    assert_eq!(
        d_inside,
        Decision::Allow,
        "Must allow inside path using 'src' key"
    );

    // 3. Nested object extraction
    let d_nested_outside = e.evaluate_tool_call(&call(
        "read_file",
        json!({"file": {"path": "C:/Windows/win.ini"}}),
    ));
    assert!(
        matches!(d_nested_outside, Decision::Block(_)),
        "Must block outside path in nested object"
    );
}

#[test]
fn test_audit_p0_2_nt_object_manager_namespace_blocked() {
    // NT DosDevices / UNC paths must be blocked without I/O
    assert!(validate_lexical_syntax(r"\??\UNC\evil.com\share\file").is_err());
    assert!(validate_lexical_syntax(r"/??/UNC/evil.com/share/file").is_err());
    assert!(validate_lexical_syntax(r"\Device\LanmanRedirector\share").is_err());
    assert!(validate_lexical_syntax(r"/device/mup/share").is_err());
}

#[test]
fn test_audit_p1_3_reserved_device_names_in_subdirectories_and_expanded_devices() {
    // Intermediate subdirectory device names must be blocked
    assert!(validate_lexical_syntax("jail/con/file.txt").is_err());
    assert!(validate_lexical_syntax("jail/nul/data.bin").is_err());
    assert!(validate_lexical_syntax("jail/aux/anything").is_err());
    assert!(validate_lexical_syntax(r"subdir/com1/output").is_err());

    // Additional reserved devices
    assert!(validate_lexical_syntax(r"CLOCK$").is_err());
    assert!(validate_lexical_syntax(r"CONFIG$").is_err());
    assert!(validate_lexical_syntax(r"subdir/CLOCK$/file").is_err());
}

// Backslash is a path separator only on Windows.
#[cfg(windows)]
#[test]
fn test_audit_p1_3_reserved_device_names_with_backslashes() {
    assert!(validate_lexical_syntax(r"C:\jail\con\file.txt").is_err());
    assert!(validate_lexical_syntax(r"C:\jail\nul\data.bin").is_err());
    assert!(validate_lexical_syntax(r"C:\jail\aux\anything").is_err());
    assert!(validate_lexical_syntax(r"C:\jail\con\").is_err());
}

#[test]
fn test_audit_p2_4_curdir_component_is_noop() {
    let e = test_engine();
    let jail = test_jail();
    let jail_str = clean_jail_str(&jail);
    let valid_file = format!("{}/curdir_test.txt", jail_str);
    std::fs::write(&valid_file, "content").unwrap();

    // Paths containing '.' must not error with "Illegal traversal component"
    let test_path = format!("{}/./curdir_test.txt", jail_str);
    let res = e.validate_path_secure(&test_path);
    assert!(
        res.is_ok(),
        "CurDir '.' must be handled as a harmless no-op, got: {:?}",
        res
    );
}

#[test]
fn test_audit_p2_3_protected_in_jail_with_trailing_spaces_and_git_file() {
    let jail = test_jail().join("sub_git_test");
    std::fs::create_dir_all(&jail).unwrap();
    let e = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![test_jail()],
        ..PolicyConfig::default()
    })
    .unwrap();
    let jail_str = clean_jail_str(&jail);

    // 1. moat.toml with trailing space
    let moat_space = format!("{}/moat.toml ", jail_str);
    let d1 = e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": moat_space, "content": "escalation"}),
    ));
    assert!(
        matches!(d1, Decision::AskOperator { .. }),
        "Writing to 'moat.toml ' with space must require operator approval, got: {:?}",
        d1
    );

    // 2. .git file (worktree/submodule) without trailing slash
    let sub_dir = format!("{}/submodule", jail_str);
    std::fs::create_dir_all(&sub_dir).unwrap();
    let git_file = format!("{}/.git", sub_dir);
    std::fs::write(&git_file, "gitdir: /foo").unwrap();
    let d2 = e.evaluate_tool_call(&call(
        "write_file",
        json!({"path": git_file, "content": "malicious gitdir"}),
    ));
    assert!(
        matches!(d2, Decision::AskOperator { .. }),
        "Writing to .git file must require operator approval, got: {:?}",
        d2
    );
}

#[test]
fn test_audit_p0_4_dlp_catches_sts_slack_and_openai_proj_and_pgp() {
    let dlp = DlpEngine::new();

    // AWS STS Token (ASIA...)
    let sts_tok = ["ASIA", "IOSFODNN7EXAMPLE"].concat();
    let sts_payload = format!("aws_session_token: {sts_tok}");
    let (out_sts, count_sts) = dlp.sanitize_text(&sts_payload);
    assert!(
        count_sts >= 1,
        "Must detect and redact AWS STS temporary access key"
    );
    assert!(!out_sts.contains(&sts_tok));
    assert!(out_sts.contains("[MCP-MOAT-REDACTED-SECRET]"));

    // Slack User Token (xoxp-...)
    let slack_tok = ["xoxp", "123456789012", "345678901234", "abcdef"].join("-");
    let slack_payload = format!("slack_token: {slack_tok}");
    let (out_slack, count_slack) = dlp.sanitize_text(&slack_payload);
    assert!(count_slack >= 1, "Must detect and redact Slack user token");
    assert!(!out_slack.contains(&slack_tok));
    assert!(out_slack.contains("[MCP-MOAT-REDACTED-SECRET]"));

    // Modern OpenAI Project Key (sk-proj-...)
    let proj_tok = ["sk", "proj", "1234567890abcdef1234567890abcdef1234"].join("-");
    let proj_payload = format!("OPENAI_KEY={proj_tok}");
    let (out_proj, count_proj) = dlp.sanitize_text(&proj_payload);
    assert!(count_proj >= 1, "Must detect and redact OpenAI sk-proj key");
    assert!(!out_proj.contains(&proj_tok));
    assert!(out_proj.contains("[MCP-MOAT-REDACTED-SECRET]"));

    // PGP Private Key Block
    let pgp_key =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIIabc\n-----END PGP PRIVATE KEY BLOCK-----";
    let (out_pgp, count_pgp) = dlp.sanitize_text(pgp_key);
    assert!(
        count_pgp >= 1,
        "Must detect and redact PGP private key block"
    );
    assert!(!out_pgp.contains("MIIabc"));
    assert!(out_pgp.contains("[MCP-MOAT-REDACTED-SECRET]"));

    // Secret stored as JSON Object Key
    let json_key_input = r#"{"sk-1234567890abcdef1234567890abcdef":"allowed_value"}"#;
    let (out_json, count_json) = dlp.sanitize_line(json_key_input);
    assert!(
        count_json >= 1,
        "Must detect and redact secret stored as a JSON object key"
    );
    assert!(!out_json.contains("sk-1234567890abcdef"));
    assert!(out_json.contains("[MCP-MOAT-REDACTED-SECRET]"));
}

#[test]
fn test_audit_p1_5_protocol_is_tool_call() {
    use mcp_moat_core::protocol::JsonRpcRequest;

    let tool_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "read_file", "arguments": {"path": "foo"}})),
    };
    assert!(tool_req.is_tool_call());
    assert!(tool_req.parse_tool_call().is_some());

    let malformed_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/call".to_string(),
        params: Some(json!("not_an_object")),
    };
    assert!(malformed_req.is_tool_call());
    assert!(malformed_req.parse_tool_call().is_none());

    let ping_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3)),
        method: "ping".to_string(),
        params: None,
    };
    assert!(!ping_req.is_tool_call());
}
