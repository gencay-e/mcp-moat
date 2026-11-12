use mcp_moat_core::audit::{verify_audit_log, AuditChain, AuditDecision, AuditDirection};
use mcp_moat_core::policy::validate_lexical_syntax;
use mcp_moat_core::protocol::parse_file_uri_to_path;
use mcp_moat_core::{Decision, DlpEngine, PolicyConfig, PolicyEngine, ToolCallParams};
use serde_json::json;
use std::path::PathBuf;

fn test_jail() -> PathBuf {
    let p = std::env::temp_dir().join("mcp-moat-adversarial-jail");
    std::fs::create_dir_all(&p).unwrap();
    let c = p.canonicalize().unwrap();
    let s = c.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
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

// Path extraction and validation

#[test]
fn test_adversarial_paths_empty_and_whitespace() {
    assert!(validate_lexical_syntax("").is_ok());
    assert!(validate_lexical_syntax("   ").is_ok());

    let engine = test_engine();
    // Empty path should be checked against jail
    let empty_call = call("read_file", json!({"path": ""}));
    let decision = engine.evaluate_tool_call(&empty_call);
    // An empty path resolves to current directory, which is outside the test jail
    assert!(matches!(decision, Decision::Block(_)));
}

#[test]
fn test_adversarial_paths_weird_types_in_args() {
    let engine = test_engine();

    // path is a boolean
    let call_bool = call("read_file", json!({"path": true}));
    let d_bool = engine.evaluate_tool_call(&call_bool);
    assert!(
        matches!(d_bool, Decision::Block(_)),
        "Non-string path must fail closed for read_file"
    );

    // path is an integer
    let call_num = call("read_file", json!({"path": 12345}));
    let d_num = engine.evaluate_tool_call(&call_num);
    assert!(
        matches!(d_num, Decision::Block(_)),
        "Non-string path must fail closed for read_file"
    );

    // path is null
    let call_null = call("read_file", json!({"path": null}));
    let d_null = engine.evaluate_tool_call(&call_null);
    assert!(
        matches!(d_null, Decision::Block(_)),
        "Null path must fail closed for read_file"
    );
}

#[test]
fn test_adversarial_deeply_nested_paths() {
    let engine = test_engine();

    // 10 levels deep object containing out-of-jail path
    let deep_args = json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": {
                            "level6": {
                                "level7": {
                                    "target": "C:/Windows/System32/drivers/etc/hosts"
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let tool_call = call("read_file", deep_args);
    let decision = engine.evaluate_tool_call(&tool_call);
    assert!(
        matches!(decision, Decision::Block(_)),
        "Deeply nested out-of-jail path must be detected and blocked"
    );
}

#[test]
fn test_adversarial_deeply_nested_commands() {
    let engine = test_engine();

    // Deeply nested destructive command
    let deep_cmd = json!({
        "config": {
            "execution": {
                "runner": {
                    "payload": {
                        "cmd": "rm -rf /"
                    }
                }
            }
        }
    });

    let tool_call = call("run_command", deep_cmd);
    let decision = engine.evaluate_tool_call(&tool_call);
    assert!(
        matches!(decision, Decision::Block(_)),
        "Deeply nested destructive command must be blocked"
    );
}

#[test]
fn test_adversarial_command_filter_whitespace_and_path_bypasses() {
    let engine = test_engine();

    let blocked_variants = [
        "rm  -rf   /",
        "/bin/rm -rf /",
        "/usr/bin/rm -rf /",
        "sudo rm -rf /",
        "rm -fr /",
        "rm -r -f /",
        "rm --recursive --force /",
        "rm -rf /*",
        "rm -rf //",
        "mkfs.ext4 /dev/sda",
        "sudo mkfs.xfs /dev/sda",
        "/sbin/dd if=/dev/zero of=/dev/sda",
        "format.com C:",
        r"C:\Windows\System32\format.com C:",
    ];

    for cmd in blocked_variants {
        let decision = engine.evaluate_tool_call(&call("bash", json!({"command": cmd})));
        assert!(
            matches!(decision, Decision::Block(_)),
            "Expected Block for destructive command variant: {cmd}, got {decision:?}"
        );
    }
}

#[test]
fn test_adversarial_command_filter_prompts_on_non_root_targets() {
    let engine = test_engine();

    let prompt_variants = [
        "rm -rf /tmp/build",
        "rm -rf ./target",
        "rm -rf /home/user/project",
        "rm -rf /tmp && echo /",
        "dd if=/dev/urandom of=/dev/sda",
        "format d:",
    ];

    for cmd in prompt_variants {
        let decision = engine.evaluate_tool_call(&call("bash", json!({"command": cmd})));
        assert!(
            matches!(decision, Decision::AskOperator { .. }),
            "Expected AskOperator (not Block) for non-root command: {cmd}, got {decision:?}"
        );
    }
}

#[test]
fn test_adversarial_multiple_colons_and_ads() {
    // Multiple colons
    assert!(validate_lexical_syntax("C:\\path\\file.txt:stream").is_err());
    assert!(validate_lexical_syntax("C:\\path\\file.txt:stream:$DATA").is_err());
    assert!(validate_lexical_syntax("file.txt:stream").is_err());
    assert!(validate_lexical_syntax(":stream").is_err());
    assert!(validate_lexical_syntax("C::foo").is_err());
}

#[test]
fn test_adversarial_device_names_with_extensions() {
    // DOS devices with arbitrary extensions must be blocked
    assert!(validate_lexical_syntax("con.txt").is_err());
    assert!(validate_lexical_syntax("prn.doc").is_err());
    assert!(validate_lexical_syntax("aux.tar.gz").is_err());
    assert!(validate_lexical_syntax("nul.bin").is_err());
    assert!(validate_lexical_syntax("com1.json").is_err());
    assert!(validate_lexical_syntax("lpt1.log").is_err());
    assert!(validate_lexical_syntax("clock$.ini").is_err());

    // Inside nested paths
    assert!(validate_lexical_syntax("a/b/c/con.txt").is_err());
    assert!(validate_lexical_syntax("a/b/c/prn/d").is_err());
    assert!(validate_lexical_syntax("a/b/c/nul").is_err());
}

#[test]
fn test_adversarial_windows_namespace_variants() {
    let forbidden = [
        r"\\?\C:\Windows",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
        r"\\.\C:\Windows",
        r"\\.\pipe\moat",
        r"\??\C:\Windows",
        r"/??/C:/Windows",
        r"\/?\C:\Windows",
        r"\Device\HarddiskVolumeShadowCopy1",
        r"/device/harddiskvolumeshadowcopy1",
        r"\GLOBAL??\C:\Windows",
        r"\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
        r"\DosDevices\C:\Windows",
        r"\SystemRoot\System32",
        r"\BaseNamedObjects\moat",
        r"\ArcName\C:\Windows",
        r"\KernelObjects\moat",
        "//server/share",
        r"\\server\share",
    ];

    for path in forbidden {
        assert!(
            validate_lexical_syntax(path).is_err(),
            "Namespace path must be rejected: {path}"
        );
    }
}

#[test]
fn test_adversarial_windows_device_names_all_separators() {
    let forbidden = [
        r"C:\temp\CON",
        r"C:/temp/CON",
        r"C:\temp\CONIN$",
        r"C:\temp\CONOUT$",
        r"C:\temp\CON.txt",
        r"C:\temp\CON ",
        r"C:\temp\CON.",
        r"C:\temp\CLOCK$",
        r"C:\temp\CONFIG$",
        r"C:\temp\AUX",
        r"C:\temp\NUL.txt",
        r"C:\temp\COM1.log",
        r"C:\temp\LPT9",
        r"C:\temp\sub\PRN\file.txt",
        "/tmp/aux",
    ];

    for path in forbidden {
        assert!(
            validate_lexical_syntax(path).is_err(),
            "Reserved device path must be rejected: {path}"
        );
    }

    let allowed = [
        r"C:\temp\console.txt",
        r"C:\temp\computer",
        r"C:\temp\auxiliary.txt",
        r"C:\temp\nullable",
        "/tmp/console",
    ];

    for path in allowed {
        assert!(
            validate_lexical_syntax(path).is_ok(),
            "Ordinary path must be accepted: {path}"
        );
    }
}

#[cfg(windows)]
#[test]
fn test_adversarial_windows_namespace_rejected_on_real_windows() {
    for path in [
        r"\\?\C:\Windows",
        r"\\.\C:\Windows",
        r"\??\C:\Windows",
        r"\Device\HarddiskVolumeShadowCopy1",
        r"\GLOBAL??\C:\Windows",
        r"\DosDevices\C:\Windows",
    ] {
        assert!(
            validate_lexical_syntax(path).is_err(),
            "Windows namespace path must be rejected: {path}"
        );
    }

    assert!(validate_lexical_syntax(r"C:\Windows\System32\drivers\etc\hosts").is_ok());
}

#[test]
fn test_adversarial_custom_config_file_is_protected() {
    let jail = test_jail();
    let config_path = jail.join("custom-policy.toml");
    std::fs::write(&config_path, "# custom policy\n").unwrap();

    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        protected_files: vec![config_path.clone()],
        ..PolicyConfig::default()
    })
    .unwrap();

    assert!(
        engine.is_protected_target(&config_path),
        "The custom --config file must be a protected target"
    );
    assert!(
        engine.is_protected_target(&config_path.canonicalize().unwrap()),
        "The canonical custom --config path must also be protected"
    );
    assert!(
        !engine.is_protected_target(&jail.join("ordinary.txt")),
        "Unrelated files must not become protected"
    );
}

#[test]
fn test_adversarial_missing_custom_config_file_is_protected() {
    let jail = test_jail();
    let missing = jail.join("not-yet-created.toml");

    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail],
        protected_files: vec![missing.clone()],
        ..PolicyConfig::default()
    })
    .unwrap();

    assert!(
        engine.is_protected_target(&missing),
        "A write that would create the custom --config file must require approval"
    );
}

#[test]
fn test_adversarial_command_argument_types() {
    let engine = test_engine();

    // Command as integer - shouldn't panic
    let call_num = call("run_command", json!({"command": 12345}));
    let ext_num = engine.extract_command_argument(&call_num);
    assert_eq!(ext_num, None);

    // Command as null - shouldn't panic
    let call_null = call("run_command", json!({"command": null}));
    let ext_null = engine.extract_command_argument(&call_null);
    assert_eq!(ext_null, None);

    // Command as boolean - shouldn't panic
    let call_bool = call("run_command", json!({"command": true}));
    let ext_bool = engine.extract_command_argument(&call_bool);
    assert_eq!(ext_bool, None);

    // Command as mixed array
    let call_arr = call(
        "run_command",
        json!({"command": ["git", 123, null, "status"]}),
    );
    let ext_arr = engine.extract_command_argument(&call_arr);
    assert_eq!(ext_arr, Some("git status".to_string()));
}

// Protocol and URI parsing

#[test]
fn test_adversarial_file_uri_edge_cases() {
    // Missing scheme
    assert!(parse_file_uri_to_path("C:/foo/bar").is_err());
    // Incomplete schemes
    assert!(parse_file_uri_to_path("file:/C:/foo").is_err());
    assert!(parse_file_uri_to_path("file:C:/foo").is_err());
    assert!(parse_file_uri_to_path("file:///").is_ok());

    // Empty authority
    let p_root = parse_file_uri_to_path("file:///").unwrap();
    assert!(!p_root.as_os_str().is_empty());

    // IPv6 host authorities (remote UNC) must be rejected
    assert!(parse_file_uri_to_path("file://[::1]/share/file").is_err());
    assert!(parse_file_uri_to_path("file://[fe80::1]/share/file").is_err());

    // Localhost with various casing
    assert!(parse_file_uri_to_path("file://LOCALHOST/C:/foo").is_ok());
    assert!(parse_file_uri_to_path("file://LocalHost/C:/foo").is_ok());

    // Percent-encoded drive letters
    let p_drv = parse_file_uri_to_path("file:///%43:/test/file").unwrap();
    let s = p_drv.to_string_lossy().replace('\\', "/");
    assert!(
        s.ends_with("C:/test/file"),
        "Expected C:/test/file, got: {}",
        s
    );
}

// Secret masking

#[test]
fn test_adversarial_dlp_patterns() {
    let dlp = DlpEngine::new();

    // 1. AWS access key variants (AKIA, ASIA, ABIA, ACCA)
    for prefix in ["AKIA", "ASIA", "ABIA", "ACCA"] {
        let text = format!("key: {}ABCDEFGHIJKLMNOP", prefix);
        let (out, count) = dlp.sanitize_text(&text);
        assert!(
            count >= 1,
            "Failed detecting AWS key with prefix {}",
            prefix
        );
        assert!(!out.contains(prefix));
        assert!(out.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }

    // 2. Stripe live and test keys
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        let text = format!("stripe_secret: {}123456789012345678901234", prefix);
        let (out, count) = dlp.sanitize_text(&text);
        assert!(
            count >= 1,
            "Failed detecting Stripe key with prefix {}",
            prefix
        );
        assert!(!out.contains(prefix));
    }

    // 3. GitHub OAuth prefixes (gho, ghu, ghs, ghr)
    for prefix in ["gho_", "ghu_", "ghs_", "ghr_"] {
        let text = format!(
            "github_token: {}123456789012345678901234567890123456",
            prefix
        );
        let (out, count) = dlp.sanitize_text(&text);
        assert!(
            count >= 1,
            "Failed detecting GitHub token with prefix {}",
            prefix
        );
        assert!(!out.contains(prefix));
    }

    // 4. Slack token prefixes (xoxb, xoxp, xoxa, xoxr, xoxs)
    for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
        let text = format!("slack_auth: {}123456789012-345678901234-abcdef", prefix);
        let (out, count) = dlp.sanitize_text(&text);
        assert!(
            count >= 1,
            "Failed detecting Slack token with prefix {}",
            prefix
        );
        assert!(!out.contains(prefix));
    }

    // 5. Huge payload (10 MB) without secrets must not crash or hang
    let huge_clean = "a".repeat(10 * 1024 * 1024);
    let (out_clean, count_clean) = dlp.sanitize_line(&huge_clean);
    assert_eq!(count_clean, 0);
    assert_eq!(out_clean.len(), huge_clean.len());

    // 6. Deeply nested JSON array with secrets
    let mut nested = json!("sk-1234567890abcdef1234567890abcdef");
    for _ in 0..50 {
        nested = json!([nested]);
    }
    let count_nested = dlp.sanitize_json_value(&mut nested);
    assert!(count_nested >= 1);
    assert!(nested.to_string().contains("[MCP-MOAT-REDACTED-SECRET]"));
}

// Audit log tampering

#[test]
fn test_adversarial_audit_log_zero_and_single_events() {
    // 0 events
    let report0 = verify_audit_log("".as_bytes()).unwrap();
    assert!(report0.is_valid);
    assert_eq!(report0.total_records, 0);

    // 1 valid event
    let mut chain = AuditChain::new("s1");
    let e1 = chain.create_event(
        "2026-10-26T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "initialize".to_string(),
        None,
        None,
        Some(AuditDecision::Allow),
        None,
        None,
        None,
    );
    let report1 = verify_audit_log(serde_json::to_string(&e1).unwrap().as_bytes()).unwrap();
    assert!(report1.is_valid);
    assert_eq!(report1.total_records, 1);
}

#[test]
fn test_adversarial_powershell_evasions() {
    let engine = test_engine();

    // 1. Colon parameter syntax (-enc:<payload>)
    let call_colon = call("bash", json!({"command": "powershell.exe -enc:SQBFAFgA"}));
    let d_colon = engine.evaluate_tool_call(&call_colon);
    assert!(
        matches!(d_colon, Decision::Block(_)),
        "Must block powershell -enc:payload"
    );

    // 2. Full path to powershell executable
    let call_fullpath = call(
        "bash",
        json!({"command": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc SQBFAFgA"}),
    );
    let d_fullpath = engine.evaluate_tool_call(&call_fullpath);
    assert!(
        matches!(d_fullpath, Decision::Block(_)),
        "Must block full path to powershell.exe with -enc"
    );

    // 3. Flags with mixed slashes and dashes
    let call_mixed = call(
        "bash",
        json!({"command": "pwsh.exe /NoProfile -ExecutionPolicy Bypass /e SQBFAFgA"}),
    );
    let d_mixed = engine.evaluate_tool_call(&call_mixed);
    assert!(
        matches!(d_mixed, Decision::Block(_)),
        "Must block pwsh.exe with mixed slashes /e"
    );
}

#[test]
fn test_adversarial_audit_log_swapped_events() {
    let mut chain = AuditChain::new("s-swap");
    let e1 = chain.create_event(
        "2026-10-26T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "init".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let e2 = chain.create_event(
        "2026-10-26T00:00:02Z".to_string(),
        AuditDirection::Inbound,
        "ping".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let e3 = chain.create_event(
        "2026-10-26T00:00:03Z".to_string(),
        AuditDirection::Inbound,
        "list".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // Swap e2 and e3
    let log_data = format!(
        "{}\n{}\n{}\n",
        serde_json::to_string(&e1).unwrap(),
        serde_json::to_string(&e3).unwrap(),
        serde_json::to_string(&e2).unwrap()
    );
    let report = verify_audit_log(log_data.as_bytes()).unwrap();
    assert!(!report.is_valid);
    assert_eq!(report.tampered_sequence, Some(3));
}

#[test]
fn test_adversarial_audit_log_duplicated_events() {
    let mut chain = AuditChain::new("s-dup");
    let e1 = chain.create_event(
        "2026-10-26T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "init".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let e2 = chain.create_event(
        "2026-10-26T00:00:02Z".to_string(),
        AuditDirection::Inbound,
        "ping".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // Duplicate e2
    let log_data = format!(
        "{}\n{}\n{}\n",
        serde_json::to_string(&e1).unwrap(),
        serde_json::to_string(&e2).unwrap(),
        serde_json::to_string(&e2).unwrap()
    );
    let report = verify_audit_log(log_data.as_bytes()).unwrap();
    assert!(!report.is_valid);
    assert_eq!(report.tampered_sequence, Some(2));
}

#[test]
fn test_adversarial_audit_log_cross_session_replay() {
    let mut chain_a = AuditChain::new("session-A");
    let e_a1 = chain_a.create_event(
        "2026-10-26T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "init".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let mut chain_b = AuditChain::new("session-B");
    let mut e_b1 = chain_b.create_event(
        "2026-10-26T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "init".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // Attacker tries to replay session A's entry_hash into session B
    e_b1.entry_hash = e_a1.entry_hash;

    let log_data = format!("{}\n", serde_json::to_string(&e_b1).unwrap());
    let report = verify_audit_log(log_data.as_bytes()).unwrap();
    assert!(
        !report.is_valid,
        "Cross-session hash replay must be rejected"
    );
}

// Windows namespaces, protected targets and tool classification

#[test]
fn test_windows_namespaces_and_devices() {
    let forbidden_paths = [
        r"\\?\C:\Windows\System32",
        "//?/C:/Windows/System32",
        r"/\?/C:/Windows",
        r"\/?/C:/Windows",
        r"\\.\COM1",
        r"\\.\PhysicalDrive0",
        r"\??\C:\Windows",
        "/??/C:/Windows",
        r"/??\C:/Windows",
        r"\??/C:/Windows",
        r"\device\harddiskvolume1\file.txt",
        "/device/harddiskvolume1/file.txt",
        r"\Device\HarddiskVolume1\file.txt",
        "/Device/HarddiskVolume1/file.txt",
        r"\DEVICE\HARDDISKVOLUME1",
        "test.txt:stream",
        "test.txt::$DATA",
        r"C:\test.txt:stream",
        r"C:\test.txt::$DATA",
        "C:relative_file.txt",
        "c:sub/dir/file.txt",
        "PROGRA~1",
        "MOAT~1.TOM",
        r"C:\safe\PROGRA~1\moat.toml",
        "sub/con",
        "sub/con.txt",
        "sub/aux.tar.gz",
        "sub/nul",
        "sub/prn.doc",
        "sub/com1.json",
        "sub/com9.log",
        "sub/lpt1.txt",
        "sub/clock$.ini",
    ];

    for path in &forbidden_paths {
        let res = validate_lexical_syntax(path);
        assert!(
            res.is_err(),
            "Path '{}' should be blocked by validate_lexical_syntax, but was allowed!",
            path
        );
    }
}

#[test]
fn test_audit_log_exhaustive_tamper_detection() {
    let mut chain = AuditChain::new("sess-exhaustive");
    let mut events = Vec::new();
    for i in 0..10 {
        events.push(chain.create_event(
            format!("2026-10-26T00:00:{:02}Z", i),
            if i % 2 == 0 {
                AuditDirection::Inbound
            } else {
                AuditDirection::Outbound
            },
            format!("method_{}", i),
            Some(format!("tool_{}", i)),
            Some(format!("path_{}", i)),
            Some(AuditDecision::Allow),
            Some("AllowOnce".to_string()),
            Some(format!("preview_{}", i)),
            Some(i as usize),
        ));
    }

    // Baseline: valid chain
    let mut baseline_lines = Vec::new();
    for ev in &events {
        baseline_lines.push(serde_json::to_string(ev).unwrap());
    }
    let baseline_report = verify_audit_log(baseline_lines.join("\n").as_bytes()).unwrap();
    assert!(baseline_report.is_valid);
    assert_eq!(baseline_report.total_records, 10);

    // Test tamper on event 5: mutating ANY field must invalidate the chain
    let fields_to_tamper = [
        "timestamp",
        "direction",
        "method",
        "tool_name",
        "target_path",
        "decision",
        "operator_decision",
        "payload_preview",
        "dlp_redactions",
        "prev_hash",
    ];

    for field in &fields_to_tamper {
        let mut tampered_events = events.clone();
        match *field {
            "timestamp" => tampered_events[5].timestamp = "2026-10-26T99:99:99Z".to_string(),
            "direction" => tampered_events[5].direction = AuditDirection::Internal,
            "method" => tampered_events[5].method = "tampered_method".to_string(),
            "tool_name" => tampered_events[5].tool_name = Some("tampered_tool".to_string()),
            "target_path" => tampered_events[5].target_path = Some("tampered_path".to_string()),
            "decision" => {
                tampered_events[5].decision = Some(AuditDecision::Block {
                    reason: "tampered".to_string(),
                })
            }
            "operator_decision" => tampered_events[5].operator_decision = Some("Deny".to_string()),
            "payload_preview" => {
                tampered_events[5].payload_preview = Some("tampered_payload".to_string())
            }
            "dlp_redactions" => tampered_events[5].dlp_redactions = Some(999),
            "prev_hash" => {
                tampered_events[5].prev_hash =
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
            }
            _ => unreachable!(),
        }

        let mut lines = Vec::new();
        for ev in &tampered_events {
            lines.push(serde_json::to_string(ev).unwrap());
        }
        let report = verify_audit_log(lines.join("\n").as_bytes()).unwrap();
        assert!(
            !report.is_valid,
            "Audit verification failed to catch tampering on field '{}'!",
            field
        );
        assert_eq!(report.tampered_sequence, Some(6)); // 1-indexed (events[5] is sequence 6)
    }
}

#[test]
fn test_copy_file_and_modifying_tools_blocked_in_read_only_and_protected_files() {
    let jail = test_jail();
    let src_file = jail.join("innocent.txt");
    std::fs::write(&src_file, "clean content").unwrap();

    // 1. Read-only mode must block copy_file and modifying tools
    let ro_engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: true,
        ..PolicyConfig::default()
    })
    .unwrap();

    let copy_call = call(
        "copy_file",
        json!({
            "source": src_file.to_str().unwrap(),
            "destination": jail.join("copied.txt").to_str().unwrap(),
        }),
    );
    let d_ro = ro_engine.evaluate_tool_call(&copy_call);
    assert!(
        matches!(d_ro, Decision::Block(_)),
        "copy_file must be blocked in read-only mode, got: {:?}",
        d_ro
    );

    // 2. copy_file targeting protected system file (moat.toml) must require operator approval
    let normal_engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: false,
        ..PolicyConfig::default()
    })
    .unwrap();

    let copy_to_moat = call(
        "copy_file",
        json!({
            "source": src_file.to_str().unwrap(),
            "destination": jail.join("moat.toml").to_str().unwrap(),
        }),
    );
    let d_moat = normal_engine.evaluate_tool_call(&copy_to_moat);
    assert!(
        matches!(d_moat, Decision::AskOperator { .. }),
        "copy_file targeting moat.toml must require operator approval, got: {:?}",
        d_moat
    );
}

#[test]
fn test_relative_protected_targets_require_approval() {
    let jail = test_jail();
    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: false,
        ..PolicyConfig::default()
    })
    .unwrap();

    for rel_path in [
        ".git/hooks/pre-commit",
        ".git/config",
        ".github/workflows/ci.yml",
        ".vscode/settings.json",
        ".ssh/id_rsa",
        ".aws/credentials",
        ".env.local",
    ] {
        let full_path = jail.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }

        let write_call = call(
            "write_file",
            json!({
                "path": full_path.to_str().unwrap(),
                "content": "escalation"
            }),
        );
        let decision = engine.evaluate_tool_call(&write_call);
        assert!(
            matches!(decision, Decision::AskOperator { .. }),
            "Writing to protected file '{}' must require operator approval, got: {:?}",
            rel_path,
            decision
        );
    }
}

#[test]
fn test_unrecognized_tool_with_valid_jail_path_fails_closed() {
    let jail = test_jail();
    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: false,
        ..PolicyConfig::default()
    })
    .unwrap();

    let test_file = jail.join("data.txt");
    std::fs::write(&test_file, "data").unwrap();

    // An unrecognized tool (not in always_allow, not in is_file_tool, not in is_modifying_tool)
    // must be BLOCKED even if the path is safely inside the jail!
    let unrec_call = call(
        "exfiltrate_to_c2_server",
        json!({
            "path": test_file.to_str().unwrap()
        }),
    );
    let decision = engine.evaluate_tool_call(&unrec_call);
    assert!(
        matches!(decision, Decision::Block(_)),
        "Unrecognized tool with in-jail path must fail-closed with Decision::Block, got: {:?}",
        decision
    );
}

#[test]
fn test_modifying_tools_coverage() {
    let jail = test_jail();
    let ro_engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: true,
        ..PolicyConfig::default()
    })
    .unwrap();

    let tools_to_test = [
        "delete_dir",
        "remove_dir",
        "rmdir",
        "clean_dir",
        "create_dir",
        "unlink_file",
        "unlink",
        "erase_file",
        "erase",
        "wipe_file",
        "wipe",
        "shred_file",
        "shred",
        "truncate_file",
        "truncate",
        "overwrite_file",
        "overwrite",
        "put_file",
        "write_to_file",
        "purge_dir",
    ];

    for t in tools_to_test {
        let call_params = call(t, json!({"path": jail.join("test.txt").to_str().unwrap()}));
        let d = ro_engine.evaluate_tool_call(&call_params);
        assert!(
            matches!(d, Decision::Block(_)),
            "Tool '{}' must be blocked in read-only mode, got: {:?}",
            t,
            d
        );
    }
}

#[test]
fn test_dlp_json_key_value_pairs() {
    let dlp = DlpEngine::new();
    let json_line = r#"{"status":"ok","password":"super_secret_password_123","api_key":"my_secret_api_key_456","client_secret":"my_client_secret_789"}"#;
    let (out, count) = dlp.sanitize_line(json_line);
    assert!(
        count >= 3,
        "Expected at least 3 redactions, got: count={}, output={}",
        count,
        out
    );
    assert!(!out.contains("super_secret_password_123"));
    assert!(!out.contains("my_secret_api_key_456"));
    assert!(!out.contains("my_client_secret_789"));
}

#[test]
fn test_junction_escape() {
    let jail = test_jail().join("junc_test_jail");
    let outside = test_jail().parent().unwrap().join("junc_outside_target");
    let _ = std::fs::remove_dir_all(&jail);
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&jail).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let outside_file = outside.join("secret.txt");
    std::fs::write(&outside_file, "super_secret_outside_jail").unwrap();

    let junc_path = jail.join("junc_link");
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                junc_path.to_str().unwrap(),
                outside.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(status.status.success());
    }

    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        ..PolicyConfig::default()
    })
    .unwrap();

    // 1. Reading through junction to outside target
    let read_call = call(
        "read_file",
        json!({"path": junc_path.join("secret.txt").to_str().unwrap()}),
    );
    let d_read = engine.evaluate_tool_call(&read_call);
    assert!(
        matches!(d_read, Decision::Block(_)),
        "Reading through junction out-of-jail must be blocked, got: {:?}",
        d_read
    );

    // 2. Writing a non-existent file through junction to outside target
    let write_call = call(
        "write_file",
        json!({"path": junc_path.join("new_file.txt").to_str().unwrap(), "content": "pwned"}),
    );
    let d_write = engine.evaluate_tool_call(&write_call);
    assert!(
        matches!(d_write, Decision::Block(_)),
        "Writing non-existent file through junction out-of-jail must be blocked, got: {:?}",
        d_write
    );

    let _ = std::fs::remove_dir_all(&jail);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn test_multipath_dest_path_and_target_path_jailing() {
    let jail = test_jail();
    let outside = std::env::temp_dir().join("moat_outside_multipath_target");
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("evil.txt");

    let src_file = jail.join("innocent.txt");
    std::fs::write(&src_file, "clean content").unwrap();

    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: false,
        ..PolicyConfig::default()
    })
    .unwrap();

    // 1. copy_file with in-jail src and out-of-jail dest_path
    let cp_call = call(
        "copy_file",
        json!({
            "src": src_file.to_str().unwrap(),
            "dest_path": outside_file.to_str().unwrap()
        }),
    );
    let d_cp = engine.evaluate_tool_call(&cp_call);
    assert!(
        matches!(d_cp, Decision::Block(_)),
        "copy_file targeting out-of-jail dest_path must be Blocked, got: {:?}",
        d_cp
    );

    // 2. copy_file with in-jail src and out-of-jail kebab-case dest-path
    let cp_kebab = call(
        "copy_file",
        json!({
            "src": "innocent.txt",
            "dest-path": outside_file.to_str().unwrap()
        }),
    );
    let d_kebab = engine.evaluate_tool_call(&cp_kebab);
    assert!(
        matches!(d_kebab, Decision::Block(_)),
        "copy_file targeting out-of-jail dest-path must be Blocked, got: {:?}",
        d_kebab
    );

    // 3. write_file with out-of-jail target_path
    let write_call = call(
        "write_file",
        json!({
            "target_path": outside_file.to_str().unwrap(),
            "content": "malicious"
        }),
    );
    let d_write = engine.evaluate_tool_call(&write_call);
    assert!(
        matches!(d_write, Decision::Block(_)),
        "write_file targeting out-of-jail target_path must be Blocked, got: {:?}",
        d_write
    );

    // 4. copy_file with in-jail src and protected file in-jail dest_path. The parent folder must
    // exist: a path that cannot be resolved is blocked, not sent to the operator. Other tests share
    // the jail, so the test creates it itself instead of relying on the test order.
    std::fs::create_dir_all(jail.join(".git/hooks")).unwrap();
    let cp_protected = call(
        "copy_file",
        json!({
            "src": src_file.to_str().unwrap(),
            "dest_path": jail.join(".git/hooks/pre-commit").to_str().unwrap()
        }),
    );
    let d_prot = engine.evaluate_tool_call(&cp_protected);
    assert!(
        matches!(d_prot, Decision::AskOperator { .. }),
        "copy_file targeting protected dest_path must require operator approval, got: {:?}",
        d_prot
    );

    // 5. write_file with arguments but no extractable path must FAIL CLOSED
    let write_no_path = call(
        "write_file",
        json!({
            "unrecognized_key": "some_value",
            "content": "malicious"
        }),
    );
    let d_no_path = engine.evaluate_tool_call(&write_no_path);
    assert!(
        matches!(d_no_path, Decision::Block(_)),
        "write_file with unverifiable path must fail closed, got: {:?}",
        d_no_path
    );

    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn test_kebab_and_camel_case_modifying_tools() {
    let jail = test_jail();
    let ro_engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: true,
        ..PolicyConfig::default()
    })
    .unwrap();

    let tools_to_test = [
        "write-file",
        "writeFile",
        "delete-file",
        "deleteFile",
        "create-directory",
        "createDirectory",
        "run-command",
        "runCommand",
        "execute-command",
        "executeCommand",
        "mkdir",
        "rmdir",
        "touch",
        "unlink",
    ];

    for t in tools_to_test {
        let call_params = call(t, json!({"path": jail.join("test.txt").to_str().unwrap()}));
        let d = ro_engine.evaluate_tool_call(&call_params);
        assert!(
            matches!(d, Decision::Block(_)),
            "Tool '{}' must be blocked in read-only mode, got: {:?}",
            t,
            d
        );
    }
}

#[test]
fn test_dlp_secret_arrays_and_auth_keywords() {
    let dlp = DlpEngine::new();

    // 1. Array of secret tokens
    let json_array =
        r#"{"status":"ok","tokens":["super_secret_token_12345678","another_raw_secret_87654321"]}"#;
    let (out_arr, count_arr) = dlp.sanitize_line(json_array);
    assert!(
        count_arr >= 2,
        "Expected at least 2 redactions in tokens array, got: count={}, output={}",
        count_arr,
        out_arr
    );
    assert!(!out_arr.contains("super_secret_token_12345678"));
    assert!(!out_arr.contains("another_raw_secret_87654321"));

    // 2. Auth / authorization / credentials key-value pairs
    let json_auth = r#"{"authorization":"secret_bearer_token_val_12345678","credentials":{"auth":"my_auth_secret_xyz_987654321"}}"#;
    let (out_auth, count_auth) = dlp.sanitize_line(json_auth);
    assert!(
        count_auth >= 2,
        "Expected at least 2 redactions for auth/credentials, got: count={}, output={}",
        count_auth,
        out_auth
    );
    assert!(!out_auth.contains("secret_bearer_token_val_12345678"));
    assert!(!out_auth.contains("my_auth_secret_xyz_987654321"));
}

#[test]
fn test_root_directory_deletion_requires_operator_approval() {
    let jail = test_jail();
    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: false,
        require_approval_on_write: false,
        ..PolicyConfig::default()
    })
    .unwrap();

    // 1. Attempting to delete or modify the jail root itself (even when require_approval_on_write is false!)
    let delete_root_call = call("delete_directory", json!({"path": jail.to_str().unwrap()}));
    let d = engine.evaluate_tool_call(&delete_root_call);
    assert!(
        matches!(d, Decision::AskOperator { .. }),
        "Deleting the allowed root directory itself must require operator approval, got: {:?}",
        d
    );

    // 2. rmdir on "." when jail is current dir
    let rmdir_dot = call("rmdir", json!({"path": "."}));
    let d_dot = engine.evaluate_tool_call(&rmdir_dot);
    assert!(
        matches!(d_dot, Decision::AskOperator { .. } | Decision::Block(_)),
        "rmdir on dot must not be automatically allowed, got: {:?}",
        d_dot
    );

    // 3. Normal file write inside jail is auto-allowed
    let normal_file = jail.join("normal_sub.txt");
    let normal_call = call(
        "write_file",
        json!({"path": normal_file.to_str().unwrap(), "content": "ok"}),
    );
    let d_norm = engine.evaluate_tool_call(&normal_call);
    assert_eq!(d_norm, Decision::Allow);
}

#[test]
fn test_kebab_case_shell_tools_and_modifying_tools() {
    let jail = test_jail();
    let ro_engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: true,
        ..PolicyConfig::default()
    })
    .unwrap();

    let new_shell_tools = [
        "run-script",
        "execute-script",
        "run-code",
        "system-exec",
        "exec-command",
        "run-cmd",
        "run_script",
        "execute_script",
        "run_code",
        "system_exec",
        "zsh",
        "fish",
        "wsl",
        "nu",
        "csh",
        "tcsh",
    ];

    for t in new_shell_tools {
        assert!(
            ro_engine.is_modifying_tool(t),
            "Tool '{}' must be classified as a modifying tool",
            t
        );
        let call_params = call(t, json!({"command": "echo test"}));
        let d = ro_engine.evaluate_tool_call(&call_params);
        assert!(
            matches!(d, Decision::Block(_)),
            "Tool '{}' must be blocked in read-only mode, got: {:?}",
            t,
            d
        );
    }
}

#[test]
fn test_file_suffix_and_prefix_path_keys() {
    let jail = test_jail();
    let outside = std::env::temp_dir().join(format!("moat_p7_out_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).unwrap();
    let outside_secret = outside.join("secret.txt");
    std::fs::write(&outside_secret, "forbidden").unwrap();

    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        always_allow_tools: vec!["diff_files".to_string(), "render_template".to_string()],
        ..PolicyConfig::default()
    })
    .unwrap();

    // 1. Tool using template_file key pointing out-of-jail must be BLOCKED
    let call_template = call(
        "render_template",
        json!({"template_file": outside_secret.to_str().unwrap()}),
    );
    let d1 = engine.evaluate_tool_call(&call_template);
    assert!(
        matches!(d1, Decision::Block(_)),
        "template_file targeting out of jail must be blocked, got: {:?}",
        d1
    );

    // 2. Tool using file1 and file2 keys (prefix keys) pointing out-of-jail must be BLOCKED
    let call_diff = call(
        "diff_files",
        json!({
            "file1": jail.join("file1.txt").to_str().unwrap(),
            "file2": outside_secret.to_str().unwrap()
        }),
    );
    let d2 = engine.evaluate_tool_call(&call_diff);
    assert!(
        matches!(d2, Decision::Block(_)),
        "file2 targeting out of jail must be blocked, got: {:?}",
        d2
    );

    // 3. Tool using input_files array pointing out-of-jail must be BLOCKED
    let call_arr = call(
        "diff_files",
        json!({
            "input_files": [outside_secret.to_str().unwrap()]
        }),
    );
    let d3 = engine.evaluate_tool_call(&call_arr);
    assert!(
        matches!(d3, Decision::Block(_)),
        "input_files targeting out of jail must be blocked, got: {:?}",
        d3
    );

    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn test_file_uri_double_encoding_and_null_bytes() {
    // 1. Double percent-encoded traversal sequence (%252e%252e) must be strictly blocked
    let uri_double_encoded = "file:///path/%252e%252e/etc/shadow";
    assert!(
        parse_file_uri_to_path(uri_double_encoded).is_err(),
        "Double percent-encoded traversal in file URI must be blocked"
    );

    // 2. Null byte in percent-encoded URI (%00) must be strictly blocked
    let uri_null_byte = "file:///safe/path%00/secret.txt";
    assert!(
        parse_file_uri_to_path(uri_null_byte).is_err(),
        "Null byte in percent-encoded URI must be blocked"
    );

    // 3. Alternate Data Stream colon in file URI must be strictly rejected
    let uri_ads = "file:///C:/safe/file.txt:secret_stream";
    assert!(
        parse_file_uri_to_path(uri_ads).is_err() || {
            let p = parse_file_uri_to_path(uri_ads).unwrap();
            validate_lexical_syntax(&p.to_string_lossy()).is_err()
        },
        "Alternate Data Stream colon in file URI must be blocked by lexical syntax"
    );
}

#[test]
fn test_deep_nesting_and_mixed_tool_call_arguments() {
    let jail = test_jail();
    let outside = std::env::temp_dir().join(format!("moat_p8_out_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).unwrap();
    let outside_file = outside.join("leak.txt");
    std::fs::write(&outside_file, "secret").unwrap();

    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        ..PolicyConfig::default()
    })
    .unwrap();

    // 1. Array containing non-object and out-of-jail paths
    let call_deep = call(
        "read_file",
        json!({
            "options": {
                "nested": {
                    "targets": [
                        jail.join("safe.txt").to_str().unwrap(),
                        outside_file.to_str().unwrap()
                    ]
                }
            }
        }),
    );
    let d1 = engine.evaluate_tool_call(&call_deep);
    assert!(
        matches!(d1, Decision::Block(_)),
        "Deeply nested out-of-jail target must be blocked: got {:?}",
        d1
    );

    // 2. Non-object arguments parameter (e.g. array or primitive) must fail-closed
    let call_bad_args = call("read_file", json!(["malicious", "array"]));
    let d2 = engine.evaluate_tool_call(&call_bad_args);
    assert!(
        matches!(d2, Decision::Block(_)),
        "Non-object arguments parameter must be blocked: got {:?}",
        d2
    );

    // 3. Unrecognized tool with valid in-jail path must fail-closed
    let call_unrec = call(
        "exfiltrate_data",
        json!({"path": jail.join("safe.txt").to_str().unwrap()}),
    );
    let d3 = engine.evaluate_tool_call(&call_unrec);
    assert!(
        matches!(d3, Decision::Block(_)),
        "Unrecognized tool must fail-closed: got {:?}",
        d3
    );

    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn test_powershell_evasion_exhaustive_patterns() {
    let engine = test_engine();

    // Permutations of PowerShell encoded command execution
    let evasions = [
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand AAAA",
        "powershell -nop -ep bypass -e AAAA",
        "powershell /ec AAAA",
        "pwsh -NoProfile -w hidden -EncodedCommand AAAA",
        "pwsh -nop -e AAAA",
        "pwsh /e AAAA",
        "pwsh.exe -enc AAAA",
    ];

    for cmd in evasions {
        let tool_call = call("bash", json!({"command": cmd}));
        let decision = engine.evaluate_tool_call(&tool_call);
        assert!(
            matches!(decision, Decision::Block(_)),
            "PowerShell evasion '{}' must be blocked, got: {:?}",
            cmd,
            decision
        );
    }
}

#[test]
fn test_dlp_deep_json_and_token_redaction() {
    let dlp = DlpEngine::new();

    // 1. Deeply nested JSON (depth > 5) containing diverse API secrets
    let test_sk = ["sk", "1234567890abcdef1234567890abcdef"].join("-");
    let test_ghp = ["ghp", "1234567890abcdef1234567890abcdef1234"].join("_");
    let test_xoxb = [
        "xoxb",
        "123456789012",
        "1234567890123",
        "abcdefghijklmnopqrstuvwx",
    ]
    .join("-");

    let mut payload = json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": {
                            "openai_key": test_sk,
                            "github_pat": test_ghp,
                            "slack_token": test_xoxb
                        }
                    }
                }
            }
        }
    });

    let count = dlp.sanitize_json_value(&mut payload);
    assert_eq!(count, 3, "All 3 secrets at depth 5 must be sanitized");
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(!serialized.contains("1234567890abcdef"));
    assert!(!serialized.contains("123456789012"));
    assert!(serialized.contains("[MCP-MOAT-REDACTED-SECRET]"));
}

#[test]
fn test_audit_log_100_events_integrity() {
    let mut chain = AuditChain::new("stress-session-p8");
    let mut events = Vec::new();

    for i in 1..=100 {
        let ev = chain.create_event(
            format!("2026-10-26T22:{:02}:00Z", i % 60),
            AuditDirection::Inbound,
            format!("method_{}", i),
            Some(format!("tool_{}", i)),
            Some(format!("path_{}.txt", i)),
            Some(AuditDecision::Allow),
            None,
            Some(format!("payload_{}", i)),
            None,
        );
        assert_eq!(ev.sequence, i as u64);
        assert!(ev.verify_hash());
        events.push(ev);
    }

    let mut log_bytes = Vec::new();
    for ev in &events {
        log_bytes.extend_from_slice(serde_json::to_string(ev).unwrap().as_bytes());
        log_bytes.push(b'\n');
    }

    let report = verify_audit_log(log_bytes.as_slice()).unwrap();
    assert!(report.is_valid);
    assert_eq!(report.total_records, 100);

    // Tamper with record #57
    let mut tampered_bytes = Vec::new();
    for ev in &events {
        let mut copy = ev.clone();
        if copy.sequence == 57 {
            copy.method = "tampered_call".to_string();
        }
        tampered_bytes.extend_from_slice(serde_json::to_string(&copy).unwrap().as_bytes());
        tampered_bytes.push(b'\n');
    }

    let fail_report = verify_audit_log(tampered_bytes.as_slice()).unwrap();
    assert!(!fail_report.is_valid);
    assert_eq!(fail_report.tampered_sequence, Some(57));
}

// Path jail casing, protected targets and secret formats across many inputs

#[test]
fn test_path_jailing_casing_and_keys() {
    let engine = test_engine();
    let jail = test_jail();

    // 1. All variations of modifying tools in read-only mode
    let ro_config = PolicyConfig {
        allowed_paths: vec![jail.clone()],
        read_only: true,
        ..PolicyConfig::default()
    };
    let ro_engine = PolicyEngine::new(ro_config).unwrap();

    let modifying_tool_names = [
        "writeFile",
        "WriteFile",
        "write-file",
        "write_file",
        "createFile",
        "CreateFile",
        "create-file",
        "create_file",
        "deleteFile",
        "DeleteFile",
        "delete-file",
        "delete_file",
        "editFile",
        "EditFile",
        "edit-file",
        "edit_file",
        "copyFile",
        "CopyFile",
        "copy-file",
        "copy_file",
        "moveFile",
        "MoveFile",
        "move-file",
        "move_file",
        "removeFile",
        "RemoveFile",
        "remove-file",
        "remove_file",
        "appendFile",
        "AppendFile",
        "append-file",
        "append_file",
        "patchFile",
        "PatchFile",
        "patch-file",
        "patch_file",
        "truncateFile",
        "TruncateFile",
        "truncate-file",
        "truncate_file",
        "touchFile",
        "TouchFile",
        "touch-file",
        "touch_file",
    ];

    for tool_name in modifying_tool_names {
        assert!(
            ro_engine.is_modifying_tool(tool_name),
            "Tool '{}' must be recognized as modifying tool",
            tool_name
        );
        let tc = call(
            tool_name,
            json!({"path": jail.join("file.txt").to_str().unwrap()}),
        );
        let decision = ro_engine.evaluate_tool_call(&tc);
        assert!(
            matches!(decision, Decision::Block(_)),
            "Tool '{}' must be blocked in read-only mode",
            tool_name
        );
    }

    // 2. All variations of path argument keys
    let path_keys = [
        "filePath",
        "FilePath",
        "file-path",
        "file_path",
        "targetPath",
        "TargetPath",
        "target-path",
        "target_path",
        "destPath",
        "DestPath",
        "dest-path",
        "dest_path",
        "destinationPath",
        "DestinationPath",
        "destination-path",
        "destination_path",
        "srcPath",
        "SrcPath",
        "src-path",
        "src_path",
        "sourcePath",
        "SourcePath",
        "source-path",
        "source_path",
        "savePath",
        "SavePath",
        "save-path",
        "save_path",
        "newPath",
        "NewPath",
        "new-path",
        "new_path",
        "oldPath",
        "OldPath",
        "old-path",
        "old_path",
    ];

    for key in path_keys {
        let evil_tc = call("read_file", json!({ key: "C:/evil/secret.txt" }));
        let decision = engine.evaluate_tool_call(&evil_tc);
        assert!(
            matches!(decision, Decision::Block(_)),
            "Key '{}' pointing outside jail must be blocked",
            key
        );

        let good_tc = call(
            "read_file",
            json!({ key: jail.join("file.txt").to_str().unwrap() }),
        );
        let decision_good = engine.evaluate_tool_call(&good_tc);
        assert_eq!(
            decision_good,
            Decision::Allow,
            "Key '{}' pointing inside jail must be allowed for read_file",
            key
        );
    }
}

#[test]
fn test_protected_targets_and_root_directory() {
    let jail = test_jail();
    let config = PolicyConfig {
        allowed_paths: vec![jail.clone()],
        ..PolicyConfig::default()
    };
    let engine = PolicyEngine::new(config).unwrap();

    // 1. Root directory itself cannot be written/deleted without operator prompt
    let root_tc = call("delete_directory", json!({"path": jail.to_str().unwrap()}));
    let d_root = engine.evaluate_tool_call(&root_tc);
    assert!(
        matches!(d_root, Decision::AskOperator { .. }),
        "Modifying root directory must require operator approval"
    );

    // 2. Protected files in any subfolder
    let sensitive_files = [
        "moat.toml",
        "sub/moat.toml",
        ".git/HEAD",
        ".git/config",
        ".github/workflows/ci.yml",
        ".vscode/settings.json",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".ssh/authorized_keys",
        ".aws/credentials",
        ".env",
        ".env.production",
        ".env.local",
        ".gitmodules",
        ".gitconfig",
    ];

    for sensitive in sensitive_files {
        let p = jail.join(sensitive);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tc = call("write_file", json!({"path": p.to_str().unwrap()}));
        let decision = engine.evaluate_tool_call(&tc);
        assert!(
            matches!(decision, Decision::AskOperator { .. }),
            "Modifying protected target '{}' must require operator approval",
            sensitive
        );
    }
}

#[test]
fn test_dlp_exhaustive_secret_formats() {
    let dlp = DlpEngine::new();

    let catalog: Vec<(&'static str, String)> = vec![
        (
            "OpenAI sk-...",
            ["sk", "abc1234567890abcdef1234567890"].join("-"),
        ),
        (
            "Anthropic sk-ant-...",
            [
                "sk-ant-api03",
                "abcdef1234567890abcdef1234567890abcdef1234567890AA",
            ]
            .join("-"),
        ),
        (
            "GitHub PAT",
            ["ghp", "1234567890abcdef1234567890abcdef1234"].join("_"),
        ),
        (
            "GitHub fine-grained",
            [
                "github_pat",
                "11ABCD1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            ]
            .join("_"),
        ),
        (
            "Stripe Live",
            ["sk", "live", "1234567890abcdef12345678"].join("_"),
        ),
        (
            "Stripe Test",
            ["sk", "test", "1234567890abcdef12345678"].join("_"),
        ),
        (
            "Stripe Restricted",
            ["rk", "live", "1234567890abcdef12345678"].join("_"),
        ),
        (
            "Slack Bot",
            [
                "xoxb",
                "123456789012",
                "1234567890123",
                "abcdefghijklmnopqrstuvwx",
            ]
            .join("-"),
        ),
        (
            "Google AI",
            ["AIza", "SyD1234567890abcdef1234567890abcde"].concat(),
        ),
        (
            "HuggingFace",
            ["hf", "abcdefghijklmnopqrstuvwxyz12345678"].join("_"),
        ),
        ("GitLab PAT", ["glpat", "abcdef1234567890_xyz12"].join("-")),
        (
            "NPM Token",
            ["npm", "abcdef1234567890abcdef1234567890"].join("_"),
        ),
        (
            "PyPI Token",
            [
                "pypi",
                "AgEIcHlwaS5vcmc",
                "CJDEyMzQ1Njc4LTBhYmMtZGVmMS0yMzQ1LTY3ODkwYWJjZGVmMQAC",
            ]
            .join("-"),
        ),
        (
            "Bearer Token",
            format!(
                "Bearer {}",
                [
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
                    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                ]
                .join(".")
            ),
        ),
    ];

    for (label, pattern_str) in catalog {
        let (sanitized, count) = dlp.sanitize_text(&pattern_str);
        assert!(
            count >= 1,
            "DLP redaction verification failed for pattern: {label}"
        );
        assert!(
            !sanitized.contains(&pattern_str),
            "Pattern was not redacted: {label}"
        );
        assert!(sanitized.contains("[MCP-MOAT-REDACTED-SECRET]"));

        // Test in JSON object with various sensitive keys
        let json_payload = format!(
            "{{\"jsonrpc\":\"2.0\",\"result\":{{\"credential\":\"{}\"}}}}",
            pattern_str
        );
        let (json_sanitized, json_count) = dlp.sanitize_line(&json_payload);
        assert!(
            json_count >= 1,
            "DLP JSON credential verification failed for pattern: {label}"
        );
        assert!(!json_sanitized.contains(&pattern_str));
        assert!(json_sanitized.contains("[MCP-MOAT-REDACTED-SECRET]"));
    }
}

// Tool authorization: a valid path alone does not authorize a tool

fn in_jail(name: &str) -> String {
    test_jail().join(name).to_string_lossy().into_owned()
}

#[test]
fn test_generic_name_pattern_does_not_authorize() {
    let engine = test_engine();
    for name in ["read_sensitive_data", "get_secrets"] {
        let d = engine.evaluate_tool_call(&call(name, json!({"path": in_jail("a.txt")})));
        assert!(
            matches!(&d, Decision::Block(m) if m.contains("not whitelisted")),
            "{name}: {d:?}"
        );
    }
    let d = engine.evaluate_tool_call(&call("write_anything", json!({"path": in_jail("a.txt")})));
    assert!(matches!(d, Decision::AskOperator { .. }), "{d:?}");
}

#[test]
fn test_generic_name_pattern_still_checks_jail() {
    let engine = test_engine();
    let d = engine.evaluate_tool_call(&call("read_sensitive_data", json!({"path": "/etc/passwd"})));
    assert!(matches!(d, Decision::Block(_)));
}

#[test]
fn test_generic_name_listed_in_custom_always_allow_is_allowed() {
    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![test_jail()],
        custom_always_allow_tools: vec![
            "read_sensitive_data".into(),
            "write_anything".into(),
            "get_secrets".into(),
        ],
        ..PolicyConfig::default()
    })
    .unwrap();
    for name in ["read_sensitive_data", "write_anything", "get_secrets"] {
        let d = engine.evaluate_tool_call(&call(name, json!({"path": in_jail("a.txt")})));
        assert!(matches!(d, Decision::Allow), "{name}: {d:?}");
    }
}

#[test]
fn test_standard_filesystem_tool_names_are_allowed_in_jail() {
    let engine = test_engine();
    for name in [
        "read_text_file",
        "read_media_file",
        "list_directory_with_sizes",
        "directory_tree",
        "get_file_info",
    ] {
        let d = engine.evaluate_tool_call(&call(name, json!({"path": in_jail("a.txt")})));
        assert!(matches!(d, Decision::Allow), "{name}: {d:?}");
    }
}

#[test]
fn test_pathless_file_tool_calls_are_blocked() {
    let engine = test_engine();
    let d = engine.evaluate_tool_call(&call("read_file", serde_json::Value::Null));
    assert!(matches!(d, Decision::Block(_)), "{d:?}");
    let cases = [
        call("read_file", json!({})),
        ToolCallParams {
            name: "read_file".into(),
            arguments: None,
        },
    ];
    for c in &cases {
        let d = engine.evaluate_tool_call(c);
        assert!(
            matches!(&d, Decision::Block(m) if m.contains("could not be verified")),
            "{d:?}"
        );
    }
}

#[test]
fn test_list_allowed_directories_without_path_is_allowed() {
    let engine = test_engine();
    let d = engine.evaluate_tool_call(&call("list_allowed_directories", json!({})));
    assert!(matches!(d, Decision::Allow), "{d:?}");
}
