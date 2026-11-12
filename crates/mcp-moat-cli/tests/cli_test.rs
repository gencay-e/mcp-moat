use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn get_moat_bin() -> &'static str {
    env!("CARGO_BIN_EXE_moat")
}

fn get_mock_server_bin() -> PathBuf {
    let moat = Path::new(get_moat_bin());
    let bin_dir = moat.parent().expect("Moat binary has parent dir");
    bin_dir.join(if cfg!(windows) {
        "mock_server.exe"
    } else {
        "mock_server"
    })
}

#[tokio::test]
async fn test_cli_help() {
    let moat = get_moat_bin();

    let output = Command::new(moat)
        .arg("--help")
        .output()
        .await
        .expect("Failed to execute moat --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sits between an MCP client and an MCP server"));
    assert!(stdout.contains("wrap"));
    assert!(stdout.contains("init"));
}

#[tokio::test]
async fn test_cli_init_command() {
    let moat = get_moat_bin();
    let tmp_dir = std::env::temp_dir();
    let config_path = tmp_dir.join(format!("moat_init_test_{}.toml", std::process::id()));
    let _ = std::fs::remove_file(&config_path);

    // 1. Initial creation
    let output = Command::new(moat)
        .args(["init", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat init");

    assert!(output.status.success(), "moat init must succeed");
    assert!(config_path.exists(), "Config file must be created on disk");

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("allowed_paths"));
    assert!(content.contains("blocked_commands"));

    // 2. Re-creation without --force should fail
    let fail_output = Command::new(moat)
        .args(["init", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat init again");

    assert!(
        !fail_output.status.success(),
        "moat init without --force must fail on existing file"
    );

    // 3. Re-creation with --force should succeed
    let force_output = Command::new(moat)
        .args(["init", config_path.to_str().unwrap(), "--force"])
        .output()
        .await
        .expect("Failed to execute moat init with --force");

    assert!(
        force_output.status.success(),
        "moat init with --force must overwrite successfully"
    );

    let _ = std::fs::remove_file(&config_path);
}

#[tokio::test]
async fn test_cli_wrap_mock_server_e2e() {
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();
    assert!(
        mock_server.exists(),
        "mock_server binary must be built at {:?}",
        mock_server
    );

    let mut child = Command::new(moat)
        .args(["wrap", "--", mock_server.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap");

    let mut stdin = child.stdin.take().expect("Child stdin unavailable");
    let stdout = child.stdout.take().expect("Child stdout unavailable");
    let mut reader = BufReader::new(stdout).lines();

    // 1. Send initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "e2e-test", "version": "1.0" }
        }
    });
    stdin
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_resp_line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .expect("Timeout waiting for initialize response")
        .expect("Error reading stdout")
        .expect("Unexpected EOF");

    let init_resp: Value = serde_json::from_str(&init_resp_line).unwrap();
    assert_eq!(init_resp["id"].as_i64(), Some(1));
    assert_eq!(
        init_resp["result"]["serverInfo"]["name"].as_str(),
        Some("mock-mcp-server")
    );

    // 2. Send ping
    let ping_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" });
    stdin
        .write_all(format!("{}\n", ping_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let ping_resp_line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .expect("Timeout waiting for ping response")
        .expect("Error reading stdout")
        .expect("Unexpected EOF");

    let ping_resp: Value = serde_json::from_str(&ping_resp_line).unwrap();
    assert_eq!(ping_resp["id"].as_i64(), Some(2));

    // 3. Close stdin and wait for clean exit
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("Timeout waiting for moat to exit")
        .expect("Child wait failed");

    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn test_cli_wrap_read_only_mode() {
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();

    let mut child = Command::new(moat)
        .args(["wrap", "--read-only", "--", mock_server.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap --read-only");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    // Send write_file call which must be blocked by --read-only policy
    let write_call = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "foo.txt",
                "content": "bar"
            }
        }
    });
    stdin
        .write_all(format!("{}\n", write_call).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(resp["id"].as_i64(), Some(10));
    assert_eq!(resp["result"]["isError"].as_bool(), Some(true));
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("Read-only policy active"),
        "Expected read-only violation message"
    );

    drop(stdin);
    let _ = child.wait().await;
}

#[tokio::test]
async fn test_cli_wrap_no_prompt_auto_denies() {
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();

    let mut child = Command::new(moat)
        .args([
            "wrap",
            "--no-prompt",
            "--require-approval",
            "--",
            mock_server.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap --no-prompt");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    let write_call = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "foo.txt",
                "content": "bar"
            }
        }
    });
    stdin
        .write_all(format!("{}\n", write_call).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // Must receive auto-denial immediately instead of hanging waiting for operator
    let resp_line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .expect("Should not hang waiting for prompt")
        .unwrap()
        .unwrap();

    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(resp["id"].as_i64(), Some(20));
    assert_eq!(resp["result"]["isError"].as_bool(), Some(true));
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("but --no-prompt is set, so the call was denied"),
        "unexpected reason: {text}"
    );
    assert!(!text.contains("rejected by operator in prompt"));

    drop(stdin);
    let _ = child.wait().await;
}

#[tokio::test]
async fn test_cli_wrap_audit_log_and_verify() {
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();

    let tmp_dir = std::env::temp_dir();
    let audit_log = tmp_dir.join(format!("cli_audit_test_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit_log);

    let mut child = Command::new(moat)
        .args([
            "wrap",
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--audit-level",
            "full",
            "--read-only",
            "--",
            mock_server.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap with audit");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "audit-cli-test", "version": "1.0" }
        }
    });
    stdin
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _ = reader.next_line().await.unwrap().unwrap();

    // 2. Ping
    let ping_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" });
    stdin
        .write_all(format!("{}\n", ping_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _ = reader.next_line().await.unwrap().unwrap();

    // 3. Blocked write_file
    let write_call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "test.txt",
                "content": "blocked"
            }
        }
    });
    stdin
        .write_all(format!("{}\n", write_call).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();
    let _ = reader.next_line().await.unwrap().unwrap();

    drop(stdin);
    let _ = child.wait().await;

    assert!(audit_log.exists(), "Audit log must exist on disk");

    // 4. Verify audit log with `moat audit verify`
    let verify_output = Command::new(moat)
        .args(["audit", "verify", audit_log.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat audit verify");

    let stderr = String::from_utf8_lossy(&verify_output.stderr);
    assert!(
        verify_output.status.success(),
        "moat audit verify must succeed. Stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("PASSED"),
        "Expected PASSED status in output"
    );
    assert!(
        stderr.contains("INTACT (SHA-256)"),
        "Expected INTACT report"
    );

    // 5. Query audit log with `moat audit query`
    let query_output = Command::new(moat)
        .args([
            "audit",
            "query",
            audit_log.to_str().unwrap(),
            "--violations-only",
        ])
        .output()
        .await
        .expect("Failed to execute moat audit query");

    assert!(query_output.status.success());
    let stdout = String::from_utf8_lossy(&query_output.stdout);
    assert!(
        stdout.contains("write_file"),
        "Violations query should show blocked write_file tool call"
    );
    assert!(
        stdout.contains("BLOCK"),
        "Query output should show BLOCK decision"
    );

    // 6. Tamper detection test with `moat audit verify`
    let original_content = std::fs::read_to_string(&audit_log).unwrap();
    let tampered_content = original_content.replacen("ping", "tampered_call", 1);
    std::fs::write(&audit_log, tampered_content).unwrap();

    let tampered_output = Command::new(moat)
        .args(["audit", "verify", audit_log.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat audit verify on tampered log");

    assert!(
        !tampered_output.status.success(),
        "moat audit verify must fail on tampered audit log"
    );
    let tampered_stderr = String::from_utf8_lossy(&tampered_output.stderr);
    assert!(
        tampered_stderr.contains("FAILED (TAMPER DETECTED)"),
        "Expected tamper detected in stderr"
    );

    let _ = std::fs::remove_file(&audit_log);
}

#[tokio::test]
async fn test_cli_audit_query_violations_includes_operator_deny_and_dlp() {
    use mcp_moat_core::audit::{AuditChain, AuditDecision, AuditDirection};

    let moat = get_moat_bin();
    let tmp_dir = std::env::temp_dir();
    let audit_log = tmp_dir.join(format!(
        "cli_query_violations_test_{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&audit_log);

    let mut chain = AuditChain::new("sess-query-test");

    // 1. Normal Allow (should be filtered out by --violations-only)
    let e1 = chain.create_event(
        "2026-10-24T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "initialize".to_string(),
        None,
        None,
        Some(AuditDecision::Allow),
        None,
        None,
        None,
    );

    // 2. Operator Deny (MUST be included in --violations-only)
    let e2 = chain.create_event(
        "2026-10-24T00:00:02Z".to_string(),
        AuditDirection::Inbound,
        "tools/call".to_string(),
        Some("delete_db".to_string()),
        None,
        Some(AuditDecision::AskOperator {
            summary: "delete_db()".to_string(),
        }),
        Some("Deny".to_string()),
        None,
        None,
    );

    // 3. Outbound DLP redaction (MUST be included in --violations-only)
    let e3 = chain.create_event(
        "2026-10-24T00:00:03Z".to_string(),
        AuditDirection::Outbound,
        "dlp_redaction".to_string(),
        None,
        None,
        None,
        None,
        Some("[MCP-MOAT-REDACTED-SECRET]".to_string()),
        Some(1),
    );

    // 4. Policy Block (MUST be included in --violations-only)
    let e4 = chain.create_event(
        "2026-10-24T00:00:04Z".to_string(),
        AuditDirection::Inbound,
        "tools/call".to_string(),
        Some("write_file".to_string()),
        Some("/etc/passwd".to_string()),
        Some(AuditDecision::Block {
            reason: "Path prohibited".to_string(),
        }),
        None,
        None,
        None,
    );

    let log_content = format!(
        "{}\n{}\n{}\n{}\n",
        serde_json::to_string(&e1).unwrap(),
        serde_json::to_string(&e2).unwrap(),
        serde_json::to_string(&e3).unwrap(),
        serde_json::to_string(&e4).unwrap()
    );
    std::fs::write(&audit_log, log_content).unwrap();

    let query_output = Command::new(moat)
        .args([
            "audit",
            "query",
            audit_log.to_str().unwrap(),
            "--violations-only",
        ])
        .output()
        .await
        .expect("Failed to execute moat audit query");

    assert!(query_output.status.success());
    let stdout = String::from_utf8_lossy(&query_output.stdout);

    // Must NOT contain event 1
    assert!(!stdout.contains("initialize"));

    // Must contain operator deny (event 2)
    assert!(stdout.contains("delete_db"));
    assert!(stdout.contains("ASK_OPERATOR [Operator: Deny]"));

    // Must contain DLP redaction (event 3)
    assert!(stdout.contains("dlp_redaction"));
    assert!(stdout.contains("[DLP: 1 redacted]"));

    // Must contain Policy Block (event 4)
    assert!(stdout.contains("write_file"));
    assert!(stdout.contains("BLOCK (Path prohibited)"));

    let _ = std::fs::remove_file(&audit_log);
}

#[tokio::test]
async fn test_cli_audit_tail_ring_buffer() {
    use mcp_moat_core::audit::{AuditChain, AuditDecision, AuditDirection};

    let moat = get_moat_bin();
    let tmp_dir = std::env::temp_dir();
    let audit_log = tmp_dir.join(format!("cli_tail_ring_test_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit_log);

    let mut chain = AuditChain::new("sess-tail-test");
    let mut log_lines = Vec::new();

    for i in 1..=20 {
        let e = chain.create_event(
            format!("2026-10-24T00:00:{:02}Z", i),
            AuditDirection::Inbound,
            format!("ping_{}", i),
            None,
            None,
            Some(AuditDecision::Allow),
            None,
            None,
            None,
        );
        log_lines.push(serde_json::to_string(&e).unwrap());
    }
    std::fs::write(&audit_log, log_lines.join("\n") + "\n").unwrap();

    // Request tail of last 5 lines
    let tail_output = Command::new(moat)
        .args(["audit", "tail", audit_log.to_str().unwrap(), "-n", "5"])
        .output()
        .await
        .expect("Failed to execute moat audit tail");

    assert!(tail_output.status.success());
    let stdout = String::from_utf8_lossy(&tail_output.stdout);

    // Should NOT contain events 1..15
    assert!(!stdout.contains("ping_1 "));
    assert!(!stdout.contains("ping_15"));

    // Should contain events 16..20
    assert!(stdout.contains("ping_16"));
    assert!(stdout.contains("ping_17"));
    assert!(stdout.contains("ping_18"));
    assert!(stdout.contains("ping_19"));
    assert!(stdout.contains("ping_20"));

    let _ = std::fs::remove_file(&audit_log);
}

#[tokio::test]
async fn test_cli_wrap_monitor_mode() {
    let monitor_target =
        std::env::temp_dir().join(format!("moat_monitor_target_{}.txt", std::process::id()));
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();

    let mut child = Command::new(moat)
        .args([
            "wrap",
            "--read-only",
            "--monitor",
            "--",
            mock_server.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap --monitor");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    // In read-only mode, write_file would normally be blocked.
    // In monitor mode, it should be forwarded to mock server without blocking!
    let write_call = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": monitor_target.to_str().unwrap(),
                "content": "allowed_in_monitor"
            }
        }
    });
    stdin
        .write_all(format!("{}\n", write_call).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .expect("Should receive response in monitor mode")
        .unwrap()
        .unwrap();

    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(resp["id"].as_i64(), Some(42));
    assert_ne!(
        resp.get("result")
            .and_then(|r| r.get("isError"))
            .and_then(|e| e.as_bool()),
        Some(true),
        "Monitor mode must not return an error frame for blocked action"
    );

    drop(stdin);
    let output = child.wait_with_output().await.expect("Wait failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[mcp-moat:MONITOR] Simulated BLOCK for tool 'write_file'"),
        "Stderr must contain monitor simulated block warning: {}",
        stderr
    );

    let _ = std::fs::remove_file(&monitor_target);
}

#[tokio::test]
async fn test_cli_audit_query_strict() {
    use mcp_moat_core::audit::{AuditChain, AuditDecision, AuditDirection};

    let moat = get_moat_bin();
    let tmp_dir = std::env::temp_dir();
    let audit_log_violation = tmp_dir.join(format!("cli_strict_viol_{}.jsonl", std::process::id()));
    let audit_log_clean = tmp_dir.join(format!("cli_strict_clean_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit_log_violation);
    let _ = std::fs::remove_file(&audit_log_clean);

    let mut chain = AuditChain::new("sess-strict-test");

    // Clean log: only Allow
    let e_allow = chain.create_event(
        "2026-10-24T00:00:01Z".to_string(),
        AuditDirection::Inbound,
        "ping".to_string(),
        None,
        None,
        Some(AuditDecision::Allow),
        None,
        None,
        None,
    );
    std::fs::write(
        &audit_log_clean,
        serde_json::to_string(&e_allow).unwrap() + "\n",
    )
    .unwrap();

    // Violation log: has Block
    let e_block = chain.create_event(
        "2026-10-24T00:00:02Z".to_string(),
        AuditDirection::Inbound,
        "tools/call".to_string(),
        Some("rm_rf".to_string()),
        None,
        Some(AuditDecision::Block {
            reason: "Forbidden command".to_string(),
        }),
        None,
        None,
        None,
    );
    std::fs::write(
        &audit_log_violation,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&e_allow).unwrap(),
            serde_json::to_string(&e_block).unwrap()
        ),
    )
    .unwrap();

    // 1. Query clean log with --strict -> Must succeed (exit code 0)
    let clean_output = Command::new(moat)
        .args([
            "audit",
            "query",
            audit_log_clean.to_str().unwrap(),
            "--strict",
        ])
        .output()
        .await
        .expect("Failed to execute moat audit query --strict on clean log");

    assert!(
        clean_output.status.success(),
        "Clean log query with --strict must return exit code 0"
    );

    // 2. Query violation log with --strict -> Must fail with exit code 1
    let viol_output = Command::new(moat)
        .args([
            "audit",
            "query",
            audit_log_violation.to_str().unwrap(),
            "--strict",
        ])
        .output()
        .await
        .expect("Failed to execute moat audit query --strict on violation log");

    assert_eq!(
        viol_output.status.code(),
        Some(1),
        "Violation log query with --strict must return exit code 1"
    );

    let _ = std::fs::remove_file(&audit_log_clean);
    let _ = std::fs::remove_file(&audit_log_violation);
}

#[tokio::test]
async fn test_cli_wrap_non_existent_command_fails_gracefully() {
    let moat = get_moat_bin();

    let output = Command::new(moat)
        .args(["wrap", "--", "non_existent_command_12345_xyz"])
        .output()
        .await
        .expect("Failed to execute moat wrap");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "[moat] Error: Failed to spawn wrapped command 'non_existent_command_12345_xyz'"
        ),
        "Expected clean moat error message on stderr, got: {}",
        stderr
    );
}

#[tokio::test]
async fn test_cli_wrap_preset_git_and_invalid_preset() {
    let moat = get_moat_bin();

    // 1. Invalid preset fails with error message
    let output = Command::new(moat)
        .args([
            "wrap",
            "--preset",
            "invalid_profile_name",
            "--",
            "mock_server",
        ])
        .output()
        .await
        .expect("Failed to execute moat wrap");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unknown preset 'invalid_profile_name'"));

    // 2. Valid preset help and option parsing
    let help_output = Command::new(moat)
        .args(["wrap", "--help"])
        .output()
        .await
        .expect("Failed to execute moat wrap --help");

    assert!(help_output.status.success());
    let stdout = String::from_utf8_lossy(&help_output.stdout);
    assert!(stdout.contains("--preset"));
}

#[tokio::test]
async fn test_cli_wrap_child_exit_code_propagation() {
    let moat = get_moat_bin();

    #[cfg(windows)]
    let (prog, args_42, args_0) = ("cmd.exe", vec!["/C", "exit", "42"], vec!["/C", "exit", "0"]);

    #[cfg(not(windows))]
    let (prog, args_42, args_0) = ("sh", vec!["-c", "exit 42"], vec!["-c", "exit 0"]);

    // 1. Verify child exit code 42 is passed through cleanly
    let mut cmd_args = vec!["wrap", "--", prog];
    cmd_args.extend(args_42);

    let output_42 = Command::new(moat)
        .args(&cmd_args)
        .output()
        .await
        .expect("Failed to execute moat wrap with exit 42");

    assert_eq!(
        output_42.status.code(),
        Some(42),
        "moat wrap must preserve child exit code 42"
    );

    // 2. Verify child exit code 0 is passed through cleanly
    let mut cmd_args_0 = vec!["wrap", "--", prog];
    cmd_args_0.extend(args_0);

    let output_0 = Command::new(moat)
        .args(&cmd_args_0)
        .output()
        .await
        .expect("Failed to execute moat wrap with exit 0");

    assert_eq!(
        output_0.status.code(),
        Some(0),
        "moat wrap must preserve child exit code 0"
    );
}

#[tokio::test]
async fn test_cli_codegen_from_json_and_spawn_mock_server() {
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();
    let tmp_dir = std::env::temp_dir();
    let json_path = tmp_dir.join(format!("moat_codegen_test_{}.json", std::process::id()));
    let _ = std::fs::remove_file(&json_path);

    let sample_tools = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Reads the contents of a file from disk with full UTF-8 validation and error handling.",
                    "inputSchema": {
                        "$schema": "http://json-schema.org/draft-07/schema#",
                        "title": "ReadFileArgs",
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to file."
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Writes content to a file on disk.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "content": { "type": "string" }
                        },
                        "required": ["path", "content"]
                    }
                }
            ]
        }
    });
    std::fs::write(
        &json_path,
        serde_json::to_string_pretty(&sample_tools).unwrap(),
    )
    .unwrap();

    // 1. Test `moat codegen --from-json ... --format ts --read-only`
    let ts_out = Command::new(moat)
        .args([
            "codegen",
            "--from-json",
            json_path.to_str().unwrap(),
            "--format",
            "ts",
            "--read-only",
        ])
        .output()
        .await
        .expect("Failed to run moat codegen --from-json");

    assert!(
        ts_out.status.success(),
        "moat codegen --from-json must succeed"
    );
    let ts_stdout = String::from_utf8_lossy(&ts_out.stdout);
    let ts_stderr = String::from_utf8_lossy(&ts_out.stderr);
    assert!(ts_stdout.contains("declare namespace mcp {"));
    assert!(ts_stdout.contains("function read_file(args: { path: string }): Promise<unknown>;"));
    assert!(
        !ts_stdout.contains("write_file"),
        "write_file must be filtered out by --read-only"
    );
    assert!(
        ts_stderr.contains("[moat:codegen] Compiled 1 tools (1 filtered by policy)"),
        "Stderr must report compiled & filtered counts, got: {}",
        ts_stderr
    );

    // 2. Test `moat codegen --format python -- <mock_server>` spawning live MCP server
    let py_out = Command::new(moat)
        .args([
            "codegen",
            "--format",
            "python",
            "--hide-tool",
            "write_file",
            "--",
            mock_server.to_str().unwrap(),
        ])
        .output()
        .await
        .expect("Failed to run moat codegen spawning mock_server");

    let py_stdout = String::from_utf8_lossy(&py_out.stdout);
    let py_stderr = String::from_utf8_lossy(&py_out.stderr);
    assert!(
        py_out.status.success(),
        "moat codegen spawning mock_server must succeed. Stderr: {}",
        py_stderr
    );
    assert!(py_stdout.contains("async def echo("));
    assert!(
        !py_stdout.contains("write_file"),
        "write_file must be hidden by --hide-tool"
    );
    assert!(py_stderr.contains("[moat:codegen] Compiled 1 tools (1 filtered by policy)"));

    let _ = std::fs::remove_file(&json_path);
}

#[test]
fn test_sse_commands_do_not_exist() {
    let moat = get_moat_bin();
    for cmd in ["sse-proxy", "sse-bridge"] {
        let out = std::process::Command::new(moat)
            .args([cmd, "--help"])
            .output()
            .expect("Failed to run moat");
        assert!(!out.status.success(), "{} must not exist", cmd);
    }
}

#[tokio::test]
async fn test_cli_check_valid_config() {
    let moat = get_moat_bin();
    let tmp_dir = std::env::temp_dir();
    let config_path = tmp_dir.join(format!("moat_check_valid_{}.toml", std::process::id()));
    let content = format!(
        "allowed_paths = ['{}']\nread_only = true\nprotected_files = ['{}']\n",
        tmp_dir.display(),
        config_path.display()
    );
    std::fs::write(&config_path, content).unwrap();

    let output = Command::new(moat)
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat check");

    let _ = std::fs::remove_file(&config_path);
    assert!(
        output.status.success(),
        "moat check must succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Config OK"));
    assert!(stdout.contains("Allowed roots"));
}

#[tokio::test]
async fn test_cli_check_accepts_short_name_config_path() {
    // Windows CI temp paths look like C:\Users\RUNNER~1\AppData\Local\Temp. The --config file
    // is added to protected_files and must not be rejected by the 8.3 rule for tool-call paths.
    let moat = get_moat_bin();
    let dir = std::env::temp_dir().join(format!("RUNNER~{}", std::process::id() % 10));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join(format!("moat_check_short_{}.toml", std::process::id()));
    std::fs::write(&config_path, "allowed_paths = ['.']\n").unwrap();

    let output = Command::new(moat)
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat check");

    let _ = std::fs::remove_file(&config_path);
    assert!(
        output.status.success(),
        "moat check must accept a config path with an 8.3-style segment. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn test_cli_check_invalid_toml() {
    let moat = get_moat_bin();
    let config_path = std::env::temp_dir().join(format!(
        "moat_check_invalid_toml_{}.toml",
        std::process::id()
    ));
    std::fs::write(&config_path, "allowed_paths = [not valid toml\n").unwrap();

    let output = Command::new(moat)
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat check");

    let _ = std::fs::remove_file(&config_path);
    assert!(
        !output.status.success(),
        "moat check must reject invalid TOML"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to parse TOML") || stderr.contains("Invalid policy configuration"),
        "unexpected stderr: {stderr}"
    );
}

#[tokio::test]
async fn test_cli_check_invalid_regex() {
    let moat = get_moat_bin();
    let config_path = std::env::temp_dir().join(format!(
        "moat_check_invalid_regex_{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &config_path,
        "allowed_paths = ['.']\nblocked_commands_regex = ['(unclosed']\n",
    )
    .unwrap();

    let output = Command::new(moat)
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat check");

    let _ = std::fs::remove_file(&config_path);
    assert!(
        !output.status.success(),
        "moat check must reject invalid regex"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid policy configuration"),
        "unexpected stderr: {stderr}"
    );
}

#[tokio::test]
async fn test_cli_check_missing_allowed_path() {
    let moat = get_moat_bin();
    let config_path = std::env::temp_dir().join(format!(
        "moat_check_missing_root_{}.toml",
        std::process::id()
    ));
    let missing = std::env::temp_dir().join("moat_definitely_missing_root_12345");
    let content = format!("allowed_paths = ['{}']\n", missing.display());
    std::fs::write(&config_path, content).unwrap();

    let output = Command::new(moat)
        .args(["check", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("Failed to execute moat check");

    let _ = std::fs::remove_file(&config_path);
    assert!(
        !output.status.success(),
        "moat check must reject a missing allowed path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Allowed path does not exist"),
        "unexpected stderr: {stderr}"
    );
}

#[tokio::test]
async fn test_cli_completion_scripts() {
    let moat = get_moat_bin();
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = Command::new(moat)
            .args(["completion", shell])
            .output()
            .await
            .expect("Failed to execute moat completion");

        assert!(
            output.status.success(),
            "moat completion {shell} must succeed"
        );
        assert!(
            !output.stdout.is_empty(),
            "moat completion {shell} must emit a script"
        );
    }
}

#[tokio::test]
async fn test_cli_wrap_protects_custom_config_path() {
    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();
    let tmp_dir = std::env::temp_dir();
    let config_path = tmp_dir.join(format!("moat_wrap_protected_{}.toml", std::process::id()));
    let content = format!(
        "allowed_paths = ['{}']\nrequire_approval_on_write = false\n",
        tmp_dir.display()
    );
    std::fs::write(&config_path, content).unwrap();

    let mut child = Command::new(moat)
        .args([
            "wrap",
            "--no-prompt",
            "--config",
            config_path.to_str().unwrap(),
            "--",
            mock_server.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap with custom config");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    let write_call = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": config_path.to_str().unwrap(),
                "content": "allowed_paths = ['.']\n"
            }
        }
    });
    stdin
        .write_all(format!("{}\n", write_call).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let resp_line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    let _ = std::fs::remove_file(&config_path);
    drop(stdin);
    let _ = child.wait().await;

    assert_eq!(resp["id"].as_i64(), Some(11));
    assert_eq!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "Writing the active --config file must be denied"
    );
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let lower = text.to_lowercase();
    assert!(
        lower.contains("approval")
            || lower.contains("protected")
            || lower.contains("denied")
            || lower.contains("rejected")
            || lower.contains("immutable_policy_violation"),
        "unexpected denial message: {text}"
    );
}

/// With `RUST_LOG=trace` no log line may carry request arguments, server responses, malformed
/// input or the environment: the log has method, id, byte length and decision only.
#[tokio::test]
async fn test_trace_logging_never_contains_payloads_or_secrets() {
    const AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    const GITHUB: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    const API_KEY: &str = "sk-1234567890abcdef1234567890abcdef"; // also leaked by the mock server
    const ENV_SECRET: &str = "env-secret-value-7f3a9c1d5e";
    const EXTRA_ARG: &str = "--unused-arg-secret-4b8e2a";

    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();
    let dir = std::env::temp_dir().join(format!("moat_trace_log_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("moat.toml");
    std::fs::write(
        &config_path,
        format!(
            "allowed_paths = ['{}']\nalways_allow_tools = ['echo']\n",
            dir.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(moat)
        .args([
            "wrap",
            "--no-prompt",
            "--config",
            config_path.to_str().unwrap(),
            "--",
            mock_server.to_str().unwrap(),
            "--leak-secret",
            EXTRA_ARG,
        ])
        .env("RUST_LOG", "trace")
        .env("MOAT_TEST_ENV_SECRET", ENV_SECRET)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    });

    let requests = vec![
        // allowed: argument and response both carry secrets
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": format!("{AWS} {GITHUB}")}}})
        .to_string(),
        // blocked: path outside the jail, secrets in the arguments
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "/etc/moat-test", "content": GITHUB}}})
        .to_string(),
        // needs approval, denied by --no-prompt
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "bash", "arguments": {"command": format!("echo {AWS}")}}})
        .to_string(),
        // wrong jsonrpc version and a secret in the version field
        json!({"jsonrpc": GITHUB, "id": 4, "method": "tools/list"}).to_string(),
        // method that is not a plain token
        json!({"jsonrpc": "2.0", "id": 5, "method": format!("x/{AWS}/{GITHUB}/long-long-long-long-long-long-long-long-long")}).to_string(),
        // malformed JSON with a secret inside
        format!("{{\"jsonrpc\": \"2.0\", \"id\": 6, \"note\": \"{AWS}\""),
        // valid JSON, invalid request
        format!("{{\"jsonrpc\": \"2.0\", \"id\": 7, \"method\": 5, \"note\": \"{GITHUB}\"}}"),
        // batch with a secret
        format!("[{{\"jsonrpc\": \"2.0\", \"id\": 8, \"method\": \"ping\", \"note\": \"{AWS}\"}}]"),
        // resource read outside the jail
        json!({"jsonrpc": "2.0", "id": 9, "method": "resources/read",
            "params": {"uri": format!("file:///etc/{GITHUB}")}})
        .to_string(),
    ];
    for r in &requests {
        stdin.write_all(format!("{r}\n").as_bytes()).await.unwrap();
    }
    stdin.flush().await.unwrap();

    // every request except possibly the notification-free ones gets exactly one response
    let mut seen = 0;
    while seen < requests.len() {
        let line = tokio::time::timeout(Duration::from_secs(10), reader.next_line())
            .await
            .expect("timeout waiting for a response")
            .unwrap()
            .expect("unexpected EOF");
        let out: Value = serde_json::from_str(&line).unwrap();
        if out["id"] == json!(1) {
            // the allowed call: the secrets in the response are masked for the client
            for secret in [AWS, GITHUB, API_KEY] {
                assert!(!line.contains(secret), "{line}");
            }
        }
        seen += 1;
    }

    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    let log = stderr_task.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    // the trace level is really on: the log is not empty and carries the safe fields
    assert!(
        log.contains("Inbound request") && log.contains("method=\"tools/call\""),
        "trace logging did not run, log was:\n{log}"
    );
    for secret in [
        AWS,
        GITHUB,
        API_KEY,
        ENV_SECRET,
        EXTRA_ARG,
        "MOAT_TEST_ENV_SECRET",
    ] {
        assert!(!log.contains(secret), "log contains {secret:?}:\n{log}");
    }
    assert!(
        !log.contains("/etc/moat-test"),
        "log contains an argument value:\n{log}"
    );
}

/// Same as the trace test, with `--monitor`: the diagnostics for simulated blocks name the tool
/// and a fixed category, never the path or the URI that the client sent.
#[tokio::test]
async fn test_monitor_mode_stderr_never_contains_request_strings() {
    const MARKER: &str = "uniq-marker-91c4e7";

    let moat = get_moat_bin();
    let mock_server = get_mock_server_bin();
    let dir = std::env::temp_dir().join(format!("moat_monitor_log_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("moat.toml");
    std::fs::write(
        &config_path,
        format!(
            "allowed_paths = ['{}']\nalways_allow_tools = ['echo']\n",
            dir.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(moat)
        .args([
            "wrap",
            "--no-prompt",
            "--monitor",
            "--config",
            config_path.to_str().unwrap(),
            "--",
            mock_server.to_str().unwrap(),
        ])
        .env("RUST_LOG", "trace")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn moat wrap");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    });

    let requests = vec![
        // path outside the jail, in the path and in the tool name
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": format!("/etc/{MARKER}/x"), "content": "c"}}})
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": format!("evil\n{MARKER}\u{1b}[2J"), "arguments": {"path": format!("/etc/{MARKER}")}}})
        .to_string(),
        // resource outside the jail
        json!({"jsonrpc": "2.0", "id": 3, "method": "resources/read",
            "params": {"uri": format!("file:///etc/{MARKER}")}})
        .to_string(),
        // unknown method (a short plain method name is logged as a token at debug level)
        json!({"jsonrpc": "2.0", "id": 4, "method": "x/unknown"}).to_string(),
        // command that needs approval
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "bash", "arguments": {"command": format!("echo {MARKER}")}}})
        .to_string(),
    ];
    for r in &requests {
        stdin.write_all(format!("{r}\n").as_bytes()).await.unwrap();
    }
    stdin.flush().await.unwrap();
    for _ in 0..requests.len() {
        tokio::time::timeout(Duration::from_secs(10), reader.next_line())
            .await
            .expect("timeout waiting for a response")
            .unwrap()
            .expect("unexpected EOF");
    }
    drop(stdin);
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    let log = stderr_task.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        log.contains("[mcp-moat:MONITOR] Simulated BLOCK"),
        "monitor diagnostics did not run, log was:\n{log}"
    );
    assert!(
        log.contains("(path outside allowed folder)") && log.contains("(method not allowed)"),
        "expected fixed categories, log was:\n{log}"
    );
    assert!(!log.contains(MARKER), "log contains the marker:\n{log}");
    assert!(!log.contains('\u{1b}'), "log contains a raw escape:\n{log}");
}
