#![allow(clippy::field_reassign_with_default)] // tests tweak single config fields
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use mcp_moat_core::{PolicyConfig, PolicyEngine};
use mcp_moat_proxy::ProxyServer;

#[tokio::test]
async fn test_stream_1000_requests_and_stderr_overflow_stress() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    // 200,000 bytes > 128 KiB to trigger OS kernel pipe buffer overflow test
    let args = vec!["--dump-stderr".to_string(), "200000".to_string()];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_err_tx, client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).expect("PolicyEngine failed");
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    // Autonomous client drain of stderr to verify > 128 KiB emitted and drained
    let stderr_drain_handle = tokio::spawn(async move {
        let mut reader = client_err_rx;
        let mut total_bytes = 0;
        let mut buf = [0u8; 8192];
        while let Ok(n) = reader.read(&mut buf).await {
            if n == 0 {
                break;
            }
            total_bytes += n;
        }
        total_bytes
    });

    let total_expected = 1001; // 1 initialize + 1000 synthetic requests
    let response_reader_handle = tokio::spawn(async move {
        let mut framed_out =
            FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));
        let mut received = 0;
        let mut received_ids = HashSet::new();

        while let Some(line_res) = framed_out.next().await {
            let line = line_res.expect("Error reading response line from proxy");
            let val: Value = serde_json::from_str(&line).expect("Invalid JSON in response");
            assert_eq!(
                val.get("jsonrpc").and_then(|v| v.as_str()),
                Some("2.0"),
                "Invalid jsonrpc version"
            );
            if let Some(id) = val.get("id").and_then(|i| i.as_i64()) {
                received_ids.insert(id);
            }
            received += 1;
            if received == total_expected {
                break;
            }
        }
        (received, received_ids)
    });

    // 1. Send initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "stress-test", "version": "1.0" }
        }
    });
    client_tx
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();

    // 2. Send initialized notification
    let init_notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    client_tx
        .write_all(format!("{}\n", init_notif).as_bytes())
        .await
        .unwrap();

    // 3. Send 1,000 synthetic requests
    for i in 1..=1000 {
        let req = match i % 3 {
            0 => json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "ping"
            }),
            1 => json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {
                        "message": format!("msg-{}", i)
                    }
                }
            }),
            _ => json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/list"
            }),
        };
        client_tx
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();
    }
    client_tx.flush().await.unwrap();

    // Wait for all 1001 responses
    let (received_count, received_ids) =
        tokio::time::timeout(Duration::from_secs(15), response_reader_handle)
            .await
            .expect("Timeout waiting for 1,000+ responses")
            .expect("Response reader task failed");

    assert_eq!(
        received_count, total_expected,
        "Zero dropped frames: expected {} responses",
        total_expected
    );
    assert_eq!(
        received_ids.len(),
        total_expected,
        "Every request must have a unique matched response ID"
    );

    // Close client input to terminate child server cleanly
    drop(client_tx);

    let exit_code = tokio::time::timeout(Duration::from_secs(5), proxy_handle)
        .await
        .expect("Timeout waiting for proxy shutdown")
        .expect("Proxy task panicked")
        .expect("Proxy failed with error");

    assert_eq!(exit_code, 0, "Mock server should exit with 0");

    let drained_stderr_bytes = tokio::time::timeout(Duration::from_secs(5), stderr_drain_handle)
        .await
        .expect("Timeout draining stderr")
        .expect("Stderr drain panicked");

    assert!(
        drained_stderr_bytes >= 131072,
        "Expected >128 KiB stderr drained without deadlock, got {} bytes",
        drained_stderr_bytes
    );
}

#[tokio::test]
async fn test_ping_bypass_overtakes_waiting_calls() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    // Simulate server processing delay of 1500ms on tool calls. The ping must arrive well
    // before that; the margin keeps the test stable on slow CI runners.
    let args = vec!["--delay".to_string(), "1500".to_string()];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // 1. Send slow tool call (id: 10)
    let slow_call = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "message": "slow" }
        }
    });
    client_tx
        .write_all(format!("{}\n", slow_call).as_bytes())
        .await
        .unwrap();

    // Small yield to ensure slow call is received by proxy first
    tokio::time::sleep(Duration::from_millis(20)).await;

    // 2. Send keepalive ping (id: 99)
    let ping = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "ping"
    });
    client_tx
        .write_all(format!("{}\n", ping).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    // 3. Read first response - MUST be the ping (id: 99) due to Ping-Bypass!
    let first_line = tokio::time::timeout(Duration::from_millis(1000), framed_out.next())
        .await
        .expect("Ping response should arrive fast via bypass before slow tool call completes")
        .expect("Expected stream line")
        .unwrap();

    let first_val: Value = serde_json::from_str(&first_line).unwrap();
    assert_eq!(
        first_val.get("id").and_then(|i| i.as_i64()),
        Some(99),
        "Ping must overtake slow tool call"
    );

    // 4. Read second response - the slow tool call (id: 10)
    let second_line = tokio::time::timeout(Duration::from_secs(5), framed_out.next())
        .await
        .expect("Timeout waiting for tool call response")
        .expect("Expected stream line")
        .unwrap();

    let second_val: Value = serde_json::from_str(&second_line).unwrap();
    assert_eq!(second_val.get("id").and_then(|i| i.as_i64()), Some(10));

    drop(client_tx);
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_fail_closed_error_responses() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // 1. Send JSON-RPC Batch array -> Fail-Closed (-32600)
    client_tx
        .write_all(b"[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]\n")
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let batch_resp_line = framed_out.next().await.unwrap().unwrap();
    let batch_resp: Value = serde_json::from_str(&batch_resp_line).unwrap();
    assert_eq!(
        batch_resp
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_i64()),
        Some(-32600),
        "Batch request must fail-closed with -32600"
    );

    // 2. Send malformed JSON line -> Fail-Closed (-32700)
    client_tx
        .write_all(b"{\"invalid\": json line without closing\n")
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let parse_err_line = framed_out.next().await.unwrap().unwrap();
    let parse_resp: Value = serde_json::from_str(&parse_err_line).unwrap();
    assert_eq!(
        parse_resp
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_i64()),
        Some(-32700),
        "Malformed JSON line must fail-closed with -32700"
    );

    // 3. Send tools/call without name/valid params -> Fail-Closed (-32602)
    let invalid_tool_call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {}
    });
    client_tx
        .write_all(format!("{}\n", invalid_tool_call).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let invalid_tool_resp_line = framed_out.next().await.unwrap().unwrap();
    let invalid_tool_resp: Value = serde_json::from_str(&invalid_tool_resp_line).unwrap();
    assert_eq!(
        invalid_tool_resp
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_i64()),
        Some(-32602),
        "tools/call without valid params/name must fail-closed with -32602"
    );

    // 4. Confirm proxy continues to process normal requests after errors
    let normal_req = json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" });
    client_tx
        .write_all(format!("{}\n", normal_req).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let normal_resp_line = framed_out.next().await.unwrap().unwrap();
    let normal_resp: Value = serde_json::from_str(&normal_resp_line).unwrap();
    assert_eq!(normal_resp.get("id").and_then(|i| i.as_i64()), Some(5));

    drop(client_tx);
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_max_frame_size_limit_16mb() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(32 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Send an oversized frame (> 16 MB)
    let payload = "A".repeat(16 * 1024 * 1024 + 1024);
    let oversized_msg = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"echo\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"message\":\"{}\"}}}}}}\n", payload);
    client_tx.write_all(oversized_msg.as_bytes()).await.unwrap();
    client_tx.flush().await.unwrap();

    // Expect fail-closed Parse error (-32700)
    let resp_line = framed_out.next().await.unwrap().unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(
        resp.get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_i64()),
        Some(-32700),
        "Oversized frame >16MB must fail-closed with -32700"
    );

    drop(client_tx);
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_ast_dlp_secret_redaction_in_stream() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args = vec!["--leak-secret".to_string()];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Send echo call that mock server will append secret to
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": { "message": "hello" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_line = framed_out.next().await.unwrap().unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();

    let content_text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        content_text.contains("[MCP-MOAT-REDACTED-SECRET]"),
        "Secret must be redacted by AST-DLP"
    );
    assert!(
        !content_text.contains("sk-1234567890abcdef1234567890abcdef"),
        "Raw secret must never leak to client"
    );

    drop(client_tx);
    let _ = proxy_handle.await;

    // Check stderr redaction as well
    let mut err_reader = client_err_rx;
    let mut err_str = String::new();
    let _ = err_reader.read_to_string(&mut err_str).await;
    if !err_str.is_empty() {
        assert!(
            err_str.contains("[MCP-MOAT-REDACTED-SECRET]"),
            "Stderr secret must also be sanitized by DLP"
        );
    }
}

#[tokio::test]
async fn test_operator_approval_and_session_cache() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.require_approval_on_write = true; // Force AskOperator on write_file
    let policy = PolicyEngine::new(config).unwrap();

    // Virtual direct console: operator enters 'a' (AllowAlways) on first prompt
    let console_input = std::io::Cursor::new(b"a\n");
    let console_output = Vec::new();
    let console = mcp_moat_tty::DirectConsole::with_io(console_input, console_output);

    let proxy =
        ProxyServer::with_console(policy, Some(console)).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    let test_file = std::env::temp_dir().join(format!("test_approval_{}.txt", std::process::id()));
    let test_file_str = test_file.to_str().unwrap().replace('\\', "/");

    // 1. First write_file call: triggers operator prompt -> operator types 'a' (AllowAlways)
    let req1 = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": test_file_str,
                "content": "hello world"
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", req1).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp1_line = tokio::time::timeout(Duration::from_secs(3), framed_out.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let resp1: Value = serde_json::from_str(&resp1_line).unwrap();
    assert_eq!(resp1.get("id").and_then(|i| i.as_i64()), Some(1));
    assert!(
        resp1.get("result").is_some(),
        "First write_file should succeed after operator 'a'"
    );

    // 2. Second write_file call: should be auto-approved by session_cache WITHOUT prompting console!
    let req2 = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": test_file_str,
                "content": "second write without prompt"
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", req2).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp2_line = tokio::time::timeout(Duration::from_secs(3), framed_out.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let resp2: Value = serde_json::from_str(&resp2_line).unwrap();
    assert_eq!(resp2.get("id").and_then(|i| i.as_i64()), Some(2));
    assert!(
        resp2.get("result").is_some(),
        "Second write_file must be auto-approved via SessionApprovalCache"
    );

    drop(client_tx);
    let _ = proxy_handle.await;
    let _ = std::fs::remove_file(&test_file);
}

#[tokio::test]
async fn test_no_prompt_denial_reason_is_truthful() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.require_approval_on_write = true;
    let policy = PolicyEngine::new(config).unwrap();

    // `--no-prompt`: no console at all
    let proxy = ProxyServer::with_console(policy, None).with_io(proxy_rx, proxy_tx, proxy_err_tx);
    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": ".env", "content": "X=1" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_line = tokio::time::timeout(Duration::from_secs(10), framed_out.next())
        .await
        .expect("no-prompt denial must not hang")
        .unwrap()
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();

    assert_eq!(resp["result"]["isError"].as_bool(), Some(true));
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("[MCP-MOAT: IMMUTABLE_POLICY_VIOLATION]\nAction blocked: "));
    assert!(
        text.contains(
            "Approval required (protected file or unlisted tool), but --no-prompt is set, so the call was denied"
        ),
        "unexpected reason: {text}"
    );
    assert!(
        !text.contains("rejected by operator in prompt"),
        "must not claim an operator rejected it: {text}"
    );
    assert!(text.contains("INSTRUCTION FOR AGENT:"));

    drop(client_tx);
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_operator_rejection() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.require_approval_on_write = true;
    let policy = PolicyEngine::new(config).unwrap();

    // Virtual direct console: operator types 'n' (deny)
    let console_input = std::io::Cursor::new(b"n\n");
    let console_output = Vec::new();
    let console = mcp_moat_tty::DirectConsole::with_io(console_input, console_output);

    let proxy =
        ProxyServer::with_console(policy, Some(console)).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "test.txt",
                "content": "malicious edit"
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", req).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_line = framed_out.next().await.unwrap().unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();

    assert_eq!(resp.get("id").and_then(|i| i.as_i64()), Some(1));
    assert_eq!(resp["result"]["isError"].as_bool(), Some(true));
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("rejected by operator"),
        "Should contain operator rejection message"
    );

    drop(client_tx);
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_stream_audit_logging_and_tamper_evidence() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let tmp_dir = std::env::temp_dir();
    let audit_file = tmp_dir.join(format!("stream_audit_test_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&audit_file);

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();

    let proxy = ProxyServer::new(policy)
        .with_audit(audit_file.clone(), mcp_moat_core::AuditLevel::Full)
        .with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "audit-test", "version": "1.0" }
        }
    });
    client_tx
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();

    let _init_resp = framed_out.next().await.unwrap().unwrap();

    // 2. Ping
    let ping_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" });
    client_tx
        .write_all(format!("{}\n", ping_req).as_bytes())
        .await
        .unwrap();
    let _ping_resp = framed_out.next().await.unwrap().unwrap();

    // 3. Call echo with secret to verify DLP sanitization in audit preview
    let secret_payload = ["ghp", "123456789012345678901234567890123456"].join("_");
    let echo_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {
                "message": format!("Token: {}", secret_payload)
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", echo_req).as_bytes())
        .await
        .unwrap();
    let _echo_resp = framed_out.next().await.unwrap().unwrap();

    // 4. Close client input to terminate
    drop(client_tx);
    let exit_code = proxy_handle.await.unwrap().unwrap();
    assert_eq!(exit_code, 0);

    // 5. Verify audit log file was written and is cryptographically intact
    assert!(
        audit_file.exists(),
        "Audit log file must be created on disk"
    );
    let content = std::fs::read_to_string(&audit_file).unwrap();
    assert!(!content.trim().is_empty(), "Audit log should have entries");

    // DLP assertion: raw secret token must NOT be present in audit log!
    assert!(
        !content.contains(&secret_payload),
        "Forensic audit log must redact raw secrets via AST-DLP!"
    );

    let reader = std::io::BufReader::new(std::fs::File::open(&audit_file).unwrap());
    let report = mcp_moat_core::verify_audit_log(reader).unwrap();
    assert!(report.is_valid, "Audit log hash chain must verify as valid");
    assert!(
        report.total_records >= 3,
        "Expected at least 3 audit records"
    );

    // 6. Tamper with audit log and verify detection
    let mut tampered_lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    // Tamper with middle event
    tampered_lines[1] = tampered_lines[1].replace("ping", "tampered_call");
    let tampered_log = tampered_lines.join("\n");

    let tampered_report = mcp_moat_core::verify_audit_log(tampered_log.as_bytes()).unwrap();
    assert!(
        !tampered_report.is_valid,
        "Tampered log must be detected as invalid"
    );
    assert_eq!(
        tampered_report.tampered_sequence,
        Some(2),
        "Tamper must point to line 2"
    );

    let _ = std::fs::remove_file(&audit_file);
}

#[tokio::test]
async fn test_stream_monitor_mode_simulated_block_and_bypass() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let tmp_dir = std::env::temp_dir();
    let audit_file = tmp_dir.join(format!("stream_monitor_test_{}.jsonl", std::process::id()));
    let monitor_target = tmp_dir.join(format!("stream_monitor_target_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&audit_file);

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.monitor_mode = true;
    config.read_only = true; // Would normally cause Decision::Block for write_file
    let policy = PolicyEngine::new(config).unwrap();

    let proxy = ProxyServer::new(policy)
        .with_audit(audit_file.clone(), mcp_moat_core::AuditLevel::Full)
        .with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // 1. Send modifying tool call in read-only mode -> Decision::Block
    // In monitor mode, it MUST be forwarded, NOT blocked with tool_error_result!
    let write_req = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": monitor_target.to_str().unwrap(),
                "content": "monitor mode test"
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", write_req).as_bytes())
        .await
        .unwrap();

    let resp_line = framed_out.next().await.unwrap().unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();

    assert_eq!(resp.get("id").and_then(|i| i.as_i64()), Some(100));
    assert_ne!(
        resp.get("result")
            .and_then(|r| r.get("isError"))
            .and_then(|e| e.as_bool()),
        Some(true),
        "Response in monitor mode must not be an error frame"
    );

    // Close client input and wait for proxy to shut down
    drop(client_tx);
    let exit_code = proxy_handle.await.unwrap().unwrap();
    assert_eq!(exit_code, 0);

    // Check that audit log recorded the event as MonitorForwarded
    assert!(audit_file.exists());
    let audit_content = std::fs::read_to_string(&audit_file).unwrap();
    assert!(
        audit_content.contains("MonitorForwarded"),
        "Audit log must contain operator_decision MonitorForwarded: {}",
        audit_content
    );
    assert!(
        audit_content.contains("write_file"),
        "Audit log must record the write_file tool call: {}",
        audit_content
    );

    let _ = std::fs::remove_file(&monitor_target);
    let _ = std::fs::remove_file(&audit_file);
}

#[tokio::test]
async fn test_protocol_edge_cases_id_preservation_and_notifications() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.read_only = true; // Enforce read-only so write_file is blocked
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // 1. Float ID (42.5) on blocked tool call
    let req_float = json!({
        "jsonrpc": "2.0",
        "id": 42.5,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req_float).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_float_line = framed_out.next().await.unwrap().unwrap();
    let resp_float: Value = serde_json::from_str(&resp_float_line).unwrap();
    assert_eq!(
        resp_float["id"],
        json!(42.5),
        "Float ID must be exactly preserved in response"
    );
    assert_eq!(resp_float["result"]["isError"], json!(true));

    // 2. Negative Integer ID (-42) on blocked tool call
    let req_neg = json!({
        "jsonrpc": "2.0",
        "id": -42,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req_neg).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_neg_line = framed_out.next().await.unwrap().unwrap();
    let resp_neg: Value = serde_json::from_str(&resp_neg_line).unwrap();
    assert_eq!(
        resp_neg["id"],
        json!(-42),
        "Negative ID must be exactly preserved in response"
    );

    // 3. String ID ("my-string-id-123") on blocked tool call
    let req_str = json!({
        "jsonrpc": "2.0",
        "id": "my-string-id-123",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req_str).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_str_line = framed_out.next().await.unwrap().unwrap();
    let resp_str: Value = serde_json::from_str(&resp_str_line).unwrap();
    assert_eq!(
        resp_str["id"],
        json!("my-string-id-123"),
        "String ID must be exactly preserved"
    );

    // 4. Large u64 ID (18446744073709551615) on blocked tool call
    let req_u64 = json!({
        "jsonrpc": "2.0",
        "id": 18446744073709551615u64,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req_u64).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_u64_line = framed_out.next().await.unwrap().unwrap();
    let resp_u64: Value = serde_json::from_str(&resp_u64_line).unwrap();
    assert_eq!(
        resp_u64["id"],
        json!(18446744073709551615u64),
        "u64::MAX ID must be exactly preserved"
    );

    // 5. Zero ID (0) on blocked tool call
    let req_zero = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req_zero).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_zero_line = framed_out.next().await.unwrap().unwrap();
    let resp_zero: Value = serde_json::from_str(&resp_zero_line).unwrap();
    assert_eq!(
        resp_zero["id"],
        json!(0),
        "Zero ID must be exactly preserved"
    );

    // 6. Explicit Null ID ("id": null) on blocked tool call
    let req_null = json!({
        "jsonrpc": "2.0",
        "id": null,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", req_null).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_null_line = framed_out.next().await.unwrap().unwrap();
    let resp_null: Value = serde_json::from_str(&resp_null_line).unwrap();
    assert_eq!(
        resp_null["id"],
        Value::Null,
        "Explicit null ID must be preserved as null"
    );

    // 7. Notification (NO "id" field) on blocked tool call:
    // JSON-RPC 2.0 Spec: "The Server MUST NOT reply to a Notification".
    let notif_tool = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "file.txt", "content": "blocked" }
        }
    });
    client_tx
        .write_all(format!("{}\n", notif_tool).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    // Send a normal ping with id: 9999 right after the notification
    let follow_up_ping = json!({
        "jsonrpc": "2.0",
        "id": 9999,
        "method": "ping"
    });
    client_tx
        .write_all(format!("{}\n", follow_up_ping).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    // Next line read MUST be the ping response (id: 9999) - NOT a null response for the notification!
    let next_resp_line = framed_out.next().await.unwrap().unwrap();
    let next_resp: Value = serde_json::from_str(&next_resp_line).unwrap();
    assert_eq!(
        next_resp["id"],
        json!(9999),
        "Notification MUST NOT produce a response; next response must be the follow-up ping"
    );

    // 8. Invalid JSON-RPC Request (valid JSON, but missing "jsonrpc" field) -> -32600 Invalid Request
    let req_no_jsonrpc = json!({
        "id": 88,
        "method": "ping"
    });
    client_tx
        .write_all(format!("{}\n", req_no_jsonrpc).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_invalid_line = framed_out.next().await.unwrap().unwrap();
    let resp_invalid: Value = serde_json::from_str(&resp_invalid_line).unwrap();
    assert_eq!(
        resp_invalid["error"]["code"],
        json!(-32600),
        "Missing jsonrpc field must return -32600 Invalid Request"
    );

    // 9. Non-2.0 jsonrpc version ("1.0") -> -32600 Invalid Request
    let req_bad_ver = json!({
        "jsonrpc": "1.0",
        "id": 89,
        "method": "ping"
    });
    client_tx
        .write_all(format!("{}\n", req_bad_ver).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let resp_bad_ver_line = framed_out.next().await.unwrap().unwrap();
    let resp_bad_ver: Value = serde_json::from_str(&resp_bad_ver_line).unwrap();
    assert_eq!(
        resp_bad_ver["error"]["code"],
        json!(-32600),
        "Wrong jsonrpc version must return -32600 Invalid Request"
    );

    drop(client_tx);
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn test_stream_token_optimization_compact_schemas_hidden_tools_and_output_budget() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let mut config = PolicyConfig::default();
    config.compact_schemas = true;
    config.max_output_bytes = Some(30);
    config.hidden_tools = vec!["write_file".to_string()];
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // 1. Request tools/list -> write_file must be hidden/pruned, only echo remains
    let tools_list_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });
    client_tx
        .write_all(format!("{}\n", tools_list_req).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let list_resp_line = framed_out.next().await.unwrap().unwrap();
    let list_resp: Value = serde_json::from_str(&list_resp_line).unwrap();
    let tools = list_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1, "write_file must be pruned from tools/list");
    assert_eq!(tools[0]["name"].as_str(), Some("echo"));

    // 2. Calling hidden tool write_file directly -> blocked by policy
    let hidden_call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "secret.txt",
                "content": "should fail"
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", hidden_call).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let hidden_resp_line = framed_out.next().await.unwrap().unwrap();
    let hidden_resp: Value = serde_json::from_str(&hidden_resp_line).unwrap();
    assert_eq!(hidden_resp["result"]["isError"].as_bool(), Some(true));
    assert!(
        hidden_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hidden and disabled by policy"),
        "Calling a hidden tool must be blocked"
    );

    // 3. Call echo with output exceeding max_output_bytes (30 bytes) -> truncated with Token Guard banner
    let long_echo = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {
                "message": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_excess_payload"
            }
        }
    });
    client_tx
        .write_all(format!("{}\n", long_echo).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let echo_resp_line = framed_out.next().await.unwrap().unwrap();
    let echo_resp: Value = serde_json::from_str(&echo_resp_line).unwrap();
    let text = echo_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("[MCP-MOAT TOKEN GUARD: truncated"),
        "Output exceeding max_output_bytes must be truncated with Token Guard notice, got: {}",
        text
    );

    drop(client_tx);
    let _ = proxy_handle.await;
}
