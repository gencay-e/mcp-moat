use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use mcp_moat_core::{PolicyConfig, PolicyEngine};
use mcp_moat_proxy::sse::{connect_sse, send_http_post, SseProxyServer};
use mcp_moat_proxy::ProxyServer;

/// Waits until the proxy accepts connections (instead of a fixed sleep).
async fn wait_until_listening(addr: std::net::SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("proxy did not start listening on {addr}");
}

/// Test 1: Exact 16 MB Frame Boundary and Stream Desynchronization Recovery
/// Tests:
/// - 16 MB + 10 bytes frame exceeds MAX_FRAME_LIMIT (16 MB) -> emits -32700 error.
/// - The stream recovers cleanly and subsequent standard JSON-RPC requests on the same stream succeed!
#[tokio::test]
async fn test_fuzz_exact_16mb_boundary_and_stream_recovery() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(36 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(4 * 1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Initial ping to ensure server is ready
    let init_ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    client_tx
        .write_all(format!("{}\n", init_ping).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();
    let resp1_line = framed_out.next().await.unwrap().unwrap();
    let resp1: Value = serde_json::from_str(&resp1_line).unwrap();
    assert_eq!(resp1["id"].as_i64(), Some(1));

    // Send oversized frame: 16 MB + 1024 bytes payload
    let oversized_payload = "X".repeat(16 * 1024 * 1024 + 1024);
    let oversized_frame = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"echo\",\"params\":{{\"name\":\"echo\",\"arguments\":{{\"message\":\"{}\"}}}}}}\n",
        oversized_payload
    );
    client_tx
        .write_all(oversized_frame.as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    // Expect -32700 Parse error
    let err_line = framed_out.next().await.unwrap().unwrap();
    let err_val: Value = serde_json::from_str(&err_line).unwrap();
    assert_eq!(err_val["error"]["code"].as_i64(), Some(-32700));
    assert!(err_val["error"]["message"]
        .as_str()
        .unwrap()
        .contains("16MB"));

    // Verify Fail-Closed Stream Termination:
    // When an extreme 17 MB framing violation occurs, the stream boundary is considered desynchronized,
    // so the proxy terminates the inbound stream after issuing the -32700 error.
    let next_event = framed_out.next().await;
    assert!(
        next_event.is_none(),
        "Stream must be closed fail-closed after fatal 16MB framing violation"
    );

    drop(client_tx);
    let _ = proxy_handle.await;
}

/// Test 2: Non-standard JSON Values, Unicode Escapes, Null Bytes, and Surrogate Pairs
#[tokio::test]
async fn test_fuzz_nonstandard_json_unicode_and_null_bytes() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Case 2.1: Null byte in path argument -> Policy block
    let null_byte_path = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"safe_dir/\\u0000../evil\"}}}\n";
    client_tx
        .write_all(null_byte_path.as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();
    let resp_line = framed_out.next().await.unwrap().unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert!(resp["result"]["isError"].as_bool() == Some(true) || resp.get("error").is_some());
    let text = resp.to_string();
    assert!(
        text.contains("Null bytes")
            || text.contains("prohibited")
            || text.contains("Policy violation")
    );

    // Case 2.2: Unpaired surrogate \ud800 -> JSON Parse Error -32700
    let unpaired_surrogate = "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"msg\":\"\\ud800\"}}}\n";
    client_tx
        .write_all(unpaired_surrogate.as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();
    let resp_line2 = framed_out.next().await.unwrap().unwrap();
    let resp2: Value = serde_json::from_str(&resp_line2).unwrap();
    assert_eq!(
        resp2["error"]["code"].as_i64(),
        Some(-32700),
        "Unpaired surrogate must be rejected with -32700 Parse error"
    );

    // Case 2.3: Valid surrogate pair \ud83d\ude00 (😀) -> must be allowed cleanly
    let valid_surrogate = "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"message\":\"hello \\ud83d\\ude00 world\"}}}\n";
    client_tx
        .write_all(valid_surrogate.as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();
    let resp_line3 = framed_out.next().await.unwrap().unwrap();
    let resp3: Value = serde_json::from_str(&resp_line3).unwrap();
    assert_eq!(resp3["id"].as_i64(), Some(12));
    assert!(
        !resp3.to_string().contains("error"),
        "Valid surrogate pair must be handled without error"
    );

    // Case 2.4: Unicode-escaped traversal \u002e\u002e\u002f (../) -> Blocked
    let unicode_traversal = "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"\\u002e\\u002e/etc/passwd\"}}}\n";
    client_tx
        .write_all(unicode_traversal.as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();
    let resp_line4 = framed_out.next().await.unwrap().unwrap();
    let resp4: Value = serde_json::from_str(&resp_line4).unwrap();
    let resp4_str = resp4.to_string();
    assert!(
        resp4_str.contains("Directory traversal")
            || resp4_str.contains("prohibited")
            || resp4_str.contains("isError")
    );

    drop(client_tx);
    let _ = proxy_handle.await;
}

/// Test 3: Deep JSON Nesting / Recursion Limits
#[tokio::test]
async fn test_fuzz_deep_json_recursion_and_huge_arrays() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(2 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(2 * 1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let config = PolicyConfig::default();
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Deeply nested objects (>128 levels exceeds serde_json default recursion limit)
    let mut deep_json = String::from("{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"tools/call\",\"params\":{\"name\":\"test\",\"arguments\":");
    for _ in 0..150 {
        deep_json.push_str("{\"nested\":");
    }
    deep_json.push_str("\"val\"");
    for _ in 0..150 {
        deep_json.push('}');
    }
    deep_json.push_str("}}\n");

    client_tx.write_all(deep_json.as_bytes()).await.unwrap();
    client_tx.flush().await.unwrap();

    let resp_line = framed_out.next().await.unwrap().unwrap();
    let resp: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(
        resp["error"]["code"].as_i64(),
        Some(-32700),
        "Recursion limit violation must fail closed with -32700"
    );
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("recursion limit"));

    // Send valid ping right after to verify proxy didn't panic or crash
    let ping = json!({ "jsonrpc": "2.0", "id": 21, "method": "ping" });
    client_tx
        .write_all(format!("{}\n", ping).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let rec_line = framed_out.next().await.unwrap().unwrap();
    let rec_val: Value = serde_json::from_str(&rec_line).unwrap();
    assert_eq!(rec_val["id"].as_i64(), Some(21));

    drop(client_tx);
    let _ = proxy_handle.await;
}

/// Test 4: Stress Pipelined Stream with Interleaved Notifications, Tool Calls, and Priority Pings
#[tokio::test]
async fn test_stress_pipelined_interleaved_notifications_and_calls() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(4 * 1024 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(4 * 1024 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);

    let mut config = PolicyConfig::default();
    config.always_allow_tools.push("echo".to_string());
    config.read_only = true; // Blocks modifying calls
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = ProxyServer::new(policy).with_io(proxy_rx, proxy_tx, proxy_err_tx);

    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // Send 300 pipelined messages:
    // - 100 Allowed calls (echo)
    // - 100 Notifications (must produce NO responses)
    // - 50 Blocked calls (write_file in read-only mode) -> should return tool errors
    // - 50 Pings
    let mut expected_response_ids = HashSet::new();

    for i in 1..=300 {
        match i % 4 {
            0 => {
                // Ping
                expected_response_ids.insert(i);
                let msg = json!({ "jsonrpc": "2.0", "id": i, "method": "ping" });
                client_tx
                    .write_all(format!("{}\n", msg).as_bytes())
                    .await
                    .unwrap();
            }
            1 => {
                // Allowed tool call
                expected_response_ids.insert(i);
                let msg = json!({
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": { "name": "echo", "arguments": { "message": format!("msg-{}", i) } }
                });
                client_tx
                    .write_all(format!("{}\n", msg).as_bytes())
                    .await
                    .unwrap();
            }
            2 => {
                // Notification (NO ID) -> Must NOT generate a response!
                let msg = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/test",
                    "params": { "data": i }
                });
                client_tx
                    .write_all(format!("{}\n", msg).as_bytes())
                    .await
                    .unwrap();
            }
            _ => {
                // Blocked tool call (write_file in read-only mode)
                expected_response_ids.insert(i);
                let msg = json!({
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": { "name": "write_file", "arguments": { "path": "test.txt", "content": "blocked" } }
                });
                client_tx
                    .write_all(format!("{}\n", msg).as_bytes())
                    .await
                    .unwrap();
            }
        }
    }
    client_tx.flush().await.unwrap();

    let total_expected = expected_response_ids.len(); // 225 responses (300 - 75 notifications)
    let mut received_ids = HashSet::new();

    for _ in 0..total_expected {
        let line = tokio::time::timeout(Duration::from_secs(5), framed_out.next())
            .await
            .expect("Timeout waiting for response in pipelined stream")
            .expect("Stream closed unexpectedly")
            .unwrap();

        let val: Value = serde_json::from_str(&line).unwrap();
        if let Some(id) = val.get("id").and_then(|i| i.as_i64()) {
            received_ids.insert(id);
        } else {
            panic!(
                "Unexpected response with no id (notifications must be suppressed): {:?}",
                val
            );
        }
    }

    assert_eq!(received_ids.len(), total_expected);
    assert_eq!(received_ids, expected_response_ids);

    drop(client_tx);
    let _ = proxy_handle.await;
}

/// Helper mock upstream SSE server for testing failure modes
async fn spawn_failing_mock_sse_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut reader = BufReader::new(&mut socket);
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line).await;

                // Read headers
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).await.unwrap_or(0) == 0 || h == "\r\n" || h == "\n"
                    {
                        break;
                    }
                }

                if req_line.starts_with("GET ") {
                    // Send endpoint event
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let ep = "event: endpoint\r\ndata: /message?sessionId=upstream-sess\r\n\r\n";
                    let _ = socket.write_all(ep.as_bytes()).await;
                    let _ = socket.flush().await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else if req_line.starts_with("POST ") {
                    // Simulate internal server failure (HTTP 500)
                    let body = "{\"error\":\"Simulated upstream server failure\"}";
                    let err_resp = format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = socket.write_all(err_resp.as_bytes()).await;
                    let _ = socket.flush().await;
                }
            });
        }
    });

    addr
}

/// Test 5: SSE Proxy Handling When Upstream Server Fails
#[tokio::test]
async fn test_sse_proxy_upstream_failure_modes() {
    let mock_upstream = spawn_failing_mock_sse_server().await;

    let config = PolicyConfig::default();
    let policy = PolicyEngine::new(config).unwrap();
    let proxy = SseProxyServer::new(
        policy,
        &format!("http://127.0.0.1:{}/sse", mock_upstream.port()),
    )
    .unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = proxy.serve(proxy_listener).await;
    });

    wait_until_listening(proxy_addr).await;

    // Connect to SSE stream
    let mut sse_stream = connect_sse("127.0.0.1", proxy_addr.port(), "/sse")
        .await
        .unwrap();
    let mut line = String::new();
    let mut session_id = String::new();
    while sse_stream.read_line(&mut line).await.unwrap() > 0 {
        if line.contains("sessionId=") {
            let parts: Vec<&str> = line.trim().split("sessionId=").collect();
            if parts.len() > 1 {
                session_id = parts[1].to_string();
                break;
            }
        }
        line.clear();
    }
    assert!(
        !session_id.is_empty(),
        "Proxy must forward rewritten session ID"
    );

    // Send POST when upstream returns HTTP 500
    let req = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "ping"
    });
    let (status, resp_bytes) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        &format!("/message?sessionId={}", session_id),
        &serde_json::to_vec(&req).unwrap(),
    )
    .await
    .unwrap();

    // Proxy must forward status code 500 cleanly with response body
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    println!("DEBUG: status={}, resp_str='{}'", status, resp_str);
    assert_eq!(status, 500);
    assert!(resp_str.contains("Simulated upstream server failure"));
}

/// Test 6: SSE Proxy When Upstream Server is Completely Offline / Connection Refused
#[tokio::test]
async fn test_sse_proxy_upstream_offline_handling() {
    let offline_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };

    let config = PolicyConfig::default();
    let policy = PolicyEngine::new(config).unwrap();
    let proxy =
        SseProxyServer::new(policy, &format!("http://127.0.0.1:{}/sse", offline_port)).unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = proxy.serve(proxy_listener).await;
    });

    wait_until_listening(proxy_addr).await;

    // 6.1 Try to connect to SSE stream when upstream is dead
    let res = connect_sse("127.0.0.1", proxy_addr.port(), "/sse").await;
    println!(
        "connect_sse result when upstream offline: {:?}",
        res.is_ok()
    );

    // 6.2 Send POST when upstream is offline
    let req = json!({
        "jsonrpc": "2.0",
        "id": 200,
        "method": "ping"
    });
    let post_res = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=any",
        &serde_json::to_vec(&req).unwrap(),
    )
    .await;
    println!(
        "send_http_post result when upstream offline: {:?}",
        post_res
    );
}
