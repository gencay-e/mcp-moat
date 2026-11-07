#![allow(clippy::field_reassign_with_default)] // tests tweak single config fields
use mcp_moat_core::{PolicyConfig, PolicyEngine};
use mcp_moat_proxy::sse::{connect_sse, send_http_post, SseProxyServer};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

async fn spawn_mock_sse_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(res) => res,
                Err(_) => break,
            };

            tokio::spawn(async move {
                let (reader, mut writer) = socket.split();
                let mut buf_reader = BufReader::new(reader);

                let mut req_line = String::new();
                if buf_reader.read_line(&mut req_line).await.unwrap_or(0) == 0 {
                    return;
                }

                let mut content_length = 0;
                loop {
                    let mut h = String::new();
                    let n = buf_reader.read_line(&mut h).await.unwrap_or(0);
                    if n == 0 || h == "\r\n" || h == "\n" {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some(val) = h.split(':').nth(1) {
                            content_length = val.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                }

                if req_line.starts_with("GET ") {
                    // Send SSE endpoint and a secret message
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: keep-alive\r\n\r\n";
                    let _ = writer.write_all(resp.as_bytes()).await;
                    let _ = writer.flush().await;

                    let ep =
                        "event: endpoint\r\ndata: /message?sessionId=mock-upstream-sess\r\n\r\n";
                    let _ = writer.write_all(ep.as_bytes()).await;
                    let _ = writer.flush().await;

                    // Event containing Anthropic secret key to test AST-DLP
                    let secret_msg = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/test\",\"params\":{\"key\":\"sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890AA\"}}\r\n\r\n";
                    let _ = writer.write_all(secret_msg.as_bytes()).await;
                    let _ = writer.flush().await;

                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else if req_line.starts_with("POST ") {
                    let mut body = vec![0u8; content_length];
                    let _ = buf_reader.read_exact(&mut body).await;

                    let resp_body = json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": { "status": "upstream_ok" }
                    });
                    let resp_str = serde_json::to_string(&resp_body).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_str.len(), resp_str
                    );
                    let _ = writer.write_all(resp.as_bytes()).await;
                    let _ = writer.flush().await;
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn test_sse_proxy_dlp_and_path_jailing() {
    let mock_addr = spawn_mock_sse_server().await;
    let target_url = format!("http://{}/sse", mock_addr);

    let temp_jail = std::env::temp_dir().join(format!("moat_sse_jail_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_jail);
    // Canonical path without the \\?\ prefix: temp_dir() can contain 8.3 short names
    // (RUNNER~1) on Windows or a symlink (/var -> /private/var) on macOS.
    let temp_jail = {
        let canonical = temp_jail.canonicalize().unwrap();
        let text = canonical.to_string_lossy().to_string();
        std::path::PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
    };
    let allowed_file = temp_jail.join("allowed.txt");
    std::fs::write(&allowed_file, "hello").unwrap();

    let mut policy_config = PolicyConfig::default();
    policy_config.allowed_paths = vec![temp_jail.clone()];
    let policy = PolicyEngine::new(policy_config).unwrap();

    let proxy = SseProxyServer::with_console(policy, None, &target_url).unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = proxy.serve(proxy_listener).await;
    });

    wait_until_listening(proxy_addr).await;

    // 1. Connect to SSE stream and test DLP sanitization
    let mut sse_stream = connect_sse("127.0.0.1", proxy_addr.port(), "/sse")
        .await
        .unwrap();
    let mut line = String::new();
    let mut received_endpoint = false;
    let mut received_sanitized_msg = false;

    for _ in 0..10 {
        line.clear();
        if sse_stream.read_line(&mut line).await.unwrap() == 0 {
            break;
        }
        if line.contains("data: /message?sessionId=moat-") {
            received_endpoint = true;
        }
        if line.contains("[MCP-MOAT-REDACTED-SECRET]") {
            received_sanitized_msg = true;
            break;
        }
    }

    assert!(
        received_endpoint,
        "Proxy must rewrite and forward endpoint event"
    );
    assert!(
        received_sanitized_msg,
        "AST-DLP must sanitize secret in outgoing SSE data line"
    );

    // 2. Test Blocked Tool Call (Path Traversal / Out of Jail)
    let evil_payload = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "../../outside_secret.txt"
            }
        }
    });
    let evil_bytes = serde_json::to_vec(&evil_payload).unwrap();

    let (status, resp_bytes) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=moat-test",
        &evil_bytes,
    )
    .await
    .unwrap();

    assert_eq!(status, 200);
    let resp_val: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert!(
        resp_val.get("error").is_some(),
        "Path traversal out of jail must be blocked with JSON-RPC error"
    );
    let err_msg = resp_val["error"]["message"].as_str().unwrap();
    assert!(err_msg.contains("Security Policy Violation"));

    // 3. Test Allowed Tool Call (Inside Sandbox Root)
    let good_payload = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": allowed_file.to_str().unwrap()
            }
        }
    });
    let good_bytes = serde_json::to_vec(&good_payload).unwrap();

    let (good_status, good_resp) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=moat-test",
        &good_bytes,
    )
    .await
    .unwrap();

    assert_eq!(good_status, 200);
    let good_val: serde_json::Value = serde_json::from_slice(&good_resp).unwrap();
    assert_eq!(
        good_val["result"]["status"], "upstream_ok",
        "Allowed tool call must be forwarded upstream and result returned"
    );

    // 4. Test Batch Array Rejection (Fail-closed)
    let batch_payload = json!([
        {
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": allowed_file.to_str().unwrap() }
            }
        }
    ]);
    let batch_bytes = serde_json::to_vec(&batch_payload).unwrap();
    let (batch_status, batch_resp) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=moat-test",
        &batch_bytes,
    )
    .await
    .unwrap();
    assert_eq!(
        batch_status, 400,
        "Batch requests must be rejected with 400 Bad Request"
    );
    let batch_val: serde_json::Value = serde_json::from_slice(&batch_resp).unwrap();
    assert_eq!(batch_val["error"]["code"], -32600);

    // 5. Test resources/subscribe Out-of-Jail Check
    let sub_payload = json!({
        "jsonrpc": "2.0",
        "id": 301,
        "method": "resources/subscribe",
        "params": {
            "uri": "file:///C:/Windows/System32/drivers/etc/hosts"
        }
    });
    let sub_bytes = serde_json::to_vec(&sub_payload).unwrap();
    let (sub_status, sub_resp) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=moat-test",
        &sub_bytes,
    )
    .await
    .unwrap();
    assert_eq!(sub_status, 200);
    let sub_val: serde_json::Value = serde_json::from_slice(&sub_resp).unwrap();
    assert!(sub_val["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Security Policy Violation"));

    let _ = std::fs::remove_dir_all(&temp_jail);
}

#[tokio::test]
async fn test_parsed_url_ipv6_and_validation() {
    use mcp_moat_proxy::sse::ParsedUrl;

    // IPv4 standard
    let u1 = ParsedUrl::parse("http://127.0.0.1:8765/sse").unwrap();
    assert_eq!(u1.host, "127.0.0.1");
    assert_eq!(u1.port, 8765);
    assert_eq!(u1.path_and_query, "/sse");

    // IPv6 bracketed
    let u2 = ParsedUrl::parse("http://[::1]:9000/messages?session=123").unwrap();
    assert_eq!(u2.host, "::1");
    assert_eq!(u2.port, 9000);
    assert_eq!(u2.path_and_query, "/messages?session=123");

    // Default port 80
    let u3 = ParsedUrl::parse("http://example.com/sse").unwrap();
    assert_eq!(u3.host, "example.com");
    assert_eq!(u3.port, 80);

    // Invalid URLs fail closed
    assert!(ParsedUrl::parse("").is_err());
    assert!(ParsedUrl::parse("http:///path").is_err());
    assert!(ParsedUrl::parse("http://[::1:8000/sse").is_err());
}

#[tokio::test]
async fn test_sse_proxy_protocol_edge_cases() {
    let mock_upstream = spawn_mock_sse_server().await;

    let temp_jail = std::env::temp_dir().join(format!("sse_proto_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_jail);

    let mut config = PolicyConfig::default();
    config.allowed_paths = vec![temp_jail.clone()];
    config.read_only = true; // Read-only policy
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

    // 1. Send request with missing jsonrpc field -> -32600 Invalid Request
    let req_no_jsonrpc = json!({
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "test.txt" }
        }
    });
    let (status, resp_bytes) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=test",
        &serde_json::to_vec(&req_no_jsonrpc).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(status, 200);
    let val: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(
        val["error"]["code"],
        json!(-32600),
        "Missing jsonrpc must return -32600"
    );

    // 2. Send request with bad jsonrpc version ("1.0") -> -32600 Invalid Request
    let req_bad_ver = json!({
        "jsonrpc": "1.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "test.txt" }
        }
    });
    let (status, resp_bytes) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=test",
        &serde_json::to_vec(&req_bad_ver).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(status, 200);
    let val: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(
        val["error"]["code"],
        json!(-32600),
        "Wrong jsonrpc version must return -32600"
    );

    // 3. Send Notification (missing id) for blocked tool call -> MUST return 204 No Content
    let notif_blocked = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": { "path": "test.txt", "content": "blocked" }
        }
    });
    let (status, resp_bytes) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=test",
        &serde_json::to_vec(&notif_blocked).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(
        status, 204,
        "Notification MUST return 204 No Content and no response body"
    );
    assert!(
        resp_bytes.is_empty(),
        "Notification response body must be empty"
    );

    let _ = std::fs::remove_dir_all(&temp_jail);
}

#[tokio::test]
async fn test_sse_proxy_inbound_audit_dlp_and_operator_decision() {
    let mock_addr = spawn_mock_sse_server().await;
    let target_url = format!("http://{}/sse", mock_addr);

    let temp_jail =
        std::env::temp_dir().join(format!("moat_sse_audit_jail_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_jail);
    let audit_file = temp_jail.join("sse_audit.jsonl");

    let mut policy_config = PolicyConfig::default();
    policy_config.allowed_paths = vec![temp_jail.clone()];
    policy_config.audit_log = Some(audit_file.clone());
    policy_config.audit_level = mcp_moat_core::audit::AuditLevel::Full;
    let policy = PolicyEngine::new(policy_config).unwrap();

    // SseProxy with None console (will auto-reject AskOperator calls)
    let proxy = SseProxyServer::with_console(policy, None, &target_url).unwrap();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = proxy.serve(proxy_listener).await;
    });

    wait_until_listening(proxy_addr).await;

    // Send a tool call containing a sensitive OpenAI key in arguments
    let sensitive_req = json!({
        "jsonrpc": "2.0",
        "id": 50,
        "method": "tools/call",
        "params": {
            "name": "login",
            "arguments": {
                "password": "SuperSecretPassword12345",
                "api_key": "sk-1234567890abcdef1234567890abcdef"
            }
        }
    });
    let req_bytes = serde_json::to_vec(&sensitive_req).unwrap();

    let (status, _) = send_http_post(
        "127.0.0.1",
        proxy_addr.port(),
        "/message?sessionId=test",
        &req_bytes,
    )
    .await
    .unwrap();

    assert_eq!(status, 200);

    // Read generated audit log file
    wait_until_listening(proxy_addr).await;
    assert!(audit_file.exists(), "Audit log must be created");
    let log_content = std::fs::read_to_string(&audit_file).unwrap();

    // Ensure raw secrets are NEVER leaked in audit log
    assert!(
        !log_content.contains("sk-1234567890abcdef1234567890abcdef"),
        "Raw API key must NOT appear in audit log!"
    );
    assert!(
        !log_content.contains("SuperSecretPassword12345"),
        "Raw password must NOT appear in audit log!"
    );
    assert!(
        log_content.contains("[MCP-MOAT-REDACTED-SECRET]"),
        "Sanitized secret marker must appear in audit log"
    );

    let _ = std::fs::remove_dir_all(&temp_jail);
}

// ---------------------------------------------------------------------------
// Endpoint rewriting (B3), https (B4), Host/Origin checks
// ---------------------------------------------------------------------------

use mcp_moat_proxy::sse::{check_request_headers, resolve_endpoint, ParsedUrl};

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

/// Upstream that answers every GET with `event_bytes` (raw SSE bytes).
/// `{ADDR}` in `event_bytes` is replaced with the mock's own address.
async fn spawn_raw_event_upstream(event_bytes: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let events = event_bytes.replace("{ADDR}", &addr.to_string());
            tokio::spawn(async move {
                let (reader, mut writer) = socket.split();
                let mut buf_reader = BufReader::new(reader);
                loop {
                    let mut h = String::new();
                    let n = buf_reader.read_line(&mut h).await.unwrap_or(0);
                    if n == 0 || h == "\r\n" || h == "\n" {
                        break;
                    }
                }
                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
                let _ = writer.write_all(head.as_bytes()).await;
                let _ = writer.write_all(events.as_bytes()).await;
                let _ = writer.flush().await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
        }
    });
    addr
}

async fn spawn_proxy_for(upstream: SocketAddr) -> SocketAddr {
    let policy = PolicyEngine::new(PolicyConfig::default()).unwrap();
    let proxy =
        SseProxyServer::with_console(policy, None, &format!("http://{}/sse", upstream)).unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = proxy.serve(proxy_listener).await;
    });
    wait_until_listening(proxy_addr).await;
    proxy_addr
}

/// Reads the whole proxied stream (until EOF or timeout) as text.
async fn read_proxied_stream(proxy_addr: SocketAddr) -> String {
    let mut stream = connect_sse("127.0.0.1", proxy_addr.port(), "/sse")
        .await
        .unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut line = String::new();
            match stream.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => out.push_str(&line),
            }
        }
    })
    .await;
    out
}

#[tokio::test]
async fn test_sse_proxy_rewrites_absolute_endpoint_url() {
    let upstream = spawn_raw_event_upstream(
        "event: endpoint\r\ndata: http://{ADDR}/messages?session_id=abc123\r\n\r\n",
    )
    .await;
    let proxy_addr = spawn_proxy_for(upstream).await;
    let text = read_proxied_stream(proxy_addr).await;
    assert!(
        text.contains("data: /message?sessionId=moat-"),
        "endpoint must be rewritten to a proxy URL, got: {text}"
    );
    assert!(
        !text.contains("abc123"),
        "upstream session id leaked: {text}"
    );
    assert!(
        !text.contains(&upstream.to_string()),
        "upstream address leaked: {text}"
    );
}

#[tokio::test]
async fn test_sse_proxy_rewrites_endpoint_with_other_parameter_name() {
    let upstream =
        spawn_raw_event_upstream("event: endpoint\r\ndata: /messages/?session_id=abc123\r\n\r\n")
            .await;
    let proxy_addr = spawn_proxy_for(upstream).await;
    let text = read_proxied_stream(proxy_addr).await;
    assert!(
        text.contains("data: /message?sessionId=moat-"),
        "got: {text}"
    );
    assert!(
        !text.contains("abc123"),
        "upstream session id leaked: {text}"
    );
}

#[tokio::test]
async fn test_sse_proxy_rewrites_endpoint_without_space_after_colon() {
    let upstream =
        spawn_raw_event_upstream("event:endpoint\r\ndata:http://{ADDR}/m?s=1\r\n\r\n").await;
    let proxy_addr = spawn_proxy_for(upstream).await;
    let text = read_proxied_stream(proxy_addr).await;
    assert!(
        text.contains("data: /message?sessionId=moat-"),
        "got: {text}"
    );
    assert!(!text.contains("/m?s=1"), "upstream endpoint leaked: {text}");
}

#[tokio::test]
async fn test_sse_proxy_closes_stream_for_endpoint_on_other_host() {
    let upstream = spawn_raw_event_upstream(
        "event: endpoint\r\ndata: http://evil.example:80/steal\r\n\r\n\
         event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"x\"}\r\n\r\n",
    )
    .await;
    let proxy_addr = spawn_proxy_for(upstream).await;
    let text = read_proxied_stream(proxy_addr).await;
    assert!(
        !text.contains("evil.example"),
        "foreign endpoint reached the client: {text}"
    );
    assert!(
        !text.contains("notifications"),
        "stream must be closed: {text}"
    );
    assert!(
        !text.contains("\"method\":\"x\""),
        "stream must be closed: {text}"
    );
}

#[tokio::test]
async fn test_sse_proxy_sanitizes_data_lines_without_space() {
    let upstream = spawn_raw_event_upstream(
        "event: endpoint\r\ndata: /message?sessionId=u\r\n\r\n\
         event: message\r\ndata:{\"k\":\"sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890AA\"}\r\n\r\n",
    )
    .await;
    let proxy_addr = spawn_proxy_for(upstream).await;
    let text = read_proxied_stream(proxy_addr).await;
    assert!(text.contains("[MCP-MOAT-REDACTED-SECRET]"), "got: {text}");
    assert!(!text.contains("sk-ant-api03"), "secret leaked: {text}");
}

#[test]
fn test_resolve_endpoint_rules() {
    let target = ParsedUrl::parse("http://127.0.0.1:8000/sse").unwrap();
    assert_eq!(
        resolve_endpoint("/messages?x=1", &target).unwrap(),
        "/messages?x=1"
    );
    assert_eq!(
        resolve_endpoint("http://127.0.0.1:8000/messages?x=1", &target).unwrap(),
        "/messages?x=1"
    );
    assert!(resolve_endpoint("http://127.0.0.1:9999/messages", &target).is_err());
    assert!(resolve_endpoint("http://other.example:8000/messages", &target).is_err());
    assert!(resolve_endpoint("//other.example/messages", &target).is_err());
    assert!(resolve_endpoint("https://127.0.0.1:8000/messages", &target).is_err());
    assert!(resolve_endpoint("javascript:alert(1)", &target).is_err());
    assert!(resolve_endpoint("", &target).is_err());
}

#[test]
fn test_https_urls_are_rejected() {
    assert!(ParsedUrl::parse("https://example.com/sse").is_err());
    assert!(ParsedUrl::parse("HTTPS://example.com/sse").is_err());
    assert!(ParsedUrl::parse("ftp://example.com/sse").is_err());
    assert!(ParsedUrl::parse("http://example.com/sse").is_ok());
    let policy = PolicyEngine::new(PolicyConfig::default()).unwrap();
    assert!(SseProxyServer::with_console(policy, None, "https://example.com/sse").is_err());
}

#[test]
fn test_check_request_headers_rules() {
    assert!(check_request_headers(Some("127.0.0.1:8765"), None, true).is_ok());
    assert!(check_request_headers(Some("localhost:8765"), None, true).is_ok());
    assert!(check_request_headers(Some("[::1]:8765"), None, true).is_ok());
    assert!(check_request_headers(Some("evil.example:8765"), None, true).is_err());
    assert!(check_request_headers(None, None, true).is_err());
    assert!(
        check_request_headers(Some("127.0.0.1:8765"), Some("http://evil.example"), true).is_err()
    );
    // Not bound to loopback: the Host header is not checked, Origin still is.
    assert!(check_request_headers(Some("proxy.internal"), None, false).is_ok());
    assert!(check_request_headers(Some("proxy.internal"), Some("http://x"), false).is_err());
}

async fn raw_request(proxy_addr: SocketAddr, request: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn test_sse_proxy_rejects_browser_origin_and_foreign_host() {
    let upstream =
        spawn_raw_event_upstream("event: endpoint\r\ndata: /m?sessionId=1\r\n\r\n").await;
    let proxy_addr = spawn_proxy_for(upstream).await;
    let port = proxy_addr.port();

    let with_origin = raw_request(
        proxy_addr,
        &format!(
            "GET /sse HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\n\r\n"
        ),
    )
    .await;
    assert!(
        with_origin.starts_with("HTTP/1.1 403"),
        "got: {with_origin}"
    );
    assert!(
        !with_origin.to_ascii_lowercase().contains("access-control"),
        "got: {with_origin}"
    );

    let foreign_host = raw_request(
        proxy_addr,
        "GET /sse HTTP/1.1\r\nHost: rebind.example\r\n\r\n",
    )
    .await;
    assert!(
        foreign_host.starts_with("HTTP/1.1 403"),
        "got: {foreign_host}"
    );

    let preflight = raw_request(
        proxy_addr,
        &format!("OPTIONS /message HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    )
    .await;
    assert!(preflight.starts_with("HTTP/1.1 405"), "got: {preflight}");
    assert!(
        !preflight.to_ascii_lowercase().contains("access-control"),
        "got: {preflight}"
    );

    let post = raw_request(
        proxy_addr,
        &format!(
            "POST /message?sessionId=x HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\nContent-Length: 2\r\n\r\n{{}}"
        ),
    )
    .await;
    assert!(post.starts_with("HTTP/1.1 403"), "got: {post}");
}
