//! Method allowlist and audit-failure behavior through the proxy, with the mock server behind it.
#![allow(clippy::field_reassign_with_default)] // tests tweak single config fields
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use mcp_moat_core::{AuditLevel, PolicyConfig, PolicyEngine};
use mcp_moat_proxy::ProxyServer;

/// Sends `lines`, then collects replies until `expected` arrived or 3 seconds passed.
async fn session(
    config: PolicyConfig,
    audit: Option<PathBuf>,
    lines: Vec<Value>,
    expected: usize,
) -> Vec<Value> {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let policy = PolicyEngine::new(config).unwrap();
    let mut proxy =
        ProxyServer::with_console(policy, None).with_io(proxy_rx, proxy_tx, proxy_err_tx);
    if let Some(path) = audit {
        proxy = proxy.with_audit(path, AuditLevel::Full);
    }
    let handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &[]).await });

    for line in &lines {
        client_tx
            .write_all(format!("{}\n", line).as_bytes())
            .await
            .unwrap();
    }
    client_tx.flush().await.unwrap();

    let mut framed = FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));
    let mut out = Vec::new();
    while out.len() < expected {
        match tokio::time::timeout(Duration::from_secs(3), framed.next()).await {
            Ok(Some(Ok(line))) => out.push(serde_json::from_str::<Value>(&line).unwrap()),
            _ => break,
        }
    }
    drop(client_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    out
}

fn by_id(replies: &[Value], id: i64) -> &Value {
    replies
        .iter()
        .find(|r| r["id"] == json!(id))
        .unwrap_or_else(|| panic!("no reply with id {id}: {replies:?}"))
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("moat-{}-{}", name, std::process::id()))
}

#[tokio::test]
async fn unknown_method_is_refused_and_not_forwarded() {
    let replies = session(
        PolicyConfig::default(),
        None,
        vec![
            json!({"jsonrpc": "2.0", "id": 77, "method": "x/delete_all"}),
            // a notification with an unknown method is dropped without any reply
            json!({"jsonrpc": "2.0", "method": "x/delete_all"}),
            json!({"jsonrpc": "2.0", "id": 78, "method": "tools/list"}),
        ],
        2,
    )
    .await;
    assert_eq!(replies.len(), 2, "{replies:?}");
    let refused = by_id(&replies, 77);
    assert_eq!(refused["error"]["code"], json!(-32601));
    assert_eq!(
        refused["error"]["message"],
        json!("Method 'x/delete_all' is not allowed by mcp-moat policy")
    );
    // the server would answer "Method not found: ..." if it had seen the request
    assert!(by_id(&replies, 78)["result"].is_object());
}

#[tokio::test]
async fn unknown_method_name_is_sanitized_in_the_error() {
    let replies = session(
        PolicyConfig::default(),
        None,
        vec![json!({"jsonrpc": "2.0", "id": 1, "method": "x/\n\u{1b}[2Jevil"})],
        1,
    )
    .await;
    let msg = replies[0]["error"]["message"].as_str().unwrap();
    assert!(!msg.contains('\n') && !msg.contains('\u{1b}'), "{msg:?}");
}

#[tokio::test]
async fn unknown_notification_is_audited_as_blocked() {
    let audit = temp("methods-audit.jsonl");
    let _ = std::fs::remove_file(&audit);
    let replies = session(
        PolicyConfig::default(),
        Some(audit.clone()),
        vec![
            json!({"jsonrpc": "2.0", "method": "x/delete_all"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        ],
        1,
    )
    .await;
    assert_eq!(replies.len(), 1, "{replies:?}");
    let log = std::fs::read_to_string(&audit).unwrap();
    let _ = std::fs::remove_file(&audit);
    let line = log
        .lines()
        .find(|l| l.contains("x/delete_all"))
        .expect("the refused notification is audited");
    assert!(line.contains("Block") || line.contains("block"), "{line}");
}

#[tokio::test]
async fn allowed_methods_are_forwarded() {
    let mut config = PolicyConfig::default();
    config.allowed_methods.push("x/delete_all".to_string());
    let replies = session(
        config,
        None,
        vec![json!({"jsonrpc": "2.0", "id": 5, "method": "x/delete_all"})],
        1,
    )
    .await;
    // the answer comes from the mock server, not from the proxy
    let msg = by_id(&replies, 5)["error"]["message"].as_str().unwrap();
    assert_eq!(msg, "Method not found: x/delete_all");
}

#[tokio::test]
async fn standard_methods_and_responses_are_unaffected() {
    let mut lines = vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
    ];
    let others = [
        "resources/list",
        "resources/templates/list",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
    ];
    for (i, m) in others.iter().enumerate() {
        lines.push(json!({"jsonrpc": "2.0", "id": 10 + i, "method": m}));
    }
    // a reply to a server request (no method) is passed on; the mock answers it as unknown
    lines.push(json!({"jsonrpc": "2.0", "id": 99, "result": {"roots": []}}));
    let expected = 3 + others.len() + 1;
    let replies = session(PolicyConfig::default(), None, lines, expected).await;
    assert_eq!(replies.len(), expected, "{replies:?}");
    for (i, m) in others.iter().enumerate() {
        let msg = by_id(&replies, 10 + i as i64)["error"]["message"]
            .as_str()
            .unwrap_or("");
        assert!(
            !msg.contains("mcp-moat policy"),
            "{m} must reach the server: {msg}"
        );
    }
    assert!(by_id(&replies, 99)["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("Method not found"));
}

/// The audit destination is a directory, so every write fails: nothing is forwarded and each
/// request with an id gets an error with its id.
#[tokio::test]
async fn audit_failure_answers_requests_instead_of_dropping_them() {
    let jail = temp("audit-fail-jail");
    std::fs::create_dir_all(&jail).unwrap();
    let jail = jail.canonicalize().unwrap();
    let witness = jail.join("witness.txt");
    let _ = std::fs::remove_file(&witness);
    let bad_audit = temp("audit-fail-dir");
    std::fs::create_dir_all(&bad_audit).unwrap();

    let mut config = PolicyConfig::default();
    config.allowed_paths = vec![jail.clone()];
    config.always_allow_tools.push("echo".to_string());
    let replies = session(
        config,
        Some(bad_audit.clone()),
        vec![
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"path": witness, "content": "x"}}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": 4, "method": "resources/read",
                "params": {"uri": format!("file://{}", jail.join("a.txt").display())}}),
            // notifications get no reply
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ],
        4,
    )
    .await;
    let _ = std::fs::remove_dir_all(&bad_audit);
    let wrote = witness.exists();
    let _ = std::fs::remove_dir_all(&jail);

    assert!(!wrote, "the server must not see the tools/call");
    assert_eq!(replies.len(), 4, "{replies:?}");
    for id in 1..=4 {
        let r = by_id(&replies, id);
        assert_eq!(r["error"]["code"], json!(-32603), "{r}");
        assert_eq!(
            r["error"]["message"],
            json!("Request not forwarded: the audit log could not be written")
        );
    }
}
