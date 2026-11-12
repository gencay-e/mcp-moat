//! Invariant: without a console (`--no-prompt`), no call that needs approval is forwarded, and
//! no approval is ever granted.
#![allow(clippy::field_reassign_with_default)] // tests tweak single config fields
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

use mcp_moat_core::{PolicyConfig, PolicyEngine};
use mcp_moat_proxy::ProxyServer;

#[path = "../../mcp-moat-core/tests/common/mod.rs"]
mod matrix;

#[tokio::test]
async fn no_prompt_never_forwards_a_call_that_needs_approval() {
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");
    let args: Vec<String> = vec![];

    let (mut client_tx, proxy_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_tx, client_rx) = tokio::io::duplex(256 * 1024);
    let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(256 * 1024);

    let witness = format!("no-prompt-witness-{}.txt", std::process::id());
    let _ = std::fs::remove_file(&witness);

    let mut config = PolicyConfig::default();
    config.require_approval_on_write = true;
    config.always_allow_tools.push("echo".to_string());
    config
        .custom_modifying_tools
        .push("deploy_site".to_string());
    let policy = PolicyEngine::new(config).unwrap();

    // `--no-prompt`: no console at all
    let proxy = ProxyServer::with_console(policy, None).with_io(proxy_rx, proxy_tx, proxy_err_tx);
    let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &args).await });

    let mut framed_out =
        FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    // (id, tool, arguments): every one of these is AskOperator in the policy.
    let needs_approval = [
        (1, "write_file", json!({"path": witness, "content": "x"})),
        (2, "bash", json!({"command": "echo hi"})),
        (3, "deploy_site", json!({"name": "x"})),
        (4, "rm", json!({"path": witness})),
        (5, "echo", json!({"message": "x", "command": "echo hi"})),
        (6, "update_thing", json!({"x": 1})),
    ];
    for (id, tool, arguments) in &needs_approval {
        let req = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
        });
        client_tx
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();
    }
    // Control: an allowed call is forwarded and answered by the mock server.
    let control = json!({
        "jsonrpc": "2.0", "id": 100, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hello"}}
    });
    client_tx
        .write_all(format!("{}\n", control).as_bytes())
        .await
        .unwrap();
    client_tx.flush().await.unwrap();

    let mut responses = std::collections::HashMap::new();
    for _ in 0..(needs_approval.len() + 1) {
        let line = tokio::time::timeout(Duration::from_secs(10), framed_out.next())
            .await
            .expect("no-prompt denial must not hang")
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        responses.insert(v["id"].as_i64().unwrap(), v);
    }

    for (id, tool, _) in &needs_approval {
        let resp = &responses[&(*id as i64)];
        assert_eq!(
            resp["result"]["isError"].as_bool(),
            Some(true),
            "{tool} must be denied: {resp}"
        );
        let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
        assert!(
            text.contains("--no-prompt is set, so the call was denied"),
            "{tool}: unexpected reason: {text}"
        );
    }
    assert!(
        responses[&100]["result"]["isError"].is_null(),
        "control call must go through: {}",
        responses[&100]
    );
    assert!(
        !std::path::Path::new(&witness).exists(),
        "the server must never have seen the write"
    );

    drop(client_tx);
    let _ = proxy_handle.await;
    let _ = std::fs::remove_file(&witness);
}

/// Canonicalizes a path and drops the Windows verbatim `\\?\` prefix, which the policy rejects.
fn plain_canonical(p: &std::path::Path) -> std::path::PathBuf {
    let c = p.canonicalize().unwrap();
    std::path::PathBuf::from(c.to_string_lossy().trim_start_matches(r"\\?\"))
}

/// The decision matrix of crates/mcp-moat-core/tests/invariants.rs through the proxy without a
/// console: a call the rule allows reaches the server, a call it blocks is blocked, and a call
/// that needs approval is denied with the `--no-prompt` message and never reaches the server.
#[tokio::test]
async fn decision_matrix_without_console() {
    use matrix::Exp;
    let mock_bin = env!("CARGO_BIN_EXE_mock_server");

    let jail = std::env::temp_dir().join(format!("mcp-moat-matrix-jail-{}", std::process::id()));
    std::fs::create_dir_all(jail.join(".git")).unwrap();
    let jail = plain_canonical(&jail);

    // one proxy session per policy; the cases of a policy differ in path and command only
    let mut groups: std::collections::BTreeMap<String, Vec<matrix::Case>> = Default::default();
    for case in matrix::cases() {
        groups.entry(case.config_key()).or_default().push(case);
    }

    let mut wrong = Vec::new();
    let mut total = 0;
    for cases in groups.values() {
        let policy = PolicyEngine::new(cases[0].config(&jail)).unwrap();
        let (mut client_tx, proxy_rx) = tokio::io::duplex(1024 * 1024);
        let (proxy_tx, client_rx) = tokio::io::duplex(1024 * 1024);
        let (proxy_err_tx, _client_err_rx) = tokio::io::duplex(1024 * 1024);
        let proxy =
            ProxyServer::with_console(policy, None).with_io(proxy_rx, proxy_tx, proxy_err_tx);
        let proxy_handle = tokio::spawn(async move { proxy.wrap_and_run(mock_bin, &[]).await });
        let mut framed_out =
            FramedRead::new(client_rx, LinesCodec::new_with_max_length(16 * 1024 * 1024));

        for (id, case) in cases.iter().enumerate() {
            let req = json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": case.tool.name, "arguments": case.arguments(&jail)}
            });
            client_tx
                .write_all(format!("{}\n", req).as_bytes())
                .await
                .unwrap();
        }
        client_tx.flush().await.unwrap();

        for _ in 0..cases.len() {
            let line = tokio::time::timeout(Duration::from_secs(20), framed_out.next())
                .await
                .expect("every call gets an answer")
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            let case = &cases[v["id"].as_u64().unwrap() as usize];
            let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
            let got = if v["result"]["isError"].as_bool() != Some(true) {
                // the mock server answered (a result, or "Tool not found")
                Exp::Allow
            } else if text.contains("--no-prompt is set, so the call was denied") {
                Exp::Ask
            } else {
                Exp::Block
            };
            total += 1;
            if got != matrix::expected(case) {
                wrong.push(format!(
                    "{case:?}: proxy {got:?}, rule {:?}: {line}",
                    matrix::expected(case)
                ));
            }
        }
        drop(client_tx);
        let _ = proxy_handle.await;
    }
    let _ = std::fs::remove_dir_all(&jail);
    assert!(
        wrong.is_empty(),
        "{} of {} cases differ:\n{}",
        wrong.len(),
        total,
        wrong.join("\n")
    );
    assert_eq!(total, matrix::cases().len());
}
