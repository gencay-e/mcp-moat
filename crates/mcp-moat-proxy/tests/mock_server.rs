use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, Stdout};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut dump_stderr_size: Option<usize> = None;
    let mut delay_ms: u64 = 0;
    let mut leak_secret = false;
    let mut stderr_on_call: usize = 0;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dump-stderr" => {
                if let Some(val) = args.next() {
                    dump_stderr_size = val.parse().ok();
                }
            }
            "--delay" => {
                if let Some(val) = args.next() {
                    delay_ms = val.parse().unwrap_or(0);
                }
            }
            "--leak-secret" => {
                leak_secret = true;
            }
            "--stderr-on-call" => {
                if let Some(val) = args.next() {
                    stderr_on_call = val.parse().unwrap_or(0);
                }
            }
            _ => {}
        }
    }

    // Trigger 1: Dump excessive stderr logs to test kernel pipe deadlock protection
    let stderr_task = dump_stderr_size.map(|size| {
        tokio::spawn(async move {
            let mut err = tokio::io::stderr();
            let chunk =
                "[DEBUG] Excessive mock server log line for pipe overflow testing 1234567890\n";
            let chunk_bytes = chunk.as_bytes();
            let mut written = 0;
            while written < size {
                if err.write_all(chunk_bytes).await.is_err() {
                    break;
                }
                written += chunk_bytes.len();
            }
            let _ = err.flush().await;
        })
    });

    if leak_secret {
        let mut err = tokio::io::stderr();
        let _ = err
            .write_all(b"[DEBUG] Leaked stderr key: api_key=sk-1234567890abcdef1234567890abcdef\n")
            .await;
        let _ = err.flush().await;
    }

    let stdin = tokio::io::stdin();
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut framed_in = FramedRead::new(stdin, LinesCodec::new_with_max_length(16 * 1024 * 1024));

    while let Some(line_res) = framed_in.next().await {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned();
        let method = req
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();

        let stdout_clone = Arc::clone(&stdout);
        tokio::spawn(async move {
            handle_request(
                &method,
                id,
                req,
                delay_ms,
                leak_secret,
                stderr_on_call,
                stdout_clone,
            )
            .await;
        });
    }

    if let Some(task) = stderr_task {
        let _ = task.await;
    }

    Ok(())
}

async fn handle_request(
    method: &str,
    id: Option<Value>,
    req: Value,
    delay_ms: u64,
    leak_secret: bool,
    stderr_on_call: usize,
    stdout: Arc<Mutex<Stdout>>,
) {
    if stderr_on_call > 0 && method == "tools/call" {
        let mut err = tokio::io::stderr();
        let chunk = vec![b'E'; stderr_on_call];
        let _ = err.write_all(&chunk).await;
        let _ = err.write_all(b"\n").await;
        let _ = err.flush().await;
    }
    let response: Option<Value> = match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mock-mcp-server",
                    "version": "0.1.0"
                }
            }
        })),
        "notifications/initialized" => None,
        "ping" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo input back",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "message": { "type": "string" }
                            }
                        }
                    },
                    {
                        "name": "write_file",
                        "description": "Write to a file",
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
        })),
        "tools/call" => {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            let params = req.get("params");
            let tool_name = params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let arguments = params.and_then(|p| p.get("arguments"));

            match tool_name {
                "echo" => {
                    let mut msg = arguments
                        .and_then(|a| a.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();

                    if leak_secret {
                        msg = format!("{} [api_key=sk-1234567890abcdef1234567890abcdef]", msg);
                    }

                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": msg
                                }
                            ]
                        }
                    }))
                }
                "write_file" => {
                    let path = arguments
                        .and_then(|a| a.get("path"))
                        .and_then(|p| p.as_str())
                        .unwrap_or("");
                    let content = arguments
                        .and_then(|a| a.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("");

                    if !path.is_empty() {
                        let _ = tokio::fs::write(path, content).await;
                    }

                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("Successfully wrote to {}", path)
                                }
                            ]
                        }
                    }))
                }
                _ => Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Tool not found: {}", tool_name)
                    }
                })),
            }
        }
        _ => {
            if id.is_some() {
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", method)
                    }
                }))
            } else {
                None
            }
        }
    };

    if let Some(resp) = response {
        let serialized = format!("{}\n", resp);
        let mut out = stdout.lock().await;
        let _ = out.write_all(serialized.as_bytes()).await;
        let _ = out.flush().await;
    }
}
