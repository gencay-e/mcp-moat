use anyhow::{Context, Result};
use mcp_moat_core::audit::{AuditChain, AuditDecision, AuditDirection, AuditEvent, AuditLevel};
use mcp_moat_core::{Decision, DlpEngine, PolicyEngine, TokenOptimizer, ToolCallParams};
use mcp_moat_tty::DirectConsole;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const MAX_HTTP_PAYLOAD: usize = 16 * 1024 * 1024; // 16 MB maximum payload ceiling
static SESSION_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct ParsedUrl {
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

impl ParsedUrl {
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            anyhow::bail!("URL cannot be empty");
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("https://") {
            anyhow::bail!(
                "https:// URLs are not supported: the SSE proxy has no TLS support and would send data unencrypted. Use http:// to a trusted local or tunneled endpoint."
            );
        }
        let without_proto = if lower.starts_with("http://") {
            &trimmed["http://".len()..]
        } else if lower.contains("://") {
            anyhow::bail!("Unsupported URL scheme: only http:// is supported");
        } else {
            trimmed
        };

        let (host_port, path_and_query) = match without_proto.find('/') {
            Some(idx) => (&without_proto[..idx], without_proto[idx..].to_string()),
            None => (without_proto, "/".to_string()),
        };

        if host_port.is_empty() {
            anyhow::bail!("URL must contain a valid host");
        }

        let (host, port) = if host_port.starts_with('[') {
            if let Some(bracket_end) = host_port.find(']') {
                let h = &host_port[1..bracket_end];
                let p = if let Some(colon) = host_port[bracket_end..].find(':') {
                    host_port[bracket_end + colon + 1..]
                        .parse::<u16>()
                        .context("Invalid port in IPv6 URL")?
                } else {
                    80
                };
                (h.to_string(), p)
            } else {
                anyhow::bail!("Unclosed IPv6 bracket in URL");
            }
        } else {
            match host_port.rfind(':') {
                Some(idx) => {
                    let h = &host_port[..idx];
                    let p = host_port[idx + 1..]
                        .parse::<u16>()
                        .context("Invalid port in URL")?;
                    (h.to_string(), p)
                }
                None => (host_port.to_string(), 80),
            }
        };

        if host.is_empty() {
            anyhow::bail!("Host cannot be empty");
        }

        Ok(Self {
            host,
            port,
            path_and_query,
        })
    }
}

/// Resolves the endpoint announced by the upstream server (`event: endpoint`) to a path on the
/// configured upstream host. Anything that would send the client to another host is rejected.
pub fn resolve_endpoint(data: &str, target: &ParsedUrl) -> Result<String> {
    let data = data.trim();
    if data.is_empty() {
        anyhow::bail!("Upstream announced an empty endpoint");
    }
    if data.starts_with("//") {
        anyhow::bail!("Upstream announced a scheme-relative endpoint '{}'", data);
    }
    if data.starts_with('/') {
        return Ok(data.to_string());
    }
    if data.to_ascii_lowercase().starts_with("http://") {
        let url = ParsedUrl::parse(data)?;
        if url.host.eq_ignore_ascii_case(&target.host) && url.port == target.port {
            return Ok(url.path_and_query);
        }
        anyhow::bail!(
            "Upstream announced an endpoint on a different host '{}:{}'",
            url.host,
            url.port
        );
    }
    anyhow::bail!("Upstream announced an unsupported endpoint '{}'", data)
}

/// Checks the Host and Origin headers of an incoming request.
///
/// Browsers always send `Origin` on cross-origin requests, MCP clients do not. Rejecting any
/// request with an `Origin` header blocks web pages from reaching the proxy. When the proxy is
/// bound to a loopback address, the Host header must be a loopback name (DNS rebinding).
pub fn check_request_headers(
    host: Option<&str>,
    origin: Option<&str>,
    loopback_only: bool,
) -> std::result::Result<(), &'static str> {
    if origin.is_some() {
        return Err("Requests with an Origin header are not allowed");
    }
    if loopback_only {
        let host = host.ok_or("Missing Host header")?.trim();
        let name = if let Some(rest) = host.strip_prefix('[') {
            rest.split(']').next().unwrap_or("")
        } else {
            host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
        };
        let name = name.to_ascii_lowercase();
        if !(name == "localhost" || name == "127.0.0.1" || name == "::1") {
            return Err("Host header is not a loopback address");
        }
    }
    Ok(())
}

pub async fn send_http_post(
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    let socket_addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    let mut stream = TcpStream::connect(&socket_addr)
        .await
        .with_context(|| format!("Failed to connect to upstream server {}", socket_addr))?;

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path, socket_addr, body.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    let bytes_read = reader.read_line(&mut status_line).await?;
    if bytes_read == 0 || status_line.trim().is_empty() {
        anyhow::bail!("Upstream server closed connection without HTTP response");
    }

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);

    let mut content_length = None;
    let mut is_chunked = false;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(val) = line.split(':').nth(1) {
                content_length = val.trim().parse::<usize>().ok();
            }
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            is_chunked = true;
        }
    }

    let mut resp_body = Vec::new();
    if let Some(len) = content_length {
        if len > MAX_HTTP_PAYLOAD {
            anyhow::bail!(
                "Upstream HTTP response payload exceeds 16MB ceiling ({} bytes)",
                len
            );
        }
        resp_body.resize(len, 0);
        reader
            .read_exact(&mut resp_body)
            .await
            .context("Premature EOF while reading HTTP response body from upstream")?;
    } else if is_chunked {
        loop {
            let mut chunk_size_str = String::new();
            reader.read_line(&mut chunk_size_str).await?;
            let chunk_size = usize::from_str_radix(chunk_size_str.trim(), 16).unwrap_or(0);
            if chunk_size == 0 {
                let mut dummy = String::new();
                let _ = reader.read_line(&mut dummy).await;
                break;
            }
            if resp_body.len().saturating_add(chunk_size) > MAX_HTTP_PAYLOAD {
                anyhow::bail!("Upstream chunked payload exceeds 16MB ceiling");
            }
            let mut chunk = vec![0u8; chunk_size];
            reader
                .read_exact(&mut chunk)
                .await
                .context("Premature EOF while reading chunked HTTP body")?;
            resp_body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await;
        }
    } else {
        reader
            .take((MAX_HTTP_PAYLOAD + 1) as u64)
            .read_to_end(&mut resp_body)
            .await?;
        if resp_body.len() > MAX_HTTP_PAYLOAD {
            anyhow::bail!("Upstream HTTP response payload exceeds 16MB ceiling");
        }
    }

    Ok((status_code, resp_body))
}

pub async fn connect_sse(host: &str, port: u16, path: &str) -> Result<BufReader<TcpStream>> {
    let socket_addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    let mut stream = TcpStream::connect(&socket_addr)
        .await
        .with_context(|| format!("Failed to connect to SSE stream {}", socket_addr))?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
        path, socket_addr
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    Ok(reader)
}

fn create_timestamp() -> String {
    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}Z", now_sec)
}

/// SseProxyServer: Runs a local HTTP/SSE proxy that transparently guards a remote MCP server.
pub struct SseProxyServer {
    policy: Arc<PolicyEngine>,
    console: Arc<Mutex<Option<DirectConsole>>>,
    audit_chain: Arc<Mutex<AuditChain>>,
    audit_path: Option<PathBuf>,
    audit_level: AuditLevel,
    dlp: Arc<DlpEngine>,
    target_url: ParsedUrl,
}

impl SseProxyServer {
    pub fn new(policy: PolicyEngine, target_url: &str) -> Result<Self> {
        let parsed_target = ParsedUrl::parse(target_url)?;
        let audit_path = policy.config().audit_log.clone();
        let audit_level = policy.config().audit_level;
        let session_id = format!(
            "sse-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        let console = match DirectConsole::open() {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(
                    "Could not open direct TTY console: {}. Approvals will auto-deny.",
                    e
                );
                None
            }
        };

        Ok(Self {
            policy: Arc::new(policy),
            console: Arc::new(Mutex::new(console)),
            audit_chain: Arc::new(Mutex::new(AuditChain::new(session_id))),
            audit_path,
            audit_level,
            dlp: Arc::new(DlpEngine::new()),
            target_url: parsed_target,
        })
    }

    pub fn with_console(
        policy: PolicyEngine,
        console: Option<DirectConsole>,
        target_url: &str,
    ) -> Result<Self> {
        let mut server = Self::new(policy, target_url)?;
        server.console = Arc::new(Mutex::new(console));
        Ok(server)
    }

    pub async fn run(&self, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("Failed to bind SseProxyServer to {}", bind_addr))?;
        self.serve(listener).await
    }

    /// Serves on a listener that is already bound. Tests use this to avoid the race between
    /// finding a free port and binding it.
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        let local_addr = listener.local_addr()?;
        info!(
            "[moat] SSE Proxy listening on http://{} -> Upstream {}:{}",
            local_addr, self.target_url.host, self.target_url.port
        );

        let sessions = Arc::new(Mutex::new(HashMap::<String, String>::new()));
        let loopback_only = local_addr.ip().is_loopback();

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    let (stream, peer_addr) = accept_res?;
                    let policy = Arc::clone(&self.policy);
                    let console = Arc::clone(&self.console);
                    let audit_chain = Arc::clone(&self.audit_chain);
                    let audit_path = self.audit_path.clone();
                    let audit_level = self.audit_level;
                    let dlp = Arc::clone(&self.dlp);
                    let target_url = self.target_url.clone();
                    let sessions = Arc::clone(&sessions);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream,
                            peer_addr,
                            policy,
                            console,
                            audit_chain,
                            audit_path,
                            audit_level,
                            dlp,
                            target_url,
                            sessions,
                            loopback_only,
                        ).await {
                            debug!("[moat] Connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("[moat] SSE Proxy received Ctrl+C shutdown signal. Exiting gracefully.");
                    break;
                }
                _ = crate::wait_for_sigterm() => {
                    info!("[moat] SSE Proxy received SIGTERM shutdown signal. Exiting gracefully.");
                    break;
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // shared per-connection state
    async fn handle_connection(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        policy: Arc<PolicyEngine>,
        console: Arc<Mutex<Option<DirectConsole>>>,
        audit_chain: Arc<Mutex<AuditChain>>,
        audit_path: Option<PathBuf>,
        audit_level: AuditLevel,
        dlp: Arc<DlpEngine>,
        target_url: ParsedUrl,
        sessions: Arc<Mutex<HashMap<String, String>>>,
        loopback_only: bool,
    ) -> Result<()> {
        let (reader_half, mut writer_half) = stream.split();
        let mut reader = BufReader::new(reader_half);

        let mut req_line = String::new();
        let bytes_read = reader.read_line(&mut req_line).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        let parts: Vec<&str> = req_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(());
        }
        let method = parts[0];
        let path = parts[1];

        // Parse headers
        let mut content_length = 0;
        let mut host_header: Option<String> = None;
        let mut origin_header: Option<String> = None;
        loop {
            let mut h = String::new();
            let n = reader.read_line(&mut h).await?;
            if n == 0 || h == "\r\n" || h == "\n" {
                break;
            }
            let lower = h.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                if let Some(val) = h.split(':').nth(1) {
                    content_length = val.trim().parse::<usize>().unwrap_or(0);
                }
            } else if lower.starts_with("host:") {
                host_header = h.split_once(':').map(|(_, v)| v.trim().to_string());
            } else if lower.starts_with("origin:") {
                origin_header = h.split_once(':').map(|(_, v)| v.trim().to_string());
            }
        }

        // No CORS: browsers must not be able to use this proxy.
        if let Err(reason) = check_request_headers(
            host_header.as_deref(),
            origin_header.as_deref(),
            loopback_only,
        ) {
            warn!("[moat] Rejected request from {}: {}", peer_addr, reason);
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                reason.len(),
                reason
            );
            writer_half.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        if method == "OPTIONS" {
            let resp =
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, POST\r\nContent-Length: 0\r\n\r\n";
            writer_half.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        // SSE stream request
        if method == "GET" {
            let mut proxy_session_id_created = None;
            let mut upstream_reader = match connect_sse(
                &target_url.host,
                target_url.port,
                &target_url.path_and_query,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!("[moat] Failed connecting to upstream SSE stream: {}", e);
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nFailed to connect to upstream SSE stream: {}\n",
                        e
                    );
                    writer_half.write_all(resp.as_bytes()).await?;
                    writer_half.flush().await?;
                    return Ok(());
                }
            };

            let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
            writer_half.write_all(header.as_bytes()).await?;
            writer_half.flush().await?;

            let mut stream_res: Result<()> = Ok(());
            let mut upstream_line = String::new();
            let mut current_event = String::new();
            loop {
                upstream_line.clear();
                match upstream_reader.read_line(&mut upstream_line).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => {
                        stream_res = Err(e.into());
                        break;
                    }
                }

                if let Some(ev) = upstream_line.strip_prefix("event:") {
                    current_event = ev.trim().to_string();
                } else if upstream_line.trim().is_empty() {
                    current_event.clear();
                }

                if let Some(rest) = upstream_line.strip_prefix("data:") {
                    let data_payload = rest.trim();
                    let is_endpoint_event = current_event == "endpoint"
                        || (data_payload.starts_with('/') && data_payload.contains("sessionId="));
                    if is_endpoint_event {
                        // Fail closed: the client must only ever learn a proxy URL. If the
                        // upstream endpoint cannot be mapped, the stream is closed.
                        let upstream_endpoint = match resolve_endpoint(data_payload, &target_url) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("[moat] Closing SSE stream: {}", e);
                                stream_res = Err(e);
                                break;
                            }
                        };
                        let counter =
                            SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let nanos = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos();
                        let proxy_session_id =
                            format!("moat-{}-{:x}-{:x}", peer_addr.port(), nanos, counter);
                        sessions
                            .lock()
                            .await
                            .insert(proxy_session_id.clone(), upstream_endpoint);
                        proxy_session_id_created = Some(proxy_session_id.clone());
                        let rewritten_data =
                            format!("data: /message?sessionId={}\n\n", proxy_session_id);
                        if let Err(e) = writer_half.write_all(rewritten_data.as_bytes()).await {
                            stream_res = Err(e.into());
                            break;
                        }
                        if let Err(e) = writer_half.flush().await {
                            stream_res = Err(e.into());
                            break;
                        }
                        continue;
                    }

                    // AST-DLP line sanitization & Token Optimization
                    let (sanitized, redactions) = dlp.sanitize_line(data_payload);
                    if redactions > 0 {
                        warn!(
                            "[moat] DLP sanitized {} secret(s) in SSE data stream",
                            redactions
                        );
                        if let Some(ref path) = audit_path {
                            let mut chain = audit_chain.lock().await;
                            let event = chain.create_event(
                                create_timestamp(),
                                AuditDirection::Outbound,
                                "sse/message".to_string(),
                                None,
                                None,
                                Some(AuditDecision::Allow),
                                None,
                                Some(sanitized.clone()),
                                Some(redactions),
                            );
                            let _ = append_audit_file(path, &event).await;
                        }
                    }

                    let (optimized, _) = TokenOptimizer::optimize_line(&sanitized, &policy);
                    let sse_out = format!("data: {}\n\n", optimized);
                    if let Err(e) = writer_half.write_all(sse_out.as_bytes()).await {
                        stream_res = Err(e.into());
                        break;
                    }
                    if let Err(e) = writer_half.flush().await {
                        stream_res = Err(e.into());
                        break;
                    }
                    continue;
                }

                if let Err(e) = writer_half.write_all(upstream_line.as_bytes()).await {
                    stream_res = Err(e.into());
                    break;
                }
                if let Err(e) = writer_half.flush().await {
                    stream_res = Err(e.into());
                    break;
                }
            }

            // Guaranteed cleanup of proxy session ID to prevent memory leak on client drop
            if let Some(ref sess_id) = proxy_session_id_created {
                sessions.lock().await.remove(sess_id);
            }

            return stream_res;
        }

        // JSON-RPC POST request
        if method == "POST" {
            if content_length > MAX_HTTP_PAYLOAD {
                let err_resp = "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\n\r\nRequest payload exceeds 16MB ceiling\n";
                writer_half.write_all(err_resp.as_bytes()).await?;
                return Ok(());
            }

            let mut body_bytes = vec![0u8; content_length];
            reader
                .read_exact(&mut body_bytes)
                .await
                .context("Premature EOF while reading POST request body")?;

            let json_body: Value = match serde_json::from_slice(&body_bytes) {
                Ok(v) => v,
                Err(_) => {
                    let err_resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    writer_half.write_all(err_resp.as_bytes()).await?;
                    return Ok(());
                }
            };

            // Fail-closed: JSON-RPC Batch-Arrays are prohibited to prevent batch-smuggling policy bypasses
            if json_body.is_array() {
                let err_obj = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32600,
                        "message": "JSON-RPC batch requests are prohibited by policy"
                    }
                });
                let resp_str = serde_json::to_string(&err_obj)?;
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp_str.len(), resp_str
                );
                writer_half.write_all(resp.as_bytes()).await?;
                return Ok(());
            }

            let is_notification = json_body.get("id").is_none();
            let req_id = json_body.get("id").cloned();
            let jsonrpc_ver = json_body.get("jsonrpc").and_then(|v| v.as_str());

            // Validate jsonrpc 2.0 version
            if jsonrpc_ver != Some("2.0") {
                if !is_notification {
                    let err_obj = json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32600,
                            "message": "Invalid Request: 'jsonrpc' must be '2.0'"
                        }
                    });
                    let resp_str = serde_json::to_string(&err_obj)?;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_str.len(), resp_str
                    );
                    writer_half.write_all(resp.as_bytes()).await?;
                } else {
                    let resp = "HTTP/1.1 204 No Content\r\n\r\n";
                    writer_half.write_all(resp.as_bytes()).await?;
                }
                return Ok(());
            }

            let req_method = json_body
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("");
            let tool_name = json_body
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .map(String::from);

            let decision = if req_method == "tools/call" {
                if let Some(params_val) = json_body.get("params") {
                    if let Ok(params) = serde_json::from_value::<ToolCallParams>(params_val.clone())
                    {
                        policy.evaluate_tool_call(&params)
                    } else {
                        Decision::Block("Malformed tools/call parameters".to_string())
                    }
                } else {
                    Decision::Block("Missing parameters for tools/call".to_string())
                }
            } else if req_method == "resources/read" || req_method == "resources/subscribe" {
                let uri = json_body
                    .get("params")
                    .and_then(|p| p.get("uri"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("");
                policy.evaluate_resource_read(uri)
            } else {
                Decision::Allow
            };

            // Audit inbound with DLP sanitization
            let (sanitized_payload, _) = dlp.sanitize_line(&String::from_utf8_lossy(&body_bytes));
            let sanitized_tool = tool_name.as_ref().map(|t| dlp.sanitize_text(t).0);
            let sanitized_decision = match &decision {
                Decision::Allow => AuditDecision::Allow,
                Decision::Block(r) => {
                    let (s, _) = dlp.sanitize_text(r);
                    AuditDecision::Block { reason: s }
                }
                Decision::AskOperator { action_summary, .. } => {
                    let (s, _) = dlp.sanitize_text(action_summary);
                    AuditDecision::AskOperator { summary: s }
                }
            };

            if let Some(ref log_p) = audit_path {
                let is_viol = matches!(&decision, Decision::Block(_));
                let should_log = match audit_level {
                    AuditLevel::Full => true,
                    AuditLevel::DecisionsOnly => true,
                    AuditLevel::ViolationsOnly => is_viol,
                };
                if should_log {
                    let mut chain = audit_chain.lock().await;
                    let event = chain.create_event(
                        create_timestamp(),
                        AuditDirection::Inbound,
                        req_method.to_string(),
                        sanitized_tool.clone(),
                        None,
                        Some(sanitized_decision.clone()),
                        None,
                        Some(sanitized_payload.clone()),
                        None,
                    );
                    let _ = append_audit_file(log_p, &event).await;
                }
            }

            match decision {
                Decision::Block(reason) => {
                    warn!("[moat] BLOCKED SSE Request: {}", reason);
                    if is_notification {
                        let resp = "HTTP/1.1 204 No Content\r\n\r\n";
                        writer_half.write_all(resp.as_bytes()).await?;
                        return Ok(());
                    }
                    let err_obj = json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32001,
                            "message": format!("[moat] Security Policy Violation: {}", reason)
                        }
                    });
                    let resp_str = serde_json::to_string(&err_obj)?;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_str.len(), resp_str
                    );
                    writer_half.write_all(resp.as_bytes()).await?;
                    return Ok(());
                }
                Decision::AskOperator { action_summary, .. } => {
                    let console_clone = Arc::clone(&console);
                    let action_summary_clone = action_summary.clone();
                    let approved = tokio::task::spawn_blocking(move || {
                        let mut c_guard = console_clone.blocking_lock();
                        if let Some(console_inst) = c_guard.as_mut() {
                            matches!(
                                console_inst.ask_approval(&action_summary_clone, None),
                                Ok(true)
                            )
                        } else {
                            false
                        }
                    })
                    .await
                    .unwrap_or(false);

                    if !approved {
                        warn!("[moat] Operator REJECTED SSE Request: {}", action_summary);
                        if let Some(ref log_p) = audit_path {
                            let mut chain = audit_chain.lock().await;
                            let event = chain.create_event(
                                create_timestamp(),
                                AuditDirection::Inbound,
                                req_method.to_string(),
                                sanitized_tool.clone(),
                                None,
                                Some(sanitized_decision.clone()),
                                Some("Deny".to_string()),
                                Some(sanitized_payload.clone()),
                                None,
                            );
                            let _ = append_audit_file(log_p, &event).await;
                        }
                        if is_notification {
                            let resp = "HTTP/1.1 204 No Content\r\n\r\n";
                            writer_half.write_all(resp.as_bytes()).await?;
                            return Ok(());
                        }
                        let resp_str = if req_method == "tools/call" {
                            serde_json::to_string(
                                &mcp_moat_core::JsonRpcResponse::tool_error_result(
                                    req_id,
                                    "Action was rejected by operator in prompt",
                                ),
                            )?
                        } else {
                            let err_obj = json!({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "error": {
                                    "code": -32002,
                                    "message": "[moat] Action rejected by operator"
                                }
                            });
                            serde_json::to_string(&err_obj)?
                        };
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            resp_str.len(), resp_str
                        );
                        writer_half.write_all(resp.as_bytes()).await?;
                        return Ok(());
                    } else if let Some(ref log_p) = audit_path {
                        let mut chain = audit_chain.lock().await;
                        let event = chain.create_event(
                            create_timestamp(),
                            AuditDirection::Inbound,
                            req_method.to_string(),
                            sanitized_tool.clone(),
                            None,
                            Some(sanitized_decision.clone()),
                            Some("AllowOnce".to_string()),
                            Some(sanitized_payload.clone()),
                            None,
                        );
                        let _ = append_audit_file(log_p, &event).await;
                    }
                }
                Decision::Allow => {}
            }

            // Map session ID to upstream endpoint
            let upstream_path = if let Some(query_start) = path.find('?') {
                let query = &path[query_start + 1..];
                let session_id = query.split('&').find_map(|pair| {
                    let mut parts = pair.split('=');
                    if parts.next() == Some("sessionId") {
                        parts.next()
                    } else {
                        None
                    }
                });
                if let Some(s_id) = session_id {
                    let map = sessions.lock().await;
                    map.get(s_id).cloned().unwrap_or_else(|| path.to_string())
                } else {
                    path.to_string()
                }
            } else {
                path.to_string()
            };

            // Forward approved request to upstream
            let (status_code, upstream_resp_bytes) = match send_http_post(
                &target_url.host,
                target_url.port,
                &upstream_path,
                &body_bytes,
            )
            .await
            {
                Ok(res) => res,
                Err(e) => {
                    warn!("[moat] Failed forwarding request to upstream server: {}", e);
                    let err_obj = json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": format!("[moat] Upstream gateway error: {}", e)
                        }
                    });
                    let resp_str = serde_json::to_string(&err_obj)?;
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_str.len(), resp_str
                    );
                    writer_half.write_all(resp.as_bytes()).await?;
                    writer_half.flush().await?;
                    return Ok(());
                }
            };

            // AST-DLP redaction & Token Optimization on outgoing response
            let (final_resp_bytes, redactions) =
                if let Ok(resp_str) = std::str::from_utf8(&upstream_resp_bytes) {
                    let (sanitized_str, red) = dlp.sanitize_line(resp_str);
                    let (optimized_str, _) = TokenOptimizer::optimize_line(&sanitized_str, &policy);
                    (optimized_str.into_bytes(), red)
                } else {
                    (upstream_resp_bytes, 0)
                };

            if redactions > 0 {
                if let Some(ref log_p) = audit_path {
                    let mut chain = audit_chain.lock().await;
                    let event = chain.create_event(
                        create_timestamp(),
                        AuditDirection::Outbound,
                        req_method.to_string(),
                        tool_name,
                        None,
                        Some(AuditDecision::Allow),
                        None,
                        Some(String::from_utf8_lossy(&final_resp_bytes).to_string()),
                        Some(redactions),
                    );
                    let _ = append_audit_file(log_p, &event).await;
                }
            }

            let status_reason = match status_code {
                200 => "OK",
                201 => "Created",
                202 => "Accepted",
                204 => "No Content",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                413 => "Payload Too Large",
                500 => "Internal Server Error",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                _ => "OK",
            };

            let resp =
                format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                status_code, status_reason, final_resp_bytes.len()
            );
            writer_half.write_all(resp.as_bytes()).await?;
            writer_half.write_all(&final_resp_bytes).await?;
            writer_half.flush().await?;
        }

        Ok(())
    }
}

/// SseBridgeServer: Bridges stdio NDJSON to a remote MCP SSE server under the Zero-Trust firewall.
pub struct SseBridgeServer {
    policy: Arc<PolicyEngine>,
    console: Arc<Mutex<Option<DirectConsole>>>,
    audit_chain: Arc<Mutex<AuditChain>>,
    audit_path: Option<PathBuf>,
    audit_level: AuditLevel,
    dlp: Arc<DlpEngine>,
    target_url: ParsedUrl,
}

impl SseBridgeServer {
    pub fn new(policy: PolicyEngine, target_url: &str) -> Result<Self> {
        let parsed_target = ParsedUrl::parse(target_url)?;
        let audit_path = policy.config().audit_log.clone();
        let audit_level = policy.config().audit_level;
        let session_id = format!(
            "bridge-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        let console = match DirectConsole::open() {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(
                    "Could not open direct TTY console: {}. Approvals will auto-deny.",
                    e
                );
                None
            }
        };

        Ok(Self {
            policy: Arc::new(policy),
            console: Arc::new(Mutex::new(console)),
            audit_chain: Arc::new(Mutex::new(AuditChain::new(session_id))),
            audit_path,
            audit_level,
            dlp: Arc::new(DlpEngine::new()),
            target_url: parsed_target,
        })
    }

    pub fn with_console(
        policy: PolicyEngine,
        console: Option<DirectConsole>,
        target_url: &str,
    ) -> Result<Self> {
        let mut server = Self::new(policy, target_url)?;
        server.console = Arc::new(Mutex::new(console));
        Ok(server)
    }

    pub async fn run(&self) -> Result<()> {
        let mut sse_reader = connect_sse(
            &self.target_url.host,
            self.target_url.port,
            &self.target_url.path_and_query,
        )
        .await?;
        let mut upstream_post_endpoint = String::new();

        let mut line = String::new();
        let mut current_event = String::new();
        while sse_reader.read_line(&mut line).await? > 0 {
            if let Some(ev) = line.strip_prefix("event:") {
                current_event = ev.trim().to_string();
            } else if line.trim().is_empty() {
                current_event.clear();
            } else if let Some(rest) = line.strip_prefix("data:") {
                let data = rest.trim();
                if current_event == "endpoint" || data.starts_with('/') {
                    upstream_post_endpoint = resolve_endpoint(data, &self.target_url)?;
                    break;
                }
            }
            line.clear();
        }

        if upstream_post_endpoint.is_empty() {
            anyhow::bail!(
                "Failed to discover upstream SSE endpoint from {}",
                self.target_url.path_and_query
            );
        }

        info!(
            "[moat] SSE Bridge established with endpoint: {}",
            upstream_post_endpoint
        );

        // Coordinated shared stdout writer to eliminate line-interleaving race conditions
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        // Background task to read asynchronous events from SSE stream
        let dlp = Arc::clone(&self.dlp);
        let policy_bg = Arc::clone(&self.policy);
        let audit_chain = Arc::clone(&self.audit_chain);
        let audit_path = self.audit_path.clone();
        let stdout_bg = Arc::clone(&stdout);
        tokio::spawn(async move {
            let mut sse_line = String::new();
            while let Ok(n) = sse_reader.read_line(&mut sse_line).await {
                if n == 0 {
                    break;
                }
                if let Some(rest) = sse_line.strip_prefix("data: ") {
                    let data_payload = rest.trim();
                    let (sanitized, redactions) = dlp.sanitize_line(data_payload);
                    if redactions > 0 {
                        if let Some(ref log_p) = audit_path {
                            let mut chain = audit_chain.lock().await;
                            let event = chain.create_event(
                                create_timestamp(),
                                AuditDirection::Outbound,
                                "sse/stream".to_string(),
                                None,
                                None,
                                Some(AuditDecision::Allow),
                                None,
                                Some(sanitized.clone()),
                                Some(redactions),
                            );
                            let _ = append_audit_file(log_p, &event).await;
                        }
                    }
                    let (optimized, _) = TokenOptimizer::optimize_line(&sanitized, &policy_bg);
                    let out_ndjson = format!("{}\n", optimized);
                    let mut out = stdout_bg.lock().await;
                    let _ = out.write_all(out_ndjson.as_bytes()).await;
                    let _ = out.flush().await;
                }
                sse_line.clear();
            }
        });

        // Read stdio NDJSON from client
        let stdin = tokio::io::stdin();
        let mut stdin_reader = BufReader::new(stdin);

        let mut stdin_line = String::new();
        loop {
            tokio::select! {
                read_res = stdin_reader.read_line(&mut stdin_line) => {
                    let bytes = read_res?;
                    if bytes == 0 {
                        break;
                    }
                    let trimmed = stdin_line.trim();
                    if trimmed.is_empty() {
                        stdin_line.clear();
                        continue;
                    }

                    if trimmed.len() > MAX_HTTP_PAYLOAD {
                        warn!("Rejecting frame exceeding 16MB ceiling in SSE bridge mode");
                        let err_obj = json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {
                                "code": -32700,
                                "message": "Parse error: Frame size exceeds maximum allowed limit (16MB)"
                            }
                        });
                        let out_line = format!("{}\n", serde_json::to_string(&err_obj)?);
                        let mut out = stdout.lock().await;
                        out.write_all(out_line.as_bytes()).await?;
                        out.flush().await?;
                        stdin_line.clear();
                        continue;
                    }

                    let json_body: Value = match serde_json::from_str(trimmed) {
                        Ok(v) => v,
                        Err(e) => {
                            let err_obj = json!({
                                "jsonrpc": "2.0",
                                "id": null,
                                "error": {
                                    "code": -32700,
                                    "message": format!("Parse error: {}", e)
                                }
                            });
                            let out_line = format!("{}\n", serde_json::to_string(&err_obj)?);
                            let mut out = stdout.lock().await;
                            out.write_all(out_line.as_bytes()).await?;
                            out.flush().await?;
                            stdin_line.clear();
                            continue;
                        }
                    };

                    // Fail-closed: Reject batch arrays in bridge mode
                    if json_body.is_array() {
                        let err_obj = json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {
                                "code": -32600,
                                "message": "JSON-RPC batch requests are prohibited by policy"
                            }
                        });
                        let out_line = format!("{}\n", serde_json::to_string(&err_obj)?);
                        let mut out = stdout.lock().await;
                        out.write_all(out_line.as_bytes()).await?;
                        out.flush().await?;
                        stdin_line.clear();
                        continue;
                    }

                    let is_notification = json_body.get("id").is_none();
                    let req_id = json_body.get("id").cloned();
                    let jsonrpc_ver = json_body.get("jsonrpc").and_then(|v| v.as_str());

                    // Validate jsonrpc 2.0 version
                    if jsonrpc_ver != Some("2.0") {
                        if !is_notification {
                            let err_obj = json!({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "error": {
                                    "code": -32600,
                                    "message": "Invalid Request: 'jsonrpc' must be '2.0'"
                                }
                            });
                            let out_line = format!("{}\n", serde_json::to_string(&err_obj)?);
                            let mut out = stdout.lock().await;
                            out.write_all(out_line.as_bytes()).await?;
                            out.flush().await?;
                        }
                        stdin_line.clear();
                        continue;
                    }

                    let req_method = json_body.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let tool_name = json_body.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str()).map(String::from);

                    let decision = if req_method == "tools/call" {
                        if let Some(params_val) = json_body.get("params") {
                            if let Ok(params) = serde_json::from_value::<ToolCallParams>(params_val.clone()) {
                                self.policy.evaluate_tool_call(&params)
                            } else {
                                Decision::Block("Malformed tools/call parameters".to_string())
                            }
                        } else {
                            Decision::Block("Missing parameters for tools/call".to_string())
                        }
                    } else if req_method == "resources/read" || req_method == "resources/subscribe" {
                        let uri = json_body.get("params").and_then(|p| p.get("uri")).and_then(|u| u.as_str()).unwrap_or("");
                        self.policy.evaluate_resource_read(uri)
                    } else {
                        Decision::Allow
                    };

                    // Audit with DLP sanitization
                    let (sanitized_payload, _) = self.dlp.sanitize_line(trimmed);
                    let sanitized_tool = tool_name.as_ref().map(|t| self.dlp.sanitize_text(t).0);
                    let sanitized_decision = match &decision {
                        Decision::Allow => AuditDecision::Allow,
                        Decision::Block(r) => {
                            let (s, _) = self.dlp.sanitize_text(r);
                            AuditDecision::Block { reason: s }
                        }
                        Decision::AskOperator { action_summary, .. } => {
                            let (s, _) = self.dlp.sanitize_text(action_summary);
                            AuditDecision::AskOperator { summary: s }
                        }
                    };

                    if let Some(ref log_p) = self.audit_path {
                        let is_viol = matches!(&decision, Decision::Block(_));
                        let should_log = match self.audit_level {
                            AuditLevel::Full => true,
                            AuditLevel::DecisionsOnly => true,
                            AuditLevel::ViolationsOnly => is_viol,
                        };
                        if should_log {
                            let mut chain = self.audit_chain.lock().await;
                            let event = chain.create_event(
                                create_timestamp(),
                                AuditDirection::Inbound,
                                req_method.to_string(),
                                sanitized_tool.clone(),
                                None,
                                Some(sanitized_decision.clone()),
                                None,
                                Some(sanitized_payload.clone()),
                                None,
                            );
                            let _ = append_audit_file(log_p, &event).await;
                        }
                    }

                    match decision {
                        Decision::Block(reason) => {
                            if !is_notification {
                                let err_obj = json!({
                                    "jsonrpc": "2.0",
                                    "id": req_id,
                                    "error": {
                                        "code": -32001,
                                        "message": format!("[moat] Security Policy Violation: {}", reason)
                                    }
                                });
                                let out_line = format!("{}\n", serde_json::to_string(&err_obj)?);
                                let mut out = stdout.lock().await;
                                out.write_all(out_line.as_bytes()).await?;
                                out.flush().await?;
                            }
                            stdin_line.clear();
                            continue;
                        }
                        Decision::AskOperator {
                            action_summary, ..
                        } => {
                            let console_clone = Arc::clone(&self.console);
                            let action_summary_clone = action_summary.clone();
                            let approved = tokio::task::spawn_blocking(move || {
                                let mut c_guard = console_clone.blocking_lock();
                                if let Some(console_inst) = c_guard.as_mut() {
                                    matches!(console_inst.ask_approval(&action_summary_clone, None), Ok(true))
                                } else {
                                    false
                                }
                            })
                            .await
                            .unwrap_or(false);

                            if !approved {
                                if let Some(ref log_p) = self.audit_path {
                                    let mut chain = self.audit_chain.lock().await;
                                    let event = chain.create_event(
                                        create_timestamp(),
                                        AuditDirection::Inbound,
                                        req_method.to_string(),
                                        sanitized_tool.clone(),
                                        None,
                                        Some(sanitized_decision.clone()),
                                        Some("Deny".to_string()),
                                        Some(sanitized_payload.clone()),
                                        None,
                                    );
                                    let _ = append_audit_file(log_p, &event).await;
                                }
                                if !is_notification {
                                    let out_line = if req_method == "tools/call" {
                                        let tool_err = mcp_moat_core::JsonRpcResponse::tool_error_result(req_id, "Action was rejected by operator in prompt");
                                        format!("{}\n", serde_json::to_string(&tool_err)?)
                                    } else {
                                        let err_obj = json!({
                                            "jsonrpc": "2.0",
                                            "id": req_id,
                                            "error": {
                                                "code": -32002,
                                                "message": "[moat] Action rejected by operator"
                                            }
                                        });
                                        format!("{}\n", serde_json::to_string(&err_obj)?)
                                    };
                                    let mut out = stdout.lock().await;
                                    out.write_all(out_line.as_bytes()).await?;
                                    out.flush().await?;
                                }
                                stdin_line.clear();
                                continue;
                            } else if let Some(ref log_p) = self.audit_path {
                                let mut chain = self.audit_chain.lock().await;
                                let event = chain.create_event(
                                    create_timestamp(),
                                    AuditDirection::Inbound,
                                    req_method.to_string(),
                                    sanitized_tool.clone(),
                                    None,
                                    Some(sanitized_decision.clone()),
                                    Some("AllowOnce".to_string()),
                                    Some(sanitized_payload.clone()),
                                    None,
                                );
                                let _ = append_audit_file(log_p, &event).await;
                            }
                        }
                        Decision::Allow => {}
                    }

                    // Send POST upstream
                    let (_, upstream_resp) = match send_http_post(
                        &self.target_url.host,
                        self.target_url.port,
                        &upstream_post_endpoint,
                        trimmed.as_bytes(),
                    ).await {
                        Ok(res) => res,
                        Err(e) => {
                            warn!("[moat] Failed forwarding request upstream: {}", e);
                            if !is_notification {
                                let err_obj = json!({
                                    "jsonrpc": "2.0",
                                    "id": req_id,
                                    "error": {
                                        "code": -32603,
                                        "message": format!("[moat] Upstream communication error: {}", e)
                                    }
                                });
                                let out_line = format!("{}\n", serde_json::to_string(&err_obj)?);
                                let mut out = stdout.lock().await;
                                out.write_all(out_line.as_bytes()).await?;
                                out.flush().await?;
                            }
                            stdin_line.clear();
                            continue;
                        }
                    };

                    if !upstream_resp.is_empty() {
                        let (final_resp, redactions) = if let Ok(resp_str) = std::str::from_utf8(&upstream_resp) {
                            let (sanitized_str, red) = self.dlp.sanitize_line(resp_str);
                            let (optimized_str, _) = TokenOptimizer::optimize_line(&sanitized_str, &self.policy);
                            (optimized_str.into_bytes(), red)
                        } else {
                            (upstream_resp, 0)
                        };

                        if redactions > 0 {
                            if let Some(ref log_p) = self.audit_path {
                                let mut chain = self.audit_chain.lock().await;
                                let event = chain.create_event(
                                    create_timestamp(),
                                    AuditDirection::Outbound,
                                    req_method.to_string(),
                                    tool_name,
                                    None,
                                    Some(AuditDecision::Allow),
                                    None,
                                    Some(String::from_utf8_lossy(&final_resp).to_string()),
                                    Some(redactions),
                                );
                                let _ = append_audit_file(log_p, &event).await;
                            }
                        }

                        let out_line = format!("{}\n", String::from_utf8_lossy(&final_resp));
                        let mut out = stdout.lock().await;
                        out.write_all(out_line.as_bytes()).await?;
                        out.flush().await?;
                    }

                    stdin_line.clear();
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("[moat] SSE Bridge received Ctrl+C shutdown signal. Exiting gracefully.");
                    break;
                }
                _ = crate::wait_for_sigterm() => {
                    info!("[moat] SSE Bridge received SIGTERM shutdown signal. Exiting gracefully.");
                    break;
                }
            }
        }

        Ok(())
    }
}

async fn append_audit_file(path: &PathBuf, event: &AuditEvent) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    let line = serde_json::to_string(event)?;
    let entry = format!("{}\n", line);
    file.write_all(entry.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}
