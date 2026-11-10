use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};
use tracing::{debug, error, info, warn};

use mcp_moat_core::audit::{AuditChain, AuditDecision, AuditDirection, AuditLevel};
use mcp_moat_core::{
    Decision, DlpEngine, JsonRpcRequest, JsonRpcResponse, PolicyEngine, TokenOptimizer,
};
use mcp_moat_tty::{ApprovalDecision, DirectConsole, SessionApprovalCache};

const MAX_FRAME_LIMIT: usize = 16 * 1024 * 1024; // 16 MB Frame-Limit

/// Returns the three piped child handles, or an error naming the missing one.
fn require_child_pipes<I, O, E>(
    stdin: Option<I>,
    stdout: Option<O>,
    stderr: Option<E>,
) -> anyhow::Result<(I, O, E)> {
    let stdin = stdin.ok_or_else(|| anyhow::anyhow!("Failed to open child stdin"))?;
    let stdout = stdout.ok_or_else(|| anyhow::anyhow!("Failed to open child stdout"))?;
    let stderr = stderr.ok_or_else(|| anyhow::anyhow!("Failed to open child stderr"))?;
    Ok((stdin, stdout, stderr))
}

fn get_exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(1))
    }

    #[cfg(not(unix))]
    {
        status.code().unwrap_or(1)
    }
}

type BoxedAsyncRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxedAsyncWrite = Box<dyn AsyncWrite + Unpin + Send>;

pub struct ProxyServer {
    policy: Arc<PolicyEngine>,
    dlp: Arc<DlpEngine>,
    console: Arc<Mutex<Option<DirectConsole>>>,
    session_cache: Arc<Mutex<SessionApprovalCache>>,
    audit_chain: Arc<std::sync::Mutex<AuditChain>>,
    audit_path: Option<PathBuf>,
    audit_level: AuditLevel,
    audit_write_lock: Arc<std::sync::Mutex<()>>,
    custom_in: Arc<Mutex<Option<BoxedAsyncRead>>>,
    custom_out: Arc<Mutex<Option<BoxedAsyncWrite>>>,
    custom_err: Arc<Mutex<Option<BoxedAsyncWrite>>>,
}

impl ProxyServer {
    pub fn new(policy: PolicyEngine) -> Self {
        let console = match DirectConsole::open() {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("Could not open direct TTY console: {}. Interactive approvals will be skipped or auto-denied.", e);
                None
            }
        };

        let audit_path = policy.config().audit_log.clone();
        let audit_level = policy.config().audit_level;
        let session_id = crate::new_session_id("sess");

        Self {
            policy: Arc::new(policy),
            dlp: Arc::new(DlpEngine::new()),
            console: Arc::new(Mutex::new(console)),
            session_cache: Arc::new(Mutex::new(SessionApprovalCache::new())),
            audit_chain: Arc::new(std::sync::Mutex::new(AuditChain::new(session_id))),
            audit_path,
            audit_level,
            audit_write_lock: Arc::new(std::sync::Mutex::new(())),
            custom_in: Arc::new(Mutex::new(None)),
            custom_out: Arc::new(Mutex::new(None)),
            custom_err: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_console(policy: PolicyEngine, console: Option<DirectConsole>) -> Self {
        let audit_path = policy.config().audit_log.clone();
        let audit_level = policy.config().audit_level;
        let session_id = crate::new_session_id("sess");

        Self {
            policy: Arc::new(policy),
            dlp: Arc::new(DlpEngine::new()),
            console: Arc::new(Mutex::new(console)),
            session_cache: Arc::new(Mutex::new(SessionApprovalCache::new())),
            audit_chain: Arc::new(std::sync::Mutex::new(AuditChain::new(session_id))),
            audit_path,
            audit_level,
            audit_write_lock: Arc::new(std::sync::Mutex::new(())),
            custom_in: Arc::new(Mutex::new(None)),
            custom_out: Arc::new(Mutex::new(None)),
            custom_err: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_audit(mut self, path: PathBuf, level: AuditLevel) -> Self {
        self.audit_path = Some(path);
        self.audit_level = level;
        self
    }

    pub fn session_cache(&self) -> Arc<Mutex<SessionApprovalCache>> {
        Arc::clone(&self.session_cache)
    }

    /// Sets custom I/O streams (useful for integration tests or embedding)
    pub fn with_io<R, W, E>(mut self, stdin: R, stdout: W, stderr: E) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        E: AsyncWrite + Unpin + Send + 'static,
    {
        // Replace the slots instead of locking them, so this cannot panic if a slot is held elsewhere.
        self.custom_in = Arc::new(Mutex::new(Some(Box::new(stdin))));
        self.custom_out = Arc::new(Mutex::new(Some(Box::new(stdout))));
        self.custom_err = Arc::new(Mutex::new(Some(Box::new(stderr))));
        self
    }

    /// Spawns the wrapped MCP server command and intercepts communication via configured or default stdio
    pub async fn wrap_and_run(&self, command: &str, args: &[String]) -> anyhow::Result<i32> {
        let client_in: BoxedAsyncRead = {
            let mut guard = self.custom_in.lock().await;
            guard.take().unwrap_or_else(|| Box::new(tokio::io::stdin()))
        };
        let client_out: BoxedAsyncWrite = {
            let mut guard = self.custom_out.lock().await;
            guard
                .take()
                .unwrap_or_else(|| Box::new(tokio::io::stdout()))
        };
        let client_err: BoxedAsyncWrite = {
            let mut guard = self.custom_err.lock().await;
            guard
                .take()
                .unwrap_or_else(|| Box::new(tokio::io::stderr()))
        };

        self.wrap_and_run_streams(command, args, client_in, client_out, client_err)
            .await
    }

    /// Intercepts communication between custom client streams and the wrapped child MCP server
    pub async fn wrap_and_run_streams<R, W, E>(
        &self,
        command: &str,
        args: &[String],
        client_in: R,
        client_out: W,
        client_err: E,
    ) -> anyhow::Result<i32>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        E: AsyncWrite + Unpin + Send + 'static,
    {
        info!("Spawning protected MCP server: {} {:?}", command, args);

        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn wrapped command '{}': {}", command, e))?;

        let (child_stdin, child_stdout, child_stderr) =
            match require_child_pipes(child.stdin.take(), child.stdout.take(), child.stderr.take())
            {
                Ok(pipes) => pipes,
                Err(e) => {
                    // Fail closed: do not leave an unsupervised child running.
                    let _ = child.start_kill();
                    return Err(e);
                }
            };

        let client_out_writer = Arc::new(Mutex::new(client_out));

        // Child Stdin Writer Task with Ping-Bypass (Priority vs Normal queue)
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel::<String>(100);
        let (normal_tx, mut normal_rx) = tokio::sync::mpsc::channel::<String>(1000);

        let child_stdin_handle = tokio::spawn(async move {
            let mut writer = child_stdin;
            loop {
                tokio::select! {
                    biased;
                    Some(line) = priority_rx.recv() => {
                        if let Err(e) = writer.write_all(line.as_bytes()).await {
                            debug!("Failed writing priority ping to child stdin: {}", e);
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            debug!("Failed flushing priority ping to child stdin: {}", e);
                            break;
                        }
                    }
                    Some(line) = normal_rx.recv() => {
                        if let Err(e) = writer.write_all(line.as_bytes()).await {
                            debug!("Failed writing normal line to child stdin: {}", e);
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            debug!("Failed flushing normal line to child stdin: {}", e);
                            break;
                        }
                    }
                    else => break,
                }
            }
        });

        // Audit writes are serialized and acknowledged before the caller can forward an action.
        let audit_failed = Arc::new(AtomicBool::new(false));
        let log_event = {
            let audit_path = self.audit_path.clone();
            let chain_ref = Arc::clone(&self.audit_chain);
            let write_lock = Arc::clone(&self.audit_write_lock);
            let audit_level = self.audit_level;
            let dlp_ref = Arc::clone(&self.dlp);
            let audit_failed_for_logger = Arc::clone(&audit_failed);

            Arc::new(
                move |direction: AuditDirection,
                      method: String,
                      tool_name: Option<String>,
                      target_path: Option<String>,
                      decision: Option<AuditDecision>,
                      operator_decision: Option<String>,
                      raw_payload: Option<String>,
                      dlp_redactions: Option<usize>| {
                    let audit_path = audit_path.clone();
                    let chain_ref = Arc::clone(&chain_ref);
                    let write_lock = Arc::clone(&write_lock);
                    let dlp_ref = Arc::clone(&dlp_ref);
                    let Some(path) = audit_path else {
                        return true;
                    };
                    if audit_failed_for_logger.load(Ordering::Acquire) {
                        return false;
                    }

                    let should_log = match audit_level {
                        AuditLevel::Full => true,
                        AuditLevel::DecisionsOnly => decision.is_some(),
                        AuditLevel::ViolationsOnly => {
                            decision.as_ref().map(|d| d.is_violation()).unwrap_or(false)
                                || operator_decision.as_deref() == Some("Deny")
                                || dlp_redactions.unwrap_or(0) > 0
                        }
                    };

                    if !should_log {
                        return true;
                    }

                    let dlp_payload = raw_payload.map(|p| {
                        let (sanitized, _) = dlp_ref.sanitize_line(&p);
                        sanitized
                    });

                    // Sanitize decision contents (Block reason, AskOperator summary) to prevent leaking secrets in audit log
                    let sanitized_decision = decision.map(|d| match d {
                        AuditDecision::Allow => AuditDecision::Allow,
                        AuditDecision::Block { reason } => {
                            let (sanitized_reason, _) = dlp_ref.sanitize_text(&reason);
                            AuditDecision::Block {
                                reason: sanitized_reason,
                            }
                        }
                        AuditDecision::AskOperator { summary } => {
                            let (sanitized_summary, _) = dlp_ref.sanitize_text(&summary);
                            AuditDecision::AskOperator {
                                summary: sanitized_summary,
                            }
                        }
                    });

                    let sanitized_target_path = target_path.map(|p| {
                        let (sanitized, _) = dlp_ref.sanitize_text(&p);
                        sanitized
                    });

                    let now_sec = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let timestamp = format!("{}Z", now_sec);

                    let _write_guard = write_lock.lock().unwrap_or_else(|e| e.into_inner());
                    let event = {
                        let mut chain = chain_ref.lock().unwrap_or_else(|e| e.into_inner());
                        chain.create_event(
                            timestamp,
                            direction,
                            method,
                            tool_name,
                            sanitized_target_path,
                            sanitized_decision,
                            operator_decision,
                            dlp_payload,
                            dlp_redactions,
                        )
                    };
                    if let Some(parent) = path.parent() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            error!("Audit log directory could not be created: {}", e);
                            audit_failed_for_logger.store(true, Ordering::Release);
                            return false;
                        }
                    }
                    let json_line = match serde_json::to_string(&event) {
                        Ok(line) => line,
                        Err(e) => {
                            error!("Audit event serialization failed: {}", e);
                            audit_failed_for_logger.store(true, Ordering::Release);
                            return false;
                        }
                    };
                    let mut file = match std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        Ok(file) => file,
                        Err(e) => {
                            error!("Audit log could not be opened: {}", e);
                            audit_failed_for_logger.store(true, Ordering::Release);
                            return false;
                        }
                    };
                    if let Err(e) =
                        std::io::Write::write_all(&mut file, format!("{}\n", json_line).as_bytes())
                    {
                        error!("Audit log write failed: {}", e);
                        audit_failed_for_logger.store(true, Ordering::Release);
                        return false;
                    }
                    if let Err(e) = std::io::Write::flush(&mut file) {
                        error!("Audit log flush failed: {}", e);
                        audit_failed_for_logger.store(true, Ordering::Release);
                        return false;
                    }
                    true
                },
            )
        };

        // Task 1: Inbound stream (LLM Client in -> Child MCP server stdin)
        let policy = Arc::clone(&self.policy);
        let console = Arc::clone(&self.console);
        let session_cache = Arc::clone(&self.session_cache);
        let client_out_for_inbound = Arc::clone(&client_out_writer);
        let priority_tx_clone = priority_tx.clone();
        let normal_tx_clone = normal_tx.clone();
        let log_inbound = log_event.clone();
        let has_audit = self.audit_path.is_some();
        let audit_failed_for_inbound = Arc::clone(&audit_failed);

        let inbound_handle = tokio::spawn(async move {
            let mut framed_in =
                FramedRead::new(client_in, LinesCodec::new_with_max_length(MAX_FRAME_LIMIT));
            let mut ping_window_start = std::time::Instant::now();
            let mut ping_count_in_window = 0usize;
            let audit_ok_flag = Arc::clone(&audit_failed_for_inbound);
            let audit_ok = move || !audit_ok_flag.load(Ordering::Acquire);

            while let Some(line_res) = framed_in.next().await {
                match line_res {
                    Ok(line) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        debug!("Inbound line from client: {}", trimmed);

                        // Reject JSON-RPC batch arrays immediately (Fail-Closed, -32600)
                        if trimmed.starts_with('[') {
                            if has_audit {
                                log_inbound(
                                    AuditDirection::Inbound,
                                    "batch".to_string(),
                                    None,
                                    None,
                                    Some(AuditDecision::Block {
                                        reason: "Batch requests are not supported".to_string(),
                                    }),
                                    None,
                                    Some(trimmed.to_string()),
                                    None,
                                );
                            }
                            if !audit_ok() {
                                continue;
                            }

                            let err_resp = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": null,
                                "error": {
                                    "code": -32600,
                                    "message": "Batch requests are not supported by mcp-moat"
                                }
                            });
                            let mut out = client_out_for_inbound.lock().await;
                            let _ = out.write_all(format!("{}\n", err_resp).as_bytes()).await;
                            let _ = out.flush().await;
                            continue;
                        }

                        // Strict JSON-RPC Deserialization (Fail-Closed: -32600 for Invalid Request, -32700 for Parse error)
                        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
                            Ok(r) => r,
                            Err(e) => {
                                let (err_code, err_name) =
                                    match serde_json::from_str::<serde_json::Value>(trimmed) {
                                        Ok(_) => (-32600, "Invalid Request"),
                                        Err(_) => (-32700, "Parse error"),
                                    };
                                warn!(
                                    "Rejecting malformed JSON-RPC line from client: {} ({})",
                                    e, err_name
                                );
                                if has_audit {
                                    log_inbound(
                                        AuditDirection::Inbound,
                                        "parse_error".to_string(),
                                        None,
                                        None,
                                        Some(AuditDecision::Block {
                                            reason: format!("{}: {}", err_name, e),
                                        }),
                                        None,
                                        Some(trimmed.to_string()),
                                        None,
                                    );
                                }
                                if !audit_ok() {
                                    continue;
                                }

                                let err_resp = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": null,
                                    "error": {
                                        "code": err_code,
                                        "message": format!("{}: {}", err_name, e)
                                    }
                                });
                                let mut out = client_out_for_inbound.lock().await;
                                let _ = out.write_all(format!("{}\n", err_resp).as_bytes()).await;
                                let _ = out.flush().await;
                                continue;
                            }
                        };

                        // Validate JSON-RPC 2.0 version
                        if req.jsonrpc != "2.0" {
                            warn!(
                                "Rejecting request with invalid jsonrpc version: '{}'",
                                req.jsonrpc
                            );
                            if !req.is_notification() {
                                let err_resp = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": req.id,
                                    "error": {
                                        "code": -32600,
                                        "message": format!("Invalid Request: jsonrpc must be '2.0', got '{}'", req.jsonrpc)
                                    }
                                });
                                let mut out = client_out_for_inbound.lock().await;
                                let _ = out.write_all(format!("{}\n", err_resp).as_bytes()).await;
                                let _ = out.flush().await;
                            }
                            continue;
                        }

                        // Ping-Bypass: Keepalive-Pings ("ping") overtake waiting tool-calls via priority bypass
                        if req.method == "ping" {
                            let now = std::time::Instant::now();
                            if now.duration_since(ping_window_start) >= Duration::from_secs(1) {
                                ping_window_start = now;
                                ping_count_in_window = 0;
                            }
                            ping_count_in_window += 1;

                            debug!("Ping keepalive request detected; dispatching");
                            if has_audit {
                                log_inbound(
                                    AuditDirection::Inbound,
                                    "ping".to_string(),
                                    None,
                                    None,
                                    Some(AuditDecision::Allow),
                                    None,
                                    None,
                                    None,
                                );
                            }
                            if !audit_ok() {
                                continue;
                            }

                            // If ping rate is within safe keepalive threshold (<= 25 pings/sec), dispatch via priority bypass.
                            // If flooded (> 25 pings/sec), dispatch via normal queue to prevent priority starvation!
                            if ping_count_in_window <= 25 {
                                if !audit_ok() {
                                    continue;
                                }
                                let _ = priority_tx_clone.send(format!("{}\n", trimmed)).await;
                            } else {
                                warn!("Excessive ping rate ({} pings/s); routing to normal queue to prevent priority starvation", ping_count_in_window);
                                if !audit_ok() {
                                    continue;
                                }
                                let _ = normal_tx_clone.send(format!("{}\n", trimmed)).await;
                            }
                            continue;
                        }

                        // Tool-Call Interception & Policy Enforcement
                        if req.is_tool_call() {
                            let tool_call = match req.parse_tool_call() {
                                Some(tc) => tc,
                                None => {
                                    warn!("tools/call request missing name or valid params");
                                    if has_audit {
                                        log_inbound(
                                            AuditDirection::Inbound,
                                            "tools/call".to_string(),
                                            None,
                                            None,
                                            Some(AuditDecision::Block {
                                                reason: "Invalid params: 'name' is required for tools/call".to_string(),
                                            }),
                                            None,
                                            Some(trimmed.to_string()),
                                            None,
                                        );
                                    }

                                    if !req.is_notification() {
                                        let err_resp = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": req.id,
                                            "error": {
                                                "code": -32602,
                                                "message": "Invalid params: 'name' is required for tools/call"
                                            }
                                        });
                                        let mut out = client_out_for_inbound.lock().await;
                                        let _ = out
                                            .write_all(format!("{}\n", err_resp).as_bytes())
                                            .await;
                                        let _ = out.flush().await;
                                    }
                                    continue;
                                }
                            };

                            let decision = policy.evaluate_tool_call(&tool_call);
                            match decision {
                                Decision::Allow => {
                                    if has_audit {
                                        log_inbound(
                                            AuditDirection::Inbound,
                                            "tools/call".to_string(),
                                            Some(tool_call.name.clone()),
                                            None,
                                            Some(AuditDecision::Allow),
                                            None,
                                            Some(trimmed.to_string()),
                                            None,
                                        );
                                    }
                                    if !audit_ok() {
                                        continue;
                                    }
                                    let _ = normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                }
                                Decision::Block(reason) => {
                                    if policy.config().monitor_mode {
                                        eprintln!(
                                            "[mcp-moat:MONITOR] Simulated BLOCK for tool '{}': {}. Forwarding request.",
                                            tool_call.name, reason
                                        );
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                "tools/call".to_string(),
                                                Some(tool_call.name.clone()),
                                                None,
                                                Some(AuditDecision::Block { reason }),
                                                Some("MonitorForwarded".to_string()),
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }
                                        if !audit_ok() {
                                            continue;
                                        }
                                        let _ =
                                            normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                    } else {
                                        warn!("Blocked tool call '{}': {}", tool_call.name, reason);
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                "tools/call".to_string(),
                                                Some(tool_call.name.clone()),
                                                None,
                                                Some(AuditDecision::Block {
                                                    reason: reason.clone(),
                                                }),
                                                None,
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }
                                        if !req.is_notification() {
                                            let error_resp =
                                                JsonRpcResponse::tool_error_result(req.id, reason);
                                            if let Ok(resp_json) =
                                                serde_json::to_string(&error_resp)
                                            {
                                                let mut out = client_out_for_inbound.lock().await;
                                                let _ = out
                                                    .write_all(
                                                        format!("{}\n", resp_json).as_bytes(),
                                                    )
                                                    .await;
                                                let _ = out.flush().await;
                                            }
                                        }
                                    }
                                }
                                Decision::AskOperator {
                                    tool_name,
                                    target_path,
                                    action_summary,
                                } => {
                                    if policy.config().monitor_mode {
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                "tools/call".to_string(),
                                                Some(tool_name),
                                                target_path
                                                    .as_ref()
                                                    .map(|p| p.display().to_string()),
                                                Some(AuditDecision::AskOperator {
                                                    summary: action_summary,
                                                }),
                                                Some("MonitorBypass".to_string()),
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }
                                        if !audit_ok() {
                                            continue;
                                        }
                                        let _ =
                                            normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                        continue;
                                    }

                                    // 1. Check Session Approval Cache first
                                    let is_cmd =
                                        policy.extract_command_argument(&tool_call).is_some()
                                            || SessionApprovalCache::is_shell_tool(&tool_name);
                                    let is_protected_target = target_path
                                        .as_ref()
                                        .map(|p| policy.is_protected_target(p))
                                        .unwrap_or(false)
                                        || action_summary.contains("protected configuration");

                                    let is_already_approved = {
                                        let cache = session_cache.lock().await;
                                        if is_protected_target || is_cmd {
                                            cache.is_action_allowed(&action_summary)
                                        } else {
                                            cache.is_allowed(&tool_name, Some(&action_summary))
                                        }
                                    };

                                    if is_already_approved {
                                        debug!(
                                            "Action '{}' is already allowed by session cache",
                                            tool_name
                                        );
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                "tools/call".to_string(),
                                                Some(tool_name.clone()),
                                                target_path
                                                    .as_ref()
                                                    .map(|p| p.display().to_string()),
                                                Some(AuditDecision::Allow),
                                                Some("SessionCache".to_string()),
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }
                                        if !audit_ok() {
                                            continue;
                                        }
                                        let _ =
                                            normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                        continue;
                                    }

                                    // 2. Extract content parameters for diff preview (deferred to spawn_blocking)
                                    let diff_target = target_path.clone();
                                    let diff_content = tool_call
                                        .arguments
                                        .as_ref()
                                        .and_then(|a| {
                                            a.get("content").or_else(|| a.get("new_content"))
                                        })
                                        .and_then(|c| c.as_str())
                                        .map(String::from);

                                    info!("Requesting operator approval for tool: {}", tool_name);
                                    let console_ref = Arc::clone(&console);
                                    let session_cache_ref = Arc::clone(&session_cache);
                                    let normal_tx_approval = normal_tx_clone.clone();
                                    let client_out_approval = Arc::clone(&client_out_for_inbound);
                                    let req_id = req.id.clone();
                                    let is_notification = req.is_notification();
                                    let forward_line = format!("{}\n", trimmed);
                                    let tool_name_cloned = tool_name.clone();
                                    let target_path_str =
                                        target_path.as_ref().map(|p| p.display().to_string());
                                    let action_summary_clone = action_summary.clone();
                                    let log_approval = log_inbound.clone();
                                    let audit_failed_for_approval =
                                        Arc::clone(&audit_failed_for_inbound);
                                    let trimmed_clone = if has_audit {
                                        Some(trimmed.to_string())
                                    } else {
                                        None
                                    };

                                    tokio::spawn(async move {
                                        let session_cache_for_prompt =
                                            Arc::clone(&session_cache_ref);
                                        let tool_name_for_prompt = tool_name_cloned.clone();
                                        let action_summary_for_prompt =
                                            action_summary_clone.clone();

                                        let decision = tokio::task::spawn_blocking(move || {
                                            // Perform disk I/O and Myers diff in dedicated blocking threadpool
                                            let diff_preview = if let (Some(path), Some(content)) =
                                                (&diff_target, &diff_content)
                                            {
                                                mcp_moat_tty::diff_for_file(path, content).ok()
                                            } else {
                                                None
                                            };

                                            let mut guard = console_ref.blocking_lock();

                                            // Re-check session cache after acquiring console lock:
                                            // A concurrent request might have been approved with AllowAlways in the meantime!
                                            {
                                                let cache =
                                                    session_cache_for_prompt.blocking_lock();
                                                let allowed = if is_protected_target || is_cmd {
                                                    cache.is_action_allowed(
                                                        &action_summary_for_prompt,
                                                    )
                                                } else {
                                                    cache.is_allowed(
                                                        &tool_name_for_prompt,
                                                        Some(&action_summary_for_prompt),
                                                    )
                                                };
                                                if allowed {
                                                    return ApprovalDecision::AllowAlways;
                                                }
                                            }

                                            if let Some(c) = guard.as_mut() {
                                                c.ask_approval_detailed(
                                                    &action_summary_clone,
                                                    diff_preview.as_deref(),
                                                )
                                                .unwrap_or(ApprovalDecision::Deny)
                                            } else {
                                                ApprovalDecision::Deny
                                            }
                                        })
                                        .await
                                        .unwrap_or(ApprovalDecision::Deny);

                                        match decision {
                                            ApprovalDecision::AllowOnce => {
                                                if has_audit {
                                                    log_approval(
                                                        AuditDirection::Inbound,
                                                        "tools/call".to_string(),
                                                        Some(tool_name_cloned),
                                                        target_path_str,
                                                        Some(AuditDecision::AskOperator {
                                                            summary: action_summary,
                                                        }),
                                                        Some("AllowOnce".to_string()),
                                                        trimmed_clone,
                                                        None,
                                                    );
                                                }
                                                if !audit_failed_for_approval
                                                    .load(Ordering::Acquire)
                                                {
                                                    let _ =
                                                        normal_tx_approval.send(forward_line).await;
                                                }
                                            }
                                            ApprovalDecision::AllowAlways => {
                                                {
                                                    let mut cache = session_cache_ref.lock().await;
                                                    if is_cmd || is_protected_target {
                                                        cache.allow_action(&action_summary);
                                                    } else {
                                                        cache.allow_always(
                                                            &tool_name_cloned,
                                                            Some(&action_summary),
                                                        );
                                                    }
                                                }
                                                info!(
                                                    "Added tool/action for '{}' to session approval cache",
                                                    tool_name_cloned
                                                );
                                                if has_audit {
                                                    log_approval(
                                                        AuditDirection::Inbound,
                                                        "tools/call".to_string(),
                                                        Some(tool_name_cloned),
                                                        target_path_str,
                                                        Some(AuditDecision::AskOperator {
                                                            summary: action_summary,
                                                        }),
                                                        Some("AllowAlways".to_string()),
                                                        trimmed_clone,
                                                        None,
                                                    );
                                                }
                                                if !audit_failed_for_approval
                                                    .load(Ordering::Acquire)
                                                {
                                                    let _ =
                                                        normal_tx_approval.send(forward_line).await;
                                                }
                                            }
                                            ApprovalDecision::Deny => {
                                                warn!(
                                                    "Operator rejected action: {}",
                                                    tool_name_cloned
                                                );
                                                if has_audit {
                                                    log_approval(
                                                        AuditDirection::Inbound,
                                                        "tools/call".to_string(),
                                                        Some(tool_name_cloned),
                                                        target_path_str,
                                                        Some(AuditDecision::AskOperator {
                                                            summary: action_summary,
                                                        }),
                                                        Some("Deny".to_string()),
                                                        trimmed_clone,
                                                        None,
                                                    );
                                                }
                                                if !is_notification {
                                                    let error_resp = JsonRpcResponse::tool_error_result(
                                                        req_id,
                                                        "Action was rejected by operator in prompt",
                                                    );
                                                    if let Ok(resp_json) =
                                                        serde_json::to_string(&error_resp)
                                                    {
                                                        let mut out =
                                                            client_out_approval.lock().await;
                                                        let _ = out
                                                            .write_all(
                                                                format!("{}\n", resp_json)
                                                                    .as_bytes(),
                                                            )
                                                            .await;
                                                        let _ = out.flush().await;
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                            continue;
                        }

                        // Resource-Call Interception & Policy Enforcement (resources/read, resources/subscribe)
                        if req.is_resource_call() {
                            let resource_params = match req.parse_resource_call() {
                                Some(rp) => rp,
                                None => {
                                    warn!("Resource call missing valid params.uri");
                                    if has_audit {
                                        log_inbound(
                                            AuditDirection::Inbound,
                                            req.method.clone(),
                                            None,
                                            None,
                                            Some(AuditDecision::Block {
                                                reason: "Invalid params: 'uri' is required for resource call".to_string(),
                                            }),
                                            None,
                                            Some(trimmed.to_string()),
                                            None,
                                        );
                                    }

                                    if !req.is_notification() {
                                        let err_resp = serde_json::json!({
                                            "jsonrpc": "2.0",
                                            "id": req.id,
                                            "error": {
                                                "code": -32602,
                                                "message": "Invalid params: 'uri' is required for resource call"
                                            }
                                        });
                                        let mut out = client_out_for_inbound.lock().await;
                                        let _ = out
                                            .write_all(format!("{}\n", err_resp).as_bytes())
                                            .await;
                                        let _ = out.flush().await;
                                    }
                                    continue;
                                }
                            };

                            let decision = policy.evaluate_resource_read(&resource_params.uri);
                            match decision {
                                Decision::Allow => {
                                    if has_audit {
                                        log_inbound(
                                            AuditDirection::Inbound,
                                            req.method.clone(),
                                            None,
                                            Some(resource_params.uri.clone()),
                                            Some(AuditDecision::Allow),
                                            None,
                                            Some(trimmed.to_string()),
                                            None,
                                        );
                                    }
                                    let _ = normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                }
                                Decision::Block(reason) => {
                                    if policy.config().monitor_mode {
                                        eprintln!(
                                            "[mcp-moat:MONITOR] Simulated BLOCK for resource '{}': {}. Forwarding request.",
                                            resource_params.uri, reason
                                        );
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                req.method.clone(),
                                                None,
                                                Some(resource_params.uri.clone()),
                                                Some(AuditDecision::Block {
                                                    reason: reason.clone(),
                                                }),
                                                Some("MonitorForwarded".to_string()),
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }
                                        if !audit_ok() {
                                            continue;
                                        }
                                        let _ =
                                            normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                    } else {
                                        warn!(
                                            "Blocking resource request for '{}': {}",
                                            resource_params.uri, reason
                                        );
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                req.method.clone(),
                                                None,
                                                Some(resource_params.uri.clone()),
                                                Some(AuditDecision::Block {
                                                    reason: reason.clone(),
                                                }),
                                                None,
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }

                                        if !req.is_notification() {
                                            let err_resp = serde_json::json!({
                                                "jsonrpc": "2.0",
                                                "id": req.id,
                                                "error": {
                                                    "code": -32001,
                                                    "message": format!("Policy violation: {}", reason)
                                                }
                                            });
                                            let mut out = client_out_for_inbound.lock().await;
                                            let _ = out
                                                .write_all(format!("{}\n", err_resp).as_bytes())
                                                .await;
                                            let _ = out.flush().await;
                                        }
                                    }
                                }
                                Decision::AskOperator { action_summary, .. } => {
                                    if policy.config().monitor_mode {
                                        eprintln!(
                                            "[mcp-moat:MONITOR] Bypassing prompt for resource '{}' ({}). Forwarding request.",
                                            resource_params.uri, action_summary
                                        );
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                req.method.clone(),
                                                None,
                                                Some(resource_params.uri.clone()),
                                                Some(AuditDecision::AskOperator {
                                                    summary: action_summary.clone(),
                                                }),
                                                Some("MonitorBypass".to_string()),
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }
                                        let _ =
                                            normal_tx_clone.send(format!("{}\n", trimmed)).await;
                                    } else {
                                        warn!(
                                            "Rejecting unapproved resource access for '{}': {}",
                                            resource_params.uri, action_summary
                                        );
                                        if has_audit {
                                            log_inbound(
                                                AuditDirection::Inbound,
                                                req.method.clone(),
                                                None,
                                                Some(resource_params.uri.clone()),
                                                Some(AuditDecision::AskOperator {
                                                    summary: action_summary.clone(),
                                                }),
                                                Some("Deny".to_string()),
                                                Some(trimmed.to_string()),
                                                None,
                                            );
                                        }

                                        if !req.is_notification() {
                                            let err_resp = serde_json::json!({
                                                "jsonrpc": "2.0",
                                                "id": req.id,
                                                "error": {
                                                    "code": -32002,
                                                    "message": format!("Access denied: {}", action_summary)
                                                }
                                            });
                                            let mut out = client_out_for_inbound.lock().await;
                                            let _ = out
                                                .write_all(format!("{}\n", err_resp).as_bytes())
                                                .await;
                                            let _ = out.flush().await;
                                        }
                                    }
                                }
                            }
                            continue;
                        }

                        // Forward other standard JSON-RPC methods (initialize, tools/list, etc.)
                        if has_audit {
                            log_inbound(
                                AuditDirection::Inbound,
                                req.method.clone(),
                                None,
                                None,
                                Some(AuditDecision::Allow),
                                None,
                                Some(trimmed.to_string()),
                                None,
                            );
                        }
                        if !audit_ok() {
                            continue;
                        }
                        let _ = normal_tx_clone.send(format!("{}\n", trimmed)).await;
                    }
                    Err(LinesCodecError::MaxLineLengthExceeded) => {
                        warn!("Rejecting frame exceeding 16MB frame limit");
                        if has_audit {
                            log_inbound(
                                AuditDirection::Inbound,
                                "frame_limit_exceeded".to_string(),
                                None,
                                None,
                                Some(AuditDecision::Block {
                                    reason: "Frame size exceeds 16MB limit".to_string(),
                                }),
                                None,
                                None,
                                None,
                            );
                        }

                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {
                                "code": -32700,
                                "message": "Parse error: Frame size exceeds maximum allowed limit (16MB)"
                            }
                        });
                        let mut out = client_out_for_inbound.lock().await;
                        let _ = out.write_all(format!("{}\n", err_resp).as_bytes()).await;
                        let _ = out.flush().await;
                    }
                    Err(e) => {
                        warn!("I/O or framing error from client input: {}", e);
                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {
                                "code": -32700,
                                "message": format!("Parse error: {}", e)
                            }
                        });
                        let mut out = client_out_for_inbound.lock().await;
                        let _ = out.write_all(format!("{}\n", err_resp).as_bytes()).await;
                        let _ = out.flush().await;
                    }
                }
            }
        });

        // Task 2: Outbound stream (Child MCP server stdout -> Client stdout) with AST-DLP Sanitization & Token Optimization
        let client_out_for_outbound = Arc::clone(&client_out_writer);
        let dlp_for_stdout = Arc::clone(&self.dlp);
        let policy_for_stdout = Arc::clone(&self.policy);
        let log_outbound = log_event.clone();
        let outbound_handle = tokio::spawn(async move {
            let mut framed_out = FramedRead::new(
                child_stdout,
                LinesCodec::new_with_max_length(MAX_FRAME_LIMIT),
            );

            while let Some(line_res) = framed_out.next().await {
                match line_res {
                    Ok(line) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        debug!("Outbound line from child MCP server: {}", trimmed);

                        // Run AST-DLP inspection & sanitization
                        let (sanitized_line, redactions) = dlp_for_stdout.sanitize_line(trimmed);
                        if redactions > 0 {
                            warn!(
                                "DLP Engine sanitized {} secret(s) in server stdout",
                                redactions
                            );
                            log_outbound(
                                AuditDirection::Outbound,
                                "dlp_redaction".to_string(),
                                None,
                                None,
                                None,
                                None,
                                Some(sanitized_line.clone()),
                                Some(redactions),
                            );
                        }

                        // Run Token-Moat schema compaction, tool pruning, and output context budget guard
                        let (final_line, token_stats) =
                            TokenOptimizer::optimize_line(&sanitized_line, &policy_for_stdout);
                        if token_stats.modified() {
                            debug!(
                                "TokenOptimizer saved {} bytes (tools_pruned={}, schemas_compacted={}, outputs_truncated={})",
                                token_stats.bytes_saved(),
                                token_stats.tools_pruned,
                                token_stats.schemas_compacted,
                                token_stats.outputs_truncated
                            );
                        }

                        let mut out = client_out_for_outbound.lock().await;
                        if let Err(e) = out.write_all(format!("{}\n", final_line).as_bytes()).await
                        {
                            error!("Failed writing to client stdout: {}", e);
                            break;
                        }
                        let _ = out.flush().await;
                    }
                    Err(LinesCodecError::MaxLineLengthExceeded) => {
                        error!("Server stdout frame exceeded 16MB limit");
                        log_outbound(
                            AuditDirection::Outbound,
                            "frame_limit_exceeded".to_string(),
                            None,
                            None,
                            Some(AuditDecision::Block {
                                reason: "Server stdout frame exceeded 16MB limit".to_string(),
                            }),
                            None,
                            None,
                            None,
                        );

                        let err_resp = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {
                                "code": -32700,
                                "message": "Parse error: Server stdout frame size exceeded maximum allowed limit (16MB)"
                            }
                        });
                        let mut out = client_out_for_outbound.lock().await;
                        let _ = out.write_all(format!("{}\n", err_resp).as_bytes()).await;
                        let _ = out.flush().await;
                    }
                    Err(e) => {
                        debug!("Child stdout stream ended or error: {}", e);
                        break;
                    }
                }
            }
        });

        // Task 3: Autonomous Stderr-Drain-Task (prevents OS kernel pipe buffer deadlocks)
        let dlp_for_stderr = Arc::clone(&self.dlp);
        let log_stderr = log_event.clone();
        let stderr_handle = tokio::spawn(async move {
            let mut framed_err = FramedRead::new(
                child_stderr,
                LinesCodec::new_with_max_length(MAX_FRAME_LIMIT),
            );
            let mut client_err = client_err;

            while let Some(line_res) = framed_err.next().await {
                match line_res {
                    Ok(line) => {
                        let (sanitized_line, redactions) = dlp_for_stderr.sanitize_line(&line);
                        if redactions > 0 {
                            warn!(
                                "DLP Engine sanitized {} secret(s) in server stderr",
                                redactions
                            );
                            log_stderr(
                                AuditDirection::Internal,
                                "stderr_dlp_redaction".to_string(),
                                None,
                                None,
                                None,
                                None,
                                Some(sanitized_line.clone()),
                                Some(redactions),
                            );
                        }

                        let write_data = format!("{}\n", sanitized_line);
                        let write_and_flush = async {
                            client_err.write_all(write_data.as_bytes()).await?;
                            client_err.flush().await
                        };
                        match tokio::time::timeout(Duration::from_millis(100), write_and_flush)
                            .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                debug!("Client stderr stream write failed: {}", e);
                                // Do not break: continuously drain child_stderr even if client_err is closed
                            }
                            Err(_) => {
                                warn!("Client stderr pipe stalled (>100ms); dropping frame to prevent child stderr deadlock");
                            }
                        }
                    }
                    Err(LinesCodecError::MaxLineLengthExceeded) => {
                        warn!("Server stderr frame exceeded 16MB limit, draining line");
                    }
                    Err(e) => {
                        debug!("Child stderr stream ended: {}", e);
                        break;
                    }
                }
            }
        });

        // Lifecycle management: wait for client input closure, child exit, or broken client stdout
        let mut inbound_handle = inbound_handle;
        let mut outbound_handle = outbound_handle;
        let exit_code = tokio::select! {
            status_res = child.wait() => {
                let status = status_res?;
                inbound_handle.abort();
                child_stdin_handle.abort();
                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                    let _ = outbound_handle.await;
                    let _ = stderr_handle.await;
                }).await;
                get_exit_code(status)
            }
            _ = &mut inbound_handle => {
                // Inbound stream finished (client closed stdin)
                // Drop writer senders so child_stdin writer task finishes and closes child stdin
                drop(priority_tx);
                drop(normal_tx);
                let _ = child_stdin_handle.await;
                let exit_code = match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                    Ok(Ok(status)) => get_exit_code(status),
                    Ok(Err(e)) => {
                        error!("Error waiting for child exit: {}", e);
                        1
                    }
                    Err(_) => {
                        warn!("Child MCP server did not exit within 3s grace period; killing child process");
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        1
                    }
                };
                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                    let _ = outbound_handle.await;
                    let _ = stderr_handle.await;
                }).await;
                exit_code
            }
            _ = &mut outbound_handle => {
                // Outbound stream ended (child stdout closed or client stdout failed)
                // Wait with a 3s grace period for child process to exit and propagate exit code
                inbound_handle.abort();
                child_stdin_handle.abort();
                let exit_code = match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                    Ok(Ok(status)) => get_exit_code(status),
                    Ok(Err(e)) => {
                        error!("Error waiting for child exit: {}", e);
                        1
                    }
                    Err(_) => {
                        warn!("Child MCP server did not exit within 3s grace period; killing child process");
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        1
                    }
                };
                let _ = tokio::time::timeout(Duration::from_millis(500), stderr_handle).await;
                exit_code
            }
            _ = tokio::signal::ctrl_c() => {
                warn!("Received SIGINT/Ctrl+C; terminating child MCP server cleanly");
                inbound_handle.abort();
                child_stdin_handle.abort();
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = tokio::time::timeout(Duration::from_millis(500), stderr_handle).await;
                130
            }
            _ = crate::wait_for_sigterm() => {
                warn!("Received SIGTERM; terminating child MCP server cleanly");
                inbound_handle.abort();
                child_stdin_handle.abort();
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = tokio::time::timeout(Duration::from_millis(500), stderr_handle).await;
                143
            }
        };

        Ok(exit_code)
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use mcp_moat_core::PolicyConfig;

    #[test]
    fn missing_child_stdin_is_an_error() {
        let r = require_child_pipes(None::<u8>, Some(1u8), Some(1u8));
        assert!(r.unwrap_err().to_string().contains("stdin"));
    }

    #[test]
    fn missing_child_stdout_is_an_error() {
        let r = require_child_pipes(Some(1u8), None::<u8>, Some(1u8));
        assert!(r.unwrap_err().to_string().contains("stdout"));
    }

    #[test]
    fn missing_child_stderr_is_an_error() {
        let r = require_child_pipes(Some(1u8), Some(1u8), None::<u8>);
        assert!(r.unwrap_err().to_string().contains("stderr"));
    }

    #[test]
    fn all_child_pipes_present_is_ok() {
        assert!(require_child_pipes(Some(1u8), Some(2u8), Some(3u8)).is_ok());
    }

    #[test]
    fn with_io_does_not_panic_when_a_slot_is_locked() {
        let policy = PolicyEngine::new(PolicyConfig::default()).unwrap();
        let server = ProxyServer::new(policy);
        let held = Arc::clone(&server.custom_in);
        let _guard = held.try_lock().unwrap();
        let _server = server.with_io(tokio::io::empty(), tokio::io::sink(), tokio::io::sink());
    }
}
