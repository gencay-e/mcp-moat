use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use mcp_moat_core::{
    verify_audit_log_with_options, AuditDecision, AuditEvent, AuditLevel, CodegenFormat,
    PolicyConfig, PolicyEngine, TokenOptimizer,
};
use mcp_moat_proxy::ProxyServer;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "moat",
    author = "Gencay",
    version,
    about = "Policy proxy for MCP servers: checks tool calls, masks known secret formats, optional audit log",
    long_about = "mcp-moat sits between an MCP client and an MCP server (stdio).\nIt checks tool calls against a policy, masks known secret formats in server output,\nasks the operator before sensitive actions and can write an audit log.\nIt is not a sandbox. See SECURITY.md for known limits."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Wrap and guard an MCP server command
    Wrap {
        /// Allowed root directory for filesystem access (can specify multiple)
        #[arg(long = "allow", short = 'a')]
        allow: Vec<PathBuf>,

        /// Enforce strict read-only mode (blocks any modifying tools)
        #[arg(long = "read-only")]
        read_only: bool,

        /// Automatically deny actions requiring operator approval without interactive TTY prompt
        #[arg(long = "no-prompt")]
        no_prompt: bool,

        /// Require explicit operator approval for writes within allowed directories
        #[arg(long = "require-approval")]
        require_approval: bool,

        /// Run in monitor-only / audit-only mode without blocking or prompting
        #[arg(long = "monitor", alias = "audit-only")]
        monitor: bool,

        /// File path for SHA-256 tamper-evident forensic audit log
        #[arg(long = "audit-log")]
        audit_log: Option<PathBuf>,

        /// Granularity of audit logging: full, decisions_only, or violations_only
        #[arg(long = "audit-level", value_parser = ["full", "decisions_only", "violations_only"])]
        audit_level: Option<String>,

        /// Preconfigured security preset (filesystem, git, fetch, sqlite, memory, postgres, playwright)
        #[arg(long = "preset", short = 'p')]
        preset: Option<String>,

        /// Compact outbound tool schemas and strip verbose metadata to save prompt tokens
        #[arg(long = "compact-schemas")]
        compact_schemas: bool,

        /// Maximum byte budget for tool/resource outputs before context-window truncation
        #[arg(long = "max-output-bytes")]
        max_output_bytes: Option<usize>,

        /// Hide and block specific tools from the LLM agent (can specify multiple)
        #[arg(long = "hide-tool")]
        hide_tool: Vec<String>,

        /// Path to custom moat.toml configuration file
        #[arg(long = "config", short = 'c')]
        config: Option<PathBuf>,

        /// The MCP server command and arguments to execute
        #[arg(raw = true, required = true)]
        server_command: Vec<String>,
    },

    /// Initialize a default moat.toml configuration file
    Init {
        /// Output path for configuration file
        #[arg(default_value = "moat.toml")]
        path: PathBuf,

        /// Overwrite file if it already exists
        #[arg(long = "force", short = 'f')]
        force: bool,
    },

    /// Validate a configuration file and policy engine without starting a server
    Check {
        /// Path to custom moat.toml configuration file (defaults to ./moat.toml)
        #[arg(long = "config", short = 'c')]
        config: Option<PathBuf>,
    },

    /// Generate shell completion scripts for moat
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Compile MCP tools/list schemas into compact Code-Mode SDK stubs (TypeScript, Python, or Markdown)
    Codegen {
        /// Output format: ts, python, or compact-md
        #[arg(long = "format", short = 'f', default_value = "ts")]
        format: String,

        /// Read tools/list JSON response from a file instead of spawning an MCP server
        #[arg(long = "from-json")]
        from_json: Option<PathBuf>,

        /// Optional file path to write the generated Code-Mode stubs (defaults to stdout)
        #[arg(long = "output", short = 'o')]
        output: Option<PathBuf>,

        /// Filter out modifying/write tools (read-only mode)
        #[arg(long = "read-only")]
        read_only: bool,

        /// Hide specific tools from generated bindings (can specify multiple)
        #[arg(long = "hide-tool")]
        hide_tool: Vec<String>,

        /// Preconfigured security preset (filesystem, git, fetch, sqlite, memory, postgres, playwright)
        #[arg(long = "preset", short = 'p')]
        preset: Option<String>,

        /// Path to custom moat.toml configuration file
        #[arg(long = "config", short = 'c')]
        config: Option<PathBuf>,

        /// Optional MCP server command and arguments to query via stdio initialize + tools/list
        #[arg(raw = true)]
        server_command: Vec<String>,
    },

    /// Manage, query, and cryptographically verify forensic audit logs
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// Cryptographically verify the SHA-256 hash chain of an audit log
    Verify {
        /// Path to audit log file (default: .moat/audit.jsonl)
        #[arg(default_value = ".moat/audit.jsonl")]
        path: PathBuf,
        #[arg(long)]
        require_seal: bool,
    },

    /// Query and inspect events in an audit log
    Query {
        /// Path to audit log file (default: .moat/audit.jsonl)
        #[arg(default_value = ".moat/audit.jsonl")]
        path: PathBuf,

        /// Only display security violations / blocked calls
        #[arg(long = "violations-only")]
        violations_only: bool,

        /// Filter events by tool name
        #[arg(long = "tool")]
        tool: Option<String>,

        /// Exit with non-zero exit code (1) if security violations are detected
        #[arg(long = "strict")]
        strict: bool,
    },

    /// Tail and follow events from an audit log
    Tail {
        /// Path to audit log file (default: .moat/audit.jsonl)
        #[arg(default_value = ".moat/audit.jsonl")]
        path: PathBuf,

        /// Number of recent events to display initially
        #[arg(short = 'n', default_value = "10")]
        lines: usize,

        /// Continuously follow appended events
        #[arg(short = 'f', long = "follow")]
        follow: bool,
    },
}

fn format_audit_event(event: &AuditEvent) -> String {
    let decision_str = match &event.decision {
        Some(AuditDecision::Allow) => "ALLOW".to_string(),
        Some(AuditDecision::Block { reason }) => format!("BLOCK ({})", reason),
        Some(AuditDecision::AskOperator { summary }) => {
            let op = event.operator_decision.as_deref().unwrap_or("Pending");
            format!("ASK_OPERATOR [Operator: {}] ({})", op, summary)
        }
        None => "-".to_string(),
    };

    let tool_str = event.tool_name.as_deref().unwrap_or("-");
    let target_str = event.target_path.as_deref().unwrap_or("-");
    let dlp_str = event
        .dlp_redactions
        .map(|r| format!(" [DLP: {} redacted]", r))
        .unwrap_or_default();

    // The fields come from client requests: no control characters on the operator's terminal.
    let line = format!(
        "#{:<4} {} [{:?}] method={:<12} tool={:<12} target={:<20} -> {}{}",
        event.sequence,
        event.timestamp,
        event.direction,
        event.method,
        tool_str,
        target_str,
        decision_str,
        dlp_str
    );
    line.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn seek_to_audit_follow_start(
    file: &mut (impl std::io::Read + std::io::Seek),
) -> std::io::Result<()> {
    use std::io::SeekFrom;

    let mut end = file.seek(SeekFrom::End(0))?;
    let mut block = [0; 8192];
    // Skip complete records and retain any unfinished record at EOF.
    while end > 0 {
        let start = end.saturating_sub(block.len() as u64);
        let bytes = &mut block[..(end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(bytes)?;
        if let Some(newline) = bytes.iter().rposition(|&byte| byte == b'\n') {
            file.seek(SeekFrom::Start(start + newline as u64 + 1))?;
            return Ok(());
        }
        end = start;
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

struct LoadedConfig {
    config: PolicyConfig,
    source: Option<PathBuf>,
}

fn load_policy_config(config: Option<&Path>) -> Result<LoadedConfig> {
    let cfg_path = config.unwrap_or_else(|| Path::new("moat.toml"));
    let config_present = config.is_some()
        || match cfg_path.symlink_metadata() {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(e).context("Failed to inspect config file 'moat.toml'");
            }
        };
    let (mut policy_config, source) = if config_present {
        let content = std::fs::read_to_string(cfg_path)
            .with_context(|| format!("Failed to read config file '{}'", cfg_path.display()))?;
        let parsed = toml::from_str::<PolicyConfig>(&content).with_context(|| {
            format!(
                "Failed to parse TOML in config file '{}'",
                cfg_path.display()
            )
        })?;
        (parsed, Some(cfg_path.to_path_buf()))
    } else {
        (PolicyConfig::default(), None)
    };

    if let Some(source) = &source {
        if !policy_config
            .protected_files
            .iter()
            .any(|protected| protected == source)
        {
            policy_config.protected_files.push(source.clone());
        }
    }

    Ok(LoadedConfig {
        config: policy_config,
        source,
    })
}

async fn read_codegen_response(
    reader: &mut tokio::io::Lines<impl tokio::io::AsyncBufRead + Unpin>,
    id: i64,
) -> std::io::Result<Option<serde_json::Value>> {
    while let Some(line) = reader.next_line().await? {
        let Ok(response) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if response.get("id").and_then(serde_json::Value::as_i64) == Some(id)
            && response.get("method").is_none()
        {
            return Ok(Some(response));
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Write diagnostics to stderr only to keep stdout clean for JSON-RPC
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path, force } => {
            if path.exists() && !force {
                eprintln!(
                    "[moat] Error: File '{}' already exists. Use --force to overwrite.",
                    path.display()
                );
                std::process::exit(1);
            }
            let default_config = PolicyConfig::default();
            let toml_str = toml::to_string_pretty(&default_config)?;
            std::fs::write(&path, toml_str)?;
            eprintln!(
                "[moat] Initialized default configuration at: {}",
                path.display()
            );
            Ok(())
        }
        Commands::Check { config } => {
            let loaded = load_policy_config(config.as_deref())?;
            let source = loaded
                .source
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<built-in defaults>".to_string());

            for root in &loaded.config.allowed_paths {
                if !root.exists() {
                    anyhow::bail!("Allowed path does not exist: {}", root.display());
                }
                if !root.is_dir() {
                    anyhow::bail!("Allowed path is not a directory: {}", root.display());
                }
            }

            if let Some(audit_log) = &loaded.config.audit_log {
                if audit_log.is_dir() {
                    anyhow::bail!(
                        "audit_log must be a file path, not a directory: {}",
                        audit_log.display()
                    );
                }
                if let Some(parent) = audit_log.parent().filter(|p| !p.as_os_str().is_empty()) {
                    if !parent.exists() {
                        anyhow::bail!(
                            "audit_log parent directory does not exist: {}",
                            parent.display()
                        );
                    }
                    if !parent.is_dir() {
                        anyhow::bail!("audit_log parent is not a directory: {}", parent.display());
                    }
                }
            }

            // protected_files come from the operator, not from the agent, so the lexical rules for
            // tool-call paths (8.3 short names, UNC) do not apply. Windows temp and profile paths
            // such as C:\Users\RUNNER~1\... are legitimate here, and the --config file is added
            // to this list automatically.

            let engine = PolicyEngine::new(loaded.config)
                .with_context(|| format!("Invalid policy configuration from {source}"))?;

            println!("Config OK: {source}");
            println!("Allowed roots: {}", engine.allowed_roots_summary());
            Ok(())
        }
        Commands::Completion { shell } => {
            let mut command = Cli::command();
            clap_complete::generate(shell, &mut command, "moat", &mut std::io::stdout());
            Ok(())
        }
        Commands::Wrap {
            allow,
            read_only,
            no_prompt,
            require_approval,
            monitor,
            audit_log,
            audit_level,
            compact_schemas,
            max_output_bytes,
            hide_tool,
            config,
            preset,
            server_command,
        } => {
            if server_command.is_empty() {
                eprintln!("[moat] Error: No server command specified to wrap.");
                std::process::exit(1);
            }

            // Load config file if specified or default
            let mut policy_config = load_policy_config(config.as_deref())?.config;

            // Apply preset if specified before CLI overrides
            if let Some(ref p_name) = preset {
                policy_config
                    .apply_preset(p_name)
                    .with_context(|| format!("Failed to apply preset '{}'", p_name))?;
            }

            // CLI flags override config
            if !allow.is_empty() {
                policy_config.allowed_paths = allow;
            }
            if read_only {
                policy_config.read_only = true;
            }
            if require_approval {
                policy_config.require_approval_on_write = true;
            }
            if monitor {
                policy_config.monitor_mode = true;
            }
            if let Some(path) = audit_log {
                policy_config.audit_log = Some(path);
            }
            if let Some(level_str) = audit_level {
                if let Ok(lvl) = level_str.parse::<AuditLevel>() {
                    policy_config.audit_level = lvl;
                }
            }
            if compact_schemas {
                policy_config.compact_schemas = true;
            }
            if let Some(m) = max_output_bytes {
                policy_config.max_output_bytes = Some(m);
            }
            for ht in hide_tool {
                if !policy_config.hidden_tools.contains(&ht) {
                    policy_config.hidden_tools.push(ht);
                }
            }

            let policy = PolicyEngine::new(policy_config)?;
            let proxy = if no_prompt {
                ProxyServer::with_console(policy, None)
            } else {
                ProxyServer::new(policy)
            };

            let cmd = &server_command[0];
            let args = &server_command[1..];

            let exit_code = match proxy.wrap_and_run(cmd, args).await {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("[moat] Error: {}", e);
                    std::process::exit(1);
                }
            };
            std::process::exit(exit_code);
        }
        Commands::Codegen {
            format,
            from_json,
            output,
            read_only,
            hide_tool,
            preset,
            config,
            server_command,
        } => {
            let codegen_format = match format.parse::<CodegenFormat>() {
                Ok(fmt) => fmt,
                Err(e) => {
                    eprintln!("[moat] Error: {}", e);
                    std::process::exit(1);
                }
            };

            let mut policy_config = load_policy_config(config.as_deref())?.config;

            if let Some(ref p_name) = preset {
                policy_config
                    .apply_preset(p_name)
                    .with_context(|| format!("Failed to apply preset '{}'", p_name))?;
            }
            if read_only {
                policy_config.read_only = true;
            }
            for ht in hide_tool {
                if !policy_config.hidden_tools.contains(&ht) {
                    policy_config.hidden_tools.push(ht);
                }
            }

            let policy = PolicyEngine::new(policy_config)?;

            let tools_json: serde_json::Value = if let Some(json_path) = from_json {
                let content = std::fs::read_to_string(&json_path).with_context(|| {
                    format!("Failed to read JSON file '{}'", json_path.display())
                })?;
                serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse JSON in '{}'", json_path.display()))?
            } else if !server_command.is_empty() {
                use std::process::Stdio;
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                use tokio::process::Command as TokioCommand;

                let cmd = &server_command[0];
                let args = &server_command[1..];

                let executable = mcp_moat_proxy::command::resolve_command(cmd.as_ref())
                    .with_context(|| format!("Failed to resolve MCP server '{}'", cmd))?;
                let mut child_command = TokioCommand::new(executable);
                mcp_moat_core::child_env::configure_child(
                    child_command.as_std_mut(),
                    policy.config(),
                );
                #[cfg(windows)]
                mcp_moat_proxy::process::prepare(&mut child_command);
                let mut child = child_command
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .with_context(|| format!("Failed to spawn MCP server '{}'", cmd))?;
                #[cfg(windows)]
                let _child_job = match mcp_moat_proxy::process::attach_and_resume(&mut child) {
                    Ok(job) => job,
                    Err(error) => {
                        let _ = child.wait().await;
                        return Err(error.into());
                    }
                };

                let handshake = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": { "name": "mcp-moat-codegen", "version": "0.1.0" }
                    }
                });
                let initialized = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                });
                let tools_req = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list"
                });

                let found_tools = async {
                    let mut stdin = child.stdin.take().context("Failed to open child stdin")?;
                    let stdout = child.stdout.take().context("Failed to open child stdout")?;
                    let mut reader = tokio::io::BufReader::new(stdout).lines();

                    tokio::time::timeout(std::time::Duration::from_secs(10), async {
                        stdin.write_all(format!("{handshake}\n").as_bytes()).await?;
                        stdin.flush().await?;
                        let response =
                            read_codegen_response(&mut reader, 1)
                                .await?
                                .with_context(|| {
                                    format!(
                                        "MCP server '{}' exited before returning initialize",
                                        cmd
                                    )
                                })?;
                        anyhow::ensure!(
                            response.get("error").is_none()
                                && response
                                    .get("result")
                                    .is_some_and(serde_json::Value::is_object),
                            "MCP server '{}' rejected initialization",
                            cmd
                        );
                        stdin
                            .write_all(format!("{initialized}\n{tools_req}\n").as_bytes())
                            .await?;
                        stdin.flush().await?;
                        read_codegen_response(&mut reader, 2)
                            .await?
                            .with_context(|| {
                                format!("MCP server '{}' exited before returning tools/list", cmd)
                            })
                    })
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("Timed out waiting for codegen responses from '{}'", cmd)
                    })?
                }
                .await;
                let _ = child.kill().await;
                let _ = child.wait().await;

                found_tools?
            } else {
                eprintln!("[moat] Error: Either --from-json <path> or a server command (-- <cmd>) is required for codegen.");
                std::process::exit(1);
            };

            let report =
                match TokenOptimizer::compile_code_mode(&tools_json, &policy, codegen_format) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[moat] Error compiling Code-Mode stubs: {}", e);
                        std::process::exit(1);
                    }
                };

            if let Some(out_path) = output {
                std::fs::write(&out_path, &report.output).with_context(|| {
                    format!("Failed to write codegen output to '{}'", out_path.display())
                })?;
            } else {
                println!("{}", report.output);
            }

            eprintln!(
                "[moat:codegen] Compiled {} tools ({} filtered by policy) | Raw schema: {} B (~{} tokens) -> Code-Mode: {} B (~{} tokens) | Saved {:.1}% tokens",
                report.tools_included,
                report.tools_filtered,
                report.raw_bytes,
                report.raw_estimated_tokens,
                report.compiled_bytes,
                report.compiled_estimated_tokens,
                report.savings_percent
            );
            Ok(())
        }
        Commands::Audit { action } => match action {
            AuditCommands::Verify { path, require_seal } => {
                if !path.exists() {
                    eprintln!(
                        "[moat] Error: Audit log file '{}' does not exist.",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open audit log '{}'", path.display()))?;
                let reader = BufReader::new(file);

                let key = std::env::var_os("MOAT_AUDIT_KEY");
                if key.as_ref().is_some_and(|v| v.is_empty()) {
                    anyhow::bail!("MOAT_AUDIT_KEY must not be empty");
                }
                match verify_audit_log_with_options(
                    reader,
                    key.as_ref().map(|v| v.as_encoded_bytes()),
                    require_seal,
                ) {
                    Ok(report) => {
                        if report.is_valid {
                            eprintln!("[moat] Audit Log Integrity Check: PASSED");
                            eprintln!("  Path:                  {}", path.display());
                            eprintln!("  Verified Records:      {}", report.total_records);
                            eprintln!("  Cryptographic Chain:   INTACT (SHA-256)");
                            Ok(())
                        } else {
                            eprintln!("[moat] Audit Log Integrity Check: FAILED (TAMPER DETECTED)");
                            eprintln!("  Path:                  {}", path.display());
                            eprintln!("  Verified Records:      {}", report.total_records);
                            if let Some(seq) = report.tampered_sequence {
                                eprintln!("  Tampered Sequence:     #{}", seq);
                            }
                            if let Some(err) = report.error_message {
                                eprintln!("  Error Details:         {}", err);
                            }
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("[moat] Error verifying audit log: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            AuditCommands::Query {
                path,
                violations_only,
                tool,
                strict,
            } => {
                if !path.exists() {
                    eprintln!(
                        "[moat] Error: Audit log file '{}' does not exist.",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open audit log '{}'", path.display()))?;
                let reader = BufReader::new(file);

                let mut matched_count = 0;
                let mut violation_count = 0;
                for line_res in reader.lines() {
                    let line = line_res?;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<AuditEvent>(trimmed) {
                        Ok(event) => {
                            let is_violation = event
                                .decision
                                .as_ref()
                                .map(|d| d.is_violation())
                                .unwrap_or(false)
                                || event.operator_decision.as_deref() == Some("Deny")
                                || event.operator_decision.as_deref() == Some("MonitorForwarded")
                                || event.dlp_redactions.unwrap_or(0) > 0;

                            if violations_only && !is_violation {
                                continue;
                            }

                            if let Some(target_tool) = &tool {
                                if event.tool_name.as_deref() != Some(target_tool.as_str()) {
                                    continue;
                                }
                            }

                            if is_violation {
                                violation_count += 1;
                            }

                            println!("{}", format_audit_event(&event));
                            matched_count += 1;
                        }
                        Err(e) => {
                            eprintln!("[moat] Warning: Malformed audit record encountered: {}", e);
                        }
                    }
                }

                if matched_count == 0 {
                    eprintln!("[moat] No audit events matched the filter.");
                }

                if strict && violation_count > 0 {
                    std::process::exit(1);
                }

                Ok(())
            }
            AuditCommands::Tail {
                path,
                lines,
                follow,
            } => {
                if !path.exists() {
                    eprintln!(
                        "[moat] Error: Audit log file '{}' does not exist.",
                        path.display()
                    );
                    std::process::exit(1);
                }
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open audit log '{}'", path.display()))?;
                let mut reader = BufReader::new(file);
                let mut line_buf = Vec::new();

                use std::collections::VecDeque;

                if lines > 0 {
                    let mut ring_buffer = VecDeque::new();
                    while reader.read_until(b'\n', &mut line_buf)? != 0 {
                        if follow && !line_buf.ends_with(b"\n") {
                            break;
                        }
                        if ring_buffer.len() == lines {
                            ring_buffer.pop_front();
                        }
                        ring_buffer.push_back(std::mem::take(&mut line_buf));
                    }

                    for line in &ring_buffer {
                        match serde_json::from_slice::<AuditEvent>(line) {
                            Ok(event) => println!("{}", format_audit_event(&event)),
                            Err(e) => eprintln!("[moat] Warning: Malformed audit record: {}", e),
                        }
                    }
                }

                if follow {
                    use tokio::io::AsyncBufReadExt;

                    let mut file = reader.into_inner();
                    if lines == 0 {
                        seek_to_audit_follow_start(&mut file)?;
                    }
                    let mut reader = tokio::io::BufReader::new(tokio::fs::File::from_std(file));

                    loop {
                        match reader.read_until(b'\n', &mut line_buf).await {
                            Ok(0) => {
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                            Ok(_) if line_buf.ends_with(b"\n") => {
                                if let Ok(event) = serde_json::from_slice::<AuditEvent>(&line_buf) {
                                    println!("{}", format_audit_event(&event));
                                }
                                line_buf.clear();
                            }
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("[moat] Error reading audit tail: {}", e);
                                break;
                            }
                        }
                    }
                }
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::seek_to_audit_follow_start;
    use std::io::Cursor;

    #[test]
    fn audit_follow_without_history_starts_at_the_unfinished_record() {
        let history = b"complete event\n";
        let mut input = history.to_vec();
        input.resize(input.len() + 16_384, b'x');
        for (bytes, expected_offset) in [
            (input.as_slice(), history.len() as u64),
            (history.as_slice(), history.len() as u64),
            (b"unfinished first event".as_slice(), 0),
            (b"".as_slice(), 0),
        ] {
            let mut file = Cursor::new(bytes);
            seek_to_audit_follow_start(&mut file).unwrap();
            assert_eq!(file.position(), expected_offset);
        }
    }
}
