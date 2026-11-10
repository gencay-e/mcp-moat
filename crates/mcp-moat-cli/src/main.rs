use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use mcp_moat_core::{
    validate_lexical_syntax, verify_audit_log, AuditDecision, AuditEvent, AuditLevel,
    CodegenFormat, PolicyConfig, PolicyEngine, TokenOptimizer,
};
use mcp_moat_proxy::ProxyServer;
#[cfg(feature = "experimental-sse")]
use mcp_moat_proxy::{SseBridgeServer, SseProxyServer};
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

        /// Preconfigured security preset (filesystem, git, fetch, sqlite, memory)
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

    #[cfg(feature = "experimental-sse")]
    /// Run an HTTP/SSE remote proxy guarding an upstream MCP server
    SseProxy {
        /// Local address and port to listen on (e.g. 127.0.0.1:8765)
        #[arg(long = "listen", short = 'l', default_value = "127.0.0.1:8765")]
        listen: String,

        /// Target upstream remote MCP server SSE URL (e.g. http://127.0.0.1:8000/sse)
        #[arg(long = "target", short = 't', required = true)]
        target: String,

        /// Allowed root directory for filesystem access (can specify multiple)
        #[arg(long = "allow", short = 'a')]
        allow: Vec<PathBuf>,

        /// Preconfigured security preset (filesystem, git, fetch, sqlite, memory)
        #[arg(long = "preset", short = 'p')]
        preset: Option<String>,

        /// Enforce strict read-only mode
        #[arg(long = "read-only")]
        read_only: bool,

        /// Automatically deny actions requiring operator approval without TTY prompt
        #[arg(long = "no-prompt")]
        no_prompt: bool,

        /// Run in monitor-only / audit-only mode
        #[arg(long = "monitor", alias = "audit-only")]
        monitor: bool,

        /// File path for SHA-256 forensic audit log
        #[arg(long = "audit-log")]
        audit_log: Option<PathBuf>,

        /// Granularity of audit logging: full, decisions_only, or violations_only
        #[arg(long = "audit-level", value_parser = ["full", "decisions_only", "violations_only"])]
        audit_level: Option<String>,

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
    },

    #[cfg(feature = "experimental-sse")]
    /// Bridge stdio JSON-RPC to a remote MCP SSE server under Zero-Trust firewall
    SseBridge {
        /// Target upstream remote MCP server SSE URL (e.g. http://127.0.0.1:8000/sse)
        #[arg(long = "target", short = 't', required = true)]
        target: String,

        /// Allowed root directory for filesystem access (can specify multiple)
        #[arg(long = "allow", short = 'a')]
        allow: Vec<PathBuf>,

        /// Preconfigured security preset (filesystem, git, fetch, sqlite, memory)
        #[arg(long = "preset", short = 'p')]
        preset: Option<String>,

        /// Enforce strict read-only mode
        #[arg(long = "read-only")]
        read_only: bool,

        /// Automatically deny actions requiring operator approval without TTY prompt
        #[arg(long = "no-prompt")]
        no_prompt: bool,

        /// Run in monitor-only / audit-only mode
        #[arg(long = "monitor", alias = "audit-only")]
        monitor: bool,

        /// File path for SHA-256 forensic audit log
        #[arg(long = "audit-log")]
        audit_log: Option<PathBuf>,

        /// Granularity of audit logging: full, decisions_only, or violations_only
        #[arg(long = "audit-level", value_parser = ["full", "decisions_only", "violations_only"])]
        audit_level: Option<String>,

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

        /// Preconfigured security preset (filesystem, git, fetch, sqlite, memory)
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

    format!(
        "#{:<4} {} [{:?}] method={:<12} tool={:<12} target={:<20} -> {}{}",
        event.sequence,
        event.timestamp,
        event.direction,
        event.method,
        tool_str,
        target_str,
        decision_str,
        dlp_str
    )
}

struct LoadedConfig {
    config: PolicyConfig,
    source: Option<PathBuf>,
}

fn load_policy_config(config: Option<&Path>) -> Result<LoadedConfig> {
    let (mut policy_config, source) = if let Some(cfg_path) = config {
        let content = std::fs::read_to_string(cfg_path)
            .with_context(|| format!("Failed to read config file '{}'", cfg_path.display()))?;
        let parsed = toml::from_str::<PolicyConfig>(&content).with_context(|| {
            format!(
                "Failed to parse TOML in config file '{}'",
                cfg_path.display()
            )
        })?;
        (parsed, Some(cfg_path.to_path_buf()))
    } else if Path::new("moat.toml").exists() {
        let content = std::fs::read_to_string("moat.toml")?;
        let parsed = toml::from_str::<PolicyConfig>(&content)?;
        (parsed, Some(PathBuf::from("moat.toml")))
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

#[tokio::main]
async fn main() -> Result<()> {
    // Write diagnostics to stderr only to keep stdout clean for JSON-RPC
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
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
                if let Some(parent) = audit_log.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        anyhow::bail!(
                            "audit_log parent directory does not exist: {}",
                            parent.display()
                        );
                    }
                }
            }

            for path in &loaded.config.protected_files {
                validate_lexical_syntax(&path.to_string_lossy()).with_context(|| {
                    format!("Invalid protected_files entry '{}'", path.display())
                })?;
            }

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
        #[cfg(feature = "experimental-sse")]
        Commands::SseProxy {
            listen,
            target,
            allow,
            preset,
            read_only,
            no_prompt,
            monitor,
            audit_log,
            audit_level,
            compact_schemas,
            max_output_bytes,
            hide_tool,
            config,
        } => {
            let mut policy_config = load_policy_config(config.as_deref())?.config;

            if let Some(ref p_name) = preset {
                policy_config
                    .apply_preset(p_name)
                    .with_context(|| format!("Failed to apply preset '{}'", p_name))?;
            }
            if !allow.is_empty() {
                policy_config.allowed_paths = allow;
            }
            if read_only {
                policy_config.read_only = true;
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
            let server = if no_prompt {
                SseProxyServer::with_console(policy, None, &target)?
            } else {
                SseProxyServer::new(policy, &target)?
            };

            server.run(&listen).await?;
            Ok(())
        }
        #[cfg(feature = "experimental-sse")]
        Commands::SseBridge {
            target,
            allow,
            preset,
            read_only,
            no_prompt,
            monitor,
            audit_log,
            audit_level,
            compact_schemas,
            max_output_bytes,
            hide_tool,
            config,
        } => {
            let mut policy_config = load_policy_config(config.as_deref())?.config;

            if let Some(ref p_name) = preset {
                policy_config
                    .apply_preset(p_name)
                    .with_context(|| format!("Failed to apply preset '{}'", p_name))?;
            }
            if !allow.is_empty() {
                policy_config.allowed_paths = allow;
            }
            if read_only {
                policy_config.read_only = true;
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
            let bridge = if no_prompt {
                SseBridgeServer::with_console(policy, None, &target)?
            } else {
                SseBridgeServer::new(policy, &target)?
            };

            bridge.run().await?;
            Ok(())
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

                let mut child = TokioCommand::new(cmd)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("Failed to spawn MCP server '{}'", cmd))?;

                let mut stdin = child.stdin.take().context("Failed to open child stdin")?;
                let stdout = child.stdout.take().context("Failed to open child stdout")?;
                let mut reader = tokio::io::BufReader::new(stdout).lines();

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

                let payload = format!("{}\n{}\n{}\n", handshake, initialized, tools_req);
                stdin.write_all(payload.as_bytes()).await?;
                stdin.flush().await?;

                let found_tools = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    while let Ok(Some(line)) = reader.next_line().await {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                            let is_id_2 = val.get("id").and_then(|i| i.as_i64()) == Some(2);
                            let has_tools =
                                val.get("result").and_then(|r| r.get("tools")).is_some();
                            if is_id_2 || has_tools {
                                return Some(val);
                            }
                        }
                    }
                    None
                })
                .await
                .map_err(|_| {
                    anyhow::anyhow!("Timed out waiting for tools/list response from '{}'", cmd)
                })?
                .ok_or_else(|| {
                    anyhow::anyhow!("MCP server '{}' exited before returning tools/list", cmd)
                })?;

                drop(stdin);
                let _ = child.kill().await;
                let _ = child.wait().await;

                found_tools
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
            AuditCommands::Verify { path } => {
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

                match verify_audit_log(reader) {
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
                let reader = BufReader::new(file);

                use std::collections::VecDeque;

                if lines > 0 {
                    let mut ring_buffer: VecDeque<String> = VecDeque::with_capacity(lines);
                    for line_res in reader.lines() {
                        let line = line_res?;
                        if ring_buffer.len() == lines {
                            ring_buffer.pop_front();
                        }
                        ring_buffer.push_back(line);
                    }

                    for line in &ring_buffer {
                        match serde_json::from_str::<AuditEvent>(line) {
                            Ok(event) => println!("{}", format_audit_event(&event)),
                            Err(e) => eprintln!("[moat] Warning: Malformed audit record: {}", e),
                        }
                    }
                }

                if follow {
                    use tokio::io::AsyncBufReadExt;
                    use tokio::io::AsyncSeekExt;

                    let mut tokio_file = tokio::fs::File::open(&path).await?;
                    let _ = tokio_file.seek(std::io::SeekFrom::End(0)).await?;
                    let mut reader = tokio::io::BufReader::new(tokio_file);
                    let mut line_buf = String::new();

                    loop {
                        line_buf.clear();
                        match reader.read_line(&mut line_buf).await {
                            Ok(0) => {
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            }
                            Ok(_) => {
                                let trimmed = line_buf.trim();
                                if !trimmed.is_empty() {
                                    if let Ok(event) = serde_json::from_str::<AuditEvent>(trimmed) {
                                        println!("{}", format_audit_event(&event));
                                    }
                                }
                            }
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
