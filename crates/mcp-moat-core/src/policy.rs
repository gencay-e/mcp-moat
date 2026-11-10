use crate::audit::AuditLevel;
use crate::error::{MoatError, Result};
pub use crate::protocol::parse_file_uri_to_path;
use crate::protocol::ToolCallParams;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<PathBuf>,

    #[serde(default = "default_read_only")]
    pub read_only: bool,

    /// If true, even ordinary writes inside allowed_paths require operator approval
    #[serde(default = "default_require_approval_on_write")]
    pub require_approval_on_write: bool,

    #[serde(default = "default_blocked_commands")]
    pub blocked_commands: Vec<String>,

    #[serde(default = "default_always_allow_tools")]
    pub always_allow_tools: Vec<String>,

    /// Path to forensic JSONL audit log file (optional)
    #[serde(default)]
    pub audit_log: Option<PathBuf>,

    /// Level of detail recorded in audit log (Full, DecisionsOnly, ViolationsOnly)
    #[serde(default)]
    pub audit_level: AuditLevel,

    /// If true, runs in monitor/audit-only mode (violations and approvals are observed without blocking or prompting)
    #[serde(default)]
    pub monitor_mode: bool,

    /// Custom modifying/write tools to be treated as destructive
    #[serde(default)]
    pub custom_modifying_tools: Vec<String>,

    /// Custom read-only tools to always allow
    #[serde(default)]
    pub custom_always_allow_tools: Vec<String>,

    /// Custom argument keys containing file/directory paths
    #[serde(default)]
    pub custom_path_keys: Vec<String>,

    /// Tools that take no file path although their name looks like a file tool (`get-sum`,
    /// `read_counter`). Without this list, a call of such a tool is blocked because no path can
    /// be verified. List only tools you know.
    #[serde(default)]
    pub non_file_tools: Vec<String>,

    /// Argument keys that never contain file paths, although their name suggests it
    /// (for example `target: "HEAD~1"` of a git diff). Their values are not checked as paths.
    #[serde(default)]
    pub ignore_path_keys: Vec<String>,

    /// Custom argument keys containing commands to execute
    #[serde(default)]
    pub custom_command_keys: Vec<String>,

    /// Regex patterns for prohibited destructive commands
    #[serde(default)]
    pub blocked_commands_regex: Vec<String>,

    /// If true, compacts bloated `tools/list` JSON schemas and prunes modifying tools in `read_only` mode
    #[serde(default)]
    pub compact_schemas: bool,

    /// Optional context-window budget (in bytes) per tool/resource output text block
    #[serde(default)]
    pub max_output_bytes: Option<usize>,

    /// Tools hidden from `tools/list` discovery and blocked on `tools/call`
    #[serde(default)]
    pub hidden_tools: Vec<String>,

    /// Additional files that must never be modified without operator approval.
    /// The CLI adds the active `--config` file here automatically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_files: Vec<PathBuf>,

    /// Named presets for specific MCP server types (filesystem, git, fetch, sqlite, memory)
    #[serde(default)]
    pub presets: HashMap<String, PresetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PresetConfig {
    #[serde(default)]
    pub allowed_paths: Option<Vec<PathBuf>>,

    #[serde(default)]
    pub read_only: Option<bool>,

    #[serde(default)]
    pub require_approval_on_write: Option<bool>,

    #[serde(default)]
    pub blocked_commands: Option<Vec<String>>,

    #[serde(default)]
    pub blocked_commands_regex: Option<Vec<String>>,

    #[serde(default)]
    pub always_allow_tools: Option<Vec<String>>,

    #[serde(default)]
    pub custom_modifying_tools: Option<Vec<String>>,

    #[serde(default)]
    pub custom_always_allow_tools: Option<Vec<String>>,

    #[serde(default)]
    pub custom_path_keys: Option<Vec<String>>,

    #[serde(default)]
    pub ignore_path_keys: Option<Vec<String>>,

    #[serde(default)]
    pub custom_command_keys: Option<Vec<String>>,

    #[serde(default)]
    pub compact_schemas: Option<bool>,

    #[serde(default)]
    pub max_output_bytes: Option<usize>,

    #[serde(default)]
    pub hidden_tools: Option<Vec<String>>,
}

fn default_allowed_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(".")]
}

fn default_read_only() -> bool {
    false
}

fn default_require_approval_on_write() -> bool {
    // Ordinary in-jail files auto-allow, but sensitive in-jail files (moat.toml, .git) still require approval!
    false
}

fn default_blocked_commands() -> Vec<String> {
    vec![
        "rm -rf /".to_string(),
        ":(){ :|:& };:".to_string(),
        "mkfs".to_string(),
        "dd if=/dev/zero".to_string(),
        "format c:".to_string(),
        "powershell -enc".to_string(),
        "powershell -encodedcommand".to_string(),
        "powershell -e".to_string(),
        "powershell -ec".to_string(),
        "powershell /e".to_string(),
        "powershell /ec".to_string(),
        "pwsh -enc".to_string(),
        "pwsh -encodedcommand".to_string(),
        "pwsh -e".to_string(),
        "pwsh -ec".to_string(),
        "pwsh /e".to_string(),
        "pwsh /ec".to_string(),
    ]
}

fn default_always_allow_tools() -> Vec<String> {
    vec![
        "list_directory".to_string(),
        "read_file".to_string(),
        "search_files".to_string(),
        "grep".to_string(),
    ]
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowed_paths: default_allowed_paths(),
            read_only: default_read_only(),
            require_approval_on_write: default_require_approval_on_write(),
            blocked_commands: default_blocked_commands(),
            always_allow_tools: default_always_allow_tools(),
            audit_log: None,
            audit_level: AuditLevel::default(),
            monitor_mode: false,
            custom_modifying_tools: Vec::new(),
            custom_always_allow_tools: Vec::new(),
            custom_path_keys: Vec::new(),
            non_file_tools: Vec::new(),
            ignore_path_keys: Vec::new(),
            custom_command_keys: Vec::new(),
            blocked_commands_regex: Vec::new(),
            compact_schemas: false,
            max_output_bytes: None,
            hidden_tools: Vec::new(),
            protected_files: Vec::new(),
            presets: HashMap::new(),
        }
    }
}

impl PolicyConfig {
    pub fn get_builtin_preset(name: &str) -> Option<PresetConfig> {
        match name.to_ascii_lowercase().as_str() {
            "filesystem" => Some(PresetConfig {
                allowed_paths: Some(vec![PathBuf::from(".")]),
                read_only: Some(false),
                require_approval_on_write: Some(false),
                blocked_commands: None,
                blocked_commands_regex: None,
                always_allow_tools: Some(vec![
                    "list_directory".to_string(),
                    "read_file".to_string(),
                    "search_files".to_string(),
                    "grep".to_string(),
                    "get_file_info".to_string(),
                    "list_allowed_directories".to_string(),
                ]),
                custom_modifying_tools: Some(vec![
                    "write_file".to_string(),
                    "edit_file".to_string(),
                    "create_directory".to_string(),
                    "move_file".to_string(),
                    "delete_file".to_string(),
                ]),
                custom_always_allow_tools: None,
                custom_path_keys: None,
                ignore_path_keys: None,
                custom_command_keys: None,
                compact_schemas: None,
                max_output_bytes: None,
                hidden_tools: None,
            }),
            "git" => Some(PresetConfig {
                allowed_paths: None,
                read_only: Some(false),
                require_approval_on_write: None,
                blocked_commands: Some(vec![
                    "git push --force".to_string(),
                    "git push -f".to_string(),
                    "git reset --hard".to_string(),
                    "git clean -fdx".to_string(),
                    "git clean -f".to_string(),
                ]),
                blocked_commands_regex: None,
                always_allow_tools: Some(vec![
                    "git_status".to_string(),
                    "git_diff".to_string(),
                    "git_log".to_string(),
                    "git_show".to_string(),
                    "git_branch".to_string(),
                    "git_diff_unstaged".to_string(),
                    "git_diff_staged".to_string(),
                ]),
                custom_modifying_tools: Some(vec![
                    "git_commit".to_string(),
                    "git_push".to_string(),
                    "git_checkout".to_string(),
                    "git_reset".to_string(),
                    "git_merge".to_string(),
                    "git_add".to_string(),
                    "git_create_branch".to_string(),
                ]),
                custom_always_allow_tools: None,
                custom_path_keys: None,
                // Values of these keys are revisions, branch names or messages, not paths.
                ignore_path_keys: Some(vec![
                    "target".to_string(),
                    "revision".to_string(),
                    "branch_name".to_string(),
                    "base_branch".to_string(),
                    "start_point".to_string(),
                    "commit".to_string(),
                    "message".to_string(),
                ]),
                custom_command_keys: Some(vec!["command".to_string(), "args".to_string()]),
                compact_schemas: None,
                max_output_bytes: None,
                hidden_tools: None,
            }),
            "fetch" => Some(PresetConfig {
                allowed_paths: None,
                read_only: Some(true),
                require_approval_on_write: None,
                blocked_commands: None,
                blocked_commands_regex: None,
                always_allow_tools: Some(vec![
                    "fetch".to_string(),
                    "http_get".to_string(),
                    "web_search".to_string(),
                    "read_url".to_string(),
                ]),
                custom_modifying_tools: Some(vec![
                    "http_post".to_string(),
                    "http_put".to_string(),
                    "http_delete".to_string(),
                    "http_patch".to_string(),
                ]),
                custom_always_allow_tools: None,
                custom_path_keys: None,
                ignore_path_keys: None,
                custom_command_keys: None,
                compact_schemas: None,
                max_output_bytes: None,
                hidden_tools: None,
            }),
            "sqlite" => Some(PresetConfig {
                allowed_paths: None,
                read_only: Some(false),
                require_approval_on_write: None,
                blocked_commands: None,
                blocked_commands_regex: None,
                always_allow_tools: Some(vec![
                    "read_query".to_string(),
                    "list_tables".to_string(),
                    "describe_table".to_string(),
                    "show_schema".to_string(),
                ]),
                custom_modifying_tools: Some(vec![
                    "write_query".to_string(),
                    "execute_query".to_string(),
                    "create_table".to_string(),
                    "drop_table".to_string(),
                ]),
                custom_always_allow_tools: None,
                custom_path_keys: Some(vec![
                    "path".to_string(),
                    "database".to_string(),
                    "db_path".to_string(),
                ]),
                ignore_path_keys: None,
                custom_command_keys: None,
                compact_schemas: None,
                max_output_bytes: None,
                hidden_tools: None,
            }),
            "memory" => Some(PresetConfig {
                allowed_paths: None,
                read_only: Some(false),
                require_approval_on_write: Some(false),
                blocked_commands: None,
                blocked_commands_regex: None,
                always_allow_tools: Some(vec![
                    "read_graph".to_string(),
                    "search_nodes".to_string(),
                    "open_nodes".to_string(),
                ]),
                custom_modifying_tools: Some(vec![
                    "create_entities".to_string(),
                    "create_relations".to_string(),
                    "delete_entities".to_string(),
                    "delete_relations".to_string(),
                    "add_observations".to_string(),
                ]),
                custom_always_allow_tools: None,
                custom_path_keys: None,
                ignore_path_keys: None,
                custom_command_keys: None,
                compact_schemas: None,
                max_output_bytes: None,
                hidden_tools: None,
            }),
            _ => None,
        }
    }

    pub fn apply_preset(&mut self, name: &str) -> Result<()> {
        let preset = self
            .presets
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .or_else(|| Self::get_builtin_preset(name))
            .ok_or_else(|| {
                MoatError::PolicyViolation(format!(
                    "Unknown preset '{}'. Available built-in presets: filesystem, git, fetch, sqlite, memory",
                    name
                ))
            })?;

        if let Some(paths) = preset.allowed_paths {
            self.allowed_paths = paths;
        }
        if let Some(ro) = preset.read_only {
            self.read_only = ro;
        }
        if let Some(req_app) = preset.require_approval_on_write {
            self.require_approval_on_write = req_app;
        }
        if let Some(cmds) = preset.blocked_commands {
            for cmd in cmds {
                if !self.blocked_commands.contains(&cmd) {
                    self.blocked_commands.push(cmd);
                }
            }
        }
        if let Some(regexes) = preset.blocked_commands_regex {
            for r in regexes {
                if !self.blocked_commands_regex.contains(&r) {
                    self.blocked_commands_regex.push(r);
                }
            }
        }
        if let Some(tools) = preset.always_allow_tools {
            for t in tools {
                if !self.always_allow_tools.contains(&t) {
                    self.always_allow_tools.push(t);
                }
            }
        }
        if let Some(mod_tools) = preset.custom_modifying_tools {
            for mt in mod_tools {
                if !self.custom_modifying_tools.contains(&mt) {
                    self.custom_modifying_tools.push(mt);
                }
            }
        }
        if let Some(always_tools) = preset.custom_always_allow_tools {
            for at in always_tools {
                if !self.custom_always_allow_tools.contains(&at) {
                    self.custom_always_allow_tools.push(at);
                }
            }
        }
        if let Some(path_keys) = preset.custom_path_keys {
            for pk in path_keys {
                if !self.custom_path_keys.contains(&pk) {
                    self.custom_path_keys.push(pk);
                }
            }
        }
        if let Some(ignore_keys) = preset.ignore_path_keys {
            for ik in ignore_keys {
                if !self.ignore_path_keys.contains(&ik) {
                    self.ignore_path_keys.push(ik);
                }
            }
        }
        if let Some(cmd_keys) = preset.custom_command_keys {
            for ck in cmd_keys {
                if !self.custom_command_keys.contains(&ck) {
                    self.custom_command_keys.push(ck);
                }
            }
        }
        if let Some(compact) = preset.compact_schemas {
            self.compact_schemas = compact;
        }
        if let Some(max_out) = preset.max_output_bytes {
            self.max_output_bytes = Some(max_out);
        }
        if let Some(hidden) = preset.hidden_tools {
            for ht in hidden {
                if !self.hidden_tools.contains(&ht) {
                    self.hidden_tools.push(ht);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block(String),
    AskOperator {
        tool_name: String,
        target_path: Option<PathBuf>,
        action_summary: String,
    },
}

const BUILTIN_PWSH_PATTERN: &str = r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*?(?:^|\s)[-/](?:e|ec|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b";

/// Compiles the built-in PowerShell encoded-command pattern.
/// A compile failure is returned as an error so the policy engine refuses to start (fail-closed).
fn builtin_pwsh_regex() -> Result<regex::Regex> {
    regex::Regex::new(BUILTIN_PWSH_PATTERN).map_err(|e| {
        MoatError::PolicyViolation(format!("Invalid built-in PowerShell regex: {}", e))
    })
}

pub struct PolicyEngine {
    config: PolicyConfig,
    canonical_allowed_roots: Vec<PathBuf>,
    compiled_blocked_regexes: Vec<regex::Regex>,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Result<Self> {
        let mut canonical_allowed_roots = Vec::new();
        for path in &config.allowed_paths {
            let canonical = match path.canonicalize() {
                Ok(p) => p,
                Err(_) => std::env::current_dir()
                    .map(|cwd| cwd.join(path))
                    .unwrap_or_else(|_| path.clone()),
            };
            canonical_allowed_roots.push(canonical);
        }

        let mut compiled_blocked_regexes = Vec::new();
        // Built-in protection against PowerShell / pwsh encoded command variations (-e, -enc, /e, -encodedcommand)
        // Defends against flags inserted before encoded command (e.g. `powershell.exe -NoProfile -ExecutionPolicy Bypass -enc <payload>`)
        let pwsh_regex = builtin_pwsh_regex()?;
        compiled_blocked_regexes.push(pwsh_regex);

        for pattern in &config.blocked_commands_regex {
            let re = regex::Regex::new(pattern).map_err(|e| {
                MoatError::PolicyViolation(format!(
                    "Invalid regex pattern in blocked_commands_regex '{}': {}",
                    pattern, e
                ))
            })?;
            compiled_blocked_regexes.push(re);
        }

        Ok(Self {
            config,
            canonical_allowed_roots,
            compiled_blocked_regexes,
        })
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn is_modifying_tool(&self, tool_name: &str) -> bool {
        is_modifying_tool(tool_name, &self.config.custom_modifying_tools)
    }

    pub fn is_tool_hidden(&self, tool_name: &str) -> bool {
        self.config
            .hidden_tools
            .iter()
            .any(|t| t.eq_ignore_ascii_case(tool_name))
    }

    fn is_non_file_tool(&self, tool_name: &str) -> bool {
        self.config
            .non_file_tools
            .iter()
            .any(|t| t.eq_ignore_ascii_case(tool_name))
    }

    pub fn extract_all_path_arguments(&self, call: &ToolCallParams) -> Vec<String> {
        extract_all_path_arguments_ignoring(
            call,
            &self.config.custom_path_keys,
            &self.config.ignore_path_keys,
        )
    }

    pub fn extract_command_argument(&self, call: &ToolCallParams) -> Option<String> {
        extract_command_argument(call, &self.config.custom_command_keys)
    }

    pub fn evaluate_resource_read(&self, uri: &str) -> Decision {
        let path = match parse_file_uri_to_path(uri) {
            Ok(p) => p,
            Err(e) => return Decision::Block(e.to_string()),
        };

        match self.validate_path_secure(&path.to_string_lossy()) {
            Ok(_) => Decision::Allow,
            Err(e) => Decision::Block(e.to_string()),
        }
    }

    /// Evaluates whether an incoming tool call is permitted, requires prompt, or is blocked
    pub fn evaluate_tool_call(&self, call: &ToolCallParams) -> Decision {
        let tool_name = call.name.as_str();

        // 0. Check if tool is explicitly hidden/disabled by policy
        if self.is_tool_hidden(tool_name) {
            return Decision::Block(format!(
                "Tool '{}' is hidden and disabled by policy",
                tool_name
            ));
        }

        // 1. Arguments validation: If arguments exist, they MUST be a JSON object
        if let Some(args) = &call.arguments {
            if !args.is_object() {
                return Decision::Block(
                    "Invalid tool call: 'arguments' parameter must be a JSON object".to_string(),
                );
            }
        }

        // 2. Check dangerous write actions in read-only mode
        let is_write = self.is_modifying_tool(tool_name);
        if is_write && self.config.read_only {
            return Decision::Block(format!(
                "Read-only policy active: modifying tool '{}' is prohibited",
                tool_name
            ));
        }

        // 3. Shell and command execution checks
        if let Some(cmd_str) = self.extract_command_argument(call) {
            for blocked in &self.config.blocked_commands {
                if command_matches_blocked(&cmd_str, blocked) {
                    return Decision::Block(format!(
                        "Prohibited destructive command detected: matches '{}'",
                        blocked
                    ));
                }
            }

            for re in &self.compiled_blocked_regexes {
                if re.is_match(&cmd_str) {
                    return Decision::Block(format!(
                        "Prohibited destructive command detected: matches pattern '{}'",
                        re.as_str()
                    ));
                }
            }

            if has_dangerous_shell_metacharacters(&cmd_str) {
                return Decision::AskOperator {
                    tool_name: tool_name.to_string(),
                    target_path: None,
                    action_summary: format!(
                        "Command contains dangerous shell metacharacters: {}",
                        summarize_call(call)
                    ),
                };
            }

            // Shell commands require operator approval by default
            return Decision::AskOperator {
                tool_name: tool_name.to_string(),
                target_path: None,
                action_summary: summarize_call(call),
            };
        }

        // 4. Extract and validate ALL target paths (single paths, arrays, source/destination)
        let extracted_paths = self.extract_all_path_arguments(call);
        let has_args = match &call.arguments {
            Some(serde_json::Value::Object(map)) => !map.is_empty(),
            Some(serde_json::Value::Array(arr)) => !arr.is_empty(),
            Some(_) => true,
            None => false,
        };

        // Fail-closed: If a file/path-based tool receives arguments but no path could be extracted,
        // it must NEVER be allowed or prompted automatically!
        if is_file_tool(tool_name)
            && !self.is_non_file_tool(tool_name)
            && has_args
            && extracted_paths.is_empty()
        {
            return Decision::Block(
                "Path argument could not be verified for file tool".to_string(),
            );
        }

        if !extracted_paths.is_empty() {
            // PASS 1: Validate EVERY path against boundary and lexical constraints first.
            // Fail-closed: If ANY path is invalid or out-of-jail, block IMMEDIATELY!
            // This prevents multi-path short-circuit bypasses (e.g. valid source + out-of-jail destination).
            let mut resolved_paths = Vec::new();
            for path_str in &extracted_paths {
                match self.validate_path_secure(path_str) {
                    Ok(resolved_path) => resolved_paths.push((resolved_path, path_str.as_str())),
                    Err(err) => return Decision::Block(err.to_string()),
                }
            }

            // PASS 2: Check if ANY resolved path targets a protected system file or audit log
            if is_write {
                for (resolved_path, raw_str) in &resolved_paths {
                    if self.is_protected_target(resolved_path) {
                        return Decision::AskOperator {
                            tool_name: tool_name.to_string(),
                            target_path: Some(resolved_path.clone()),
                            action_summary: format!(
                                "Attempted modification of protected configuration/hook: {}",
                                raw_str
                            ),
                        };
                    }
                }

                // PASS 3: Operator approval on write if configured
                if self.config.require_approval_on_write {
                    let first_resolved = resolved_paths.first().map(|(p, _)| p.clone());
                    return Decision::AskOperator {
                        tool_name: tool_name.to_string(),
                        target_path: first_resolved,
                        action_summary: summarize_call(call),
                    };
                }
            }

            // Fail-closed: If a tool provides a path in jail, it must still be a recognized file tool,
            // modifying tool, or always-allowed tool. Unrecognized tools cannot bypass authorization!
            let is_always_allowed = self
                .config
                .always_allow_tools
                .iter()
                .any(|t| t == tool_name)
                || self
                    .config
                    .custom_always_allow_tools
                    .iter()
                    .any(|t| t == tool_name);

            if !is_file_tool(tool_name) && !is_write && !is_always_allowed {
                return Decision::Block(format!(
                    "Unrecognized tool '{}' is not whitelisted by policy",
                    tool_name
                ));
            }

            return Decision::Allow;
        }

        // 5. Always allowed read tools (if no path argument was extracted)
        let is_always_allowed = self
            .config
            .always_allow_tools
            .iter()
            .any(|t| t == tool_name)
            || self
                .config
                .custom_always_allow_tools
                .iter()
                .any(|t| t == tool_name);

        if is_always_allowed {
            return Decision::Allow;
        }

        // 6. Fail-closed: Unknown or unclassified tools are NOT allowed by default!
        if is_write {
            Decision::AskOperator {
                tool_name: tool_name.to_string(),
                target_path: None,
                action_summary: summarize_call(call),
            }
        } else {
            Decision::Block(format!(
                "Unrecognized tool '{}' is not whitelisted by policy",
                tool_name
            ))
        }
    }

    /// Hardened path validation: Lexical fast-fail, component-by-component symlink check, inode check
    pub fn validate_path_secure(&self, raw_path: &str) -> Result<PathBuf> {
        // Step 1: Lexical Fast-Fail Checks (Zero I/O, prevents Windows NTLM Coercion)
        validate_lexical_syntax(raw_path)?;

        let candidate = Path::new(raw_path);
        let absolute_target = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(candidate))
                .unwrap_or_else(|_| candidate.to_path_buf())
        };

        // Step 2: Component-by-component traversal to defeat symlink escapes to non-existent files
        let mut verified_prefix = PathBuf::new();
        for component in absolute_target.components() {
            match component {
                Component::Prefix(p) => verified_prefix.push(p.as_os_str()),
                Component::RootDir => verified_prefix.push(Component::RootDir.as_os_str()),
                Component::Normal(segment) => {
                    verified_prefix.push(segment);

                    // If component exists, inspect metadata without following symlinks
                    if let Ok(meta) = std::fs::symlink_metadata(&verified_prefix) {
                        if meta.file_type().is_symlink() {
                            // Resolve symlink target immediately and ensure it remains inside boundary
                            let target = std::fs::read_link(&verified_prefix)?;
                            let resolved = if target.is_absolute() {
                                target
                            } else {
                                verified_prefix
                                    .parent()
                                    .unwrap_or(Path::new("."))
                                    .join(target)
                            };

                            let canonical_target = resolved.canonicalize()?;
                            if !self.is_within_allowed_roots(&canonical_target) {
                                return Err(MoatError::PathBoundaryViolation {
                                    attempted: canonical_target.display().to_string(),
                                    allowed: self.allowed_roots_summary(),
                                });
                            }
                            verified_prefix = canonical_target;
                        }

                        // Hardlink Inode Check: If file has multiple links, reject
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            if meta.is_file() && meta.nlink() > 1 {
                                return Err(MoatError::PolicyViolation(format!(
                                    "Hardlink Inode-Aliasing detected on '{}' (nlink = {}). Access denied.",
                                    verified_prefix.display(),
                                    meta.nlink()
                                )));
                            }
                        }

                        #[cfg(windows)]
                        {
                            // Note: std::os::windows::fs::MetadataExt::number_of_links is nightly-only (feature windows_by_handle)
                            // On Windows without unstable features, symlink and reparse point checks above handle link protection
                        }
                    }
                }
                Component::CurDir => {
                    // Current directory component '.' is a harmless no-op
                    continue;
                }
                Component::ParentDir => {
                    return Err(MoatError::PolicyViolation(
                        "Illegal traversal component in path resolution".to_string(),
                    ));
                }
            }
        }

        // Step 3: Final canonical check if destination exists or canonical ancestor check
        let final_canonical = match absolute_target.canonicalize() {
            Ok(c) => c,
            Err(_) => {
                // For non-existent files (e.g. write_file), canonicalize verified parent
                let parent = absolute_target.parent().unwrap_or(Path::new("."));
                let canonical_parent = parent.canonicalize()?;
                let file_name = absolute_target.file_name().unwrap_or_default();
                canonical_parent.join(file_name)
            }
        };

        if !self.is_within_allowed_roots(&final_canonical) {
            return Err(MoatError::PathBoundaryViolation {
                attempted: final_canonical.display().to_string(),
                allowed: self.allowed_roots_summary(),
            });
        }

        Ok(final_canonical)
    }

    pub fn is_protected_target(&self, path: &Path) -> bool {
        if is_protected_system_file(path) {
            return true;
        }
        if self
            .config
            .protected_files
            .iter()
            .any(|protected| same_file_or_path(path, protected))
        {
            return true;
        }
        // Protect the jail/allowed root directory itself from direct modification or deletion
        if let Ok(c) = path.canonicalize() {
            if self.canonical_allowed_roots.iter().any(|root| root == &c) {
                return true;
            }
        }
        if let Some(audit_path) = &self.config.audit_log {
            if let (Ok(c1), Ok(c2)) = (path.canonicalize(), audit_path.canonicalize()) {
                if c1 == c2 {
                    return true;
                }
            }
            let s = path.to_string_lossy().to_lowercase().replace('\\', "/");
            let audit_s = audit_path
                .to_string_lossy()
                .to_lowercase()
                .replace('\\', "/");
            let audit_trimmed = audit_s.trim_start_matches("./");
            if s == audit_s || s.ends_with(&format!("/{}", audit_trimmed)) {
                return true;
            }
        }
        false
    }

    fn is_within_allowed_roots(&self, target: &Path) -> bool {
        self.canonical_allowed_roots
            .iter()
            .any(|root| target.starts_with(root))
    }

    pub fn allowed_roots_summary(&self) -> String {
        self.canonical_allowed_roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Compares two paths after resolving them as far as possible. Existing files are
/// compared by canonical path; non-existent targets are compared by canonical
/// parent plus file name. This keeps a relative `--config` path protected even
/// when the write would create the file.
fn same_file_or_path(a: &Path, b: &Path) -> bool {
    match (absolute_normalized_path(a), absolute_normalized_path(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn absolute_normalized_path(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let parent = absolute.parent()?.canonicalize().ok()?;
    Some(parent.join(absolute.file_name()?))
}

/// True if a path segment looks like a DOS 8.3 short name: up to six characters, a tilde, digits,
/// and an optional extension of up to three characters (`PROGRA~1`, `RUNNER~1`, `MOAT~1.TOM`).
fn has_dos_short_name_segment(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| {
        let Some(pos) = segment.find('~') else {
            return false;
        };
        let (stem, rest) = (&segment[..pos], &segment[pos + 1..]);
        let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if stem.is_empty() || stem.chars().count() > 6 || digits == 0 {
            return false;
        }
        let tail = &rest[digits..];
        tail.is_empty()
            || (tail.starts_with('.')
                && tail.chars().count() <= 4
                && !tail[1..].contains(['.', '~']))
    })
}

pub fn validate_lexical_syntax(path_str: &str) -> Result<()> {
    let trimmed = path_str.trim();

    // 1. Prevent Windows UNC paths and NT Object Manager namespaces. Normalize
    //    separators first so mixed forms such as `\/?\C:\` are caught too.
    //    `//` covers `\\`, `\\?\`, `\\.\` and `//server/share`.
    let normalized_prefix = trimmed.replace('\\', "/").to_lowercase();
    let forbidden_prefixes = [
        "//",
        "/??/",
        "/device/",
        "/global??/",
        "/globalroot/",
        "/dosdevices/",
        "/systemroot/",
        "/basenamedobjects/",
        "/arcname/",
        "/kernelobjects/",
    ];
    if forbidden_prefixes
        .iter()
        .any(|prefix| normalized_prefix.starts_with(prefix))
    {
        return Err(MoatError::PolicyViolation(
            "UNC network and device namespace paths are strictly prohibited".to_string(),
        ));
    }

    // 2. Prevent Alternate Data Streams and drive-relative paths (colon check)
    // Colon is ONLY permitted at index 1 for Windows drive letters followed by / or \ (e.g. "C:\")
    for (idx, ch) in trimmed.char_indices() {
        if ch == ':' {
            if idx != 1 {
                return Err(MoatError::PolicyViolation(format!(
                    "Illegal colon in path at position {}. Alternate Data Streams are prohibited.",
                    idx
                )));
            }
            let first_char = trimmed.chars().next().unwrap_or(' ');
            if !first_char.is_ascii_alphabetic() {
                return Err(MoatError::PolicyViolation(
                    "Colon is only permitted as Windows drive letter indicator (e.g. C:)"
                        .to_string(),
                ));
            }
            // Must be followed by / or \ (disallowing drive-relative C:foo)
            let third_char = trimmed.chars().nth(2);
            if third_char != Some('/') && third_char != Some('\\') {
                return Err(MoatError::PolicyViolation(
                    "Drive-relative paths without directory slash (e.g. C:foo) are prohibited"
                        .to_string(),
                ));
            }
        }
    }

    // 3. Prevent null byte injection
    if trimmed.contains('\0') {
        return Err(MoatError::PolicyViolation(
            "Null bytes in path are prohibited".to_string(),
        ));
    }

    // 4. Prevent DOS 8.3 short names (PROGRA~1, MOAT~1.TOM). Names that only contain a tilde,
    //    such as "iCloud~md~obsidian", are ordinary names.
    if has_dos_short_name_segment(trimmed) {
        return Err(MoatError::PolicyViolation(
            "DOS 8.3 short names containing '~' are prohibited".to_string(),
        ));
    }

    // 5. Prevent relative traversal components anywhere (start, middle, or end)
    if trimmed == ".."
        || trimmed.starts_with("../")
        || trimmed.starts_with(r"..\")
        || trimmed.ends_with("/..")
        || trimmed.ends_with(r"\..")
        || trimmed.contains("/../")
        || trimmed.contains(r"\..\")
        || trimmed.contains(r"/..\")
        || trimmed.contains(r"\../")
    {
        return Err(MoatError::PolicyViolation(
            "Directory traversal sequence '..' is prohibited".to_string(),
        ));
    }

    // 6. Prevent Windows reserved device names across ALL path components. Split
    //    on both separators so Windows-style paths are checked on every platform.
    let reserved_devices = [
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "CONFIG$", "COM1", "COM2",
        "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
        "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    for segment in trimmed.split(['/', '\\']) {
        let seg_str = segment.trim();
        if seg_str.is_empty() {
            continue;
        }
        let base_name = seg_str
            .split('.')
            .next()
            .unwrap_or(seg_str)
            .trim()
            .to_uppercase();
        if reserved_devices.contains(&base_name.as_str()) {
            return Err(MoatError::PolicyViolation(format!(
                "Reserved device name '{}' is prohibited",
                seg_str
            )));
        }
    }

    Ok(())
}

pub fn is_modifying_tool(tool_name: &str, custom_tools: &[String]) -> bool {
    let lower_raw = tool_name.to_lowercase();
    let lower = lower_raw.replace('-', "_");
    let standard = matches!(
        lower.as_str(),
        "write_file"
            | "edit_file"
            | "delete_file"
            | "remove_file"
            | "append_file"
            | "create_directory"
            | "create_dir"
            | "delete_directory"
            | "delete_dir"
            | "remove_directory"
            | "remove_dir"
            | "rmdir"
            | "mkdir"
            | "move_file"
            | "rename_file"
            | "copy_file"
            | "copy"
            | "cp"
            | "mv"
            | "rm"
            | "touch"
            | "touch_file"
            | "save_file"
            | "create_file"
            | "patch_file"
            | "overwrite_file"
            | "truncate_file"
            | "replace_file"
            | "unlink"
            | "unlink_file"
            | "erase"
            | "erase_file"
            | "wipe"
            | "wipe_file"
            | "shred"
            | "shred_file"
            | "truncate"
            | "overwrite"
            | "clean_dir"
            | "purge_dir"
            | "put_file"
            | "write_to_file"
            | "run_command"
            | "execute_command"
            | "exec_command"
            | "run_cmd"
            | "run_script"
            | "execute_script"
            | "run_code"
            | "system_exec"
            | "run_terminal_cmd"
            | "bash"
            | "sh"
            | "powershell"
            | "pwsh"
            | "cmd"
            | "zsh"
            | "fish"
            | "wsl"
            | "nu"
            | "csh"
            | "tcsh"
            | "shell"
            | "terminal"
            | "eval"
            | "evaluate"
            | "delete_everything"
    ) || lower.starts_with("write_")
        || lower.starts_with("edit_")
        || lower.starts_with("create_")
        || lower.starts_with("delete_")
        || lower.starts_with("remove_")
        || lower.starts_with("modify_")
        || lower.starts_with("update_")
        || lower.starts_with("append_")
        || lower.starts_with("patch_")
        || lower.starts_with("copy_")
        || lower.starts_with("move_")
        || lower.starts_with("rename_")
        || lower.starts_with("touch_")
        || lower.starts_with("save_")
        || lower.starts_with("replace_")
        || lower.starts_with("put_")
        || lower.starts_with("erase_")
        || lower.starts_with("wipe_")
        || lower.starts_with("shred_")
        || lower.starts_with("unlink_")
        || lower.starts_with("truncate_")
        || lower.starts_with("overwrite_")
        || lower.starts_with("clean_")
        || lower.starts_with("purge_")
        || lower.starts_with("eval_")
        || lower.starts_with("run_")
        || lower.starts_with("exec_")
        || lower.starts_with("execute_")
        || lower.starts_with("system_")
        || lower.ends_with("_write")
        || lower.ends_with("_edit")
        || lower.ends_with("_create")
        || lower.ends_with("_delete")
        || lower.ends_with("_remove")
        || lower.ends_with("_modify")
        || lower.ends_with("_update")
        || lower.ends_with("_append")
        || lower.ends_with("_patch")
        || lower.ends_with("_copy")
        || lower.ends_with("_move")
        || lower.ends_with("_rename")
        || lower.ends_with("_touch")
        || lower.ends_with("_save")
        || lower.ends_with("_replace")
        || lower.ends_with("_erase")
        || lower.ends_with("_wipe")
        || lower.ends_with("_shred")
        || lower.ends_with("_unlink")
        || lower.ends_with("_truncate")
        || lower.ends_with("_overwrite")
        || lower.ends_with("_cmd")
        || lower.ends_with("_command")
        || lower.ends_with("_shell")
        || lower.ends_with("_terminal")
        || lower.ends_with("_script")
        || lower.ends_with("_eval")
        || lower_raw.starts_with("write")
        || lower_raw.starts_with("edit")
        || lower_raw.starts_with("create")
        || lower_raw.starts_with("delete")
        || lower_raw.starts_with("remove")
        || lower_raw.starts_with("modify")
        || lower_raw.starts_with("update")
        || lower_raw.starts_with("append")
        || lower_raw.starts_with("patch")
        || lower_raw.starts_with("copy")
        || lower_raw.starts_with("move")
        || lower_raw.starts_with("rename")
        || lower_raw.starts_with("truncate")
        || lower_raw.starts_with("touch")
        || lower_raw.starts_with("erase")
        || lower_raw.starts_with("wipe")
        || lower_raw.starts_with("shred")
        || lower_raw.starts_with("unlink")
        || lower_raw.starts_with("overwrite")
        || lower_raw.starts_with("save")
        || lower_raw.starts_with("replace")
        || lower_raw.starts_with("put")
        || lower_raw.starts_with("clean")
        || lower_raw.starts_with("purge")
        || lower_raw.starts_with("eval")
        || lower_raw.starts_with("exec")
        || lower_raw.starts_with("run")
        || lower_raw.starts_with("runcommand")
        || lower_raw.starts_with("executecommand");

    standard
        || custom_tools
            .iter()
            .any(|t| t.eq_ignore_ascii_case(tool_name))
}

fn is_protected_system_file(path: &Path) -> bool {
    // 1. Component-based check: if any segment in the path hierarchy matches protected directories or files
    for comp in path.components() {
        if let Component::Normal(os_str) = comp {
            let seg = os_str.to_string_lossy().to_lowercase();
            let seg_trimmed = seg.trim_end_matches([' ', '.']);
            if seg_trimmed == ".git"
                || seg_trimmed == ".vscode"
                || seg_trimmed == ".github"
                || seg_trimmed == ".ssh"
                || seg_trimmed == ".aws"
                || seg_trimmed == "moat.toml"
                || seg_trimmed == "fence.toml"
                || seg_trimmed == ".gitmodules"
                || seg_trimmed == ".gitconfig"
                || seg_trimmed == "id_rsa"
                || seg_trimmed == "id_ed25519"
                || seg_trimmed == "id_ecdsa"
                || seg_trimmed == "authorized_keys"
                || seg_trimmed == "known_hosts"
                || seg_trimmed == ".env"
                || seg_trimmed.starts_with(".env.")
            {
                return true;
            }
        }
    }

    // 2. String-based check for raw strings, prefixes, suffixes, and substring patterns
    let s_raw = path.to_string_lossy().to_lowercase().replace('\\', "/");
    let s = s_raw.trim_end_matches([' ', '.']);
    s == "moat.toml"
        || s == "fence.toml"
        || s == ".git"
        || s.starts_with(".git/")
        || s.ends_with("/.git")
        || s.contains("/.git/")
        || s == ".vscode"
        || s.starts_with(".vscode/")
        || s.ends_with("/.vscode")
        || s.contains("/.vscode/")
        || s == ".github"
        || s.starts_with(".github/")
        || s.ends_with("/.github")
        || s.contains("/.github/")
        || s == ".env"
        || s.starts_with(".env.")
        || s.starts_with(".env/")
        || s.ends_with("/.env")
        || s.contains("/.env.")
        || s.contains("/.env/")
        || s == ".ssh"
        || s.starts_with(".ssh/")
        || s.ends_with("/.ssh")
        || s.contains("/.ssh/")
        || s == ".aws"
        || s.starts_with(".aws/")
        || s.ends_with("/.aws")
        || s.contains("/.aws/")
        || s == "id_rsa"
        || s.ends_with("/id_rsa")
        || s == "id_ed25519"
        || s.ends_with("/id_ed25519")
        || s == "id_ecdsa"
        || s.ends_with("/id_ecdsa")
        || s == "authorized_keys"
        || s.ends_with("/authorized_keys")
        || s == "known_hosts"
        || s.ends_with("/known_hosts")
        || s == ".gitmodules"
        || s.ends_with("/.gitmodules")
        || s == ".gitconfig"
        || s.ends_with("/.gitconfig")
}

fn is_file_tool(tool_name: &str) -> bool {
    let lower_raw = tool_name.to_lowercase();
    let lower = lower_raw.replace('-', "_");
    let standard = matches!(
        lower.as_str(),
        "read_file"
            | "list_directory"
            | "search_files"
            | "grep"
            | "read_multiple_files"
            | "view_file"
            | "cat"
            | "head"
            | "tail"
            | "get_file"
            | "fetch_file"
            | "open_file"
            | "read_lines"
            | "get_file_info"
            | "list_allowed_directories"
            | "list_tables"
            | "describe_table"
            | "show_schema"
            | "read_query"
            | "read_graph"
            | "search_nodes"
            | "open_nodes"
            | "write_file"
            | "edit_file"
            | "create_file"
            | "delete_file"
            | "remove_file"
            | "append_file"
            | "patch_file"
            | "replace_file"
            | "truncate_file"
            | "overwrite_file"
            | "touch_file"
            | "save_file"
            | "put_file"
            | "write_to_file"
            | "create_directory"
            | "create_dir"
            | "delete_directory"
            | "delete_dir"
            | "remove_directory"
            | "remove_dir"
            | "rmdir"
            | "mkdir"
            | "move_file"
            | "rename_file"
            | "copy_file"
            | "copy"
            | "cp"
            | "mv"
            | "rm"
            | "touch"
            | "unlink"
            | "unlink_file"
            | "erase"
            | "erase_file"
            | "wipe"
            | "wipe_file"
            | "shred"
            | "shred_file"
            | "truncate"
            | "overwrite"
            | "clean_dir"
            | "purge_dir"
            // read-only tool of the official filesystem MCP server
            | "directory_tree"
    );
    standard
        || lower.starts_with("read_")
        || lower.starts_with("list_")
        || lower.starts_with("search_")
        || lower.starts_with("get_")
        || lower.starts_with("view_")
        || lower.starts_with("write_")
        || lower.starts_with("edit_")
        || lower.starts_with("create_")
        || lower.starts_with("delete_")
        || lower.starts_with("remove_")
        || lower.starts_with("copy_")
        || lower.starts_with("move_")
        || lower.starts_with("rename_")
        || lower.ends_with("_file")
        || lower.ends_with("_files")
        || lower.ends_with("_directory")
        || lower.ends_with("_dir")
        || lower.ends_with("_read")
        || lower.ends_with("_view")
        || lower_raw.starts_with("read")
        || lower_raw.starts_with("write")
        || lower_raw.starts_with("delete")
        || lower_raw.starts_with("edit")
        || lower_raw.starts_with("create")
        || lower_raw.ends_with("file")
        || lower_raw.ends_with("files")
        || lower_raw.ends_with("directory")
        || lower_raw.ends_with("dir")
}

/// Argument keys that name the directory other relative paths in the same call refer to.
const BASE_DIR_KEYS: [&str; 7] = [
    "repopath",
    "repositorypath",
    "repodir",
    "cwd",
    "workdir",
    "workingdir",
    "workingdirectory",
];

fn is_relative_path_text(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.starts_with('/') || t.starts_with('\\') || t.starts_with('~') {
        return false;
    }
    if t.to_ascii_lowercase().starts_with("file://") {
        return false;
    }
    let bytes = t.as_bytes();
    !(bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// A relative path next to a base directory key (`repo_path`, `cwd`, ...) is meant relative to
/// that directory, not relative to the working directory of mcp-moat. The joined path is checked.
fn resolve_against_base(base: &Option<String>, value: &str) -> String {
    match base {
        Some(b) if is_relative_path_text(value) => {
            format!("{}/{}", b.trim_end_matches(['/', '\\']), value)
        }
        _ => value.to_string(),
    }
}

fn extract_paths_with_ignored_keys(
    val: &serde_json::Value,
    paths: &mut Vec<String>,
    custom_path_keys: &[String],
    ignore_keys: &[String],
) {
    match val {
        serde_json::Value::Object(map) => {
            let single_keys = [
                "path",
                "filepath",
                "target",
                "targetpath",
                "targetfile",
                "targetdir",
                "targetdirectory",
                "file",
                "filename",
                "directory",
                "dir",
                "folder",
                "dest",
                "destination",
                "destpath",
                "destinationpath",
                "destfile",
                "destinationfile",
                "destdir",
                "destinationdir",
                "source",
                "sourcepath",
                "sourcefile",
                "sourcedir",
                "sourcedirectory",
                "src",
                "srcpath",
                "srcfile",
                "srcdir",
                "srcdirectory",
                "from",
                "to",
                "uri",
                "url",
                "inputpath",
                "outputpath",
                "inputfile",
                "outputfile",
                "inpath",
                "outpath",
                "infile",
                "outfile",
                "indir",
                "outdir",
                "oldpath",
                "newpath",
                "oldfile",
                "newfile",
                "olddir",
                "newdir",
                "pathname",
                "location",
                "href",
                "root",
                "rootdir",
                "basepath",
                "basedir",
                "savepath",
                "savedir",
                "savefile",
                "database",
                "dbpath",
                "dbfile",
            ];
            let array_keys = [
                "paths",
                "filepaths",
                "targetpaths",
                "files",
                "targets",
                "directories",
                "folders",
                "sources",
                "destinations",
                "destpaths",
                "sourcepaths",
            ];

            let base: Option<String> = map.iter().find_map(|(k, v)| {
                let kn = k.to_lowercase().replace(['_', '-'], "");
                if BASE_DIR_KEYS.contains(&kn.as_str()) {
                    v.as_str().map(String::from)
                } else {
                    None
                }
            });
            let no_base: Option<String> = None;

            for (k, v) in map {
                let k_norm = k.to_lowercase().replace(['_', '-'], "");
                let ignored = ignore_keys
                    .iter()
                    .any(|ik| ik.to_lowercase().replace(['_', '-'], "") == k_norm);
                let base_ref = if BASE_DIR_KEYS.contains(&k_norm.as_str()) {
                    &no_base
                } else {
                    &base
                };
                let matches_custom = custom_path_keys
                    .iter()
                    .any(|ck| ck.to_lowercase().replace(['_', '-'], "") == k_norm);
                let is_path_key = !ignored
                    && (matches_custom
                        || single_keys.iter().any(|sk| *sk == k_norm)
                        || array_keys.iter().any(|ak| *ak == k_norm)
                        || k_norm.ends_with("path")
                        || k_norm.ends_with("paths")
                        || k_norm.ends_with("dir")
                        || k_norm.ends_with("directory")
                        || k_norm.ends_with("folder")
                        || k_norm.ends_with("directories")
                        || k_norm.ends_with("folders")
                        || k_norm.ends_with("file")
                        || k_norm.ends_with("files")
                        || k_norm.starts_with("file")
                        || k_norm.starts_with("path"));

                if is_path_key {
                    if let Some(s) = v.as_str() {
                        if s.to_ascii_lowercase().starts_with("file://") {
                            if let Ok(parsed) = parse_file_uri_to_path(s) {
                                paths.push(parsed.to_string_lossy().to_string());
                            } else {
                                paths.push(resolve_against_base(base_ref, s));
                            }
                        } else {
                            paths.push(resolve_against_base(base_ref, s));
                        }
                    } else if let Some(arr) = v.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                if s.to_ascii_lowercase().starts_with("file://") {
                                    if let Ok(parsed) = parse_file_uri_to_path(s) {
                                        paths.push(parsed.to_string_lossy().to_string());
                                    } else {
                                        paths.push(resolve_against_base(base_ref, s));
                                    }
                                } else {
                                    paths.push(resolve_against_base(base_ref, s));
                                }
                            }
                        }
                    }
                }
                if v.is_object() || v.is_array() {
                    extract_paths_with_ignored_keys(v, paths, custom_path_keys, ignore_keys);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_paths_with_ignored_keys(item, paths, custom_path_keys, ignore_keys);
            }
        }
        _ => {}
    }
}

pub fn extract_all_path_arguments(call: &ToolCallParams, custom_keys: &[String]) -> Vec<String> {
    extract_all_path_arguments_ignoring(call, custom_keys, &[])
}

/// Like [`extract_all_path_arguments`], but values of the keys in `ignore_keys` are not paths.
pub fn extract_all_path_arguments_ignoring(
    call: &ToolCallParams,
    custom_keys: &[String],
    ignore_keys: &[String],
) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(args) = &call.arguments {
        extract_paths_with_ignored_keys(args, &mut paths, custom_keys, ignore_keys);
    }
    paths
}

fn find_args_in_value(val: &serde_json::Value) -> Option<String> {
    let arg_keys = ["args", "arguments", "parameters", "params"];
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let k_norm = k.to_lowercase().replace(['_', '-'], "");
                if arg_keys.iter().any(|&ak| ak == k_norm) {
                    if let Some(s) = v.as_str() {
                        return Some(s.to_string());
                    } else if let Some(arr) = v.as_array() {
                        let parts: Vec<&str> =
                            arr.iter().filter_map(|item| item.as_str()).collect();
                        if !parts.is_empty() {
                            return Some(parts.join(" "));
                        }
                    }
                }
            }
            for v in map.values() {
                if v.is_object() || v.is_array() {
                    if let Some(res) = find_args_in_value(v) {
                        return Some(res);
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(res) = find_args_in_value(item) {
                    return Some(res);
                }
            }
        }
        _ => {}
    }
    None
}

fn extract_strings_from_value(v: &serde_json::Value) -> Vec<String> {
    if let Some(s) = v.as_str() {
        if !s.is_empty() {
            return vec![s.to_string()];
        }
    } else if let Some(arr) = v.as_array() {
        let parts: Vec<&str> = arr.iter().filter_map(|item| item.as_str()).collect();
        if !parts.is_empty() {
            return vec![parts.join(" ")];
        }
    }
    Vec::new()
}

fn extract_command_from_value(val: &serde_json::Value, custom_keys: &[String]) -> Option<String> {
    match val {
        serde_json::Value::Object(map) => {
            let cmd_keys = ["command", "cmd", "commandline", "exec", "program", "line"];
            let arg_keys = ["args", "arguments", "parameters", "params"];
            let script_keys = ["script", "code", "input", "expression"];

            let is_arg_key = |k_norm: &str| arg_keys.contains(&k_norm);
            let is_script_key = |k_norm: &str| script_keys.contains(&k_norm);
            let is_cmd_key = |k_norm: &str| {
                !is_arg_key(k_norm)
                    && !is_script_key(k_norm)
                    && (cmd_keys.contains(&k_norm)
                        || custom_keys
                            .iter()
                            .any(|ck| ck.to_lowercase().replace(['_', '-'], "") == k_norm))
            };

            let mut cmd_parts = Vec::new();
            let mut script_parts = Vec::new();
            let mut arg_parts = Vec::new();

            for (k, v) in map {
                let k_norm = k.to_lowercase().replace(['_', '-'], "");
                if is_cmd_key(&k_norm) {
                    cmd_parts.extend(extract_strings_from_value(v));
                } else if is_script_key(&k_norm) {
                    script_parts.extend(extract_strings_from_value(v));
                } else if is_arg_key(&k_norm) {
                    arg_parts.extend(extract_strings_from_value(v));
                }
            }

            if arg_parts.is_empty() {
                for v in map.values() {
                    if v.is_object() || v.is_array() {
                        if let Some(nested_args) = find_args_in_value(v) {
                            arg_parts.push(nested_args);
                            break;
                        }
                    }
                }
            }

            let mut combined_parts = Vec::new();
            if !cmd_parts.is_empty() {
                combined_parts.push(cmd_parts.join(" "));
            }
            if !script_parts.is_empty() {
                combined_parts.push(script_parts.join(" "));
            }
            if !arg_parts.is_empty() {
                combined_parts.push(arg_parts.join(" "));
            }

            if !combined_parts.is_empty() {
                return Some(combined_parts.join(" "));
            }

            for v in map.values() {
                if v.is_object() || v.is_array() {
                    if let Some(cmd) = extract_command_from_value(v, custom_keys) {
                        return Some(cmd);
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(cmd) = extract_command_from_value(item, custom_keys) {
                    return Some(cmd);
                }
            }
        }
        _ => {}
    }

    None
}

pub fn extract_command_argument(call: &ToolCallParams, custom_keys: &[String]) -> Option<String> {
    if let Some(args) = &call.arguments {
        extract_command_from_value(args, custom_keys)
    } else {
        None
    }
}

pub fn has_dangerous_shell_metacharacters(cmd: &str) -> bool {
    const DANGEROUS: &[char] = &['|', '&', ';', '$', '`', '>', '<', '\n', '\r', '\0'];
    cmd.contains(DANGEROUS)
}

const SHELL_SEPARATORS: &[char] = &[
    '|', '&', ';', '(', ')', '`', '$', '>', '<', '\n', '\r', '\0',
];

/// Tools that use single-letter POSIX flags. Combined short flags such as
/// `-rf` are expanded for these programs only, because other programs (for
/// example PowerShell) use single-dash long options such as `-NoProfile`.
const POSIX_SHORT_FLAG_TOOLS: &[&str] = &[
    "awk", "cat", "chgrp", "chmod", "chown", "chroot", "cp", "cut", "df", "du", "find", "grep",
    "head", "kill", "ln", "ls", "mkdir", "mount", "mv", "ps", "rm", "rmdir", "sed", "sort", "tail",
    "tar", "touch", "tr", "umount", "uniq", "wc", "xargs",
];

/// Tokenizes a shell command line into words, honoring single/double quotes.
/// Backslashes are only treated as escapes for whitespace and quote characters
/// so that Windows paths such as `C:\Windows\System32` remain intact.
fn tokenize_shell_command(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && quote != Some('\'') {
            match chars.peek().copied() {
                Some(next) if next.is_whitespace() || next == '"' || next == '\'' => {
                    current.push(next);
                    chars.next();
                }
                _ => current.push('\\'),
            }
            continue;
        }

        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Splits tokens into shell command segments at operators such as `;`, `&&`,
/// and `|`. This keeps a destructive program from being matched against an
/// argument of a later command (e.g. `rm -rf /tmp && echo /`).
fn split_into_command_segments(tokens: &[String]) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut current = Vec::new();

    for token in tokens {
        let mut remainder = token.as_str();
        loop {
            match remainder.find(|c| SHELL_SEPARATORS.contains(&c)) {
                Some(idx) => {
                    if idx > 0 {
                        current.push(remainder[..idx].to_string());
                    }
                    if !current.is_empty() {
                        segments.push(std::mem::take(&mut current));
                    }
                    remainder = &remainder[idx + 1..];
                }
                None => {
                    if !remainder.is_empty() {
                        current.push(remainder.to_string());
                    }
                    break;
                }
            }
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    segments
}

/// Resolves a program token to its basename: `/bin/rm` -> `rm`,
/// `C:\Windows\System32\format.com` -> `format`, `mkfs.ext4` stays intact.
fn normalize_program_token(token: &str) -> String {
    let base = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();

    for ext in [".exe", ".com", ".bat", ".cmd", ".ps1"] {
        if let Some(stripped) = base.strip_suffix(ext) {
            return stripped.to_string();
        }
    }

    base
}

/// Normalizes a non-program token for comparison. Root-like tokens (`/`, `//`,
/// `/*`) all refer to the filesystem root and are treated as equivalent.
fn normalize_arg_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    if !lower.is_empty() && lower.chars().all(|c| c == '/' || c == '\\') {
        return "/".to_string();
    }
    if lower == "/*" || lower == "\\*" {
        return "/".to_string();
    }
    lower
}

fn normalize_whitespace_lower(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase()
}

/// Returns true when `token` is an option for `program`. PowerShell and pwsh
/// accept slash-prefixed options (`/e`), while for other programs a leading
/// slash denotes a path.
fn is_flag_token(program: &str, token: &str) -> bool {
    if token.starts_with('-') {
        return true;
    }
    if let Some(rest) = token.strip_prefix('/') {
        return matches!(program, "powershell" | "pwsh")
            && !rest.is_empty()
            && rest.chars().all(|c| c.is_ascii_alphabetic());
    }
    false
}

fn canonical_flag(token: &str) -> String {
    // PowerShell also accepts `-enc:<payload>`.
    let base = token.split(':').next().unwrap_or(token);
    match base {
        "--recursive" => "-r".to_string(),
        "--force" => "-f".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

fn expand_short_flags(program: &str, tokens: &[String]) -> Vec<String> {
    if !POSIX_SHORT_FLAG_TOOLS.contains(&program) {
        return tokens.to_vec();
    }

    let mut expanded = Vec::with_capacity(tokens.len());
    for token in tokens {
        let is_combined_short_flag = token.len() > 2
            && token.starts_with('-')
            && !token.starts_with("--")
            && token[1..].chars().all(|c| c.is_ascii_alphabetic());
        if is_combined_short_flag {
            for ch in token[1..].chars() {
                expanded.push(format!("-{}", ch.to_ascii_lowercase()));
            }
        } else {
            expanded.push(token.to_ascii_lowercase());
        }
    }
    expanded
}

fn split_flags_and_args(program: &str, tokens: &[String]) -> (Vec<String>, Vec<String>) {
    let mut flags = Vec::new();
    let mut args = Vec::new();
    for token in tokens {
        if is_flag_token(program, token) {
            flags.push(canonical_flag(token));
        } else {
            args.push(normalize_arg_token(token));
        }
    }
    (flags, args)
}

fn contains_contiguous(haystack: &[String], needle: &[String]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Matches a command line against a configured blocked-command rule using
/// tokenization instead of raw substring matching. This prevents whitespace
/// and path-prefix bypasses while avoiding false blocks for non-root targets
/// (e.g. `rm -rf /tmp/build` prompts instead of being hard-blocked).
fn command_matches_blocked(cmd: &str, blocked: &str) -> bool {
    let blocked = blocked.trim();
    if blocked.is_empty() {
        return false;
    }

    // Shell constructs (e.g. fork bombs) cannot be matched reliably token by
    // token, so compare them after removing all whitespace.
    if blocked.chars().any(|c| SHELL_SEPARATORS.contains(&c)) {
        return normalize_whitespace_lower(cmd).contains(&normalize_whitespace_lower(blocked));
    }

    let cmd_tokens = tokenize_shell_command(cmd);
    let blocked_tokens = tokenize_shell_command(blocked);
    if blocked_tokens.is_empty() {
        return false;
    }

    // Quoted or script payloads (e.g. `python -c "rm -rf /"`) are tokenized
    // recursively so a destructive command hidden inside a string is still
    // detected. Quotes are stripped before recursion, so the input shrinks and
    // the recursion terminates.
    if cmd_tokens.iter().any(|token| {
        token.chars().any(char::is_whitespace) && command_matches_blocked(token, blocked)
    }) {
        return true;
    }

    // A single-token rule such as `mkfs` matches the program anywhere in the
    // pipeline (including wrappers like sudo) and versioned names (mkfs.ext4).
    if blocked_tokens.len() == 1 {
        let target = normalize_program_token(&blocked_tokens[0]);
        return cmd_tokens.iter().any(|token| {
            let normalized = normalize_program_token(token);
            normalized == target || normalized.starts_with(&format!("{target}."))
        });
    }

    let blocked_program = normalize_program_token(&blocked_tokens[0]);
    let blocked_rest = expand_short_flags(&blocked_program, &blocked_tokens[1..]);
    let (blocked_flags, blocked_args) = split_flags_and_args(&blocked_program, &blocked_rest);

    for segment in split_into_command_segments(&cmd_tokens) {
        for (start, token) in segment.iter().enumerate() {
            if normalize_program_token(token) != blocked_program {
                continue;
            }

            let rest = expand_short_flags(&blocked_program, &segment[start + 1..]);
            let (cmd_flags, cmd_args) = split_flags_and_args(&blocked_program, &rest);

            if blocked_flags.iter().all(|flag| cmd_flags.contains(flag))
                && contains_contiguous(&cmd_args, &blocked_args)
            {
                return true;
            }
        }
    }

    false
}

fn summarize_call(call: &ToolCallParams) -> String {
    if let Some(args) = &call.arguments {
        format!(
            "{}({})",
            call.name,
            serde_json::to_string(args).unwrap_or_default()
        )
    } else {
        format!("{}()", call.name)
    }
}

#[cfg(test)]
mod builtin_regex_tests {
    use super::*;

    #[test]
    fn builtin_pwsh_regex_compiles_and_matches_encoded_command() {
        let re = builtin_pwsh_regex().expect("built-in pattern must compile");
        assert!(re.is_match("powershell.exe -NoProfile -enc AAAA"));
        assert!(re.is_match("pwsh /encodedcommand AAAA"));
        assert!(!re.is_match("powershell.exe -File script.ps1"));
    }

    #[test]
    fn policy_engine_with_default_config_builds() {
        assert!(PolicyEngine::new(PolicyConfig::default()).is_ok());
    }
}

#[cfg(test)]
mod command_matcher_tests {
    use super::*;

    #[test]
    fn matches_destructive_rm_root_across_whitespace_and_path_prefixes() {
        assert!(command_matches_blocked("rm -rf /", "rm -rf /"));
        assert!(command_matches_blocked("rm  -rf   /", "rm -rf /"));
        assert!(command_matches_blocked("/bin/rm -rf /", "rm -rf /"));
        assert!(command_matches_blocked("/usr/bin/rm -rf /", "rm -rf /"));
        assert!(command_matches_blocked("sudo rm -rf /", "rm -rf /"));
        assert!(command_matches_blocked("rm -fr /", "rm -rf /"));
        assert!(command_matches_blocked("rm -r -f /", "rm -rf /"));
        assert!(command_matches_blocked(
            "rm --recursive --force /",
            "rm -rf /"
        ));
        assert!(command_matches_blocked("rm -rf /*", "rm -rf /"));
        assert!(command_matches_blocked("rm -rf //", "rm -rf /"));
    }

    #[test]
    fn does_not_block_non_root_rm_targets() {
        assert!(!command_matches_blocked("rm -rf /tmp/build", "rm -rf /"));
        assert!(!command_matches_blocked("rm -rf ./target", "rm -rf /"));
        assert!(!command_matches_blocked(
            "rm -rf /tmp && echo /",
            "rm -rf /"
        ));
        assert!(!command_matches_blocked("echo rm -rf /tmp", "rm -rf /"));
    }

    #[test]
    fn matches_single_token_rules_with_extensions_and_wrappers() {
        assert!(command_matches_blocked("mkfs", "mkfs"));
        assert!(command_matches_blocked("mkfs.ext4 /dev/sda", "mkfs"));
        assert!(command_matches_blocked("sudo mkfs.xfs /dev/sda", "mkfs"));
        assert!(!command_matches_blocked("mkfsnot /dev/sda", "mkfs"));
    }

    #[test]
    fn matches_dd_and_format_variants() {
        assert!(command_matches_blocked(
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/zero"
        ));
        assert!(command_matches_blocked(
            "/bin/dd bs=1M if=/dev/zero",
            "dd if=/dev/zero"
        ));
        assert!(!command_matches_blocked(
            "dd if=/dev/urandom of=/dev/sda",
            "dd if=/dev/zero"
        ));
        assert!(command_matches_blocked("format c:", "format c:"));
        assert!(command_matches_blocked("format.com C:", "format c:"));
        assert!(!command_matches_blocked("format d:", "format c:"));
    }

    #[test]
    fn matches_powershell_encoded_flags_with_wrappers() {
        assert!(command_matches_blocked(
            "powershell -enc AAAA",
            "powershell -enc"
        ));
        assert!(command_matches_blocked(
            "powershell.exe -NoProfile -enc AAAA",
            "powershell -enc"
        ));
        assert!(command_matches_blocked("pwsh /e AAAA", "pwsh /e"));
        assert!(!command_matches_blocked(
            "powershell -File script.ps1",
            "powershell -enc"
        ));
    }

    #[test]
    fn matches_fork_bomb_across_whitespace() {
        assert!(command_matches_blocked(":(){ :|:& };:", ":(){ :|:& };:"));
        assert!(command_matches_blocked(":(){ :|:&};:", ":(){ :|:& };:"));
        assert!(!command_matches_blocked("echo fork bomb", ":(){ :|:& };:"));
    }

    #[test]
    fn windows_paths_are_not_treated_as_escape_sequences() {
        assert!(command_matches_blocked(
            r"C:\Windows\System32\format.com C:",
            "format c:"
        ));
        assert!(command_matches_blocked(r"C:\bin\rm.exe -rf /", "rm -rf /"));
    }
}
