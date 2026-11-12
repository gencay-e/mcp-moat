use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

#[derive(Debug, Default, Clone)]
pub struct SessionApprovalCache {
    allowed_tools: HashSet<String>,
    allowed_actions: HashSet<String>,
}

impl SessionApprovalCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_shell_tool(name: &str) -> bool {
        let lower_raw = name.to_lowercase();
        let lower = lower_raw.replace('-', "_");
        matches!(
            lower.as_str(),
            "bash"
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
                | "execute_command"
                | "run_terminal_cmd"
                | "run_command"
                | "terminal"
                | "shell"
                | "exec"
                | "exec_command"
                | "execute"
                | "run_cmd"
                | "run_script"
                | "execute_script"
                | "run_code"
                | "system_exec"
                | "eval"
                | "evaluate"
        ) || lower.starts_with("run_")
            || lower.starts_with("exec_")
            || lower.starts_with("execute_")
            || lower.starts_with("eval_")
            || lower.starts_with("system_")
            || lower.ends_with("_cmd")
            || lower.ends_with("_command")
            || lower.ends_with("_shell")
            || lower.ends_with("_terminal")
            || lower.ends_with("_script")
            || lower.ends_with("_eval")
            || lower.contains("command")
            || lower.contains("shell")
            || lower.contains("terminal")
            || lower_raw.starts_with("run")
            || lower_raw.starts_with("exec")
    }

    pub fn is_action_allowed(&self, action_summary: &str) -> bool {
        self.allowed_actions.contains(action_summary)
    }

    pub fn is_allowed(&self, tool_name: &str, action_summary: Option<&str>) -> bool {
        // Sensitive self-escalation attempts (protected configuration/hooks or root directory) must NEVER be bypassed tool-wide!
        let is_sensitive_target = action_summary
            .map(|s| {
                s.contains("protected configuration")
                    || s.contains("protected in-jail")
                    || s.contains("protected root")
                    || s.contains("allowed root directory")
            })
            .unwrap_or(false);

        if !is_sensitive_target
            && !Self::is_shell_tool(tool_name)
            && self.allowed_tools.contains(tool_name)
        {
            return true;
        }
        if let Some(summary) = action_summary {
            if self.allowed_actions.contains(summary) {
                return true;
            }
        }
        false
    }

    pub fn allow_tool(&mut self, tool_name: impl Into<String>) {
        let name = tool_name.into();
        // Shell tools must NEVER be cached tool-wide!
        if Self::is_shell_tool(&name) {
            return;
        }
        self.allowed_tools.insert(name);
    }

    pub fn allow_action(&mut self, action_summary: impl Into<String>) {
        self.allowed_actions.insert(action_summary.into());
    }

    pub fn allow_always(&mut self, tool_name: &str, action_summary: Option<&str>) {
        let is_sensitive_target = action_summary
            .map(|s| {
                s.contains("protected configuration")
                    || s.contains("protected in-jail")
                    || s.contains("protected root")
                    || s.contains("allowed root directory")
            })
            .unwrap_or(false);

        if Self::is_shell_tool(tool_name) || is_sensitive_target {
            if let Some(summary) = action_summary {
                self.allow_action(summary);
            }
        } else {
            self.allow_tool(tool_name);
        }
    }

    pub fn clear(&mut self) {
        self.allowed_tools.clear();
        self.allowed_actions.clear();
    }
}

pub struct DirectConsole {
    reader: Option<Box<dyn BufRead + Send>>,
    writer: Option<Box<dyn Write + Send>>,
}

impl DirectConsole {
    pub fn open() -> io::Result<Self> {
        #[cfg(windows)]
        {
            let in_file = OpenOptions::new().read(true).write(false).open("CONIN$")?;
            let out_file = OpenOptions::new().read(false).write(true).open("CONOUT$")?;
            Ok(Self {
                reader: Some(Box::new(BufReader::new(in_file))),
                writer: Some(Box::new(out_file)),
            })
        }

        #[cfg(not(windows))]
        {
            let tty_in = OpenOptions::new()
                .read(true)
                .write(false)
                .open("/dev/tty")?;
            let tty_out = OpenOptions::new()
                .read(false)
                .write(true)
                .open("/dev/tty")?;
            Ok(Self {
                reader: Some(Box::new(BufReader::new(tty_in))),
                writer: Some(Box::new(tty_out)),
            })
        }
    }

    /// Creates a console instance backed by arbitrary I/O (ideal for automated testing)
    pub fn with_io<R, W>(reader: R, writer: W) -> Self
    where
        R: BufRead + Send + 'static,
        W: Write + Send + 'static,
    {
        Self {
            reader: Some(Box::new(reader)),
            writer: Some(Box::new(writer)),
        }
    }

    /// Fallback in case direct console device cannot be opened (e.g. non-interactive daemon)
    pub fn is_available(&self) -> bool {
        self.reader.is_some() && self.writer.is_some()
    }

    pub fn write_str(&mut self, s: &str) -> io::Result<()> {
        if let Some(w) = &mut self.writer {
            w.write_all(s.as_bytes())?;
            w.flush()?;
        }
        Ok(())
    }

    pub fn prompt_user(&mut self, prompt: &str) -> io::Result<String> {
        self.write_str(prompt)?;
        let mut line = String::new();
        if let Some(r) = &mut self.reader {
            let n = r.read_line(&mut line)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TTY input closed (EOF)",
                ));
            }
        }
        Ok(line.trim().to_lowercase())
    }

    /// Asks operator for approval of a proposed action (convenience method returning boolean)
    pub fn ask_approval(&mut self, summary: &str, diff_preview: Option<&str>) -> io::Result<bool> {
        match self.ask_approval_detailed(summary, diff_preview)? {
            ApprovalDecision::AllowOnce | ApprovalDecision::AllowAlways => Ok(true),
            ApprovalDecision::Deny => Ok(false),
        }
    }

    /// Asks operator for approval with detailed choice (AllowOnce, AllowAlways, Deny)
    pub fn ask_approval_detailed(
        &mut self,
        summary: &str,
        diff_preview: Option<&str>,
    ) -> io::Result<ApprovalDecision> {
        let separator = "===============================================================\n";
        self.write_str("\n")?;
        self.write_str(separator)?;
        self.write_str(" [MCP-MOAT INTERCEPT] Sensitive Tool Action Requested:\n")?;
        self.write_str(&format!(" Action: {}\n", display_safe(summary, false)))?;

        if let Some(diff) = diff_preview {
            self.write_str("\n Diff Preview:\n")?;
            self.write_str(&display_safe(diff, true))?;
            self.write_str("\n")?;
        }

        self.write_str(separator)?;

        loop {
            let choice =
                self.prompt_user(" Allow this operation? [y]es / [n]o / [a]llow always: ")?;
            match choice.as_str() {
                "y" | "yes" => return Ok(ApprovalDecision::AllowOnce),
                "n" | "no" | "q" | "quit" => return Ok(ApprovalDecision::Deny),
                "a" | "always" => return Ok(ApprovalDecision::AllowAlways),
                _ => {
                    self.write_str(
                        " Please enter 'y' to approve, 'n' to reject, or 'a' to allow always.\n",
                    )?;
                }
            }
        }
    }
}

/// Replaces control characters (escape sequences, carriage returns, bells) so request-derived
/// text cannot rewrite the operator's terminal. Newlines and tabs stay when `keep_layout` is set.
fn display_safe(text: &str, keep_layout: bool) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && !(keep_layout && (c == '\n' || c == '\t')) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_prompt_text_has_no_control_characters() {
        let input = Cursor::new(b"n\n");
        #[derive(Clone)]
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let buf = Shared(Default::default());
        let mut console = DirectConsole::with_io(input, buf.clone());
        console
            .ask_approval_detailed("write\x1b[2J\r\nfake: ok", Some("a\x1b[31m\nb"))
            .unwrap();
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(!out.contains('\x1b') && !out.contains('\r'), "{out:?}");
        assert!(out.contains("write?[2J??fake: ok"));
    }

    #[test]
    fn test_approval_decision_yes() {
        let input = Cursor::new(b"y\n");
        let output = Vec::new();
        let mut console = DirectConsole::with_io(input, output);

        let decision = console
            .ask_approval_detailed("write_file(/etc/passwd)", None)
            .unwrap();
        assert_eq!(decision, ApprovalDecision::AllowOnce);
    }

    #[test]
    fn test_approval_decision_always() {
        let input = Cursor::new(b"always\n");
        let output = Vec::new();
        let mut console = DirectConsole::with_io(input, output);

        let decision = console
            .ask_approval_detailed("run_command(git status)", None)
            .unwrap();
        assert_eq!(decision, ApprovalDecision::AllowAlways);
    }

    #[test]
    fn test_approval_decision_deny() {
        let input = Cursor::new(b"n\n");
        let output = Vec::new();
        let mut console = DirectConsole::with_io(input, output);

        let decision = console
            .ask_approval_detailed("delete_file(src/main.rs)", None)
            .unwrap();
        assert_eq!(decision, ApprovalDecision::Deny);
    }

    #[test]
    fn test_approval_invalid_then_yes() {
        let input = Cursor::new(b"invalid_input\nyes\n");
        let output = Vec::new();
        let mut console = DirectConsole::with_io(input, output);

        let decision = console
            .ask_approval_detailed("write_file(foo.txt)", None)
            .unwrap();
        assert_eq!(decision, ApprovalDecision::AllowOnce);
    }

    #[test]
    fn test_approval_eof_error() {
        let input = Cursor::new(b"");
        let output = Vec::new();
        let mut console = DirectConsole::with_io(input, output);

        let res = console.ask_approval_detailed("write_file(foo.txt)", None);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_session_approval_cache() {
        let mut cache = SessionApprovalCache::new();
        assert!(!cache.is_allowed("write_file", Some("write_file(test.txt)")));

        cache.allow_tool("write_file");
        assert!(cache.is_allowed("write_file", None));
        assert!(cache.is_allowed("write_file", Some("write_file(anything)")));
        assert!(!cache.is_allowed("delete_file", None));

        cache.allow_action("delete_file(cache.tmp)");
        assert!(cache.is_allowed("delete_file", Some("delete_file(cache.tmp)")));
        assert!(!cache.is_allowed("delete_file", Some("delete_file(other.tmp)")));
    }

    #[test]
    fn test_session_approval_cache_shell_tools_never_cached_tool_wide() {
        let mut cache = SessionApprovalCache::new();
        let shell_tools = [
            "bash",
            "sh",
            "powershell",
            "pwsh",
            "cmd",
            "zsh",
            "fish",
            "wsl",
            "nu",
            "csh",
            "tcsh",
            "execute_command",
            "run_terminal_cmd",
            "run_command",
            "terminal",
            "shell",
        ];

        for tool in shell_tools {
            assert!(SessionApprovalCache::is_shell_tool(tool));
            cache.allow_tool(tool);
            // Must NOT be allowed tool-wide
            assert!(!cache.is_allowed(tool, None));
            assert!(!cache.is_allowed(tool, Some(&format!("{}(whoami)", tool))));

            // But allow_action must allow that specific action
            let action = format!("{}(echo test)", tool);
            cache.allow_action(&action);
            assert!(cache.is_allowed(tool, Some(&action)));
            assert!(!cache.is_allowed(tool, Some(&format!("{}(rm -rf /)", tool))));
            assert!(!cache.is_allowed(tool, None));
        }
    }

    #[test]
    fn test_session_approval_cache_allow_always_helper() {
        let mut cache = SessionApprovalCache::new();
        // Normal tool allowed tool-wide
        cache.allow_always("write_file", Some("write_file(foo.txt)"));
        assert!(cache.is_allowed("write_file", None));
        assert!(cache.is_allowed("write_file", Some("write_file(bar.txt)")));

        // Shell tool only allowed for specific action
        cache.allow_always("bash", Some("bash(git status)"));
        assert!(!cache.is_allowed("bash", None));
        assert!(cache.is_allowed("bash", Some("bash(git status)")));
        assert!(!cache.is_allowed("bash", Some("bash(git reset --hard)")));
    }

    #[test]
    fn test_session_approval_cache_protected_target_never_bypassed_tool_wide() {
        let mut cache = SessionApprovalCache::new();
        // User approved write_file tool-wide
        cache.allow_always("write_file", Some("write_file(foo.txt)"));
        assert!(cache.is_allowed("write_file", Some("write_file(bar.txt)")));

        // Protected in-jail target must NEVER be allowed tool-wide
        let protected_action = "Attempted modification of protected configuration/hook: moat.toml";
        assert!(!cache.is_allowed("write_file", Some(protected_action)));
        assert!(!cache.is_action_allowed(protected_action));

        // Approving protected target only allows that specific action
        cache.allow_always("write_file", Some(protected_action));
        assert!(cache.is_action_allowed(protected_action));
        assert!(cache.is_allowed("write_file", Some(protected_action)));
    }

    #[test]
    fn test_session_approval_cache_isolation() {
        let mut cache = SessionApprovalCache::new();

        // 1. Operator allows an ordinary safe file always: write_file("src/safe.rs")
        cache.allow_always("write_file", Some("write_file(src/safe.rs)"));

        // Tool write_file is now in cache.allowed_tools
        // BUT any protected configuration or in-jail file MUST NOT be allowed!
        let protected_summaries = [
            "Attempted modification of protected configuration/hook: moat.toml",
            "Attempted modification of protected configuration/hook: fence.toml",
            "Attempted modification of protected configuration/hook: .git/hooks/pre-commit",
            "Attempted modification of protected configuration/hook: .github/workflows/ci.yml",
            "Attempted modification of protected configuration/hook: .vscode/settings.json",
            "Attempted modification of protected configuration/hook: .env",
            "Attempted modification of protected configuration/hook: .env.local",
            "Attempted modification of protected configuration/hook: .env.production",
            "Attempted modification of protected configuration/hook: .ssh/id_rsa",
            "Attempted modification of protected configuration/hook: .ssh/authorized_keys",
            "Attempted modification of protected configuration/hook: .aws/credentials",
            "Attempted modification of protected configuration/hook: .gitmodules",
            "Attempted modification of protected configuration/hook: .gitconfig",
        ];

        for summary in &protected_summaries {
            assert!(
                !cache.is_allowed("write_file", Some(summary)),
                "Cache allowed protected target '{}' via tool-wide write_file!",
                summary
            );
            assert!(
                !cache.is_action_allowed(summary),
                "Action '{}' should not be in allowed_actions!",
                summary
            );
        }

        // 2. Shell tools (including kebab-case) must never be cached tool-wide
        for shell_tool in [
            "bash",
            "sh",
            "powershell",
            "pwsh",
            "cmd",
            "run_command",
            "execute_command",
            "terminal",
            "shell",
            "exec",
            "exec_command",
            "run_cmd",
            "run_script",
            "execute_script",
            "system_exec",
            "run_code",
            "execute",
            "run-script",
            "execute-script",
            "run-code",
            "system-exec",
            "exec-cmd",
        ] {
            cache.allow_always(shell_tool, Some(&format!("{}(git status)", shell_tool)));
            // Should allow the exact action git status
            assert!(cache.is_action_allowed(&format!("{}(git status)", shell_tool)));
            // But MUST NEVER allow another action via tool-wide caching!
            assert!(
                !cache.is_allowed(shell_tool, Some(&format!("{}(rm -rf /)", shell_tool))),
                "Shell tool '{}' was bypassed tool-wide!",
                shell_tool
            );
        }

        // 3. Allowed root directory target must NEVER be bypassed tool-wide
        let root_summary = "Attempted modification or deletion of allowed root directory: .";
        assert!(!cache.is_allowed("delete_directory", Some(root_summary)));
        assert!(!cache.is_action_allowed(root_summary));
    }
}
