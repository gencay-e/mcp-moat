//! Decision matrix shared by the policy test (invariants.rs) and the proxy test (no_prompt.rs).
//!
//! `expected()` restates the order of checks of docs/security-model.md as a plain function of
//! the case. It does not call the policy engine and shares no code with it. If the engine and
//! this function disagree, the documentation decides which one is wrong.
#![allow(dead_code)] // each test binary uses a part of this module

use mcp_moat_core::PolicyConfig;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    /// Not in any list, not a preset tool, not a standard filesystem tool name.
    Unlisted,
    AlwaysAllow,
    CustomAlwaysAllow,
    /// Listed by a built-in preset.
    Preset,
    /// Exact name of a tool of @modelcontextprotocol/server-filesystem.
    Standard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Read,
    /// Modifying because of its name (`update_*`, `write_file`, ...).
    ModByName,
    /// Modifying only because it is in `custom_modifying_tools`.
    ModByCustomList,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathArg {
    /// No path argument; a file tool is listed in `non_file_tools` (a tool that is not a file
    /// tool needs no entry).
    NoneExempt,
    /// No path argument; a file tool is not listed in `non_file_tools`.
    NoneNotExempt,
    InJail,
    OutOfJail,
    /// Inside the jail, in a protected location (`.git`).
    Protected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Absent,
    Safe,
    Metachar,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exp {
    Allow,
    Block,
    Ask,
}

#[derive(Clone, Debug)]
pub struct Tool {
    pub name: &'static str,
    /// The name matches the file-tool patterns, so a path is required unless exempted.
    pub file_like: bool,
    pub auth: Auth,
    pub class: Class,
    pub preset: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct Case {
    pub tool: Tool,
    pub path: PathArg,
    pub cmd: Cmd,
    pub require_approval: bool,
    pub read_only: bool,
}

pub fn tools() -> Vec<Tool> {
    let mut v = Vec::new();
    // (name, file_like, class)
    let generic = [
        ("inspect_file", true, Class::Read),
        ("inspect_data", false, Class::Read),
        ("update_file", true, Class::ModByName),
        ("update_thing", false, Class::ModByName),
        ("deploy_dir", true, Class::ModByCustomList),
        ("deploy_site", false, Class::ModByCustomList),
    ];
    for auth in [Auth::Unlisted, Auth::AlwaysAllow, Auth::CustomAlwaysAllow] {
        for (name, file_like, class) in generic {
            v.push(Tool {
                name,
                file_like,
                auth,
                class,
                preset: None,
            });
        }
    }
    // Preset tools. The presets list no tool that is modifying by name, so that cell is empty.
    v.push(Tool {
        name: "read_graph",
        file_like: true,
        auth: Auth::Preset,
        class: Class::Read,
        preset: Some("memory"),
    });
    v.push(Tool {
        name: "git_add",
        file_like: false,
        auth: Auth::Preset,
        class: Class::ModByCustomList,
        preset: Some("git"),
    });
    for (name, class) in [
        ("read_file", Class::Read),
        ("write_file", Class::ModByName),
        ("read_file", Class::ModByCustomList),
    ] {
        v.push(Tool {
            name,
            file_like: true,
            auth: Auth::Standard,
            class,
            preset: None,
        });
    }
    v
}

pub fn cases() -> Vec<Case> {
    let mut v = Vec::new();
    for tool in tools() {
        for path in [
            PathArg::NoneExempt,
            PathArg::NoneNotExempt,
            PathArg::InJail,
            PathArg::OutOfJail,
            PathArg::Protected,
        ] {
            for cmd in [Cmd::Absent, Cmd::Safe, Cmd::Metachar, Cmd::Blocked] {
                for require_approval in [false, true] {
                    for read_only in [false, true] {
                        v.push(Case {
                            tool: tool.clone(),
                            path,
                            cmd,
                            require_approval,
                            read_only,
                        });
                    }
                }
            }
        }
    }
    v
}

impl Case {
    /// True if the tool is listed in `non_file_tools` for this case.
    pub fn exempt(&self) -> bool {
        self.path == PathArg::NoneExempt
    }

    pub fn has_path(&self) -> bool {
        !matches!(self.path, PathArg::NoneExempt | PathArg::NoneNotExempt)
    }

    /// Everything of the case that goes into the policy, except the call. Cases with the same
    /// key can share one engine.
    pub fn config_key(&self) -> String {
        format!(
            "{:?}/{}/{:?}/{}/{}/{}",
            self.tool.auth,
            self.tool.name,
            self.tool.class,
            self.exempt(),
            self.require_approval,
            self.read_only
        )
    }

    pub fn config(&self, jail: &Path) -> PolicyConfig {
        let mut c = PolicyConfig {
            allowed_paths: vec![jail.to_path_buf()],
            // the default list names read_file; the cases must not inherit it
            always_allow_tools: Vec::new(),
            ..PolicyConfig::default()
        };
        if let Some(preset) = self.tool.preset {
            c.apply_preset(preset).unwrap();
            c.allowed_paths = vec![jail.to_path_buf()];
        }
        let name = self.tool.name.to_string();
        match self.tool.auth {
            Auth::AlwaysAllow => c.always_allow_tools.push(name.clone()),
            Auth::CustomAlwaysAllow => c.custom_always_allow_tools.push(name.clone()),
            Auth::Unlisted | Auth::Preset | Auth::Standard => {}
        }
        if self.tool.class == Class::ModByCustomList && !c.custom_modifying_tools.contains(&name) {
            c.custom_modifying_tools.push(name.clone());
        }
        c.non_file_tools.retain(|t| t != &name);
        if self.exempt() && self.tool.file_like {
            c.non_file_tools.push(name);
        }
        c.require_approval_on_write = self.require_approval;
        c.read_only = self.read_only;
        c
    }

    pub fn arguments(&self, jail: &Path) -> Value {
        let mut args = serde_json::Map::new();
        match self.path {
            PathArg::NoneExempt | PathArg::NoneNotExempt => {}
            PathArg::InJail => {
                args.insert("path".into(), json!(jail.join("a.txt").to_string_lossy()));
            }
            PathArg::OutOfJail => {
                args.insert("path".into(), json!("/etc/passwd"));
            }
            PathArg::Protected => {
                args.insert(
                    "path".into(),
                    json!(jail.join(".git").join("config").to_string_lossy()),
                );
            }
        }
        match self.cmd {
            Cmd::Absent => {}
            Cmd::Safe => {
                args.insert("command".into(), json!("echo hi"));
            }
            Cmd::Metachar => {
                args.insert("command".into(), json!("echo hi; id"));
            }
            Cmd::Blocked => {
                args.insert("command".into(), json!("rm -rf /"));
            }
        }
        Value::Object(args)
    }
}

/// The expected decision. The order is the table in docs/security-model.md.
pub fn expected(c: &Case) -> Exp {
    let modifying = c.tool.class != Class::Read;

    // 1. a path outside the jail
    if c.path == PathArg::OutOfJail {
        return Exp::Block;
    }
    // 2. a file tool needs a path unless it is exempted
    if c.tool.file_like && !c.has_path() && !c.exempt() {
        return Exp::Block;
    }
    // 3. read-only mode
    if modifying && c.read_only {
        return Exp::Block;
    }
    // 4. authorization: listed (by the user or a preset), or the exact name of a standard
    // filesystem tool. A standard tool that modifies is authorized only with a path.
    let authorized = match c.tool.auth {
        Auth::Unlisted => false,
        Auth::AlwaysAllow | Auth::CustomAlwaysAllow | Auth::Preset => true,
        Auth::Standard => !modifying || c.has_path(),
    };
    if !authorized && !modifying {
        return Exp::Block;
    }
    // 5. blocked command
    if c.cmd == Cmd::Blocked {
        return Exp::Block;
    }
    // 6. any other command asks
    if matches!(c.cmd, Cmd::Safe | Cmd::Metachar) {
        return Exp::Ask;
    }
    // 7. modifying tools: protected path, approval on write, not authorized
    if modifying && (c.path == PathArg::Protected || c.require_approval || !authorized) {
        return Exp::Ask;
    }
    // 8.
    Exp::Allow
}
