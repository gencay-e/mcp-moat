use mcp_moat_core::policy::{Decision, PolicyConfig, PolicyEngine};
use mcp_moat_core::protocol::ToolCallParams;
use serde_json::json;

fn engine() -> PolicyEngine {
    let mut config = PolicyConfig::default();
    config.blocked_commands.clear();
    config.custom_modifying_tools = vec!["execute_command".into()];
    config.non_file_tools = vec!["execute_command".into()];
    config.custom_path_keys = vec!["path".into()];
    config.blocked_commands_regex = vec![r"^rm\s+-rf\s+/$".into()];
    PolicyEngine::new(config).unwrap()
}

fn call(command: &str) -> ToolCallParams {
    ToolCallParams {
        name: "execute_command".into(),
        arguments: Some(json!({"command": command})),
    }
}

fn is_block(decision: &Decision) -> bool {
    matches!(decision, Decision::Block(_))
}

fn is_ask(decision: &Decision) -> bool {
    matches!(decision, Decision::AskOperator { .. })
}

#[test]
fn anchored_destructive_regex_matches_shell_and_platform_wrappers() {
    let engine = engine();
    let commands = [
        "sh -c 'rm -rf /'",
        "bash -c 'rm -rf /'",
        "zsh -c 'rm -rf /'",
        "cmd /c \"rm -rf /\"",
        "powershell -c \"rm -rf /\"",
        "pwsh -Command \"rm -rf /\"",
        "env FOO=1 bash -c 'rm -rf /'",
        "nohup nice -n 5 timeout 5 xargs sh -c 'rm -rf /'",
        "sh -c 'echo ok && bash -c \"rm -rf /\"'",
    ];

    for command in commands {
        let decision = engine.evaluate_tool_call(&call(command));
        assert!(
            matches!(&decision, Decision::Block(reason) if reason.contains("matches pattern")),
            "{command:?} gave {decision:?}"
        );
    }
}

#[test]
fn ordinary_recursive_remove_still_requires_operator_approval() {
    let decision = engine().evaluate_tool_call(&call("rm -rf /tmp/build"));
    assert!(is_ask(&decision), "got {decision:?}");
}

#[test]
fn path_jail_decision_precedes_wrapped_command_regex() {
    let mut call = call("sh -c 'rm -rf /'");
    call.arguments = Some(json!({"command": "sh -c 'rm -rf /'", "path": "../outside"}));
    let decision = engine().evaluate_tool_call(&call);
    assert!(
        matches!(&decision, Decision::Block(reason) if reason.contains("Directory traversal")),
        "got {decision:?}"
    );
}

#[test]
fn nested_command_analysis_fails_closed_at_its_limit() {
    let mut command = "echo harmless".to_string();
    for _ in 0..40 {
        command = format!("sh -c '{command}'");
    }
    let decision = engine().evaluate_tool_call(&call(&command));
    assert!(is_block(&decision), "deep wrapper chain gave {decision:?}");
}
