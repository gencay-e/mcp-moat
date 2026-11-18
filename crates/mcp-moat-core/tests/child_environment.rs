use mcp_moat_core::child_env::filter_environment;
use mcp_moat_core::PolicyConfig;
use std::ffi::OsString;

fn names(config: PolicyConfig) -> Vec<String> {
    let entries = [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "TEMP",
        "LANG",
        "TERM",
        "OPENAI_API_KEY",
        "CLIENT_SECRET_VALUE",
        "GITHUB_TOKEN",
        "DB_PASSWORD",
        "MOAT_AUDIT_KEY",
        "MOAT_OTHER",
        "PUBLIC_VALUE",
    ];
    filter_environment(
        entries
            .into_iter()
            .map(|name| (OsString::from(name), OsString::from("value"))),
        &config,
    )
    .into_iter()
    .map(|(name, _)| name.to_string_lossy().into_owned())
    .collect()
}

#[test]
fn default_environment_removes_sensitive_names() {
    assert_eq!(
        names(PolicyConfig::default()),
        [
            "PATH",
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "TEMP",
            "LANG",
            "TERM",
            "PUBLIC_VALUE"
        ]
    );
}

#[test]
fn explicit_pass_list_preserves_only_requested_secrets() {
    let config = PolicyConfig {
        pass_env: vec!["GITHUB_TOKEN".into(), "MOAT_AUDIT_KEY".into()],
        ..PolicyConfig::default()
    };
    let filtered = names(config);
    assert!(filtered.iter().any(|name| name == "GITHUB_TOKEN"));
    assert!(!filtered.iter().any(|name| name == "MOAT_AUDIT_KEY"));
    assert!(!filtered.iter().any(|name| name == "DB_PASSWORD"));
}

#[test]
fn clear_environment_keeps_base_and_explicit_names_only() {
    let config = PolicyConfig {
        clear_env: true,
        pass_env: vec!["GITHUB_TOKEN".into()],
        ..PolicyConfig::default()
    };
    let filtered = names(config);
    assert!(filtered.iter().any(|name| name == "PATH"));
    assert!(filtered.iter().any(|name| name == "GITHUB_TOKEN"));
    assert!(!filtered.iter().any(|name| name == "PUBLIC_VALUE"));
    assert!(!filtered.iter().any(|name| name == "MOAT_AUDIT_KEY"));
}

#[test]
fn disabling_scrubbing_never_exposes_audit_key() {
    let config = PolicyConfig {
        scrub_env: false,
        ..PolicyConfig::default()
    };
    let filtered = names(config);
    assert!(filtered.iter().any(|name| name == "GITHUB_TOKEN"));
    assert!(!filtered.iter().any(|name| name == "MOAT_AUDIT_KEY"));
}
