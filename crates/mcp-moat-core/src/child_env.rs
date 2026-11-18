//! Environment passed to wrapped servers, shared by wrap and codegen.
use crate::PolicyConfig;
use std::ffi::OsString;

pub fn filter_environment(
    entries: impl IntoIterator<Item = (OsString, OsString)>,
    config: &PolicyConfig,
) -> Vec<(OsString, OsString)> {
    entries
        .into_iter()
        .filter(|(name, _)| {
            let Some(name) = name.to_str() else {
                return !config.clear_env && !config.scrub_env;
            };
            let upper = name.to_ascii_uppercase();
            // The audit authenticator is private even when scrubbing is disabled.
            if upper == "MOAT_AUDIT_KEY" {
                return false;
            }
            let passed = config.pass_env.iter().any(|allowed| {
                if cfg!(windows) {
                    allowed.eq_ignore_ascii_case(name)
                } else {
                    allowed == name
                }
            });
            if passed {
                return true;
            }
            if config.clear_env {
                return matches!(
                    upper.as_str(),
                    "PATH"
                        | "PATHEXT"
                        | "HOME"
                        | "USERPROFILE"
                        | "SYSTEMROOT"
                        | "WINDIR"
                        | "COMSPEC"
                        | "TEMP"
                        | "TMP"
                        | "LANG"
                        | "LC_ALL"
                        | "LC_CTYPE"
                        | "TERM"
                );
            }
            !config.scrub_env
                || !(upper.ends_with("_API_KEY")
                    || upper.contains("_SECRET")
                    || upper.ends_with("_TOKEN")
                    || upper.ends_with("_PASSWORD")
                    || upper.starts_with("MOAT_"))
        })
        .collect()
}

/// Replace inherited variables without changing the parent process environment.
pub fn configure_child(command: &mut std::process::Command, config: &PolicyConfig) {
    command
        .env_clear()
        .envs(filter_environment(std::env::vars_os(), config));
}
