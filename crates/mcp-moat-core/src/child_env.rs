//! Environment passed to wrapped servers, shared by wrap and codegen.
use crate::PolicyConfig;
use std::ffi::OsString;

#[cfg(windows)]
fn same_env_name(left: &str, right: &str) -> bool {
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    if left.is_ascii() && right.is_ascii() {
        return left.eq_ignore_ascii_case(right);
    }

    let left: Vec<_> = left.encode_utf16().collect();
    let right: Vec<_> = right.encode_utf16().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // Both pointers refer to live UTF-16 slices of the specified lengths.
    (unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) })
        == CSTR_EQUAL
}

#[cfg(not(windows))]
fn same_env_name(left: &str, right: &str) -> bool {
    left == right
}

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
            if same_env_name(&upper, "MOAT_AUDIT_KEY") {
                return false;
            }
            let passed = config
                .pass_env
                .iter()
                .any(|allowed| same_env_name(allowed, name));
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
