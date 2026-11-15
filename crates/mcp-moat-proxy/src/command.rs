use std::ffi::OsStr;
use std::path::PathBuf;

/// Resolve Windows launchers before passing arguments to the standard library.
/// Batch quoting and invocation are handled by Rust, without raw shell arguments.
pub fn resolve_command(command: &OsStr) -> std::io::Result<PathBuf> {
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(command))
    }
    #[cfg(windows)]
    {
        resolve_windows(
            command,
            std::env::var_os("PATH").as_deref(),
            std::env::var_os("PATHEXT").as_deref(),
        )
    }
}

#[cfg(windows)]
fn resolve_windows(
    command: &OsStr,
    path: Option<&OsStr>,
    pathext: Option<&OsStr>,
) -> std::io::Result<PathBuf> {
    use std::path::Path;
    let command = Path::new(command);
    let extensions: Vec<String> = pathext
        .unwrap_or(OsStr::new(".EXE;.CMD;.BAT"))
        .to_string_lossy()
        .split(';')
        .map(str::to_ascii_lowercase)
        .filter(|ext| matches!(ext.as_str(), ".exe" | ".com" | ".cmd" | ".bat"))
        .collect();
    let explicit = command.is_absolute() || command.components().count() > 1;
    let candidates: Vec<PathBuf> = if explicit {
        vec![command.to_owned()]
    } else {
        path.map(std::env::split_paths)
            .into_iter()
            .flatten()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(|dir| dir.join(command))
            .collect()
    };
    for candidate in candidates {
        if candidate.extension().is_some() {
            if candidate.is_file() {
                return std::path::absolute(candidate);
            }
        } else {
            for ext in &extensions {
                let mut name = candidate.as_os_str().to_owned();
                name.push(ext);
                let name = PathBuf::from(name);
                if name.is_file() {
                    return std::path::absolute(name);
                }
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "command not found in PATH/PATHEXT",
    ))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn resolves_batch_and_executable_in_pathext_order() {
        let dir = std::env::var_os("MOAT_TEST_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("moat-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for ext in ["cmd", "bat", "exe"] {
            std::fs::write(dir.join(format!("launcher.{ext}")), "").unwrap();
            let resolved = resolve_windows(
                OsStr::new("launcher"),
                Some(dir.as_os_str()),
                Some(OsStr::new(&format!(".{ext}"))),
            )
            .unwrap();
            assert_eq!(resolved, dir.join(format!("launcher.{ext}")));
        }
        assert_eq!(
            resolve_windows(
                OsStr::new("launcher"),
                Some(dir.as_os_str()),
                Some(OsStr::new(".CMD;.EXE"))
            )
            .unwrap(),
            dir.join("launcher.cmd")
        );
        assert!(resolve_windows(OsStr::new("missing"), Some(dir.as_os_str()), None).is_err());
        assert!(resolve_windows(
            OsStr::new("launcher"),
            Some(dir.as_os_str()),
            Some(OsStr::new(".PS1"))
        )
        .is_err());
    }
}
