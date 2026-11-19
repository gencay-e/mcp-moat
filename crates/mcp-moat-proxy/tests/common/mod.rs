use std::path::PathBuf;
use std::sync::OnceLock;

pub fn mock_server_bin() -> &'static str {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| {
        let current = std::env::current_exe().expect("test executable path");
        let is_release = current
            .ancestors()
            .any(|dir| dir.file_name().and_then(|n| n.to_str()) == Some("release"));
        let mut cmd = std::process::Command::new(env!("CARGO"));
        cmd.args([
            "build",
            "--locked",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "--example",
            "mock_server",
            "--message-format=json-render-diagnostics",
        ]);
        if is_release {
            cmd.arg("--release");
        }
        let output = cmd.output().expect("build mock_server example");
        assert!(
            output.status.success(),
            "failed to build mock_server example: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) {
                if msg.get("reason").and_then(|v| v.as_str()) == Some("compiler-artifact")
                    && msg.pointer("/target/name").and_then(|v| v.as_str()) == Some("mock_server")
                {
                    if let Some(executable) = msg.get("executable").and_then(|v| v.as_str()) {
                        let path = PathBuf::from(executable);
                        assert!(
                            path.is_file(),
                            "mock_server example binary not found at {}",
                            path.display()
                        );
                        return executable.to_string();
                    }
                }
            }
        }
        panic!("mock_server example executable not reported by cargo build");
    })
}
