use std::sync::OnceLock;

pub fn mock_server_bin() -> &'static str {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| {
        let current = std::env::current_exe().expect("test executable path");
        let profile_dir = current
            .parent()
            .and_then(|p| p.parent())
            .expect("target profile directory");
        let exe = if cfg!(windows) {
            "mock_server.exe"
        } else {
            "mock_server"
        };
        let path = profile_dir.join("examples").join(exe);
        if !path.is_file() {
            let mut cmd = std::process::Command::new(env!("CARGO"));
            cmd.args([
                "build",
                "--manifest-path",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
                "--example",
                "mock_server",
            ]);
            if profile_dir.file_name().and_then(|n| n.to_str()) == Some("release") {
                cmd.arg("--release");
            }
            let status = cmd.status().expect("build mock_server example");
            assert!(status.success(), "failed to build mock_server example");
        }
        assert!(
            path.is_file(),
            "mock_server example binary not found at {}",
            path.display()
        );
        path.to_string_lossy().into_owned()
    })
}
