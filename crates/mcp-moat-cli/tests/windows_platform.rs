#![cfg(windows)]

use mcp_moat_proxy::process::{attach_and_resume, prepare};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, id: u32) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, millis: u32) -> u32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

#[tokio::test]
async fn job_close_terminates_child_and_grandchild() {
    let script = "$p=Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 60' -PassThru -WindowStyle Hidden; Write-Output $p.Id; Start-Sleep -Seconds 60";
    let mut command = Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    prepare(&mut command);
    let mut child = command.spawn().unwrap();
    let guard = attach_and_resume(&mut child).unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let pid: u32 = line.trim().parse().unwrap();
    // SYNCHRONIZE keeps a handle to this exact process even if its PID is later reused.
    let grandchild = unsafe { OpenProcess(0x0010_0000, 0, pid) };
    assert!(!grandchild.is_null());
    drop(guard);
    assert!(tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .is_ok());
    let result = unsafe { WaitForSingleObject(grandchild, 5000) };
    unsafe {
        CloseHandle(grandchild);
    }
    assert_eq!(result, 0);
}

fn windows_link_test(symlink: bool) {
    use mcp_moat_core::{PolicyConfig, PolicyEngine};
    let kind = if symlink { "symlink" } else { "junction" };
    let root = std::env::var_os("MOAT_TEST_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!(
            "moat-windows-{kind}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let jail = root.join("jail");
    let outside = root.join("outside");
    std::fs::create_dir_all(&jail).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("target.txt"), b"test").unwrap();
    let link = jail.join("link");
    if symlink {
        if let Err(error) = std::os::windows::fs::symlink_dir(&outside, &link) {
            std::fs::remove_file(outside.join("target.txt")).unwrap();
            std::fs::remove_dir(&outside).unwrap();
            std::fs::remove_dir(&jail).unwrap();
            std::fs::remove_dir(&root).unwrap();
            panic!("Windows symlink creation requires permission or Developer Mode: {error}");
        }
    } else {
        let result = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(result.status.success(), "junction creation failed");
    }
    assert!(std::fs::read(link.join("target.txt")).is_ok());
    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail.clone()],
        ..PolicyConfig::default()
    })
    .unwrap();
    assert!(engine
        .validate_path_secure(&link.join("target.txt").to_string_lossy())
        .is_err());
    let extended = outside.join("target.txt").canonicalize().unwrap();
    assert!(std::fs::metadata(&extended).is_ok());
    assert!(engine
        .validate_path_secure(&extended.to_string_lossy())
        .is_err());
    std::fs::remove_dir(&link).unwrap();
    std::fs::remove_file(outside.join("target.txt")).unwrap();
    std::fs::remove_dir(outside).unwrap();
    std::fs::remove_dir(jail).unwrap();
    std::fs::remove_dir(root).unwrap();
}
#[test]
fn real_junction_escape_is_rejected() {
    windows_link_test(false);
}
#[test]
#[ignore = "requires Windows symlink privilege or Developer Mode; run --ignored for platform acceptance"]
fn real_symlink_escape_is_rejected() {
    windows_link_test(true);
}

#[test]
#[ignore = "requires access to the local administrative SMB share; run --ignored for platform acceptance"]
fn real_unc_share_is_rejected() {
    use mcp_moat_core::{PolicyConfig, PolicyEngine};
    let windows = std::env::var("SystemRoot").unwrap();
    let bytes = windows.as_bytes();
    assert!(bytes.len() >= 3 && bytes[1] == b':');
    let unc = format!(
        r"\\localhost\{}${}\System32\notepad.exe",
        bytes[0] as char,
        &windows[2..]
    );
    assert!(
        std::fs::File::open(&unc).is_ok(),
        "local administrative share must be reachable"
    );
    let jail = std::env::var_os("MOAT_TEST_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let engine = PolicyEngine::new(PolicyConfig {
        allowed_paths: vec![jail],
        ..PolicyConfig::default()
    })
    .unwrap();
    assert!(engine.validate_path_secure(&unc).is_err());
}
