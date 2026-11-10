pub mod engine;
pub mod sse;

pub use engine::ProxyServer;
pub use sse::{SseBridgeServer, SseProxyServer};

pub(crate) fn new_session_id(prefix: &str) -> String {
    let mut random = [0u8; 16];
    fill_os_random(&mut random)
        .expect("OS randomness unavailable; refusing to create a session without a unique ID");
    let random = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}-{random}")
}

#[cfg(unix)]
fn fill_os_random(bytes: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

#[cfg(windows)]
fn fill_os_random(bytes: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }

    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            0x00000002,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "BCryptGenRandom failed with status 0x{status:08x}"
        )))
    }
}

pub(crate) async fn wait_for_sigterm() {
    #[cfg(unix)]
    {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::new_session_id;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn session_ids_are_unique_under_parallel_generation() {
        let ids = Arc::new(Mutex::new(HashSet::new()));
        let threads = (0..16)
            .map(|_| {
                let ids = Arc::clone(&ids);
                thread::spawn(move || {
                    for _ in 0..256 {
                        ids.lock().unwrap().insert(new_session_id("sess"));
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(ids.lock().unwrap().len(), 16 * 256);
    }
}
