pub mod engine;
pub mod sse;

pub use engine::ProxyServer;
pub use sse::{SseBridgeServer, SseProxyServer};

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
