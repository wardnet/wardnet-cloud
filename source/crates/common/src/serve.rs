//! Serve an axum [`Router`] over a single already-accepted (and possibly
//! TLS-terminated) byte stream via hyper.
//!
//! The bridge cannot use `axum::serve` for its public listeners: it must first
//! strip the PROXY protocol header (and, on `:8443`, peek the SNI and terminate
//! TLS) before any HTTP is spoken. So each connection is driven through hyper
//! by hand. The real client address — recovered from the PROXY header — is
//! injected as [`ConnectInfo`] so handlers (and the per-IP rate limiter) see the
//! true client rather than the L4 proxy.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::proxy_protocol;

/// Timeout for reading the PROXY v1 header on a public API listener.
const PROXY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent in-flight API connections (accept-storm guard).
const MAX_CONCURRENT_API: usize = 4096;

/// Serve `router` over `io` for one connection, attributing every request to
/// `client_addr` via [`ConnectInfo`].
///
/// # Errors
/// Returns an error if the HTTP connection terminates abnormally.
pub async fn connection<IO>(io: IO, router: Router, client_addr: SocketAddr) -> anyhow::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Inject the real client address so `ConnectInfo<SocketAddr>` resolves to it.
    let app = router.layer(axum::Extension(ConnectInfo(client_addr)));
    let service = TowerToHyperService::new(app);

    Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(io), service)
        .await
        .map_err(|e| anyhow::anyhow!("connection error: {e}"))
}

/// Run a public control-plane API listener: plain HTTP behind nginx, which fronts
/// it with a transparent L4 proxy (PROXY protocol v1).
///
/// The PROXY header is **required** — it is the only unforgeable source of the real
/// client IP, on which the per-IP rate limiter and IP-bound `PoW` depend (threaded
/// in as `ConnectInfo`). A connection whose client address cannot be resolved
/// (missing/invalid header, read timeout, or `PROXY UNKNOWN`) is **dropped** rather
/// than served against nginx's loopback address — which would otherwise let a
/// caller spoof `X-Forwarded-For`. In-flight connections are bounded by a semaphore;
/// transient `accept` errors are logged, not fatal.
///
/// # Errors
/// Returns an error only if the listener cannot be bound.
pub async fn run_api(addr: &str, router: Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        addr,
        "control-plane API listening (plain HTTP; nginx fronts TLS)"
    );

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_API));

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "API listener accept error");
                continue;
            }
        };
        let router = router.clone();
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            let client_addr = match tokio::time::timeout(
                PROXY_READ_TIMEOUT,
                proxy_protocol::read_required(&mut stream),
            )
            .await
            {
                Ok(Ok(Some(addr))) => addr,
                Ok(Ok(None)) => {
                    tracing::debug!(%peer, "API connection with PROXY UNKNOWN family, dropping");
                    return;
                }
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "API connection missing/invalid PROXY header, dropping");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "API connection PROXY header read timeout, dropping");
                    return;
                }
            };
            if let Err(e) = connection(stream, router, client_addr).await {
                tracing::debug!(error = %e, "API connection error");
            }
        });
    }
}
