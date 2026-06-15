use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_cloud::{
    api,
    cloudflare::CloudflareDnsProvider,
    config::Config,
    db,
    repository::{
        ChallengeRepository, IdentityRepository, OperationalRepository, PgChallengeRepository,
        PgIdentityRepository, PgOperationalRepository,
    },
    service::{DdnsService, TenantsService},
    sni,
    state::AppState,
    tunnel::TunnelRegistry,
};
use wardnet_common::config as common_config;
use wardnet_common::dns_provider::DnsProvider;
use wardnet_common::proxy_protocol::{self, Inspected};
use wardnet_common::serve;
use wardnet_common::token;

/// Timeout for reading the optional PROXY v1 header on the API listener.
const PROXY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Ports the SNI passthrough listeners forward to on the tenant tunnels.
const HTTPS_TUNNEL_PORT: u16 = 443;
const DOT_TUNNEL_PORT: u16 = 853;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;

    tracing::info!(
        region = %config.region,
        subdomain_parent = %config.subdomain_parent,
        api_listen_addr = %config.api_listen_addr,
        https_listen_addr = %config.https_listen_addr,
        dot_listen_addr = %config.dot_listen_addr,
        "wardnet-cloud starting"
    );

    let pools = db::init(&config.database_url).await?;
    let global_pools = db::init_global(&config.global_database_url).await?;

    // Identity + challenges live in the global Tenants DB; operational DNS state in
    // the regional DB.
    let identities = Arc::new(PgIdentityRepository::new_pools(global_pools.clone()));
    let challenges = Arc::new(PgChallengeRepository::new_pools(global_pools));
    let operational = Arc::new(PgOperationalRepository::new_pools(pools));
    let dns_provider = Arc::new(CloudflareDnsProvider::new(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
    )?);
    let tunnel_registry = Arc::new(TunnelRegistry::new());

    // Tenants signs identity JWTs at registration. The private key is read here and
    // consumed into the signer — it is never seated in the shared `Config`/AppState.
    let jwt_signing_key_pem = common_config::load_jwt_signing_key_pem()?;
    let jwt_signer = token::Signer::from_pem(jwt_signing_key_pem.as_bytes(), None)?;
    drop(jwt_signing_key_pem);

    // The auth middleware verifies identity JWTs offline with the matching public
    // key (at the service split this verifier lives in DDNS/Tunneller).
    let jwt_verifier =
        token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes())?;

    // Service layer: handlers reach data only through these (each owns its repos).
    let tenants = Arc::new(TenantsService::new(
        identities as Arc<dyn IdentityRepository>,
        challenges as Arc<dyn ChallengeRepository>,
        jwt_signer,
    ));
    let ddns = Arc::new(DdnsService::new(
        operational as Arc<dyn OperationalRepository>,
        dns_provider as Arc<dyn DnsProvider>,
    ));

    let state = AppState::new(
        config.clone(),
        tenants,
        ddns,
        jwt_verifier,
        Arc::clone(&tunnel_registry),
    );
    let api_router = api::router(state);

    tokio::select! {
        // Control-plane API over plain HTTP — inforge's nginx sidecar fronts TLS.
        res = serve_api(&config.api_listen_addr, api_router) => res?,

        // Tenant TLS is never terminated here: both listeners are pure L4 SNI
        // passthrough to the tenant's reverse tunnel.
        res = sni::run(
            &config.https_listen_addr,
            &config.subdomain_parent,
            Arc::clone(&tunnel_registry),
            HTTPS_TUNNEL_PORT,
        ) => res?,

        res = sni::run(
            &config.dot_listen_addr,
            &config.subdomain_parent,
            Arc::clone(&tunnel_registry),
            DOT_TUNNEL_PORT,
        ) => res?,
    }

    Ok(())
}

/// Serve the control-plane API over a plain-HTTP listener.
///
/// nginx fronts this with a transparent L4 proxy (PROXY protocol v1), so each
/// connection's optional header is stripped first to recover the **real** client
/// address, which is threaded into the router as `ConnectInfo` (via
/// [`serve::connection`]). That keeps `client_ip()`, the per-IP rate limiter, and
/// `PoW` working off the true client rather than nginx's loopback address. A direct
/// health probe carries no header and falls back to the TCP peer.
async fn serve_api(addr: &str, router: axum::Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        addr,
        "control-plane API listening (plain HTTP; nginx fronts TLS)"
    );

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            // Recover the real client IP from the optional PROXY header; a direct
            // connection (no header), a timeout, or a parse error falls back to the
            // TCP peer.
            let client_addr = match tokio::time::timeout(
                PROXY_READ_TIMEOUT,
                proxy_protocol::read_optional(&mut stream),
            )
            .await
            {
                Ok(Ok(Inspected::Header(addr))) => addr.unwrap_or(peer),
                _ => peer,
            };

            if let Err(e) = serve::connection(stream, router, client_addr).await {
                tracing::debug!(error = %e, "API connection error");
            }
        });
    }
}
