use std::sync::Arc;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_cloud::{
    api,
    cloudflare::CloudflareDnsProvider,
    config::Config,
    db,
    repository::{OperationalRepository, PgOperationalRepository},
    service::DdnsService,
    sni,
    state::AppState,
    tunnel::TunnelRegistry,
};
use wardnet_common::config as common_config;
use wardnet_common::dns_provider::DnsProvider;
use wardnet_common::{serve, token};

/// Ports the SNI passthrough listeners forward to on the tenant tunnels.
const HTTPS_TUNNEL_PORT: u16 = 443;
const DOT_TUNNEL_PORT: u16 = 853;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env())
        .init();

    // rustls 0.23 needs a process-default crypto provider before any TLS work (the
    // reqwest Cloudflare client + mesh-mTLS primitives rely on it); idempotent.
    wardnet_common::mtls::install_crypto_provider();

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
    let operational = Arc::new(PgOperationalRepository::new_pools(pools));
    let dns_provider = Arc::new(CloudflareDnsProvider::new(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
    )?);
    let tunnel_registry = Arc::new(TunnelRegistry::new());

    // Identity is authenticated JWT-only here: the daemon presents its Tenants-signed
    // identity JWT, verified offline against the matching public key. The signing key
    // and the identity DB live in the Tenants service.
    let jwt_verifier =
        token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes())?;

    let ddns = Arc::new(DdnsService::new(
        operational as Arc<dyn OperationalRepository>,
        dns_provider as Arc<dyn DnsProvider>,
    ));

    let state = AppState::new(
        config.clone(),
        ddns,
        jwt_verifier,
        Arc::clone(&tunnel_registry),
    );
    let api_router = api::router(state);

    tokio::select! {
        // Control-plane API over plain HTTP — inforge's nginx sidecar fronts TLS.
        res = serve::run_api(&config.api_listen_addr, api_router) => res?,

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
