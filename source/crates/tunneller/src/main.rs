use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use wardnet_common::config as common_config;
use wardnet_common::mtls::MeshClient;
use wardnet_common::{mtls, serve, token};
use wardnet_tunneller::{
    api,
    config::Config,
    db,
    mesh::{InterNodeForwarder, MtlsForwarder, TenantsClient, TenantsResolver, serve_forward},
    reconcile,
    repository::{PgTunnelRouteRepository, TunnelRouteRepository},
    router::{LocalRouter, TunnelRouter},
    sni,
    state::AppState,
    tunnel::TunnelRegistry,
};

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
    // mesh client, the forward listener/dialer); idempotent.
    mtls::install_crypto_provider();

    let config = Config::from_env()?;
    tracing::info!(
        region = %config.region,
        subdomain_parent = %config.subdomain_parent,
        api_listen_addr = %config.api_listen_addr,
        forward_advertise_addr = %config.forward_advertise_addr,
        mesh_base_url = %config.mesh_base_url,
        "wardnet-tunneller starting"
    );

    let pools = db::init(&config.database_url).await?;
    let routes: Arc<dyn TunnelRouteRepository> =
        Arc::new(PgTunnelRouteRepository::new_pools(pools));
    let registry = Arc::new(TunnelRegistry::new());

    // Mesh PEM material (mTLS): trust anchor + this node's leaf. Static for now —
    // certificate rotation is deferred.
    let mesh_ca = std::fs::read(&config.mesh_ca_path)
        .map_err(|e| anyhow::anyhow!("read mesh CA at {}: {e}", config.mesh_ca_path))?;
    let mesh_cert = std::fs::read(&config.mesh_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh cert at {}: {e}", config.mesh_cert_path))?;
    let mesh_key = std::fs::read(&config.mesh_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.mesh_key_path))?;

    // Routing-policy reads against Tenants (mesh mTLS over HTTP).
    let mesh_client = MeshClient::new(&mesh_cert, &mesh_key, &mesh_ca)?;
    let tenants: Arc<dyn TenantsResolver> = Arc::new(TenantsClient::new(
        mesh_client,
        config.mesh_base_url.clone(),
    ));

    // Inter-node forward dialer (raw mTLS L4 splice).
    let forwarder: Arc<dyn InterNodeForwarder> = Arc::new(MtlsForwarder::new(
        &mesh_cert,
        &mesh_key,
        &mesh_ca,
        &config.forward_server_name,
    )?);

    // The SNI demuxer routes through this — local registry first, else inter-node.
    let tunnel_router: Arc<dyn TunnelRouter> = Arc::new(LocalRouter::new(
        Arc::clone(&registry),
        Arc::clone(&routes),
        forwarder,
        config.forward_advertise_addr.clone(),
    ));

    // Offline JWT verification (Tenants-signed daemon tokens).
    let verifier = token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes())?;

    // Values captured before `config` is cloned into the AppState.
    let https_listen_addr = config.https_listen_addr.clone();
    let dot_listen_addr = config.dot_listen_addr.clone();
    let api_listen_addr = config.api_listen_addr.clone();
    let subdomain_parent = config.subdomain_parent.clone();
    let node_addr = config.forward_advertise_addr.clone();
    let reconcile_interval = Duration::from_secs(config.reconcile_interval_secs);
    let reconcile_jitter = config.reconcile_jitter_secs;
    let route_ttl = Duration::from_secs(config.route_ttl_secs);
    let ttl_reaper_interval = Duration::from_secs(config.ttl_reaper_interval_secs);

    let state = AppState::new(
        config.clone(),
        Arc::clone(&registry),
        Arc::clone(&routes),
        Arc::clone(&tenants),
        verifier,
    );
    let api_router = api::router(state);

    tokio::select! {
        // Public, nginx-fronted daemon API (the tunnel upgrade + health).
        res = serve::run_api(&api_listen_addr, api_router) => res?,

        // Tenant TLS is never terminated: both SNI listeners are pure L4 passthrough.
        res = sni::run(&https_listen_addr, &subdomain_parent, Arc::clone(&tunnel_router), HTTPS_TUNNEL_PORT) => res?,
        res = sni::run(&dot_listen_addr, &subdomain_parent, Arc::clone(&tunnel_router), DOT_TUNNEL_PORT) => res?,

        // Private inter-node forward listener (mesh mTLS).
        res = serve_forward(&config, Arc::clone(&registry)) => res?,

        // Pull-reconcile abort + heartbeat over this node's own routes.
        () = reconcile::abort_reaper(
            Arc::clone(&registry),
            Arc::clone(&routes),
            Arc::clone(&tenants),
            node_addr,
            reconcile_interval,
            reconcile_jitter,
        ) => {},

        // Purge routes orphaned by a crashed node.
        () = reconcile::ttl_reaper(Arc::clone(&routes), route_ttl, ttl_reaper_interval) => {},
    }

    Ok(())
}
