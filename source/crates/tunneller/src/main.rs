use std::sync::Arc;
use std::time::Duration;

use wardnet_common::config as common_config;
use wardnet_common::mtls::{ExpectedPeer, MeshClient, ReloadableServerConfig, SpiffeId};
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

/// The mesh mTLS consumers [`setup_mesh`] builds, plus this node's own SPIFFE id.
type MeshSetup = (
    Arc<MeshClient>,
    Arc<MtlsForwarder>,
    Arc<ReloadableServerConfig>,
    SpiffeId,
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Telemetry (logs + metrics + traces over OTLP); opt-in by endpoint. Held for
    // the lifetime of `main` so the final batch flushes on exit.
    let _telemetry =
        wardnet_common::telemetry::init("wardnet-tunneller", env!("CARGO_PKG_VERSION"));

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

    // Domain metric: tunnels currently registered on this node (bounded scalar, no
    // labels — plan §5a). An observable gauge polled by the meter on each export.
    {
        let registry = Arc::clone(&registry);
        opentelemetry::global::meter(wardnet_common::telemetry::SCOPE)
            .u64_observable_gauge("tunneller.active_tunnels")
            .with_description("Tunnels currently registered on this node.")
            .with_callback(move |observer| observer.observe(registry.active_count(), &[]))
            .build();
    }

    // Mesh mTLS consumers (Tenants reader, inter-node forwarder, forward acceptor
    // config) + the rotation watcher; `own_id` carries this node's scope/service.
    let (mesh_client, forwarder, forward_server_config, own_id) = setup_mesh(&config)?;
    let tenants: Arc<dyn TenantsResolver> = Arc::new(TenantsClient::new(
        Arc::clone(&mesh_client),
        config.mesh_base_url.clone(),
    ));

    // The SNI demuxer routes through this — local registry first, else inter-node.
    let tunnel_router: Arc<dyn TunnelRouter> = Arc::new(LocalRouter::new(
        Arc::clone(&registry),
        Arc::clone(&routes),
        Arc::clone(&forwarder) as Arc<dyn InterNodeForwarder>,
        config.forward_advertise_addr.clone(),
    ));

    // Offline JWT verification (Tenants-signed daemon tokens), scoped to this
    // service's own audience (ADR-0008): only a network-scoped daemon token (whose
    // `aud` includes `tunneller`) is accepted at `GET /v1/tunnel`.
    let verifier = token::Verifier::from_pem(
        common_config::load_jwt_verify_key_pem()?.as_bytes(),
        "tunneller",
    )?;

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
        res = serve_forward(
            &config.forward_listen_addr,
            Arc::clone(&forward_server_config),
            Arc::clone(&registry),
            own_id.scope.clone(),
        ) => res?,

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

/// Load the mesh PEM material, build the mTLS consumers (Tenants reader, inter-node
/// forwarder, forward acceptor config), and spawn the in-process rotation watcher.
/// Returns the consumers plus this node's own SPIFFE id (its scope/service, parsed from
/// its own leaf). inforge re-projects the leaf/key/bundle files in place on renewal; the
/// watcher re-reads them and hot-reloads every consumer.
fn setup_mesh(config: &Config) -> anyhow::Result<MeshSetup> {
    let leaf = std::fs::read(&config.leaf_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh leaf at {}: {e}", config.leaf_cert_path))?;
    let key = std::fs::read(&config.leaf_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.leaf_key_path))?;
    let bundle = std::fs::read(&config.trust_bundle_path)
        .map_err(|e| anyhow::anyhow!("read trust bundle at {}: {e}", config.trust_bundle_path))?;

    // Learn this node's own identity (scope/service) by parsing its own leaf.
    let own_id = mtls::own_spiffe_id(&leaf)?;
    tracing::info!(scope = %own_id.scope, service = %own_id.service, "mesh identity");

    // Routing-policy reads against Tenants (mesh mTLS over HTTP); pin Tenants (global).
    let mesh_client =
        MeshClient::new(&leaf, &key, &bundle, ExpectedPeer::new("tenants", "global"))?;
    // Inter-node forward dialer; pin a `tunneller` in our own scope.
    let forwarder = MtlsForwarder::new(
        &leaf,
        &key,
        &bundle,
        ExpectedPeer::new("tunneller", own_id.scope.clone()),
    )?;
    // Inter-node forward acceptor config (mesh mTLS), hot-reloadable per connection.
    let forward_server_config = ReloadableServerConfig::new(&leaf, &key, &bundle)?;

    let leaf_path = config.leaf_cert_path.clone();
    let key_path = config.leaf_key_path.clone();
    let bundle_path = config.trust_bundle_path.clone();
    let w_mesh = Arc::clone(&mesh_client);
    let w_fwd = Arc::clone(&forwarder);
    let w_srv = Arc::clone(&forward_server_config);
    mtls::watch_mesh_files(
        &[leaf_path.clone(), key_path.clone(), bundle_path.clone()],
        move || {
            let (Ok(leaf), Ok(key), Ok(bundle)) = (
                std::fs::read(&leaf_path),
                std::fs::read(&key_path),
                std::fs::read(&bundle_path),
            ) else {
                tracing::error!("failed to re-read mesh cert files after change");
                return;
            };
            for r in [
                w_mesh.reload(&leaf, &key, &bundle),
                w_fwd.reload(&leaf, &key, &bundle),
                w_srv.reload(&leaf, &key, &bundle),
            ] {
                if let Err(e) = r {
                    tracing::error!(error = %e, "mesh cert reload failed");
                }
            }
            tracing::info!("reloaded mesh certificates");
        },
    )?;

    Ok((mesh_client, forwarder, forward_server_config, own_id))
}
