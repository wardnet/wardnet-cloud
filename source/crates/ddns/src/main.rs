use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_common::config as common_config;
use wardnet_common::mtls::{ExpectedPeer, MeshClient};
use wardnet_common::{mtls, serve, token};
use wardnet_ddns::{
    api,
    cloudflare::CloudflareDnsProvider,
    config::Config,
    db, reconcile,
    repository::{OperationalRepository, PgOperationalRepository},
    service::DdnsService,
    state::AppState,
    work_queue::{TenantsWorkQueue, WorkQueue},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env())
        .init();

    // rustls 0.23 needs a process-default crypto provider before any TLS (the
    // mesh client) is built.
    mtls::install_crypto_provider();

    let config = Config::from_env()?;
    tracing::info!(
        api_listen_addr = %config.api_listen_addr,
        region = %config.region,
        mesh_base_url = %config.mesh_base_url,
        "starting wardnet-ddns"
    );

    let pools = db::init(&config.database_url).await?;
    let operational: Arc<dyn OperationalRepository> =
        Arc::new(PgOperationalRepository::new_pools(pools));

    let dns_provider = Arc::new(CloudflareDnsProvider::with_base_url(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
        config.cloudflare_api_base.as_deref(),
    )?);

    let ddns = Arc::new(DdnsService::new(operational.clone(), dns_provider));

    // Offline JWT verification (Tenants-signed daemon tokens), scoped to this
    // service's own audience (ADR-0008): a token whose `aud` omits `ddns` — e.g. a
    // user token or a tenant-scoped daemon token — is rejected.
    let verifier =
        token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes(), "ddns")?;

    // Mesh client (mTLS) consuming the Tenants work-queue. inforge re-projects the
    // leaf/key/bundle files in place on rotation; we file-watch + hot-reload.
    let mesh_leaf = std::fs::read(&config.leaf_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh leaf at {}: {e}", config.leaf_cert_path))?;
    let mesh_key = std::fs::read(&config.leaf_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.leaf_key_path))?;
    let trust_bundle = std::fs::read(&config.trust_bundle_path)
        .map_err(|e| anyhow::anyhow!("read trust bundle at {}: {e}", config.trust_bundle_path))?;

    // Learn our own identity (scope/service) from our leaf, for diagnostics.
    let own_id = mtls::own_spiffe_id(&mesh_leaf)?;
    tracing::info!(scope = %own_id.scope, service = %own_id.service, "mesh identity");

    // Pin the work-queue peer to Tenants (global scope).
    let mesh = MeshClient::new(
        &mesh_leaf,
        &mesh_key,
        &trust_bundle,
        ExpectedPeer::new("tenants", "global"),
    )?;
    let work: Arc<dyn WorkQueue> = Arc::new(TenantsWorkQueue::new(
        Arc::clone(&mesh),
        config.mesh_base_url.clone(),
    ));

    // Hot-reload the mesh client when inforge re-projects the cert files in place.
    {
        let leaf_path = config.leaf_cert_path.clone();
        let key_path = config.leaf_key_path.clone();
        let bundle_path = config.trust_bundle_path.clone();
        let w_mesh = Arc::clone(&mesh);
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
                if let Err(e) = w_mesh.reload(&leaf, &key, &bundle) {
                    tracing::error!(error = %e, "mesh cert reload failed");
                } else {
                    tracing::info!("reloaded mesh certificates");
                }
            },
        )?;
    }

    // Loop parameters captured before `config` moves into the AppState.
    let region = config.region.clone();
    let subdomain_parent = config.subdomain_parent.clone();
    let provisioner_interval = Duration::from_secs(config.provisioner_interval_secs);
    let reaper_interval = Duration::from_secs(config.reaper_interval_secs);
    let reaper_jitter = config.reaper_jitter_secs;
    let api_listen_addr = config.api_listen_addr.clone();

    let state = AppState::new(config, ddns.clone(), verifier);
    let api_router = api::router(state);

    tokio::select! {
        // Public, nginx-fronted daemon API (report-IP + ACME).
        res = serve::run_api(&api_listen_addr, api_router) => res?,
        // Short-interval provisioner: publish A records for `provisioning` networks.
        () = reconcile::provisioner(
            work.clone(),
            ddns.clone(),
            operational,
            region.clone(),
            subdomain_parent,
            provisioner_interval,
        ) => {},
        // Long-interval reaper: tear DNS down for `deprovisioning` networks.
        () = reconcile::reaper(
            work,
            ddns,
            region,
            reaper_interval,
            reaper_jitter,
        ) => {},
    }

    Ok(())
}
