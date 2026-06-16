use std::sync::Arc;
use std::time::Duration;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_common::config as common_config;
use wardnet_common::mtls::MeshClient;
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

    let dns_provider = Arc::new(CloudflareDnsProvider::new(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
    )?);

    let ddns = Arc::new(DdnsService::new(operational.clone(), dns_provider));

    // Offline JWT verification (Tenants-signed daemon tokens).
    let verifier = token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes())?;

    // Mesh client (mTLS) consuming the Tenants work-queue. Static for now —
    // certificate rotation is deferred.
    let mesh_ca = std::fs::read(&config.mesh_ca_path)
        .map_err(|e| anyhow::anyhow!("read mesh CA at {}: {e}", config.mesh_ca_path))?;
    let mesh_cert = std::fs::read(&config.mesh_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh cert at {}: {e}", config.mesh_cert_path))?;
    let mesh_key = std::fs::read(&config.mesh_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.mesh_key_path))?;
    let mesh = MeshClient::new(&mesh_cert, &mesh_key, &mesh_ca)?;
    let work: Arc<dyn WorkQueue> =
        Arc::new(TenantsWorkQueue::new(mesh, config.mesh_base_url.clone()));

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
