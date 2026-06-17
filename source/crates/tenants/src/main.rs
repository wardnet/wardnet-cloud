use std::sync::Arc;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_common::config as common_config;
use wardnet_common::{mtls, serve, token};
use wardnet_tenants::{
    api,
    config::Config,
    db, mesh,
    repository::{
        DaemonRepository, EnrollmentRepository, NetworkRepository, PgDaemonRepository,
        PgEnrollmentRepository, PgNetworkRepository, PgTenantRepository, TenantRepository,
    },
    service::TenantsService,
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env())
        .init();

    // rustls 0.23 needs a process-default crypto provider before any TLS work —
    // the internal mesh-mTLS work-queue listener relies on it.
    mtls::install_crypto_provider();

    let config = Config::from_env()?;
    tracing::info!(
        region = %config.region,
        api_listen_addr = %config.api_listen_addr,
        mesh_listen_addr = %config.mesh_listen_addr,
        "wardnet-tenants starting"
    );

    let pools = db::init(&config.global_database_url).await?;

    let tenants_repo = Arc::new(PgTenantRepository::new_pools(pools.clone()));
    let networks_repo = Arc::new(PgNetworkRepository::new_pools(pools.clone()));
    let daemons_repo = Arc::new(PgDaemonRepository::new_pools(pools.clone()));
    let enrollment_repo = Arc::new(PgEnrollmentRepository::new_pools(pools));

    // Tenants signs identity JWTs; the private key is consumed into the signer and
    // never seated in the shared state.
    let signing_key_pem = common_config::load_jwt_signing_key_pem()?;
    let signer = token::Signer::from_pem(signing_key_pem.as_bytes(), None)?;
    drop(signing_key_pem);

    // The auth layer verifies identity JWTs offline with the matching public key.
    let verifier = token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes())?;

    let service = Arc::new(TenantsService::new(
        tenants_repo as Arc<dyn TenantRepository>,
        networks_repo as Arc<dyn NetworkRepository>,
        daemons_repo as Arc<dyn DaemonRepository>,
        enrollment_repo as Arc<dyn EnrollmentRepository>,
        signer,
        config.known_regions.clone(),
    ));

    let state = AppState::new(config.clone(), service, verifier);
    let api_router = api::router(state.clone());

    // Mesh listener material (mTLS). inforge re-projects the leaf/key/bundle files in
    // place on rotation; we file-watch + hot-reload the acceptor config.
    let mesh_leaf = std::fs::read(&config.leaf_cert_path)
        .map_err(|e| anyhow::anyhow!("read mesh leaf at {}: {e}", config.leaf_cert_path))?;
    let mesh_key = std::fs::read(&config.leaf_key_path)
        .map_err(|e| anyhow::anyhow!("read mesh key at {}: {e}", config.leaf_key_path))?;
    let trust_bundle = std::fs::read(&config.trust_bundle_path)
        .map_err(|e| anyhow::anyhow!("read trust bundle at {}: {e}", config.trust_bundle_path))?;

    let own_id = mtls::own_spiffe_id(&mesh_leaf)?;
    tracing::info!(scope = %own_id.scope, service = %own_id.service, "mesh identity");

    let mesh_server_config =
        mtls::ReloadableServerConfig::new(&mesh_leaf, &mesh_key, &trust_bundle)?;

    {
        let leaf_path = config.leaf_cert_path.clone();
        let key_path = config.leaf_key_path.clone();
        let bundle_path = config.trust_bundle_path.clone();
        let w_srv = Arc::clone(&mesh_server_config);
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
                if let Err(e) = w_srv.reload(&leaf, &key, &bundle) {
                    tracing::error!(error = %e, "mesh cert reload failed");
                } else {
                    tracing::info!("reloaded mesh certificates");
                }
            },
        )?;
    }

    tokio::select! {
        // Public, nginx-fronted control-plane API (daemon + user JWT, bootstrap).
        res = serve::run_api(&config.api_listen_addr, api_router) => res?,

        // Internal mesh-mTLS work-queue listener (DDNS provisioner/reaper ↔ Tenants).
        res = mesh::serve_mesh(
            &config.mesh_listen_addr,
            Arc::clone(&mesh_server_config),
            state,
        ) => res?,
    }

    Ok(())
}
