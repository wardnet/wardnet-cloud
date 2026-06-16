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
    ));

    let state = AppState::new(config.clone(), service, verifier);
    let api_router = api::router(state.clone());

    tokio::select! {
        // Public, nginx-fronted control-plane API (daemon + user JWT, bootstrap).
        res = serve::run_api(&config.api_listen_addr, api_router) => res?,

        // Internal mesh-mTLS work-queue listener (DDNS provisioner/reaper ↔ Tenants).
        res = mesh::serve_mesh(&config, state) => res?,
    }

    Ok(())
}
