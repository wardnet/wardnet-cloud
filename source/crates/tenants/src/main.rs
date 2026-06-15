use std::sync::Arc;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_common::config as common_config;
use wardnet_common::{mtls, serve, token};
use wardnet_tenants::{
    api,
    config::Config,
    db, mesh,
    repository::{
        ChallengeRepository, IdentityRepository, PgChallengeRepository, PgIdentityRepository,
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
    // the internal mesh-mTLS introspect listener relies on it.
    mtls::install_crypto_provider();

    let config = Config::from_env()?;

    tracing::info!(
        region = %config.region,
        api_listen_addr = %config.api_listen_addr,
        introspect_listen_addr = %config.introspect_listen_addr,
        "wardnet-tenants starting"
    );

    let pools = db::init(&config.global_database_url).await?;

    let identities = Arc::new(PgIdentityRepository::new_pools(pools.clone()));
    let challenges = Arc::new(PgChallengeRepository::new_pools(pools));

    // Tenants signs identity JWTs. The private key is read here and consumed into
    // the signer — it is never seated in the shared `Config`/`AppState`.
    let jwt_signing_key_pem = common_config::load_jwt_signing_key_pem()?;
    let jwt_signer = token::Signer::from_pem(jwt_signing_key_pem.as_bytes(), None)?;
    drop(jwt_signing_key_pem);

    // The auth middleware verifies identity JWTs offline with the matching public key.
    let jwt_verifier =
        token::Verifier::from_pem(common_config::load_jwt_verify_key_pem()?.as_bytes())?;

    let tenants = Arc::new(TenantsService::new(
        identities as Arc<dyn IdentityRepository>,
        challenges as Arc<dyn ChallengeRepository>,
        jwt_signer,
    ));

    let state = AppState::new(config.clone(), tenants, jwt_verifier);
    let api_router = api::router(state.clone());

    tokio::select! {
        // Public, nginx-fronted control-plane API (daemon JWT / bearer auth).
        res = serve::run_api(&config.api_listen_addr, api_router) => res?,

        // Internal mesh-mTLS introspect listener (DDNS reaper ↔ Tenants).
        res = mesh::serve_introspect(&config, state) => res?,
    }

    Ok(())
}
