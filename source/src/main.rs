use std::sync::Arc;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_cloud::{
    api,
    cloudflare::CloudflareDnsProvider,
    config::{self, Config},
    db,
    dns_provider::DnsProvider,
    http01,
    repository::{
        ChallengeRepository, IdentityRepository, OperationalRepository, PgChallengeRepository,
        PgIdentityRepository, PgOperationalRepository, PgTlsRepository, TlsRepository,
    },
    service::{DdnsService, TenantsService},
    sni::{self, Role},
    state::AppState,
    sweep,
    tls::{self, CertResolver, TlsRenewalRunner},
    token,
    tunnel::TunnelRegistry,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;

    // rustls 0.23 needs an explicit default crypto provider before any TLS work.
    tls::install_crypto_provider();

    tracing::info!(
        region = %config.region,
        fqdn = %config.fqdn,
        subdomain_parent = %config.subdomain_parent,
        http01_listen_addr = %config.http01_listen_addr,
        tls_listen_addr = %config.tls_listen_addr,
        dot_listen_addr = %config.dot_listen_addr,
        "wardnet-bridge starting"
    );

    let pools = db::init(&config.database_url).await?;
    let global_pools = db::init_global(&config.global_database_url).await?;

    // Identity + challenges live in the global Tenants DB; operational DNS state in
    // the regional DB.
    let identities = Arc::new(PgIdentityRepository::new_pools(global_pools.clone()));
    let challenges = Arc::new(PgChallengeRepository::new_pools(global_pools));
    let operational = Arc::new(PgOperationalRepository::new_pools(pools.clone()));
    let tls_repo: Arc<dyn TlsRepository> = Arc::new(PgTlsRepository::new_pools(pools.clone()));
    let dns_provider = Arc::new(CloudflareDnsProvider::new(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
    )?);
    let tunnel_registry = Arc::new(TunnelRegistry::new());

    // Tenants signs identity JWTs at registration. The private key is read here and
    // consumed into the signer — it is never seated in the shared `Config`/AppState.
    let jwt_signing_key_pem = config::load_jwt_signing_key_pem()?;
    let jwt_signer = token::Signer::from_pem(jwt_signing_key_pem.as_bytes(), None)?;
    drop(jwt_signing_key_pem);

    // The auth middleware verifies identity JWTs offline with the matching public
    // key (at the service split this verifier lives in DDNS/Tunneller).
    let jwt_verifier = token::Verifier::from_pem(config::load_jwt_verify_key_pem()?.as_bytes())?;

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

    // Reap expired ACME HTTP-01 challenge tokens for this region.
    tokio::spawn(sweep::run(Arc::clone(&tls_repo)));

    let state = AppState::new(
        config.clone(),
        tenants,
        ddns,
        jwt_verifier,
        Arc::clone(&tunnel_registry),
    );
    let api_router = api::router(state);

    // The :8443 listener serves the API over a cert that starts as a placeholder
    // and is hot-swapped to the real one by the renewal runner. The same resolver
    // is shared by both so a swap is immediately visible to new connections.
    let resolver = CertResolver::with_placeholder()?;

    let runner = TlsRenewalRunner::new(
        Arc::clone(&tls_repo),
        Arc::clone(&resolver),
        config.fqdn.clone(),
        config.acme_directory_url.clone(),
        config.encryption_key,
    );
    tokio::spawn(runner.run());

    let fqdn: Arc<str> = Arc::from(config.fqdn.as_str());

    tokio::select! {
        res = http01::run(&config.http01_listen_addr, Arc::clone(&tls_repo)) => res?,

        res = sni::run(
            &config.tls_listen_addr,
            Arc::clone(&fqdn),
            &config.subdomain_parent,
            Arc::clone(&tunnel_registry),
            Role::Https { resolver: Arc::clone(&resolver), api_router },
        ) => res?,

        res = sni::run(
            &config.dot_listen_addr,
            Arc::clone(&fqdn),
            &config.subdomain_parent,
            Arc::clone(&tunnel_registry),
            Role::Dot,
        ) => res?,
    }

    Ok(())
}
