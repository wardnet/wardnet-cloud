use std::sync::Arc;

use std::collections::HashMap;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use wardnet_common::config as common_config;
use wardnet_common::event::{BroadcastEventBus, EventPublisher};
use wardnet_common::{mtls, serve, token};

use wardnet_tenants::{
    api,
    config::Config,
    db,
    email::{EmailSender, NoopEmailSender, ResendEmailSender},
    identities::{
        IdentitiesService,
        provider::{ExternalIdentityProvider, GitHubProvider, OidcProvider},
        reactor as identities_reactor,
    },
    mesh,
    repository::{
        DaemonRepository, EnrollmentRepository, NetworkRepository, PgDaemonRepository,
        PgEnrollmentRepository, PgNetworkRepository, PgSessionRepository, PgSubscriptionRepository,
        PgTenantIdentityRepository, PgTenantRepository, SessionRepository, SubscriptionRepository,
        TenantIdentityRepository, TenantRepository,
    },
    service::TenantsService,
    state::AppState,
    stripe::StripeClient,
    subscription::{SubscriptionService, TrialPolicy, reactor},
};

/// Broadcast channel depth for domain events. Generous so a momentarily-busy reactor
/// never lags (a dropped event is still recovered by the reconcile loop).
const EVENT_BUS_CAPACITY: usize = 1024;

// `main` is end-to-end process wiring (repos → services → reactors → listeners);
// keeping it linear reads better than splintering it into single-call helpers.
#[allow(clippy::too_many_lines)]
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
    let subscriptions_repo = Arc::new(PgSubscriptionRepository::new_pools(pools.clone()));
    // Identities aggregate repos (WS-F).
    let identity_repo = Arc::new(PgTenantIdentityRepository::new_pools(pools.clone()));
    let session_repo = Arc::new(PgSessionRepository::new_pools(pools.clone()));
    let enrollment_repo = Arc::new(PgEnrollmentRepository::new_pools(pools));

    // Tenants signs both daemon (TenantsService) and user (IdentitiesService) JWTs; the
    // signing key is a shared capability behind an `Arc`. The private key PEM is
    // consumed into the signer and never seated in the shared state.
    let signing_key_pem = common_config::load_jwt_signing_key_pem()?;
    let signer = Arc::new(token::Signer::from_pem(signing_key_pem.as_bytes(), None)?);
    drop(signing_key_pem);

    // The auth layer verifies identity JWTs offline with the matching public key,
    // scoped to this service's own audience (ADR-0008): a token whose `aud` omits
    // `tenants` is rejected.
    let verifier = token::Verifier::from_pem(
        common_config::load_jwt_verify_key_pem()?.as_bytes(),
        "tenants",
    )?;

    // Domain-event bus: services publish, reactors react (one-way, never a direct
    // cross-aggregate write call).
    let events: Arc<dyn EventPublisher> = Arc::new(BroadcastEventBus::new(EVENT_BUS_CAPACITY));

    // Stripe gateway (real async-stripe client; the signature secret is the webhook
    // credential). Secrets arrive in the env via inforge, like the DSN.
    let stripe = Arc::new(StripeClient::new(
        &config.stripe_secret_key,
        &config.stripe_webhook_secret,
        &config.account_base_url,
    ));

    // Build the subscription aggregate first (Tenants reads it via a service method).
    let subscriptions = Arc::new(SubscriptionService::new(
        subscriptions_repo as Arc<dyn SubscriptionRepository>,
        Arc::clone(&events),
        stripe,
        TrialPolicy {
            trial_days: config.trial_days,
            trial_grace_days: config.trial_grace_days,
            payment_grace_days: config.payment_grace_days,
        },
    ));
    // Transactional email: Resend when configured, else the dev no-op (logs the code).
    let email: Arc<dyn EmailSender> = if let Some(key) = &config.resend_api_key {
        Arc::new(ResendEmailSender::new(key, &config.email_from)?)
    } else {
        tracing::warn!("RESEND_API_KEY unset; using the no-op email sender (codes are logged)");
        Arc::new(NoopEmailSender)
    };

    let service = Arc::new(TenantsService::new(
        tenants_repo as Arc<dyn TenantRepository>,
        networks_repo as Arc<dyn NetworkRepository>,
        daemons_repo as Arc<dyn DaemonRepository>,
        enrollment_repo as Arc<dyn EnrollmentRepository>,
        Arc::clone(&subscriptions),
        Arc::clone(&events),
        email,
        Arc::clone(&signer),
        config.known_regions.clone(),
    ));

    // The Identities aggregate (WS-F): human/web login. Holds only its own repos +
    // the tenant aggregate (read/create edge) + the shared signer + the federated
    // providers (built from config; absent ones simply disable that login button).
    let providers = build_identity_providers(&config).await?;
    let identities = Arc::new(IdentitiesService::new(
        identity_repo as Arc<dyn TenantIdentityRepository>,
        session_repo as Arc<dyn SessionRepository>,
        Arc::clone(&service),
        providers,
        Arc::clone(&signer),
        config.user_jwt_ttl_secs,
    ));

    // Reactors: turn published events into the owning service's method calls.
    tokio::spawn(reactor::run_subscription_reactor(
        Arc::clone(&subscriptions),
        events.subscribe(),
    ));
    tokio::spawn(reactor::run_network_reactor(
        Arc::clone(&service),
        events.subscribe(),
    ));
    // Identities reactor: TenantDeregistered → purge sessions + login methods.
    tokio::spawn(identities_reactor::run_identities_reactor(
        Arc::clone(&identities),
        events.subscribe(),
    ));

    let state = AppState::new(
        config.clone(),
        Arc::clone(&service),
        Arc::clone(&subscriptions),
        Arc::clone(&identities),
        verifier,
    );
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

    let sweep_interval = std::time::Duration::from_secs(config.sweep_interval_secs);
    let sub_reaper_interval = std::time::Duration::from_secs(config.sub_reaper_interval_secs);

    tokio::select! {
        // Public, nginx-fronted control-plane API (daemon + user JWT, bootstrap).
        res = serve::run_api(&config.api_listen_addr, api_router) => res?,

        // Internal mesh-mTLS work-queue listener (DDNS provisioner/reaper ↔ Tenants).
        res = mesh::serve_mesh(
            &config.mesh_listen_addr,
            Arc::clone(&mesh_server_config),
            state.clone(),
        ) => res?,

        // Periodic tombstone sweep: delete deregistered tenants whose networks are gone.
        () = sweep_loop(Arc::clone(&service), sweep_interval) => {},

        // Periodic subscription reaper + reconcile (the dropped-event safety net).
        () = sub_reaper_loop(
            Arc::clone(&subscriptions),
            Arc::clone(&service),
            sub_reaper_interval,
        ) => {},
    }

    Ok(())
}

/// Build the configured federated login providers (WS-F). Each provider is enabled
/// only when both halves of its credential are present; Google performs OIDC discovery
/// here (one network call at boot). The per-provider `redirect_uri` hangs off
/// `oauth_redirect_base`.
async fn build_identity_providers(
    config: &Config,
) -> anyhow::Result<HashMap<String, Arc<dyn ExternalIdentityProvider>>> {
    let mut providers: HashMap<String, Arc<dyn ExternalIdentityProvider>> = HashMap::new();
    let redirect = |provider: &str| {
        format!(
            "{}/v1/auth/oidc/{provider}/callback",
            config.oauth_redirect_base
        )
    };

    if let (Some(id), Some(secret)) = (&config.google_client_id, &config.google_client_secret) {
        // Discovery is a network call to the provider. A provider outage must not block
        // the whole service from booting (it also serves the daemon JWT plane, the Stripe
        // webhook, and the mesh work-queue) — so a failure disables only Google login.
        match OidcProvider::discover(
            "google",
            "https://accounts.google.com",
            id.clone(),
            secret.clone(),
            redirect("google"),
        )
        .await
        {
            Ok(google) => {
                providers.insert("google".to_string(), Arc::new(google));
                tracing::info!("google login enabled");
            }
            Err(e) => {
                tracing::error!(error = %e, "google OIDC discovery failed; google login disabled");
            }
        }
    }
    if let (Some(id), Some(secret)) = (&config.github_client_id, &config.github_client_secret) {
        let github = GitHubProvider::new(id.clone(), secret.clone(), redirect("github"))?;
        providers.insert("github".to_string(), Arc::new(github));
        tracing::info!("github login enabled");
    }
    Ok(providers)
}

/// Periodically delete tombstoned tenants whose networks are fully deprovisioned. The
/// first tick fires immediately, then every `interval`. N-replica-safe (the delete is
/// idempotent), so every node may run it.
async fn sweep_loop(service: Arc<TenantsService>, interval: std::time::Duration) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        if let Err(e) = service.sweep_deregistered().await {
            tracing::error!(error = %e, "tombstone sweep failed");
        }
    }
}

/// Periodically cancel overdue subscriptions (expired trials / past-due past grace)
/// and reconcile desired state — the safety net for any dropped domain event.
/// N-replica-safe and idempotent.
async fn sub_reaper_loop(
    subscriptions: Arc<SubscriptionService>,
    service: Arc<TenantsService>,
    interval: std::time::Duration,
) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        if let Err(e) = subscriptions.expire_overdue().await {
            tracing::error!(error = %e, "subscription reaper failed");
        }
        if let Err(e) = service.reconcile().await {
            tracing::error!(error = %e, "subscription reconcile failed");
        }
    }
}
