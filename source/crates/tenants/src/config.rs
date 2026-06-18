//! Runtime configuration for the Tenants service, loaded from environment.
//!
//! In production the inforge bootstrapper injects the deployment identity and all
//! secrets (`GLOBAL_DATABASE_URL`, the JWT signing/verify keys, the mesh PEM
//! material) into the process environment. Required variables must be present at
//! startup; optional ones fall back to documented defaults.
//!
//! Tenants serves two listeners: a public, nginx-fronted control-plane API
//! ([`Self::api_listen_addr`]) and an internal mesh-mTLS work-queue listener
//! ([`Self::mesh_listen_addr`]) consumed by the regional DDNS provisioner/reaper.

use wardnet_common::config::required;

/// Runtime configuration.
#[derive(Clone)]
pub struct Config {
    /// `PostgreSQL` DSN for the global Tenants DB (tenants, networks, daemons, …).
    pub global_database_url: String,

    /// Deployment region slug (for logging / deployment identity).
    pub region: String,

    /// The fleet's real regions (from `KNOWN_REGIONS`, comma-separated). A network
    /// may only be created in one of these — others would never be reconciled.
    pub known_regions: Vec<String>,

    /// Loopback address for the public control-plane API (public `:80` via nginx).
    pub api_listen_addr: String,

    /// Address for the internal mesh-mTLS work-queue listener (DDNS ↔ Tenants).
    pub mesh_listen_addr: String,

    /// PEM path: the mesh CA the mesh listener requires client certs to chain to.
    pub trust_bundle_path: String,
    /// PEM path: this service's mesh server leaf certificate.
    pub leaf_cert_path: String,
    /// PEM path: this service's mesh server private key.
    pub leaf_key_path: String,

    /// Interval (seconds) between sweeps that delete tombstoned tenants whose networks
    /// are fully deprovisioned. Default 3600 (hourly).
    pub sweep_interval_secs: u64,

    /// Free-trial length (days) applied when a tenant's trial subscription is opened.
    /// Default 60.
    pub trial_days: i64,
    /// Extra days a lapsed trial keeps service before the reaper cancels it. Default 15.
    pub trial_grace_days: i64,
    /// Extra days a `past_due` subscription keeps service before the reaper cancels it.
    /// Default 15.
    pub payment_grace_days: i64,
    /// Interval (seconds) between subscription-reaper + reconcile passes. Default 3600.
    pub sub_reaper_interval_secs: u64,

    /// Stripe secret API key (inforge-injected, like the DSN). Redacted in `Debug`.
    pub stripe_secret_key: String,
    /// Stripe webhook signing secret — the credential the webhook endpoint verifies.
    /// Redacted in `Debug`.
    pub stripe_webhook_secret: String,
    /// Base URL of the account SPA; Stripe checkout success/cancel + portal return
    /// URLs hang off it.
    pub account_base_url: String,
}

impl std::fmt::Debug for Config {
    /// Redacts the secret-bearing DSN so the config can be logged safely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("global_database_url", &"<redacted>")
            .field("region", &self.region)
            .field("known_regions", &self.known_regions)
            .field("api_listen_addr", &self.api_listen_addr)
            .field("mesh_listen_addr", &self.mesh_listen_addr)
            .field("trust_bundle_path", &self.trust_bundle_path)
            .field("leaf_cert_path", &self.leaf_cert_path)
            .field("leaf_key_path", &self.leaf_key_path)
            .field("sweep_interval_secs", &self.sweep_interval_secs)
            .field("trial_days", &self.trial_days)
            .field("trial_grace_days", &self.trial_grace_days)
            .field("payment_grace_days", &self.payment_grace_days)
            .field("sub_reaper_interval_secs", &self.sub_reaper_interval_secs)
            .field("stripe_secret_key", &"<redacted>")
            .field("stripe_webhook_secret", &"<redacted>")
            .field("account_base_url", &self.account_base_url)
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    /// Returns an error if any required variable is absent.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            global_database_url: required("GLOBAL_DATABASE_URL")?,
            region: required("INFORGE_DEPLOYMENT_REGION_SLUG")?,
            known_regions: required("KNOWN_REGIONS")?
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            api_listen_addr: std::env::var("API_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            mesh_listen_addr: std::env::var("MESH_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9443".to_string()),
            trust_bundle_path: required("MTLS_TRUST_BUNDLE_PATH")?,
            leaf_cert_path: required("MTLS_LEAF_CERT_PATH")?,
            leaf_key_path: required("MTLS_LEAF_KEY_PATH")?,
            sweep_interval_secs: std::env::var("TENANT_SWEEP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            trial_days: std::env::var("TRIAL_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            trial_grace_days: std::env::var("TRIAL_GRACE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            payment_grace_days: std::env::var("PAYMENT_GRACE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            sub_reaper_interval_secs: std::env::var("SUB_REAPER_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            stripe_secret_key: required("STRIPE_SECRET_KEY")?,
            stripe_webhook_secret: required("STRIPE_WEBHOOK_SECRET")?,
            account_base_url: required("ACCOUNT_BASE_URL")?,
        })
    }
}
