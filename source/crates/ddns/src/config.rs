//! Runtime configuration for the DDNS service.
//!
//! In production the inforge bootstrapper injects the deployment identity
//! (`INFORGE_DEPLOYMENT_*`) and all secrets (`DATABASE_URL`, the Cloudflare token,
//! the mesh PEM paths) into the environment. Required variables must be present at
//! startup; `Config::from_env` exits with a human-readable error if one is missing.
//!
//! The service runs a public, nginx-fronted API (daemon report-IP / ACME) and two
//! reconcile loops that *consume* the Tenants mesh-mTLS work-queue as an mTLS
//! client (`mesh_base_url` + the mesh PEM material). It does not serve an mTLS
//! listener of its own.

use wardnet_common::config::required;

/// Default provisioner tick interval (short — publish records promptly).
const DEFAULT_PROVISIONER_INTERVAL_SECS: u64 = 10;
/// Default reaper tick interval (long — teardown is not latency-sensitive).
const DEFAULT_REAPER_INTERVAL_SECS: u64 = 300;
/// Default reaper jitter ceiling, so regional replicas don't reap in lockstep.
const DEFAULT_REAPER_JITTER_SECS: u64 = 30;

/// DDNS service configuration.
pub struct Config {
    /// Regional `PostgreSQL` DSN for the operational state.
    pub database_url: String,
    /// Cloudflare API token, scoped to **DNS:Edit** on the target zone only.
    pub cloudflare_api_token: String,
    /// Cloudflare zone ID that owns [`Self::subdomain_parent`].
    pub cloudflare_zone_id: String,
    /// Optional Cloudflare API base-URL override (`CLOUDFLARE_API_BASE`). Unset in
    /// production (real API); the e2e harness points it at a mock Cloudflare.
    pub cloudflare_api_base: Option<String>,
    /// DNS parent under which network records are created
    /// (e.g. `my.wardnet.services`).
    pub subdomain_parent: String,
    /// This deployment's region slug (e.g. `"use1"`); the reconcile filter.
    pub region: String,
    /// Plain-HTTP control-plane API listen address (fronted by nginx).
    pub api_listen_addr: String,
    /// Base URL of the Tenants mesh work-queue (e.g. `https://tenants.mesh:9443`).
    pub mesh_base_url: String,
    /// Mesh trust-bundle PEM path (anchors that verify the Tenants server leaf).
    pub trust_bundle_path: String,
    /// This service's mesh client leaf cert PEM path.
    pub leaf_cert_path: String,
    /// This service's mesh client leaf key PEM path.
    pub leaf_key_path: String,
    /// Provisioner tick interval (seconds).
    pub provisioner_interval_secs: u64,
    /// Reaper tick interval (seconds).
    pub reaper_interval_secs: u64,
    /// Reaper jitter ceiling (seconds).
    pub reaper_jitter_secs: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("cloudflare_api_token", &"<redacted>")
            .field("cloudflare_zone_id", &self.cloudflare_zone_id)
            .field("cloudflare_api_base", &self.cloudflare_api_base)
            .field("subdomain_parent", &self.subdomain_parent)
            .field("region", &self.region)
            .field("api_listen_addr", &self.api_listen_addr)
            .field("mesh_base_url", &self.mesh_base_url)
            .field("trust_bundle_path", &self.trust_bundle_path)
            .field("leaf_cert_path", &self.leaf_cert_path)
            .field("leaf_key_path", &self.leaf_key_path)
            .field("provisioner_interval_secs", &self.provisioner_interval_secs)
            .field("reaper_interval_secs", &self.reaper_interval_secs)
            .field("reaper_jitter_secs", &self.reaper_jitter_secs)
            .finish()
    }
}

impl Config {
    /// Load configuration from the environment.
    ///
    /// # Errors
    /// Returns an error if a required variable is missing or a numeric override
    /// cannot be parsed.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            cloudflare_api_token: required("CLOUDFLARE_API_TOKEN")?,
            cloudflare_zone_id: required("CLOUDFLARE_ZONE_ID")?,
            cloudflare_api_base: std::env::var("CLOUDFLARE_API_BASE")
                .ok()
                .filter(|s| !s.is_empty()),
            subdomain_parent: required("SUBDOMAIN_PARENT")?,
            region: required("INFORGE_DEPLOYMENT_REGION_SLUG")?,
            api_listen_addr: std::env::var("API_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            mesh_base_url: required("MESH_BASE_URL")?,
            trust_bundle_path: required("MTLS_TRUST_BUNDLE_PATH")?,
            leaf_cert_path: required("MTLS_LEAF_CERT_PATH")?,
            leaf_key_path: required("MTLS_LEAF_KEY_PATH")?,
            provisioner_interval_secs: parse_secs(
                "PROVISIONER_INTERVAL_SECS",
                DEFAULT_PROVISIONER_INTERVAL_SECS,
            )?,
            reaper_interval_secs: parse_secs("REAPER_INTERVAL_SECS", DEFAULT_REAPER_INTERVAL_SECS)?,
            reaper_jitter_secs: parse_secs("REAPER_JITTER_SECS", DEFAULT_REAPER_JITTER_SECS)?,
        })
    }
}

/// Parse an optional `u64` seconds env var, falling back to `default`.
fn parse_secs(var: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(var) {
        Ok(v) => v
            .parse()
            .map_err(|e| anyhow::anyhow!("{var} must be a non-negative integer: {e}")),
        Err(_) => Ok(default),
    }
}
