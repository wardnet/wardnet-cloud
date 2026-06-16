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

    /// Loopback address for the public control-plane API (public `:80` via nginx).
    pub api_listen_addr: String,

    /// Address for the internal mesh-mTLS work-queue listener (DDNS ↔ Tenants).
    pub mesh_listen_addr: String,

    /// PEM path: the mesh CA the mesh listener requires client certs to chain to.
    pub mesh_ca_path: String,
    /// PEM path: this service's mesh server leaf certificate.
    pub mesh_cert_path: String,
    /// PEM path: this service's mesh server private key.
    pub mesh_key_path: String,
}

impl std::fmt::Debug for Config {
    /// Redacts the secret-bearing DSN so the config can be logged safely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("global_database_url", &"<redacted>")
            .field("region", &self.region)
            .field("api_listen_addr", &self.api_listen_addr)
            .field("mesh_listen_addr", &self.mesh_listen_addr)
            .field("mesh_ca_path", &self.mesh_ca_path)
            .field("mesh_cert_path", &self.mesh_cert_path)
            .field("mesh_key_path", &self.mesh_key_path)
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
            api_listen_addr: std::env::var("API_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            mesh_listen_addr: std::env::var("MESH_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9443".to_string()),
            mesh_ca_path: required("MESH_CA_PATH")?,
            mesh_cert_path: required("MESH_CERT_PATH")?,
            mesh_key_path: required("MESH_KEY_PATH")?,
        })
    }
}
