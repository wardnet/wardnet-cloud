use wardnet_common::config::required;

/// Runtime configuration for the Tenants service, loaded from the environment.
///
/// In production the inforge bootstrapper injects the deployment identity and
/// secrets. The JWT key paths are not fields here — `main` loads them once via the
/// shared `wardnet_common::config` helpers and consumes them into the `Signer` /
/// `Verifier`.
///
/// # Listeners
///
/// - [`Self::api_listen_addr`] — the **public** control-plane API (nginx fronts
///   TLS; plain HTTP behind it). Daemon-authenticated (JWT / bearer).
/// - [`Self::introspect_listen_addr`] — the **internal** mesh-mTLS listener
///   serving `POST /v1/introspect`. Authenticated by client certificate chained to
///   [`Self::mesh_ca_path`]; never exposed publicly.
#[derive(Clone)]
pub struct Config {
    /// `PostgreSQL` DSN for the global naming authority (identities + challenges).
    pub global_database_url: String,

    /// Short region slug, e.g. `"use1"` — returned to the daemon at registration.
    pub region: String,

    /// DNS parent under which tenant subdomains live, e.g. `"my.wardnet.services"`.
    /// Tenants needs it only to return the install's full subdomain at registration;
    /// the DDNS service (which owns record creation) reads the same `SUBDOMAIN_PARENT`.
    pub subdomain_parent: String,

    /// Public control-plane API listen address. Default `127.0.0.1:8080`.
    pub api_listen_addr: String,

    /// Internal mesh-mTLS introspect listen address. Default `127.0.0.1:9443`.
    pub introspect_listen_addr: String,

    /// PEM path: the mesh CA used to verify introspect client certificates.
    pub mesh_ca_path: String,
    /// PEM path: this service's mesh server certificate chain.
    pub mesh_cert_path: String,
    /// PEM path: this service's mesh server private key.
    pub mesh_key_path: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("global_database_url", &"<redacted>")
            .field("region", &self.region)
            .field("subdomain_parent", &self.subdomain_parent)
            .field("api_listen_addr", &self.api_listen_addr)
            .field("introspect_listen_addr", &self.introspect_listen_addr)
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
            subdomain_parent: required("SUBDOMAIN_PARENT")?,
            api_listen_addr: std::env::var("API_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            introspect_listen_addr: std::env::var("INTROSPECT_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9443".to_string()),
            mesh_ca_path: required("MESH_CA_PATH")?,
            mesh_cert_path: required("MESH_CERT_PATH")?,
            mesh_key_path: required("MESH_KEY_PATH")?,
        })
    }

    /// Construct an install's full subdomain, e.g.
    /// `"happy-einstein"` → `"happy-einstein.my.wardnet.services"`.
    #[must_use]
    pub fn install_fqdn(&self, name: &str) -> String {
        format!("{name}.{}", self.subdomain_parent)
    }
}
