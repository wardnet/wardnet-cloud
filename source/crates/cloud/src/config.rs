use wardnet_common::config::required;

/// Runtime configuration loaded from environment variables.
///
/// In production the inforge bootstrapper injects the deployment identity
/// (`INFORGE_DEPLOYMENT_*`) and all secrets (`DATABASE_URL`, the Cloudflare token,
/// …) into the process environment. All required variables must be present at
/// startup; the process exits with a human-readable error if any are missing.
/// Optional variables fall back to documented defaults.
///
/// # Edge topology
///
/// Public TLS is terminated by an **inforge-injected nginx sidecar** (ACME runs
/// there too); this process speaks only plain HTTP for its control-plane API and
/// pure **L4 passthrough** for tenant tunnels. nginx fronts every listener with a
/// transparent L4 proxy (PROXY protocol v1) that maps public privileged ports to
/// these unprivileged localhost ports:
///
/// | Public | Process | Purpose |
/// |---|---|---|
/// | `:80`  | [`Self::api_listen_addr`] `127.0.0.1:8080` | plain-HTTP control-plane API + `/health` |
/// | `:443` | `127.0.0.1:8443` | SNI passthrough to tenant tunnels (port 443) |
/// | `:853` | [`Self::dot_listen_addr`] `127.0.0.1:8853` | `DoT` passthrough to tenant tunnels (port 853) |
///
/// The process never terminates tenant TLS — the connection carries the daemon's
/// own certificate end-to-end.
#[derive(Clone)]
pub struct Config {
    /// Loopback address for the plain-HTTP control-plane API + `/health`. Default
    /// `127.0.0.1:8080` (public `:80` via nginx).
    pub api_listen_addr: String,

    /// Loopback address for the SNI-passthrough HTTPS listener. Default
    /// `127.0.0.1:8443` (public `:443` via nginx); forwards to tenant tunnels on 443.
    pub https_listen_addr: String,

    /// Loopback address for the DNS-over-TLS passthrough listener. Default
    /// `127.0.0.1:8853` (public `:853` via nginx); forwards to tenant tunnels on 853.
    pub dot_listen_addr: String,

    /// `PostgreSQL` DSN for this bridge's **regional** install DB.
    pub database_url: String,

    /// `PostgreSQL` DSN for the **global naming authority** (shared across the
    /// fleet; holds the `names` allocation lock).
    pub global_database_url: String,

    /// Cloudflare API token scoped to DNS:Edit on [`Self::cloudflare_zone_id`].
    pub cloudflare_api_token: String,

    /// Cloudflare zone ID that owns [`Self::subdomain_parent`].
    pub cloudflare_zone_id: String,

    /// Short region slug, e.g. `"use1"` (from `INFORGE_DEPLOYMENT_REGION_SLUG`).
    /// Selects which region this bridge owns; returned to the Pi at registration.
    pub region: String,

    /// DNS parent under which **tenant** subdomains are created,
    /// e.g. `"my.wardnet.services"`.
    pub subdomain_parent: String,
}

impl std::fmt::Debug for Config {
    /// Redacts secret-bearing fields so the config can be logged safely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_listen_addr", &self.api_listen_addr)
            .field("https_listen_addr", &self.https_listen_addr)
            .field("dot_listen_addr", &self.dot_listen_addr)
            .field("database_url", &"<redacted>")
            .field("global_database_url", &"<redacted>")
            .field("cloudflare_api_token", &"<redacted>")
            .field("cloudflare_zone_id", &self.cloudflare_zone_id)
            .field("region", &self.region)
            .field("subdomain_parent", &self.subdomain_parent)
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
            api_listen_addr: std::env::var("API_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            https_listen_addr: std::env::var("HTTPS_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8443".to_string()),
            dot_listen_addr: std::env::var("DOT_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8853".to_string()),
            database_url: required("DATABASE_URL")?,
            global_database_url: required("GLOBAL_DATABASE_URL")?,
            cloudflare_api_token: required("CLOUDFLARE_API_TOKEN")?,
            cloudflare_zone_id: required("CLOUDFLARE_ZONE_ID")?,
            region: required("INFORGE_DEPLOYMENT_REGION_SLUG")?,
            subdomain_parent: required("SUBDOMAIN_PARENT")?,
        })
    }

    /// Construct the fully-qualified domain name for an install's A record.
    ///
    /// `"happy-einstein"` → `"happy-einstein.my.wardnet.services"`
    #[must_use]
    pub fn install_fqdn(&self, name: &str) -> String {
        format!("{name}.{}", self.subdomain_parent)
    }

    /// Construct the FQDN for an install's ACME DNS-01 TXT record.
    ///
    /// `"happy-einstein"` → `"_acme-challenge.happy-einstein.my.wardnet.services"`
    #[must_use]
    pub fn acme_fqdn(&self, name: &str) -> String {
        format!("_acme-challenge.{name}.{}", self.subdomain_parent)
    }
}

#[cfg(test)]
mod tests;
