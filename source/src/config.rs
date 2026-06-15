use base64::Engine as _;

/// Let's Encrypt production ACME directory.
const LE_PROD_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging ACME directory (untrusted certs, generous rate limits).
const LE_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Runtime configuration loaded from environment variables.
///
/// In production the inforge bootstrapper injects the deployment identity
/// (`INFORGE_DEPLOYMENT_*`) and all secrets (`DATABASE_URL`, the Cloudflare token,
/// `ENCRYPTION_KEY`, …) into the process environment. All required variables must
/// be present at startup; the process exits with a human-readable error if any are
/// missing. Optional variables fall back to documented defaults.
///
/// # Edge topology
///
/// The bridge sits behind a **transparent L4 reverse proxy** (nginx with PROXY
/// protocol v1) that maps the public privileged ports to the bridge's unprivileged
/// localhost ports:
///
/// | Public | Bridge | Purpose |
/// |---|---|---|
/// | `:80`  | [`Self::http01_listen_addr`] `127.0.0.1:8080` | ACME HTTP-01 responder + `/health` |
/// | `:443` | [`Self::tls_listen_addr`] `127.0.0.1:8443`   | SNI demux: terminate own FQDN / passthrough tenant tunnels |
/// | `:853` | [`Self::dot_listen_addr`] `127.0.0.1:8853`   | `DoT` passthrough to tenant tunnels |
///
/// The bridge terminates TLS for its **own** [`Self::fqdn`] (cert issued via ACME
/// HTTP-01) and passes every other SNI through to the home-Pi reverse tunnels.
///
/// # Two domains
///
/// [`Self::fqdn`] is the bridge's **own** host under the infra domain
/// (`…wardnet.network`) — it gets an HTTP-01 cert and needs no DNS edit. Tenant DDNS
/// is a *separate* concern: the bridge edits records under
/// [`Self::subdomain_parent`] (`my.wardnet.services`) via [`Self::cloudflare_zone_id`].
#[derive(Clone)]
pub struct Config {
    /// Loopback address for the ACME HTTP-01 responder + `/health`. Default
    /// `127.0.0.1:8080` (public `:80` via the L4 proxy).
    pub http01_listen_addr: String,

    /// Loopback address for the SNI-demuxing TLS listener. Default `127.0.0.1:8443`
    /// (public `:443` via the L4 proxy).
    pub tls_listen_addr: String,

    /// Loopback address for the DNS-over-TLS passthrough listener. Default
    /// `127.0.0.1:8853` (public `:853` via the L4 proxy).
    pub dot_listen_addr: String,

    /// `PostgreSQL` DSN for this bridge's **regional** install DB.
    pub database_url: String,

    /// `PostgreSQL` DSN for the **global naming authority** (shared across the
    /// fleet; holds the `names` allocation lock).
    pub global_database_url: String,

    /// Cloudflare API token scoped to DNS:Edit on [`Self::cloudflare_zone_id`].
    pub cloudflare_api_token: String,

    /// Cloudflare zone ID that owns [`Self::subdomain_parent`] (the `wardnet.services`
    /// tenant zone — distinct from the bridge's own `wardnet.network` FQDN).
    pub cloudflare_zone_id: String,

    /// Short region slug, e.g. `"use1"` (from `INFORGE_DEPLOYMENT_REGION_SLUG`).
    /// Selects which region this bridge owns; returned to the Pi at registration.
    pub region: String,

    /// DNS parent under which **tenant** subdomains are created,
    /// e.g. `"my.wardnet.services"`.
    pub subdomain_parent: String,

    /// The bridge's **own** fully-qualified hostname (from `INFORGE_DEPLOYMENT_FQDN`),
    /// e.g. `"bridge.svc.prod.use1.wardnet.network"`. TLS connections with this SNI
    /// are terminated locally and served by the API; all others are tenant traffic.
    pub fqdn: String,

    /// ACME directory URL for the bridge's own certificate. Let's Encrypt
    /// **production** when the deployment environment is `prod`, otherwise **staging**
    /// (so redeploys/crash-loops don't burn the production rate limit).
    pub acme_directory_url: String,

    /// 32-byte AES-256-GCM key for sealing cert/account material at rest in Postgres
    /// (base64 in `ENCRYPTION_KEY`). Identical across all hosts in a region.
    pub encryption_key: [u8; 32],
}

impl std::fmt::Debug for Config {
    /// Redacts secret-bearing fields so the config can be logged safely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("http01_listen_addr", &self.http01_listen_addr)
            .field("tls_listen_addr", &self.tls_listen_addr)
            .field("dot_listen_addr", &self.dot_listen_addr)
            .field("database_url", &"<redacted>")
            .field("global_database_url", &"<redacted>")
            .field("cloudflare_api_token", &"<redacted>")
            .field("cloudflare_zone_id", &self.cloudflare_zone_id)
            .field("region", &self.region)
            .field("subdomain_parent", &self.subdomain_parent)
            .field("fqdn", &self.fqdn)
            .field("acme_directory_url", &self.acme_directory_url)
            .field("encryption_key", &"<redacted>")
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    /// Returns an error if any required variable is absent or malformed (e.g. an
    /// `ENCRYPTION_KEY` that is not base64 of exactly 32 bytes).
    pub fn from_env() -> anyhow::Result<Self> {
        // Deployment environment selects the ACME directory. Unknown/absent ⇒
        // staging, so we never accidentally hammer the production rate limit.
        let environment = std::env::var("INFORGE_DEPLOYMENT_ENVIRONMENT")
            .unwrap_or_else(|_| "staging".to_string());
        let acme_directory_url = std::env::var("ACME_DIRECTORY_URL").unwrap_or_else(|_| {
            if environment == "prod" {
                LE_PROD_DIRECTORY.to_string()
            } else {
                LE_STAGING_DIRECTORY.to_string()
            }
        });

        Ok(Self {
            http01_listen_addr: std::env::var("HTTP01_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            tls_listen_addr: std::env::var("TLS_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8443".to_string()),
            dot_listen_addr: std::env::var("DOT_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8853".to_string()),
            database_url: required("DATABASE_URL")?,
            global_database_url: required("GLOBAL_DATABASE_URL")?,
            cloudflare_api_token: required("CLOUDFLARE_API_TOKEN")?,
            cloudflare_zone_id: required("CLOUDFLARE_ZONE_ID")?,
            region: required("INFORGE_DEPLOYMENT_REGION_SLUG")?,
            subdomain_parent: required("SUBDOMAIN_PARENT")?,
            fqdn: required("INFORGE_DEPLOYMENT_FQDN")?,
            acme_directory_url,
            encryption_key: encryption_key("ENCRYPTION_KEY")?,
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

/// Load the Tenants JWT signing key (`EdDSA` PKCS#8 PEM) from the file at
/// `JWT_SIGNING_KEY_PATH`.
///
/// Deliberately **not** a [`Config`] field: the private signing key is consumed
/// once at startup to build the JWT signer and must not live in the long-lived,
/// `Clone`d config that is shared into every request handler via `AppState`. The
/// caller builds the signer and lets this `String` drop.
///
/// # Errors
/// Returns an error if `JWT_SIGNING_KEY_PATH` is unset or the file is unreadable.
pub fn load_jwt_signing_key_pem() -> anyhow::Result<String> {
    read_secret_file("JWT_SIGNING_KEY_PATH")
}

/// Load the Tenants JWT **verify** key (`EdDSA` SPKI public-key PEM) from the file
/// at `JWT_VERIFY_KEY_PATH`.
///
/// Consumed once at startup to build the JWT [`Verifier`](crate::token::Verifier);
/// like the signing key it is not seated in [`Config`] (the verifier holds the
/// parsed key). The public key is not secret, but keeping the two key loaders
/// symmetric keeps the startup flow uniform.
///
/// # Errors
/// Returns an error if `JWT_VERIFY_KEY_PATH` is unset or the file is unreadable.
pub fn load_jwt_verify_key_pem() -> anyhow::Result<String> {
    read_secret_file("JWT_VERIFY_KEY_PATH")
}

fn required(key: &str) -> anyhow::Result<String> {
    std::env::var(key)
        .map_err(|_| anyhow::anyhow!("required environment variable `{key}` is not set"))
}

/// Read a secret file whose path is given by the `path_var` environment variable.
///
/// INFORGE projects secrets (PEM keys, …) onto tmpfs and passes only the path in
/// the environment — the material itself never appears in an env var.
fn read_secret_file(path_var: &str) -> anyhow::Result<String> {
    let path = required(path_var)?;
    std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read secret file at `{path_var}` ({path}): {e}"))
}

/// Read and decode a base64 32-byte AES-256 key from `key`.
fn encryption_key(key: &str) -> anyhow::Result<[u8; 32]> {
    let raw = required(key)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| anyhow::anyhow!("`{key}` is not valid base64: {e}"))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("`{key}` must decode to exactly 32 bytes, got {}", v.len())
    })
}

#[cfg(test)]
mod tests;
