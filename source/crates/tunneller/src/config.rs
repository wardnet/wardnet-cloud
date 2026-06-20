use wardnet_common::config::required;

/// Runtime configuration loaded from environment variables.
///
/// In production the inforge bootstrapper injects the deployment identity
/// (`INFORGE_DEPLOYMENT_*`) and all secrets (`DATABASE_URL`, the mesh PEM paths)
/// into the process environment. All required variables must be present at startup;
/// the process exits with a human-readable error if any are missing. Optional
/// variables fall back to documented defaults.
///
/// # Edge topology
///
/// Public TLS is terminated by an **inforge-injected nginx sidecar**; this process
/// speaks plain HTTP for its control-plane API and pure **L4 passthrough** for
/// tenant tunnels. nginx fronts every public listener with a transparent L4 proxy
/// (PROXY protocol v1) mapping public privileged ports to these unprivileged
/// localhost ports:
///
/// | Public | Process | Purpose |
/// |---|---|---|
/// | `:80`  | [`Self::api_listen_addr`] `127.0.0.1:8080` | plain-HTTP daemon API (`GET /v1/tunnel`) + `/v1/health` |
/// | `:443` | [`Self::https_listen_addr`] `127.0.0.1:8443` | SNI passthrough to tenant tunnels (port 443) |
/// | `:853` | [`Self::dot_listen_addr`] `127.0.0.1:8853` | `DoT` passthrough to tenant tunnels (port 853) |
///
/// The **inter-node forward** listener ([`Self::forward_listen_addr`]) is a private
/// mesh-mTLS port — *not* nginx-fronted — that peer Tunneller nodes dial directly.
#[derive(Clone)]
pub struct Config {
    /// Loopback address for the plain-HTTP daemon API + `/health`. Default
    /// `127.0.0.1:8080` (public `:80` via nginx).
    pub api_listen_addr: String,

    /// Loopback address for the SNI-passthrough HTTPS listener. Default
    /// `127.0.0.1:8443` (public `:443` via nginx); forwards to tenant tunnels on 443.
    pub https_listen_addr: String,

    /// Loopback address for the DNS-over-TLS passthrough listener. Default
    /// `127.0.0.1:8853` (public `:853` via nginx); forwards to tenant tunnels on 853.
    pub dot_listen_addr: String,

    /// `PostgreSQL` DSN for this region's **regional** Tunneller DB (the
    /// `tunnel_routes` map). Each region owns its own pool.
    pub database_url: String,

    /// Base URL of the Tenants mesh-mTLS listener, e.g. `https://tenants.mesh:9443`
    /// (no trailing slash). The routing policy reads networks/tenants from it.
    pub mesh_base_url: String,

    /// Mesh trust-bundle PEM path — anchors for both the outbound mesh client and the
    /// inbound inter-node forward listener's client-cert verifier.
    pub trust_bundle_path: String,
    /// This node's mesh leaf certificate PEM path.
    pub leaf_cert_path: String,
    /// This node's mesh leaf private-key PEM path.
    pub leaf_key_path: String,

    /// Private bind address for the inter-node forward listener (mesh mTLS). Default
    /// `0.0.0.0:9444`.
    pub forward_listen_addr: String,
    /// The address peers dial to reach **this** node's forward listener — the
    /// `node_addr` written into every `tunnel_routes` row this node owns, e.g.
    /// `node-use1-0.tunneller.mesh:9444`.
    pub forward_advertise_addr: String,

    /// Short region slug, e.g. `"use1"` (from `INFORGE_DEPLOYMENT_REGION_SLUG`).
    pub region: String,

    /// DNS parent under which **tenant** subdomains live, e.g.
    /// `"my.wardnet.services"`. The SNI demuxer strips it to recover the slug.
    pub subdomain_parent: String,

    /// Interval between abort-reconcile + heartbeat passes over this node's own
    /// `tunnel_routes` rows. Default `30`.
    pub reconcile_interval_secs: u64,
    /// Max extra jitter (seconds) added to each reconcile interval to de-sync nodes.
    /// Default `5`.
    pub reconcile_jitter_secs: u64,
    /// A route row is considered orphaned once its `last_seen` is older than this
    /// (the owning node crashed without deleting it). Default `120`.
    pub route_ttl_secs: u64,
    /// Interval between TTL-reaper passes that purge orphaned route rows. Default
    /// `60`.
    pub ttl_reaper_interval_secs: u64,
}

impl std::fmt::Debug for Config {
    /// Redacts secret-bearing fields so the config can be logged safely.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_listen_addr", &self.api_listen_addr)
            .field("https_listen_addr", &self.https_listen_addr)
            .field("dot_listen_addr", &self.dot_listen_addr)
            .field("database_url", &"<redacted>")
            .field("mesh_base_url", &self.mesh_base_url)
            .field("trust_bundle_path", &self.trust_bundle_path)
            .field("leaf_cert_path", &self.leaf_cert_path)
            .field("leaf_key_path", &"<redacted>")
            .field("forward_listen_addr", &self.forward_listen_addr)
            .field("forward_advertise_addr", &self.forward_advertise_addr)
            .field("region", &self.region)
            .field("subdomain_parent", &self.subdomain_parent)
            .field("reconcile_interval_secs", &self.reconcile_interval_secs)
            .field("reconcile_jitter_secs", &self.reconcile_jitter_secs)
            .field("route_ttl_secs", &self.route_ttl_secs)
            .field("ttl_reaper_interval_secs", &self.ttl_reaper_interval_secs)
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    /// Returns an error if any required variable is absent or an optional numeric
    /// override fails to parse.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            api_listen_addr: std::env::var("API_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            https_listen_addr: std::env::var("HTTPS_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8443".to_string()),
            dot_listen_addr: std::env::var("DOT_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8853".to_string()),
            database_url: required("DATABASE_URL")?,
            mesh_base_url: required("MESH_BASE_URL")?,
            trust_bundle_path: required("MTLS_TRUST_BUNDLE_PATH")?,
            leaf_cert_path: required("MTLS_LEAF_CERT_PATH")?,
            leaf_key_path: required("MTLS_LEAF_KEY_PATH")?,
            forward_listen_addr: std::env::var("FORWARD_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:9444".to_string()),
            forward_advertise_addr: required("FORWARD_ADVERTISE_ADDR")?,
            region: required("INFORGE_DEPLOYMENT_REGION_SLUG")?,
            subdomain_parent: required("SUBDOMAIN_PARENT")?,
            reconcile_interval_secs: parse_secs("RECONCILE_INTERVAL_SECS", 30)?,
            reconcile_jitter_secs: parse_secs("RECONCILE_JITTER_SECS", 5)?,
            route_ttl_secs: parse_secs("ROUTE_TTL_SECS", 120)?,
            ttl_reaper_interval_secs: parse_secs("TTL_REAPER_INTERVAL_SECS", 60)?,
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
