//! The **daemon** — a device bound to a network, holding an Ed25519 keypair. A
//! network has 1..N daemons (active/active). The row is created at register-network
//! (see [`NetworkRepository::register_network`](crate::repository::NetworkRepository::register_network));
//! this repository serves the reads (JWT issue lookup, management listings).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::db::DbPools;

/// A daemon binding.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Daemon {
    pub id: String,
    pub tenant_id: String,
    pub network_id: String,
    /// Standard-base64 of the daemon's 32-byte Ed25519 public key (the `cnf` value).
    pub public_key: String,
    pub created_at: DateTime<Utc>,
}

/// Data access for the `daemons` table.
#[async_trait]
pub trait DaemonRepository: Send + Sync {
    /// Find a daemon by its public key — the JWT-issue lookup that decides the
    /// token's network scope.
    async fn find_by_public_key(&self, public_key: &str) -> anyhow::Result<Option<Daemon>>;
    /// All daemons of a tenant.
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Daemon>>;
    /// All daemons of a network.
    async fn list_by_network(&self, network_id: &str) -> anyhow::Result<Vec<Daemon>>;
}

/// `PostgreSQL`-backed [`DaemonRepository`].
pub struct PgDaemonRepository {
    pools: DbPools,
}

impl PgDaemonRepository {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pools: DbPools::single(pool),
        }
    }

    #[must_use]
    pub fn new_pools(pools: DbPools) -> Self {
        Self { pools }
    }
}

const DAEMON_COLS: &str = "id, tenant_id, network_id, public_key, created_at";

#[async_trait]
impl DaemonRepository for PgDaemonRepository {
    async fn find_by_public_key(&self, public_key: &str) -> anyhow::Result<Option<Daemon>> {
        let row = sqlx::query_as::<_, Daemon>(&format!(
            "SELECT {DAEMON_COLS} FROM daemons WHERE public_key = $1"
        ))
        .bind(public_key)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row)
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Daemon>> {
        let rows = sqlx::query_as::<_, Daemon>(&format!(
            "SELECT {DAEMON_COLS} FROM daemons WHERE tenant_id = $1 ORDER BY created_at"
        ))
        .bind(tenant_id)
        .fetch_all(&self.pools.read)
        .await?;
        Ok(rows)
    }

    async fn list_by_network(&self, network_id: &str) -> anyhow::Result<Vec<Daemon>> {
        let rows = sqlx::query_as::<_, Daemon>(&format!(
            "SELECT {DAEMON_COLS} FROM daemons WHERE network_id = $1 ORDER BY created_at"
        ))
        .bind(network_id)
        .fetch_all(&self.pools.read)
        .await?;
        Ok(rows)
    }
}
