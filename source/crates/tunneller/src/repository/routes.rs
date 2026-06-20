//! The **tunnel routes** table — the regional `slug → node_addr` ownership map.
//!
//! Each node writes its ownership of a slug on tunnel connect (`upsert`) and deletes
//! it on disconnect (`delete`, guarded to its own `node_addr`). The owning node
//! refreshes `last_seen` (`touch`) each reconcile pass; a TTL reaper (`reap_expired`)
//! purges rows orphaned by a node that crashed without deleting.
//!
//! The table is a routing **hint**, not the source of truth: each node's in-memory
//! [`TunnelRegistry`](crate::tunnel::TunnelRegistry) is authoritative, so a forward
//! to a `node_addr` whose registry no longer holds the slug fails closed.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::db::DbPools;

/// A row of the `tunnel_routes` table — one live (or recently live) tunnel.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TunnelRoute {
    /// Vanity slug (primary key — globally unique, the SNI routing key).
    pub slug: String,
    /// Address peers dial to reach the node that owns this tunnel.
    pub node_addr: String,
    /// The network the tunnel serves (the daemon's `net` claim).
    pub network_id: String,
    /// The tenant that owns the network (denormalized for the abort reaper).
    pub tenant_id: String,
    /// Last heartbeat from the owning node.
    pub last_seen: DateTime<Utc>,
}

/// Data access for the `tunnel_routes` table.
#[async_trait]
pub trait TunnelRouteRepository: Send + Sync {
    /// Claim (or re-claim) `slug` for `node_addr`, stamping `last_seen = now()`.
    /// A reconnect that lands on a different node moves the row to the new owner.
    async fn upsert(
        &self,
        slug: &str,
        node_addr: &str,
        network_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<()>;

    /// Delete `slug`'s row **iff** it is owned by `node_addr` (so a stale handler on
    /// another node cannot delete the live owner's row). Returns whether a row was
    /// removed.
    async fn delete(&self, slug: &str, node_addr: &str) -> anyhow::Result<bool>;

    /// Look up the current owner of `slug`, if any.
    async fn find_by_slug(&self, slug: &str) -> anyhow::Result<Option<TunnelRoute>>;

    /// Every row this node currently owns — the abort reaper's work list.
    async fn list_owned(&self, node_addr: &str) -> anyhow::Result<Vec<TunnelRoute>>;

    /// Refresh `last_seen = now()` for `slug` **iff** owned by `node_addr`. Returns
    /// whether a row was touched.
    async fn touch(&self, slug: &str, node_addr: &str) -> anyhow::Result<bool>;

    /// Delete every row whose `last_seen` is older than `deadline` (orphaned by a
    /// crashed node). Returns the number purged.
    async fn reap_expired(&self, deadline: DateTime<Utc>) -> anyhow::Result<u64>;
}

const ROUTE_COLS: &str = "slug, node_addr, network_id, tenant_id, last_seen";

const UPSERT_SQL: &str = "INSERT INTO tunnel_routes (slug, node_addr, network_id, tenant_id, last_seen) \
     VALUES ($1, $2, $3, $4, $5) \
     ON CONFLICT (slug) DO UPDATE SET \
       node_addr = EXCLUDED.node_addr, \
       network_id = EXCLUDED.network_id, \
       tenant_id = EXCLUDED.tenant_id, \
       last_seen = EXCLUDED.last_seen";

const DELETE_SQL: &str = "DELETE FROM tunnel_routes WHERE slug = $1 AND node_addr = $2";

const TOUCH_SQL: &str =
    "UPDATE tunnel_routes SET last_seen = $3 WHERE slug = $1 AND node_addr = $2";

const REAP_SQL: &str = "DELETE FROM tunnel_routes WHERE last_seen < $1";

/// `PostgreSQL`-backed [`TunnelRouteRepository`].
pub struct PgTunnelRouteRepository {
    pools: DbPools,
}

impl PgTunnelRouteRepository {
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

#[async_trait]
impl TunnelRouteRepository for PgTunnelRouteRepository {
    async fn upsert(
        &self,
        slug: &str,
        node_addr: &str,
        network_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(UPSERT_SQL)
            .bind(slug)
            .bind(node_addr)
            .bind(network_id)
            .bind(tenant_id)
            .bind(Utc::now())
            .execute(&self.pools.write)
            .await?;
        Ok(())
    }

    async fn delete(&self, slug: &str, node_addr: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(DELETE_SQL)
            .bind(slug)
            .bind(node_addr)
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    async fn find_by_slug(&self, slug: &str) -> anyhow::Result<Option<TunnelRoute>> {
        let row = sqlx::query_as::<_, TunnelRoute>(sqlx::AssertSqlSafe(format!(
            "SELECT {ROUTE_COLS} FROM tunnel_routes WHERE slug = $1"
        )))
        .bind(slug)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row)
    }

    async fn list_owned(&self, node_addr: &str) -> anyhow::Result<Vec<TunnelRoute>> {
        let rows = sqlx::query_as::<_, TunnelRoute>(sqlx::AssertSqlSafe(format!(
            "SELECT {ROUTE_COLS} FROM tunnel_routes WHERE node_addr = $1 ORDER BY slug"
        )))
        .bind(node_addr)
        .fetch_all(&self.pools.read)
        .await?;
        Ok(rows)
    }

    async fn touch(&self, slug: &str, node_addr: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(TOUCH_SQL)
            .bind(slug)
            .bind(node_addr)
            .bind(Utc::now())
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    async fn reap_expired(&self, deadline: DateTime<Utc>) -> anyhow::Result<u64> {
        let affected = sqlx::query(REAP_SQL)
            .bind(deadline)
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(affected)
    }
}
