//! The **network** — one wardnet network: a globally-unique vanity slug plus a
//! `provisioning_state` lifecycle, owned by a tenant. Desired state only; the
//! actual DNS records live in the regional DDNS DB.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

// The lifecycle enum is part of the shared API contract; it doubles as the
// DB-domain enum here (its `as_str` / `from_db` helpers travel with it).
pub use wardnet_common::contract::ProvisioningState;

use crate::db::DbPools;
use crate::repository::daemon::Daemon;

/// A network.
#[derive(Debug, Clone)]
pub struct Network {
    pub id: String,
    pub tenant_id: String,
    pub slug: String,
    pub display_name: String,
    pub region: String,
    pub provisioning_state: ProvisioningState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct NetworkRow {
    id: String,
    tenant_id: String,
    slug: String,
    display_name: String,
    region: String,
    provisioning_state: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<NetworkRow> for Network {
    type Error = anyhow::Error;
    fn try_from(r: NetworkRow) -> anyhow::Result<Self> {
        Ok(Self {
            id: r.id,
            tenant_id: r.tenant_id,
            slug: r.slug,
            display_name: r.display_name,
            region: r.region,
            provisioning_state: ProvisioningState::from_db(&r.provisioning_state)?,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
    }
}

const NETWORK_COLS: &str =
    "id, tenant_id, slug, display_name, region, provisioning_state, created_at, updated_at";

/// Outcome of [`NetworkRepository::register_network`] — the atomic network+daemon
/// creation done at the daemon's register-network call.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterNetworkOutcome {
    /// Network + daemon created.
    Created,
    /// The vanity slug is already taken.
    SlugTaken,
    /// The tenant is at its `max_networks` limit.
    NetworkLimit,
    /// The tenant is at its `max_daemons` limit.
    DaemonLimit,
    /// A daemon with this public key already exists.
    DaemonExists,
}

/// Data access for the `networks` table (plus the network+daemon creation saga).
#[async_trait]
pub trait NetworkRepository: Send + Sync {
    /// Fetch a network by id.
    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Network>>;
    /// Fetch a network by its (globally unique) slug.
    async fn find_by_slug(&self, slug: &str) -> anyhow::Result<Option<Network>>;
    /// All networks of a tenant.
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Network>>;
    /// Count a tenant's networks (any state) — the `max_networks` check input.
    async fn count_by_tenant(&self, tenant_id: &str) -> anyhow::Result<i64>;

    /// **Atomic** register-network: re-check the tenant's `max_networks` /
    /// `max_daemons` limits, insert `network` (slug-unique) and `daemon`
    /// (pubkey-unique), and consume the daemon's `pending_enrollments` row — all in
    /// one transaction. The outcome distinguishes every rejection cause.
    async fn register_network(
        &self,
        network: &Network,
        daemon: &Daemon,
        max_networks: u32,
        max_daemons: u32,
    ) -> anyhow::Result<RegisterNetworkOutcome>;

    /// Cursor page of networks in `state` for `region`, ids strictly greater than
    /// `after_id`, ascending, capped at `limit`. Drives the DDNS provisioner/reaper.
    async fn list_for_reconcile(
        &self,
        state: ProvisioningState,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<Network>>;

    /// `provisioning → active` (provisioner). `false` if not in `provisioning`.
    async fn mark_active(&self, id: &str) -> anyhow::Result<bool>;
    /// `deprovisioning →` delete row (reaper). `false` if not in `deprovisioning`.
    async fn delete_if_deprovisioning(&self, id: &str) -> anyhow::Result<bool>;
    /// `{active, provisioning} → deprovisioning` for one network. `false` otherwise.
    async fn set_deprovisioning(&self, id: &str) -> anyhow::Result<bool>;
    /// Cascade `{active, provisioning} → deprovisioning` for all of a tenant's
    /// networks (subscription cancel). Returns the number transitioned.
    async fn set_deprovisioning_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64>;
}

/// `PostgreSQL`-backed [`NetworkRepository`].
pub struct PgNetworkRepository {
    pools: DbPools,
}

impl PgNetworkRepository {
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
impl NetworkRepository for PgNetworkRepository {
    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Network>> {
        let row = sqlx::query_as::<_, NetworkRow>(&format!(
            "SELECT {NETWORK_COLS} FROM networks WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pools.read)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn find_by_slug(&self, slug: &str) -> anyhow::Result<Option<Network>> {
        let row = sqlx::query_as::<_, NetworkRow>(&format!(
            "SELECT {NETWORK_COLS} FROM networks WHERE slug = $1"
        ))
        .bind(slug)
        .fetch_optional(&self.pools.read)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Network>> {
        let rows = sqlx::query_as::<_, NetworkRow>(&format!(
            "SELECT {NETWORK_COLS} FROM networks WHERE tenant_id = $1 ORDER BY created_at"
        ))
        .bind(tenant_id)
        .fetch_all(&self.pools.read)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn count_by_tenant(&self, tenant_id: &str) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM networks WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&self.pools.read)
            .await?;
        Ok(count)
    }

    async fn register_network(
        &self,
        network: &Network,
        daemon: &Daemon,
        max_networks: u32,
        max_daemons: u32,
    ) -> anyhow::Result<RegisterNetworkOutcome> {
        let mut tx = self.pools.write.begin().await?;

        // Limit checks inside the tx so they are consistent with the inserts.
        let network_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM networks WHERE tenant_id = $1")
                .bind(&network.tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        if network_count >= i64::from(max_networks) {
            tx.rollback().await?;
            return Ok(RegisterNetworkOutcome::NetworkLimit);
        }
        let daemon_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM daemons WHERE tenant_id = $1")
                .bind(&network.tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        if daemon_count >= i64::from(max_daemons) {
            tx.rollback().await?;
            return Ok(RegisterNetworkOutcome::DaemonLimit);
        }

        let network_insert = sqlx::query(
            "INSERT INTO networks (id, tenant_id, slug, display_name, region, provisioning_state, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (slug) DO NOTHING",
        )
        .bind(&network.id)
        .bind(&network.tenant_id)
        .bind(&network.slug)
        .bind(&network.display_name)
        .bind(&network.region)
        .bind(network.provisioning_state.as_str())
        .bind(network.created_at)
        .bind(network.updated_at)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if network_insert == 0 {
            tx.rollback().await?;
            return Ok(RegisterNetworkOutcome::SlugTaken);
        }

        let daemon_insert = sqlx::query(
            "INSERT INTO daemons (id, tenant_id, network_id, public_key, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (public_key) DO NOTHING",
        )
        .bind(&daemon.id)
        .bind(&daemon.tenant_id)
        .bind(&network.id)
        .bind(&daemon.public_key)
        .bind(daemon.created_at)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if daemon_insert == 0 {
            tx.rollback().await?;
            return Ok(RegisterNetworkOutcome::DaemonExists);
        }

        // The pending binding has served its purpose; drop it now.
        sqlx::query("DELETE FROM pending_enrollments WHERE public_key = $1")
            .bind(&daemon.public_key)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(RegisterNetworkOutcome::Created)
    }

    async fn list_for_reconcile(
        &self,
        state: ProvisioningState,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<Network>> {
        let rows = sqlx::query_as::<_, NetworkRow>(&format!(
            "SELECT {NETWORK_COLS} FROM networks \
             WHERE provisioning_state = $1 AND region = $2 \
               AND ($3::text IS NULL OR id > $3) \
             ORDER BY id LIMIT $4"
        ))
        .bind(state.as_str())
        .bind(region)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pools.read)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn mark_active(&self, id: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE networks SET provisioning_state = 'active', updated_at = $2 \
             WHERE id = $1 AND provisioning_state = 'provisioning'",
        )
        .bind(id)
        .bind(Utc::now())
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn delete_if_deprovisioning(&self, id: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "DELETE FROM networks WHERE id = $1 AND provisioning_state = 'deprovisioning'",
        )
        .bind(id)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn set_deprovisioning(&self, id: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE networks SET provisioning_state = 'deprovisioning', updated_at = $2 \
             WHERE id = $1 AND provisioning_state IN ('active', 'provisioning')",
        )
        .bind(id)
        .bind(Utc::now())
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn set_deprovisioning_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        let affected = sqlx::query(
            "UPDATE networks SET provisioning_state = 'deprovisioning', updated_at = $2 \
             WHERE tenant_id = $1 AND provisioning_state IN ('active', 'provisioning')",
        )
        .bind(tenant_id)
        .bind(Utc::now())
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected)
    }
}
