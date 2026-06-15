use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::db::DbPools;

/// An install's **regional operational DNS state**.
///
/// Lives in the per-region DB. Created lazily on the first IP publish, so a
/// registered-but-not-yet-active install has no row (reads yield `None`).
#[derive(Debug, Clone)]
pub struct Operational {
    pub install_id: String,
    /// Last known public IPv4 address; `None` until the first IP publish.
    pub ip: Option<String>,
    /// Cloudflare A-record ID; `None` until created.
    pub cf_a_record_id: Option<String>,
    /// Cloudflare ACME DNS-01 TXT-record IDs (a per-user wildcard cert publishes
    /// more than one at once). Empty when no challenge is live.
    pub cf_acme_record_ids: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

/// Raw `PostgreSQL` row for `sqlx::query_as` mapping.
#[derive(sqlx::FromRow)]
struct OperationalRow {
    install_id: String,
    ip: Option<String>,
    cf_a_record_id: Option<String>,
    cf_acme_record_ids: Vec<String>,
    updated_at: DateTime<Utc>,
}

impl From<OperationalRow> for Operational {
    fn from(r: OperationalRow) -> Self {
        Self {
            install_id: r.install_id,
            ip: r.ip,
            cf_a_record_id: r.cf_a_record_id,
            cf_acme_record_ids: r.cf_acme_record_ids,
            updated_at: r.updated_at,
        }
    }
}

/// Data access for the regional `operational` table.
#[async_trait]
pub trait OperationalRepository: Send + Sync {
    /// Fetch the operational row for `install_id` (the live DNS state), or `None`
    /// if the install has never published any.
    async fn find_by_id(&self, install_id: &str) -> anyhow::Result<Option<Operational>>;

    /// Upsert the A-record state (creates the row on first publish). Leaves the
    /// ACME record list untouched.
    async fn upsert_ip(
        &self,
        install_id: &str,
        ip: &str,
        cf_a_record_id: &str,
        updated_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;

    /// **Compare-and-set** the ACME TXT-record IDs: replace them only if the
    /// currently-stored list still equals `expected` (creating the row when
    /// `expected` is empty and none exists). Returns `false` when the stored list
    /// has changed underneath us — a concurrent ACME write — so the caller can
    /// surface a conflict instead of clobbering it.
    async fn cas_acme_records(
        &self,
        install_id: &str,
        expected: &[String],
        new_ids: &[String],
        updated_at: DateTime<Utc>,
    ) -> anyhow::Result<bool>;

    /// Delete an install's operational row (deregistration).
    async fn delete(&self, install_id: &str) -> anyhow::Result<()>;
}

/// PostgreSQL-backed [`OperationalRepository`] against the regional pool.
pub struct PgOperationalRepository {
    pools: DbPools,
}

impl PgOperationalRepository {
    /// Create a repository backed by a single pool (tests).
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pools: DbPools::single(pool),
        }
    }

    /// Create a repository with split reader / writer pools.
    #[must_use]
    pub fn new_pools(pools: DbPools) -> Self {
        Self { pools }
    }
}

#[async_trait]
impl OperationalRepository for PgOperationalRepository {
    async fn find_by_id(&self, install_id: &str) -> anyhow::Result<Option<Operational>> {
        let row = sqlx::query_as::<_, OperationalRow>(
            "SELECT install_id, ip, cf_a_record_id, cf_acme_record_ids, updated_at \
             FROM operational WHERE install_id = $1",
        )
        .bind(install_id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn upsert_ip(
        &self,
        install_id: &str,
        ip: &str,
        cf_a_record_id: &str,
        updated_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO operational (install_id, ip, cf_a_record_id, cf_acme_record_ids, updated_at)
             VALUES ($1, $2, $3, '{}', $4)
             ON CONFLICT (install_id)
             DO UPDATE SET ip = $2, cf_a_record_id = $3, updated_at = $4",
        )
        .bind(install_id)
        .bind(ip)
        .bind(cf_a_record_id)
        .bind(updated_at)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }

    async fn cas_acme_records(
        &self,
        install_id: &str,
        expected: &[String],
        new_ids: &[String],
        updated_at: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        // Only an empty `expected` may create the row (a fresh read of an absent
        // row yields `[]`). With a non-empty `expected` the row MUST already exist,
        // so a plain UPDATE that misses an absent or changed row is a CAS miss —
        // never a silent INSERT. (This keeps the absent-row + non-empty-expected
        // case a miss, matching the mock and avoiding a CAS bypass.)
        let affected = if expected.is_empty() {
            sqlx::query(
                "INSERT INTO operational (install_id, cf_acme_record_ids, updated_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (install_id)
                 DO UPDATE SET cf_acme_record_ids = $2, updated_at = $3
                 WHERE operational.cf_acme_record_ids = '{}'",
            )
            .bind(install_id)
            .bind(new_ids)
            .bind(updated_at)
            .execute(&self.pools.write)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE operational SET cf_acme_record_ids = $2, updated_at = $3
                 WHERE install_id = $1 AND cf_acme_record_ids = $4",
            )
            .bind(install_id)
            .bind(new_ids)
            .bind(updated_at)
            .bind(expected)
            .execute(&self.pools.write)
            .await?
            .rows_affected()
        };
        Ok(affected > 0)
    }

    async fn delete(&self, install_id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM operational WHERE install_id = $1")
            .bind(install_id)
            .execute(&self.pools.write)
            .await?;
        Ok(())
    }
}
