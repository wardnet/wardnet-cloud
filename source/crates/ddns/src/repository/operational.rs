use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::db::DbPools;

/// A network's **regional operational DNS state**.
///
/// Lives in the per-region DB, keyed by the Tenants-owned `network_id`. Created
/// lazily on the first IP report, so a network that has registered but never
/// reported an IP has no row (reads yield `None`).
#[derive(Debug, Clone)]
pub struct Operational {
    pub network_id: String,
    /// Last known public IPv4 address; `None` until the first IP report.
    pub ip: Option<String>,
    /// The FQDN the provisioner published the A record under (`<slug>.<parent>`);
    /// `None` until the network is provisioned. Stored so report-IP can update the
    /// A record in place and the ACME handler can derive `_acme-challenge.<slug>…`.
    pub fqdn: Option<String>,
    /// Cloudflare A-record ID; `None` until the provisioner's CAS claim sets it.
    pub cf_a_record_id: Option<String>,
    /// Cloudflare ACME DNS-01 TXT-record IDs (a per-user wildcard cert publishes
    /// more than one at once). Empty when no challenge is live.
    pub cf_acme_record_ids: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

/// Raw `PostgreSQL` row for `sqlx::query_as` mapping.
#[derive(sqlx::FromRow)]
struct OperationalRow {
    network_id: String,
    ip: Option<String>,
    fqdn: Option<String>,
    cf_a_record_id: Option<String>,
    cf_acme_record_ids: Vec<String>,
    updated_at: DateTime<Utc>,
}

impl From<OperationalRow> for Operational {
    fn from(r: OperationalRow) -> Self {
        Self {
            network_id: r.network_id,
            ip: r.ip,
            fqdn: r.fqdn,
            cf_a_record_id: r.cf_a_record_id,
            cf_acme_record_ids: r.cf_acme_record_ids,
            updated_at: r.updated_at,
        }
    }
}

/// Data access for the regional `operational` table.
#[async_trait]
pub trait OperationalRepository: Send + Sync {
    /// Fetch the operational row for `network_id` (the live DNS state), or `None`
    /// if the network has never reported an IP.
    async fn find_by_id(&self, network_id: &str) -> anyhow::Result<Option<Operational>>;

    /// Store the reported `ip`, creating the row on first report. Touches **only**
    /// `ip` (and `updated_at`) — never `fqdn` or `cf_a_record_id`, so a report racing
    /// the provisioner cannot clobber a concurrently-set A-record claim. This is the
    /// daemon's only write; it never creates a Cloudflare record (see docs/adr/0003).
    async fn record_ip(&self, network_id: &str, ip: &str, now: DateTime<Utc>)
    -> anyhow::Result<()>;

    /// **Compare-and-set** the A-record claim: store `fqdn` + `record_id` only if no
    /// A-record id is stored yet (`cf_a_record_id IS NULL`). Returns `false` when a
    /// peer replica already claimed it, so the provisioner can drop its duplicate.
    /// Requires the row to exist (the provisioner runs after an IP is reported).
    async fn claim_a_record(
        &self,
        network_id: &str,
        fqdn: &str,
        record_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool>;

    /// **Compare-and-set** the ACME TXT-record IDs: replace them only if the
    /// currently-stored list still equals `expected` (creating the row when
    /// `expected` is empty and none exists). Returns `false` when the stored list
    /// has changed underneath us — a concurrent ACME write — so the caller can
    /// surface a conflict instead of clobbering it.
    async fn cas_acme_records(
        &self,
        network_id: &str,
        expected: &[String],
        new_ids: &[String],
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool>;

    /// Delete a network's operational row (after the reaper tears DNS down).
    async fn delete(&self, network_id: &str) -> anyhow::Result<()>;
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

const OPERATIONAL_COLS: &str =
    "network_id, ip, fqdn, cf_a_record_id, cf_acme_record_ids, updated_at";

#[async_trait]
impl OperationalRepository for PgOperationalRepository {
    async fn find_by_id(&self, network_id: &str) -> anyhow::Result<Option<Operational>> {
        let sql = format!("SELECT {OPERATIONAL_COLS} FROM operational WHERE network_id = $1");
        let row = sqlx::query_as::<_, OperationalRow>(&sql)
            .bind(network_id)
            .fetch_optional(&self.pools.read)
            .await?;
        Ok(row.map(Into::into))
    }

    async fn record_ip(
        &self,
        network_id: &str,
        ip: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        // ip-only upsert: never write fqdn / cf_a_record_id, so this can't clobber
        // the provisioner's concurrently-set A-record claim.
        sqlx::query(
            "INSERT INTO operational (network_id, ip, updated_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (network_id)
             DO UPDATE SET ip = $2, updated_at = $3",
        )
        .bind(network_id)
        .bind(ip)
        .bind(now)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }

    async fn claim_a_record(
        &self,
        network_id: &str,
        fqdn: &str,
        record_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE operational SET fqdn = $2, cf_a_record_id = $3, updated_at = $4
             WHERE network_id = $1 AND cf_a_record_id IS NULL",
        )
        .bind(network_id)
        .bind(fqdn)
        .bind(record_id)
        .bind(now)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn cas_acme_records(
        &self,
        network_id: &str,
        expected: &[String],
        new_ids: &[String],
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        // (An empty `expected` means "no challenge currently live"; the INSERT path
        // also creates the row when none exists, matching the mock and avoiding a
        // CAS bypass.)
        let affected = if expected.is_empty() {
            sqlx::query(
                "INSERT INTO operational (network_id, cf_acme_record_ids, updated_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (network_id)
                 DO UPDATE SET cf_acme_record_ids = $2, updated_at = $3
                 WHERE operational.cf_acme_record_ids = '{}'",
            )
            .bind(network_id)
            .bind(new_ids)
            .bind(now)
            .execute(&self.pools.write)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE operational SET cf_acme_record_ids = $2, updated_at = $3
                 WHERE network_id = $1 AND cf_acme_record_ids = $4",
            )
            .bind(network_id)
            .bind(new_ids)
            .bind(now)
            .bind(expected)
            .execute(&self.pools.write)
            .await?
            .rows_affected()
        };
        Ok(affected > 0)
    }

    async fn delete(&self, network_id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM operational WHERE network_id = $1")
            .bind(network_id)
            .execute(&self.pools.write)
            .await?;
        Ok(())
    }
}
