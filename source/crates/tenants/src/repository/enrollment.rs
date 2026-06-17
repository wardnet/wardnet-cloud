//! Enrollment artifacts: the one-time **code** (issued at signup / add-daemon,
//! burned at enroll) and the TTL'd **pending binding** (pubkey↔tenant) that lets a
//! not-yet-registered daemon authenticate. Also the per-IP rate-limit log for the
//! public signup-code endpoint.
//!
//! The [`enroll`](EnrollmentRepository::enroll) saga spans several tables
//! (`enrollment_codes`, `tenants`, `pending_enrollments`, plus a `daemons` count),
//! so it lives here as one transaction — mirroring the single-transaction
//! registration pattern the prior identity authority used.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::types::Json;

use crate::db::DbPools;
use crate::repository::tenant::Entitlement;

/// Outcome of the [`enroll`](EnrollmentRepository::enroll) saga.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// The daemon is bound to `tenant_id` via a fresh pending record.
    Enrolled { tenant_id: String },
    /// The code is unknown, expired, or already used.
    BadCode,
    /// The (existing) tenant is already at its `max_daemons` limit.
    DaemonLimit,
}

/// Data access for the enrollment tables.
#[async_trait]
pub trait EnrollmentRepository: Send + Sync {
    /// Persist a one-time code. `tenant_id` is `None` for a new-signup code (enroll
    /// then creates the tenant) or `Some` for an add-daemon code.
    async fn issue_code(
        &self,
        code_hash: &str,
        email: &str,
        tenant_id: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;

    /// The enroll saga (one transaction): validate + **burn** the code; resolve the
    /// tenant (create with `default_entitlement` for a new-signup code, else the
    /// code's tenant / the existing tenant for that email); enforce `max_daemons`;
    /// upsert the TTL'd pending pubkey↔tenant binding. `new_tenant_id` is used only
    /// when a tenant must be created.
    async fn enroll(
        &self,
        code_hash: &str,
        public_key: &str,
        new_tenant_id: &str,
        default_entitlement: Entitlement,
        now: DateTime<Utc>,
        pending_ttl_secs: i64,
    ) -> anyhow::Result<EnrollOutcome>;

    /// The tenant a still-pending (unexpired) daemon pubkey is bound to, if any.
    /// The JWT-issue fallback when the pubkey has no `daemons` row yet.
    async fn find_pending_tenant(
        &self,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>>;

    /// Count signup-code requests from `remote_ip` since `since` (rate limit).
    async fn count_code_requests_from_ip(
        &self,
        remote_ip: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64>;

    /// Record a signup-code request from `remote_ip`.
    async fn log_code_request(
        &self,
        remote_ip: &str,
        created_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
}

/// `PostgreSQL`-backed [`EnrollmentRepository`].
pub struct PgEnrollmentRepository {
    pools: DbPools,
}

impl PgEnrollmentRepository {
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
impl EnrollmentRepository for PgEnrollmentRepository {
    async fn issue_code(
        &self,
        code_hash: &str,
        email: &str,
        tenant_id: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO enrollment_codes (code_hash, email, tenant_id, expires_at, used_at)
             VALUES ($1, $2, $3, $4, NULL)",
        )
        .bind(code_hash)
        .bind(email)
        .bind(tenant_id)
        .bind(expires_at)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }

    async fn enroll(
        &self,
        code_hash: &str,
        public_key: &str,
        new_tenant_id: &str,
        default_entitlement: Entitlement,
        now: DateTime<Utc>,
        pending_ttl_secs: i64,
    ) -> anyhow::Result<EnrollOutcome> {
        let mut tx = self.pools.write.begin().await?;

        // Atomically validate + burn the code, recovering its email + tenant scope.
        let burned: Option<(String, Option<String>)> = sqlx::query_as(
            "UPDATE enrollment_codes SET used_at = $2 \
             WHERE code_hash = $1 AND used_at IS NULL AND expires_at > $2 \
             RETURNING email, tenant_id",
        )
        .bind(code_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((email, code_tenant_id)) = burned else {
            tx.rollback().await?;
            return Ok(EnrollOutcome::BadCode);
        };

        // Resolve the tenant: the code's tenant (add-daemon), or create/reuse by
        // email (new signup).
        let tenant_id = if let Some(tid) = code_tenant_id {
            // Add-daemon into an existing tenant — but never into a deregistered one.
            let live: Option<bool> =
                sqlx::query_scalar("SELECT deregistered_at IS NULL FROM tenants WHERE id = $1")
                    .bind(&tid)
                    .fetch_optional(&mut *tx)
                    .await?;
            if live != Some(true) {
                tx.rollback().await?;
                return Ok(EnrollOutcome::BadCode);
            }
            tid
        } else {
            // New signup: create the tenant, or reuse the existing LIVE one for this
            // email. The partial unique index only reserves emails of live tenants, so
            // a tombstoned tenant's email is free for a fresh signup.
            let created: Option<String> = sqlx::query_scalar(
                "INSERT INTO tenants (id, email, entitlement, subscription_status, subscription_id, created_at)
                 VALUES ($1, $2, $3, 'active', NULL, $4)
                 ON CONFLICT (email) WHERE deregistered_at IS NULL DO NOTHING
                 RETURNING id",
            )
            .bind(new_tenant_id)
            .bind(&email)
            .bind(Json(default_entitlement))
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(id) = created {
                id
            } else {
                sqlx::query_scalar(
                    "SELECT id FROM tenants WHERE email = $1 AND deregistered_at IS NULL",
                )
                .bind(&email)
                .fetch_one(&mut *tx)
                .await?
            }
        };

        // Enforce the resolved tenant's daemon limit.
        let entitlement: Json<Entitlement> =
            sqlx::query_scalar("SELECT entitlement FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_one(&mut *tx)
                .await?;
        // Count both registered daemons AND live pending bindings (other keys) so a
        // burst of enrolls cannot over-subscribe `max_daemons` before any of them
        // reaches register-network. The current key is excluded so a re-enroll
        // (refresh) of an already-pending key does not count itself.
        let used: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM daemons WHERE tenant_id = $1) \
                  + (SELECT COUNT(*) FROM pending_enrollments \
                     WHERE tenant_id = $1 AND public_key <> $2 AND expires_at > $3)",
        )
        .bind(&tenant_id)
        .bind(public_key)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        if used >= i64::from(entitlement.0.max_daemons) {
            tx.rollback().await?;
            return Ok(EnrollOutcome::DaemonLimit);
        }

        // Upsert the TTL'd pending binding (a re-enroll refreshes it).
        let expires_at = now + Duration::seconds(pending_ttl_secs);
        sqlx::query(
            "INSERT INTO pending_enrollments (public_key, tenant_id, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (public_key)
             DO UPDATE SET tenant_id = $2, expires_at = $3",
        )
        .bind(public_key)
        .bind(&tenant_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(EnrollOutcome::Enrolled { tenant_id })
    }

    async fn find_pending_tenant(
        &self,
        public_key: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        let tenant_id: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM pending_enrollments WHERE public_key = $1 AND expires_at > $2",
        )
        .bind(public_key)
        .bind(now)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(tenant_id)
    }

    async fn count_code_requests_from_ip(
        &self,
        remote_ip: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM enrollment_code_log WHERE remote_ip = $1 AND created_at > $2",
        )
        .bind(remote_ip)
        .bind(since)
        .fetch_one(&self.pools.read)
        .await?;
        Ok(count)
    }

    async fn log_code_request(
        &self,
        remote_ip: &str,
        created_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO enrollment_code_log (remote_ip, created_at) VALUES ($1, $2)")
            .bind(remote_ip)
            .bind(created_at)
            .execute(&self.pools.write)
            .await?;
        Ok(())
    }
}
