//! The **session** (`sessions`) — the browser-durable, revocable web credential
//! behind an httpOnly cookie (ADR-0009). Part of the **Identities aggregate**, owned
//! by [`IdentitiesService`](crate::identities::IdentitiesService).
//!
//! Only `hex(SHA-256(token))` is stored; the raw token lives only in the cookie
//! (invariant #1). The session is what logout / password-reset / deregister destroy —
//! revocation, not JWT TTL, is the primary hijack defence.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::db::DbPools;

/// A server-side session row.
#[derive(Debug, Clone)]
pub struct Session {
    /// `hex(SHA-256(raw session token))` — the at-rest form.
    pub token_hash: String,
    /// The tenant this session authenticates.
    pub tenant_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Data access for the `sessions` table (Identities aggregate).
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Persist a new session.
    async fn create(&self, session: &Session) -> anyhow::Result<()>;

    /// Resolve a **live** session belonging to a **live** tenant by its token hash and
    /// slide its expiry forward to `new_expires_at` (the 30-day sliding window),
    /// returning the tenant id. An expired/unknown hash — or a session whose tenant has
    /// been deregistered — yields `None` (and is not extended). The deregistered-tenant
    /// guard is in the statement itself, so a token can never be minted for a tombstoned
    /// tenant even in the window before the identities reactor purges the row. This
    /// single statement is the silent-exchange read.
    async fn touch_and_get_tenant(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
        new_expires_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>>;

    /// Delete a single session by its token hash (logout). Returns whether a row was
    /// removed.
    async fn delete(&self, token_hash: &str) -> anyhow::Result<bool>;

    /// Delete every session for a tenant (logout-all / password-reset / deregister
    /// purge). Returns the number of rows deleted. Idempotent.
    async fn delete_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64>;
}

/// `PostgreSQL`-backed [`SessionRepository`].
pub struct PgSessionRepository {
    pools: DbPools,
}

impl PgSessionRepository {
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

const CREATE: &str =
    "INSERT INTO sessions (token_hash, tenant_id, expires_at, created_at) VALUES ($1, $2, $3, $4)";

const TOUCH_AND_GET_TENANT: &str = "UPDATE sessions SET expires_at = $3 \
     WHERE token_hash = $1 AND expires_at > $2 \
       AND EXISTS ( \
         SELECT 1 FROM tenants t \
         WHERE t.id = sessions.tenant_id AND t.deregistered_at IS NULL \
       ) \
     RETURNING tenant_id";

const DELETE: &str = "DELETE FROM sessions WHERE token_hash = $1";

const DELETE_FOR_TENANT: &str = "DELETE FROM sessions WHERE tenant_id = $1";

#[async_trait]
impl SessionRepository for PgSessionRepository {
    async fn create(&self, session: &Session) -> anyhow::Result<()> {
        sqlx::query(CREATE)
            .bind(&session.token_hash)
            .bind(&session.tenant_id)
            .bind(session.expires_at)
            .bind(session.created_at)
            .execute(&self.pools.write)
            .await?;
        Ok(())
    }

    async fn touch_and_get_tenant(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
        new_expires_at: DateTime<Utc>,
    ) -> anyhow::Result<Option<String>> {
        let tenant_id: Option<String> = sqlx::query_scalar(TOUCH_AND_GET_TENANT)
            .bind(token_hash)
            .bind(now)
            .bind(new_expires_at)
            .fetch_optional(&self.pools.write)
            .await?;
        Ok(tenant_id)
    }

    async fn delete(&self, token_hash: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(DELETE)
            .bind(token_hash)
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    async fn delete_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        let affected = sqlx::query(DELETE_FOR_TENANT)
            .bind(tenant_id)
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(affected)
    }
}
