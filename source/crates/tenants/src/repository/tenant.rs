//! The **tenant** — an account, identity only (email). Root of the
//! `tenant → {subscription, network → daemon}` model, in the global Tenants DB.
//! All billing/entitlement state lives on the [`subscription`](super::subscription)
//! aggregate, never here.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::db::DbPools;

/// A tenant account.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: String,
    /// Lowercased account email (the account identifier).
    pub email: String,
    pub created_at: DateTime<Utc>,
    /// Account-deregistration tombstone: `None` = live; `Some` = terminally
    /// deregistered (its email is freed, and mint/enroll reject it).
    pub deregistered_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct TenantRow {
    id: String,
    email: String,
    created_at: DateTime<Utc>,
    deregistered_at: Option<DateTime<Utc>>,
}

impl From<TenantRow> for Tenant {
    fn from(r: TenantRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            created_at: r.created_at,
            deregistered_at: r.deregistered_at,
        }
    }
}

/// Outcome of a tenant insert (the email UNIQUE is the conflict point).
#[derive(Debug, PartialEq, Eq)]
pub enum CreateTenantOutcome {
    /// The tenant row was inserted.
    Created,
    /// A tenant already exists with that email.
    EmailTaken,
}

/// Data access for the `tenants` table.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Insert a tenant. Returns [`CreateTenantOutcome::EmailTaken`] on email clash.
    async fn create(&self, tenant: &Tenant) -> anyhow::Result<CreateTenantOutcome>;
    /// Fetch a tenant by id.
    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Tenant>>;
    /// Fetch a tenant by (lowercased) email.
    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<Tenant>>;
    /// Ids of all live (non-tombstoned) tenants — the reconcile scan input.
    async fn list_live_ids(&self) -> anyhow::Result<Vec<String>>;
    /// Stamp the deregistration tombstone on a live tenant. Returns `true` if it newly
    /// tombstoned the tenant, `false` if it was already tombstoned or no such tenant
    /// (idempotent).
    async fn set_deregistered(&self, id: &str) -> anyhow::Result<bool>;
    /// Delete every tombstoned tenant that no longer owns any networks, returning the
    /// number of rows deleted. FK `ON DELETE CASCADE` removes the tenant's
    /// subscriptions, daemons, enrollment codes, pending enrollments, and the Identities
    /// aggregate's rows (`tenant_identities`, `sessions`). N-replica-safe and idempotent.
    async fn delete_tombstoned_empty(&self) -> anyhow::Result<u64>;
}

/// `PostgreSQL`-backed [`TenantRepository`].
pub struct PgTenantRepository {
    pools: DbPools,
}

impl PgTenantRepository {
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
impl TenantRepository for PgTenantRepository {
    async fn create(&self, tenant: &Tenant) -> anyhow::Result<CreateTenantOutcome> {
        let affected = sqlx::query(
            "INSERT INTO tenants (id, email, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (email) WHERE deregistered_at IS NULL DO NOTHING",
        )
        .bind(&tenant.id)
        .bind(&tenant.email)
        .bind(tenant.created_at)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(if affected == 1 {
            CreateTenantOutcome::Created
        } else {
            CreateTenantOutcome::EmailTaken
        })
    }

    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Tenant>> {
        let row = sqlx::query_as::<_, TenantRow>(
            "SELECT id, email, created_at, deregistered_at FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<Tenant>> {
        let row = sqlx::query_as::<_, TenantRow>(
            "SELECT id, email, created_at, deregistered_at \
             FROM tenants WHERE email = $1 AND deregistered_at IS NULL",
        )
        .bind(email)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn list_live_ids(&self) -> anyhow::Result<Vec<String>> {
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM tenants WHERE deregistered_at IS NULL")
                .fetch_all(&self.pools.read)
                .await?;
        Ok(ids)
    }

    async fn set_deregistered(&self, id: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            "UPDATE tenants SET deregistered_at = now() \
             WHERE id = $1 AND deregistered_at IS NULL",
        )
        .bind(id)
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn delete_tombstoned_empty(&self) -> anyhow::Result<u64> {
        let affected = sqlx::query(
            "DELETE FROM tenants \
             WHERE deregistered_at IS NOT NULL \
               AND NOT EXISTS (SELECT 1 FROM networks WHERE networks.tenant_id = tenants.id)",
        )
        .execute(&self.pools.write)
        .await?
        .rows_affected();
        Ok(affected)
    }
}
