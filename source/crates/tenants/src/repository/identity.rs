//! The **login method** (`tenant_identities`) — one row per way an account can
//! authenticate (a `password` hash or a linked `google`/`github` identity). Part of
//! the **Identities aggregate**, owned by
//! [`IdentitiesService`](crate::identities::IdentitiesService) — *not* the tenant
//! aggregate. All rows resolve to a tenant by the verified email (ADR-0009).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::db::DbPools;

/// A single login method bound to a tenant.
#[derive(Debug, Clone)]
pub struct TenantIdentity {
    /// The tenant this login method authenticates.
    pub tenant_id: String,
    /// Login method: `password` | `google` | `github` | …
    pub provider: String,
    /// The provider's stable subject (email for `password`, the provider subject/id
    /// for an OIDC/OAuth provider).
    pub subject: String,
    /// argon2id PHC string for `password`; `None` for a federated identity. Never
    /// logged or echoed.
    pub secret_hash: Option<String>,
    /// The provider-verified email this identity resolved against (lowercased).
    pub email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct TenantIdentityRow {
    tenant_id: String,
    provider: String,
    subject: String,
    secret_hash: Option<String>,
    email: String,
    created_at: DateTime<Utc>,
}

impl From<TenantIdentityRow> for TenantIdentity {
    fn from(r: TenantIdentityRow) -> Self {
        Self {
            tenant_id: r.tenant_id,
            provider: r.provider,
            subject: r.subject,
            secret_hash: r.secret_hash,
            email: r.email,
            created_at: r.created_at,
        }
    }
}

/// Outcome of inserting a login method (the `(provider, subject)` PK is the conflict
/// point).
#[derive(Debug, PartialEq, Eq)]
pub enum InsertIdentityOutcome {
    /// The login method was inserted.
    Created,
    /// A login method with that `(provider, subject)` already exists.
    AlreadyExists,
}

/// Data access for the `tenant_identities` table (Identities aggregate).
#[async_trait]
pub trait TenantIdentityRepository: Send + Sync {
    /// Look up a login method by its provider + subject (the callback's
    /// returning-vs-new decision).
    async fn find_by_provider_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> anyhow::Result<Option<TenantIdentity>>;

    /// Insert a login method. Returns [`InsertIdentityOutcome::AlreadyExists`] if a row
    /// with that `(provider, subject)` is already present (idempotent re-link).
    async fn insert(&self, identity: &TenantIdentity) -> anyhow::Result<InsertIdentityOutcome>;

    /// Set (or replace) the `secret_hash` of an existing `(provider, subject)` row —
    /// the password-reset write. Returns whether a row was updated.
    async fn update_secret_hash(
        &self,
        provider: &str,
        subject: &str,
        secret_hash: &str,
    ) -> anyhow::Result<bool>;

    /// Delete every login method for a tenant (the identities-purge on deregister).
    /// Returns the number of rows deleted. Idempotent.
    async fn delete_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64>;
}

/// `PostgreSQL`-backed [`TenantIdentityRepository`].
pub struct PgTenantIdentityRepository {
    pools: DbPools,
}

impl PgTenantIdentityRepository {
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

const FIND_BY_PROVIDER_SUBJECT: &str = "SELECT tenant_id, provider, subject, secret_hash, email, created_at \
     FROM tenant_identities WHERE provider = $1 AND subject = $2";

const INSERT: &str = "INSERT INTO tenant_identities \
     (tenant_id, provider, subject, secret_hash, email, created_at) \
     VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (provider, subject) DO NOTHING";

const UPDATE_SECRET_HASH: &str =
    "UPDATE tenant_identities SET secret_hash = $3 WHERE provider = $1 AND subject = $2";

const DELETE_FOR_TENANT: &str = "DELETE FROM tenant_identities WHERE tenant_id = $1";

#[async_trait]
impl TenantIdentityRepository for PgTenantIdentityRepository {
    async fn find_by_provider_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> anyhow::Result<Option<TenantIdentity>> {
        let row = sqlx::query_as::<_, TenantIdentityRow>(FIND_BY_PROVIDER_SUBJECT)
            .bind(provider)
            .bind(subject)
            .fetch_optional(&self.pools.read)
            .await?;
        Ok(row.map(Into::into))
    }

    async fn insert(&self, identity: &TenantIdentity) -> anyhow::Result<InsertIdentityOutcome> {
        let affected = sqlx::query(INSERT)
            .bind(&identity.tenant_id)
            .bind(&identity.provider)
            .bind(&identity.subject)
            .bind(&identity.secret_hash)
            .bind(&identity.email)
            .bind(identity.created_at)
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(if affected == 1 {
            InsertIdentityOutcome::Created
        } else {
            InsertIdentityOutcome::AlreadyExists
        })
    }

    async fn update_secret_hash(
        &self,
        provider: &str,
        subject: &str,
        secret_hash: &str,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query(UPDATE_SECRET_HASH)
            .bind(provider)
            .bind(subject)
            .bind(secret_hash)
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
