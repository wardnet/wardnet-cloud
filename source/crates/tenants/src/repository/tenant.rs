//! The **tenant** — an account: email, entitlement, subscription. Root of the
//! `tenant → network → daemon` model, in the global Tenants DB.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

use crate::db::DbPools;

/// Per-tenant limits. JSONB-stored so new dimensions need no migration; `serde`
/// defaults keep old rows readable as dimensions are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Entitlement {
    /// Maximum networks the tenant may hold.
    #[serde(default = "Entitlement::one")]
    pub max_networks: u32,
    /// Maximum daemons across all the tenant's networks.
    #[serde(default = "Entitlement::one")]
    pub max_daemons: u32,
}

impl Entitlement {
    /// The default a self-service (wizard-enrolled) tenant receives.
    pub const DEFAULT: Entitlement = Entitlement {
        max_networks: 1,
        max_daemons: 1,
    };

    const fn one() -> u32 {
        1
    }
}

impl Default for Entitlement {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Subscription state. Drives the network-deprovisioning cascade on cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionStatus {
    /// Live subscription (or trial).
    Active,
    /// Cancelled — its networks are cascaded to `deprovisioning`.
    Canceled,
}

impl SubscriptionStatus {
    /// The DB/text form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::Canceled => "canceled",
        }
    }

    /// Parse from the DB/text form (unknown → `Active`, the safe default).
    #[must_use]
    pub fn from_db(s: &str) -> Self {
        match s {
            "canceled" => SubscriptionStatus::Canceled,
            _ => SubscriptionStatus::Active,
        }
    }
}

/// A tenant account.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: String,
    /// Lowercased account email (the account identifier).
    pub email: String,
    pub entitlement: Entitlement,
    pub subscription_status: SubscriptionStatus,
    /// Provider-agnostic subscription handle; `None` until billing is wired.
    pub subscription_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct TenantRow {
    id: String,
    email: String,
    entitlement: Json<Entitlement>,
    subscription_status: String,
    subscription_id: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<TenantRow> for Tenant {
    fn from(r: TenantRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            entitlement: r.entitlement.0,
            subscription_status: SubscriptionStatus::from_db(&r.subscription_status),
            subscription_id: r.subscription_id,
            created_at: r.created_at,
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
    /// Set the subscription status. Returns `false` if no such tenant.
    async fn set_subscription_status(
        &self,
        id: &str,
        status: SubscriptionStatus,
    ) -> anyhow::Result<bool>;
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
            "INSERT INTO tenants (id, email, entitlement, subscription_status, subscription_id, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (email) DO NOTHING",
        )
        .bind(&tenant.id)
        .bind(&tenant.email)
        .bind(Json(tenant.entitlement))
        .bind(tenant.subscription_status.as_str())
        .bind(&tenant.subscription_id)
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
            "SELECT id, email, entitlement, subscription_status, subscription_id, created_at \
             FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<Tenant>> {
        let row = sqlx::query_as::<_, TenantRow>(
            "SELECT id, email, entitlement, subscription_status, subscription_id, created_at \
             FROM tenants WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pools.read)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn set_subscription_status(
        &self,
        id: &str,
        status: SubscriptionStatus,
    ) -> anyhow::Result<bool> {
        let affected = sqlx::query("UPDATE tenants SET subscription_status = $2 WHERE id = $1")
            .bind(id)
            .bind(status.as_str())
            .execute(&self.pools.write)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }
}
