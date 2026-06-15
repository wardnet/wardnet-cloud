use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::db::DbPools;

/// A registered install's **global identity**.
///
/// Lives in the global Tenants DB. One row per Pi; the `name` is the user-chosen
/// vanity slug (UNIQUE = the cross-region allocation lock) and `id` is a
/// server-assigned `UUIDv4` used in all subsequent API paths. Operational DNS
/// state (IP, Cloudflare record IDs) lives separately in the regional
/// [`crate::repository::Operational`] table.
#[derive(Debug, Clone)]
pub struct Identity {
    pub id: String,
    /// Subdomain slug — validated as `[a-z0-9-]`, 3–32 chars.
    pub name: String,
    /// Region the install registered against.
    pub region: String,
    /// Base64-encoded raw Ed25519 verifying-key bytes (32 bytes).
    pub public_key: String,
    /// Raw Ed25519 verifying-key bytes, decoded once on row load (avoids repeated
    /// base64 decoding on the authenticated hot path).
    pub pub_key_bytes: [u8; 32],
    /// Hex SHA-256 of the bearer token — the raw token is never stored.
    pub token_hash: String,
    /// Lifecycle status. `find_by_*` only ever return `Active` rows (the filter is
    /// in SQL), so a returned `Identity` is always `Active`; the field stays for
    /// faithfulness to the table and any future all-status query.
    pub status: Status,
    pub created_at: DateTime<Utc>,
}

/// An identity's lifecycle status. Stored as a `VARCHAR` (`'active'` /
/// `'deregistered'`) under a `CHECK` constraint; the enum gives the domain layer
/// type safety. Deregistration is a tombstone (`Active` → `Deregistered`), never a
/// row delete, so the name allocation and audit trail survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Deregistered,
}

impl Status {
    /// Parse the stored `status` column value.
    fn from_db(s: &str) -> anyhow::Result<Self> {
        match s {
            "active" => Ok(Self::Active),
            "deregistered" => Ok(Self::Deregistered),
            other => anyhow::bail!("unknown identity status '{other}'"),
        }
    }
}

/// Outcome of [`IdentityRepository::register`] — registration is a single global
/// transaction, so its three terminal states are returned as one value.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The identity was inserted and the challenge consumed.
    Registered,
    /// The vanity name is already taken (the transaction rolled back, so the
    /// challenge was **not** burned — the caller can retry with a new name).
    NameTaken,
    /// The challenge was already used (a concurrent registration won the burn).
    ChallengeAlreadyUsed,
}

/// Raw `PostgreSQL` row for `sqlx::query_as` mapping.
#[derive(sqlx::FromRow)]
struct IdentityRow {
    id: String,
    name: String,
    region: String,
    public_key: String,
    token_hash: String,
    status: String,
    created_at: DateTime<Utc>,
}

impl IdentityRow {
    fn into_identity(self) -> anyhow::Result<Identity> {
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| {
                anyhow::anyhow!("base64-decode public_key for identity {}: {e}", self.id)
            })?;
        let pub_key_bytes: [u8; 32] = pk_bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Ed25519 public key for identity {} must be 32 bytes",
                self.id
            )
        })?;
        Ok(Identity {
            id: self.id,
            name: self.name,
            region: self.region,
            public_key: self.public_key,
            pub_key_bytes,
            token_hash: self.token_hash,
            status: Status::from_db(&self.status)?,
            created_at: self.created_at,
        })
    }
}

const SELECT_COLS: &str =
    "id, name, region, public_key, token_hash, status, created_at FROM identities";

/// Data access for the global `identities` + `registration_log` tables, plus the
/// atomic registration transaction (which also burns the challenge).
#[async_trait]
pub trait IdentityRepository: Send + Sync {
    /// Register an install in a **single transaction**: consume the `PoW` challenge
    /// (`UPDATE ... WHERE used_at IS NULL`) and insert the identity (whose `name`
    /// UNIQUE constraint is the allocation lock). Both succeed or neither does, so
    /// a name clash never burns the challenge and a reused challenge never leaves a
    /// half-registered identity.
    async fn register(
        &self,
        identity: &Identity,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<RegisterOutcome>;

    /// Find an active identity by its server-assigned UUID.
    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Identity>>;

    /// Find an **active** identity by the hex SHA-256 of its bearer token.
    /// Deregistered (tombstoned) installs do not authenticate.
    async fn find_by_token_hash(&self, token_hash: &str) -> anyhow::Result<Option<Identity>>;

    /// Whether `name` is already allocated (the availability check). A tombstoned
    /// install keeps its `name` (the row + UNIQUE constraint survive), so a
    /// deregistered name still reads as taken.
    async fn is_name_taken(&self, name: &str) -> anyhow::Result<bool>;

    /// Tombstone an identity (deregistration): flip `status` to `deregistered` and
    /// stamp `deregistered_at`. Idempotent — a no-op if already tombstoned. The row
    /// (and its name allocation) survive so introspection can report it.
    async fn tombstone(&self, id: &str, now: DateTime<Utc>) -> anyhow::Result<()>;

    /// Of the given install IDs, return those with **no active identity** —
    /// tombstoned or never-registered. Drives the DDNS reconcile reaper (which
    /// tears down their regional DNS state).
    async fn find_inactive(&self, ids: &[String]) -> anyhow::Result<Vec<String>>;

    /// Count registrations from `remote_ip` since `since` (per-IP rate limit).
    async fn count_registrations_from_ip(
        &self,
        remote_ip: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64>;

    /// Append a row to `registration_log` for rate-limit tracking.
    async fn log_registration(
        &self,
        remote_ip: &str,
        created_at: DateTime<Utc>,
    ) -> anyhow::Result<()>;
}

/// PostgreSQL-backed [`IdentityRepository`] against the global pool.
pub struct PgIdentityRepository {
    pools: DbPools,
}

impl PgIdentityRepository {
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
impl IdentityRepository for PgIdentityRepository {
    async fn register(
        &self,
        identity: &Identity,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<RegisterOutcome> {
        let mut tx = self.pools.write.begin().await?;

        // Burn the challenge first. The row lock here serialises concurrent
        // registrations using the same challenge: the second waiter re-evaluates
        // `used_at IS NULL` after the first commits and matches zero rows.
        let consumed = sqlx::query(
            "UPDATE registration_challenges SET used_at = $1 WHERE id = $2 AND used_at IS NULL",
        )
        .bind(now)
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if consumed == 0 {
            tx.rollback().await?;
            return Ok(RegisterOutcome::ChallengeAlreadyUsed);
        }

        // Insert the identity. A unique violation on `name` (or `token_hash`) means
        // the name is taken; rolling back un-burns the challenge so the user can
        // retry without re-solving the PoW (invariant #3).
        let insert = sqlx::query(
            "INSERT INTO identities (id, name, region, public_key, token_hash, status, created_at)
             VALUES ($1, $2, $3, $4, $5, 'active', $6)",
        )
        .bind(&identity.id)
        .bind(&identity.name)
        .bind(&identity.region)
        .bind(&identity.public_key)
        .bind(&identity.token_hash)
        .bind(identity.created_at)
        .execute(&mut *tx)
        .await;

        match insert {
            Ok(_) => {
                tx.commit().await?;
                Ok(RegisterOutcome::Registered)
            }
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                tx.rollback().await?;
                Ok(RegisterOutcome::NameTaken)
            }
            Err(e) => {
                tx.rollback().await?;
                Err(e.into())
            }
        }
    }

    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Identity>> {
        let query = format!("SELECT {SELECT_COLS} WHERE id = $1 AND status = 'active'");
        sqlx::query_as::<_, IdentityRow>(&query)
            .bind(id)
            .fetch_optional(&self.pools.read)
            .await?
            .map(IdentityRow::into_identity)
            .transpose()
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> anyhow::Result<Option<Identity>> {
        let query = format!("SELECT {SELECT_COLS} WHERE token_hash = $1 AND status = 'active'");
        sqlx::query_as::<_, IdentityRow>(&query)
            .bind(token_hash)
            .fetch_optional(&self.pools.read)
            .await?
            .map(IdentityRow::into_identity)
            .transpose()
    }

    async fn is_name_taken(&self, name: &str) -> anyhow::Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identities WHERE name = $1)")
                .bind(name)
                .fetch_one(&self.pools.read)
                .await?;
        Ok(exists)
    }

    async fn tombstone(&self, id: &str, now: DateTime<Utc>) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE identities SET status = 'deregistered', deregistered_at = $2
             WHERE id = $1 AND status = 'active'",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pools.write)
        .await?;
        Ok(())
    }

    async fn find_inactive(&self, ids: &[String]) -> anyhow::Result<Vec<String>> {
        let inactive: Vec<String> = sqlx::query_scalar(
            "SELECT u.id FROM unnest($1::text[]) AS u(id)
             WHERE NOT EXISTS (
                 SELECT 1 FROM identities i WHERE i.id = u.id AND i.status = 'active'
             )",
        )
        .bind(ids)
        .fetch_all(&self.pools.read)
        .await?;
        Ok(inactive)
    }

    async fn count_registrations_from_ip(
        &self,
        remote_ip: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM registration_log WHERE remote_ip = $1 AND created_at > $2",
        )
        .bind(remote_ip)
        .bind(since)
        .fetch_one(&self.pools.read)
        .await?;
        Ok(count)
    }

    async fn log_registration(
        &self,
        remote_ip: &str,
        created_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO registration_log (remote_ip, created_at) VALUES ($1, $2)")
            .bind(remote_ip)
            .bind(created_at)
            .execute(&self.pools.write)
            .await?;
        Ok(())
    }
}
