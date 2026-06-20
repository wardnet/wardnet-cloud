use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};

/// Reader / writer pool pair backed by `PostgreSQL`.
///
/// Both `read` and `write` point at the same underlying connection pool;
/// the split is retained for API compatibility with the rest of the codebase
/// and to allow future reader replicas to be introduced without changing
/// call sites.
#[derive(Clone)]
pub struct DbPools {
    pub read: PgPool,
    pub write: PgPool,
}

impl DbPools {
    /// Wrap a single pool as both reader and writer.
    #[must_use]
    pub fn single(pool: PgPool) -> Self {
        Self {
            read: pool.clone(),
            write: pool,
        }
    }
}

/// Open a `PostgreSQL` connection pool with the fleet's standard Neon-friendly
/// options (`min_connections = 0`, capped size, bounded acquire timeout).
///
/// Migrations are **not** run here: `sqlx::migrate!` resolves its directory at
/// compile time relative to the calling crate, so each service runs its own
/// `migrate!` against the pool this returns (see the service's `db` module).
///
/// # Errors
/// Returns an error if the pool cannot be established.
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(10)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?)
}
