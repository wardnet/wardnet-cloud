//! Database initialisation for the cloud bin.
//!
//! The pool plumbing ([`DbPools`], `connect`) lives in [`wardnet_common::db`].
//! Migrations stay here because `sqlx::migrate!` resolves its directory at compile
//! time relative to *this* crate (`crates/cloud/migrations*`); once the services
//! carve out, each binary owns its own migration set and `init`.

pub use wardnet_common::db::DbPools;

/// Initialise the **regional** install pool and run its pending migrations.
///
/// # Errors
/// Returns an error if the pool cannot be established or a migration fails.
pub async fn init(database_url: &str) -> anyhow::Result<DbPools> {
    let pool = wardnet_common::db::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("regional database initialised");
    Ok(DbPools::single(pool))
}

/// Initialise the **global naming authority** pool and run its pending
/// migrations (the `names` table). A separate database from the regional pool,
/// shared across the whole fleet.
///
/// # Errors
/// Returns an error if the pool cannot be established or a migration fails.
pub async fn init_global(database_url: &str) -> anyhow::Result<DbPools> {
    let pool = wardnet_common::db::connect(database_url).await?;
    sqlx::migrate!("./migrations-global").run(&pool).await?;
    tracing::info!("global naming database initialised");
    Ok(DbPools::single(pool))
}
