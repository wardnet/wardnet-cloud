//! Database initialisation for the Tenants bin.
//!
//! The pool plumbing ([`DbPools`], `connect`) lives in [`wardnet_common::db`].
//! Tenants owns the single global DB; migrations stay here because `sqlx::migrate!`
//! resolves its directory at compile time relative to this crate.

pub use wardnet_common::db::DbPools;

/// Initialise the global pool and run its pending migrations.
///
/// # Errors
/// Returns an error if the pool cannot be established or a migration fails.
pub async fn init(global_database_url: &str) -> anyhow::Result<DbPools> {
    let pool = wardnet_common::db::connect(global_database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("global database initialised");
    Ok(DbPools::single(pool))
}
