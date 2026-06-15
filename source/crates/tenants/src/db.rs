//! Database initialisation for the Tenants bin.
//!
//! The pool plumbing ([`DbPools`], `connect`) lives in [`wardnet_common::db`].
//! Tenants owns a single database — the **global** naming authority (identities +
//! registration challenges) shared across the fleet. Migrations stay here because
//! `sqlx::migrate!` resolves its directory at compile time relative to this crate.

pub use wardnet_common::db::DbPools;

/// Initialise the global naming-authority pool and run its pending migrations.
///
/// # Errors
/// Returns an error if the pool cannot be established or a migration fails.
pub async fn init(database_url: &str) -> anyhow::Result<DbPools> {
    let pool = wardnet_common::db::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("tenants global database initialised");
    Ok(DbPools::single(pool))
}
