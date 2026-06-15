//! Database initialisation for the cloud bin.
//!
//! The pool plumbing ([`DbPools`], `connect`) lives in [`wardnet_common::db`].
//! This bin owns a single **regional** database (operational DNS state). Migrations
//! stay here because `sqlx::migrate!` resolves its directory at compile time
//! relative to this crate. (The global naming-authority DB moved to the
//! `wardnet-tenants` crate in WS-B.)

pub use wardnet_common::db::DbPools;

/// Initialise the regional install pool and run its pending migrations.
///
/// # Errors
/// Returns an error if the pool cannot be established or a migration fails.
pub async fn init(database_url: &str) -> anyhow::Result<DbPools> {
    let pool = wardnet_common::db::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("regional database initialised");
    Ok(DbPools::single(pool))
}
