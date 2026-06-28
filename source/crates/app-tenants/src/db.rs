//! Composition-root database init: one shared Postgres, one linear migration history.
//!
//! Each aggregate crate owns its own `migrations/` dir and exposes a `MIGRATOR`
//! (`sqlx::migrate!`, compile-time-relative). Here we merge them into a single
//! ordered history and run it against the default `_sqlx_migrations` table — so the DB
//! has one coherent schema history while each crate keeps file ownership of its
//! migrations (ADR-0010). We deliberately avoid `Migrator::dangerous_set_table_name`
//! (a documented production data-loss footgun): the merge keeps the standard tracking
//! table.

use sqlx::migrate::{Migration, Migrator};

use wardnet_common::db::DbPools;

/// Initialise the global pool and run the merged pending migrations.
///
/// Ordering is by migration **version** (timestamp), independent of crate dependency
/// order: billing's `billing_customers` (+ back-fill) is timestamped *before*
/// subscriptions' `drop_stripe_cols`, so the back-fill reads the `stripe_*` columns
/// before they are dropped.
///
/// # Errors
/// Returns an error if the pool cannot be established or a migration fails.
pub async fn init(global_database_url: &str) -> anyhow::Result<DbPools> {
    let pool = wardnet_common::db::connect(global_database_url).await?;

    let mut all: Vec<Migration> = wardnet_tenants::db::MIGRATOR
        .iter()
        .chain(wardnet_subscriptions::MIGRATOR.iter())
        .chain(wardnet_billing::MIGRATOR.iter())
        .cloned()
        .collect();
    all.sort_by_key(|m| m.version);

    Migrator::with_migrations(all).run(&pool).await?;
    tracing::info!("global database initialised (merged tenants + subscriptions + billing)");
    Ok(DbPools::single(pool))
}
