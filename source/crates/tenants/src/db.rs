//! Database plumbing for the Tenants aggregate.
//!
//! The pool plumbing ([`DbPools`], `connect`) lives in [`wardnet_common::db`]. This
//! crate owns the tenant/identity schema; its migration set is exposed as [`MIGRATOR`]
//! and composed with the other aggregates' migrators by the binary's `db::init`
//! (against the single shared DB — ADR-0010). `sqlx::migrate!` resolves the directory
//! at compile time relative to this crate.

pub use wardnet_common::db::DbPools;

/// The tenant/identity schema migration set (`init` + `identities_sessions`). Composed
/// with the `subscriptions` + `billing` migrators by the composition root.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
