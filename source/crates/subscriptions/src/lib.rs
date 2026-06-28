//! Wardnet **Subscriptions** — the provider-agnostic **license** aggregate.
//!
//! Owns *what entitlement a tenant currently holds* and its lifecycle
//! (`trialing → active → past_due → canceled`, with trial/payment **grace**
//! windows and the reaper that cancels overdue rows). It is the **source of truth
//! for entitlement** and knows **nothing** about payment providers — no Stripe
//! types appear anywhere in this crate. *How* a subscription is paid for lives in
//! the separate `billing` aggregate.
//!
//! This crate depends only on `wardnet_common` and **never** on `tenants`/`billing`
//! (decision #5 / ADR-0010): it *implements* the [`SubscriptionReader`] (entitlement
//! reads) and [`SubscriptionCommands`] (the one-way Billing → Subscription write
//! edge) ports from [`wardnet_common::ports`]; consumers hold those as `dyn` trait
//! objects, so the boundary is compiler-enforced.
//!
//! [`SubscriptionReader`]: wardnet_common::ports::SubscriptionReader
//! [`SubscriptionCommands`]: wardnet_common::ports::SubscriptionCommands

pub mod error;
pub mod reactor;
pub mod repository;
pub mod service;

pub use error::SubscriptionError;
pub use repository::{PgSubscriptionRepository, Subscription, SubscriptionRepository};
pub use service::{SubscriptionService, TrialPolicy};

/// This crate's migration set (the license-only schema deltas). `sqlx::migrate!`
/// resolves the directory at compile time relative to this crate.
///
/// **Not independently runnable.** These migrations `ALTER` the `subscriptions` table
/// (created by the `tenants` migrator), so running this `Migrator` alone against a
/// fresh DB fails. The schema authority is the **composed** migrator in the binary's
/// `db::init` (tenants + subscriptions + billing, ordered by version); any live-pool
/// repo test must migrate through that composed set, not this fragment.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
