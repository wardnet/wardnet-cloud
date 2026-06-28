//! Wardnet **Billing** — the payment aggregate: *how* a subscription is paid for.
//!
//! Owns the payment provider (Stripe today, behind the [`StripeGateway`] port),
//! hosted Checkout/Portal, the webhook + signature verification, the
//! `processed_stripe_events` idempotency ledger, and the `billing_customers`
//! provider-reference table. It is **swappable** and provider-specific.
//!
//! It depends only on `wardnet_common` and **never** on `subscriptions`/`tenants`
//! (decision #5 / ADR-0010): it implements [`BillingPort`] and drives the license
//! aggregate solely through the [`SubscriptionReader`] / [`SubscriptionCommands`]
//! ports. Subscription never calls Billing back.
//!
//! [`StripeGateway`]: crate::gateway::StripeGateway
//! [`BillingPort`]: wardnet_common::ports::BillingPort
//! [`SubscriptionReader`]: wardnet_common::ports::SubscriptionReader
//! [`SubscriptionCommands`]: wardnet_common::ports::SubscriptionCommands

pub mod gateway;
pub mod repository;
pub mod service;

pub use gateway::{StripeClient, StripeGateway};
pub use repository::{BillingRepository, PgBillingRepository};
pub use service::BillingService;

/// This crate's migration set (the `billing_customers` table + back-fill).
/// `sqlx::migrate!` resolves the directory at compile time relative to this crate.
///
/// **Not independently runnable.** The migration FKs `tenants(id)` and back-fills from
/// `subscriptions` (both owned by the `tenants` migrator), so running this `Migrator`
/// alone against a fresh DB fails. The schema authority is the **composed** migrator in
/// the binary's `db::init` (tenants + subscriptions + billing, ordered by version); any
/// live-pool repo test must migrate through that composed set, not this fragment.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
