//! Data-access layer for the Tenants global DB.
//!
//! One repository per aggregate (`tenant` / `network` / `daemon` / `enrollment`),
//! each a trait + a `Pg*` implementation. The two multi-table sagas live on the
//! repository that owns their primary aggregate: enroll on
//! [`EnrollmentRepository`], network+daemon creation on [`NetworkRepository`].
//!
//! The **Identities aggregate** (WS-F, ADR-0009) — login methods + browser sessions
//! — owns [`identity`] (`tenant_identities`) and [`session`] (`sessions`). It is a
//! distinct aggregate, owned by
//! [`IdentitiesService`](crate::identities::IdentitiesService), which holds *only*
//! these two repositories.

pub mod daemon;
pub mod enrollment;
pub mod identity;
pub mod network;
pub mod session;
pub mod subscription;
pub mod tenant;

pub use daemon::{Daemon, DaemonRepository, PgDaemonRepository};
pub use enrollment::{EnrollOutcome, EnrollmentRepository, PgEnrollmentRepository};
pub use identity::{
    InsertIdentityOutcome, PgTenantIdentityRepository, TenantIdentity, TenantIdentityRepository,
};
pub use session::{PgSessionRepository, Session, SessionRepository};
pub use network::{
    Network, NetworkRepository, PgNetworkRepository, ProvisioningState, RegisterNetworkOutcome,
};
pub use subscription::{
    Entitlement, PgSubscriptionRepository, Subscription, SubscriptionRepository, SubscriptionStatus,
};
pub use tenant::{CreateTenantOutcome, PgTenantRepository, Tenant, TenantRepository};
