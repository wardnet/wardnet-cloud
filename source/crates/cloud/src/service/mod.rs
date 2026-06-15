//! The cloud service layer.
//!
//! Mirrors the daemon's layered design (`.agents/architecture.md`): **API
//! handlers never touch repositories** — they call a service, and each service
//! **owns** its repositories. Cross-service access is service-to-service (a
//! service holds an `Arc` to a sibling *service*, never a sibling's repository),
//! so every domain's business rules stay behind its own service.
//!
//! Two services map to the eventual process split (#610):
//! - [`TenantsService`] — global identity/naming concern: single-transaction
//!   registration, the `PoW` challenge lifecycle, name availability, install
//!   authentication, and deregistration. Owns the identity + challenge repos (both
//!   in the global Tenants DB).
//! - [`DdnsService`] — regional DNS operational concern: Cloudflare A/TXT record
//!   management **and** the operational row that records them. Owns the regional
//!   [`OperationalRepository`](crate::repository::OperationalRepository) and the
//!   [`DnsProvider`](wardnet_common::dns_provider::DnsProvider).

pub mod ddns;
pub mod tenants;

pub use ddns::{DdnsError, DdnsService};
pub use tenants::{RegisterParams, RegisterResult, TenantsError, TenantsService};
