//! The cloud service layer (DDNS — the regional operational concern).
//!
//! Mirrors the daemon's layered design: **API handlers never touch repositories** —
//! they call a service, and each service **owns** its repositories.
//!
//! - [`DdnsService`] — regional DNS operational concern: Cloudflare A/TXT record
//!   management **and** the operational row that records them. Owns the regional
//!   [`OperationalRepository`](crate::repository::OperationalRepository) and the
//!   [`DnsProvider`](wardnet_common::dns_provider::DnsProvider).
//!
//! The global identity/naming concern (Tenants) was carved into its own
//! `wardnet-tenants` binary in WS-B; the Tunneller concern follows in WS-D.

pub mod ddns;

pub use ddns::{DdnsError, DdnsService};
