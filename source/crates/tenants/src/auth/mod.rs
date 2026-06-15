//! Tenants auth wiring.
//!
//! The signed-request middleware ([`wardnet_common::auth::auth_layer`]) and its
//! security core live in `common`; this module supplies the Tenants-specific
//! credential resolver via the [`AuthContext`](wardnet_common::auth::AuthContext)
//! impl in [`middleware`]. Tenants is the only service with the identity DB, so it
//! accepts **both** the identity JWT and the opaque bearer token.

pub mod middleware;

pub use wardnet_common::auth::{AuthenticatedInstall, Principal};
