//! The mesh plane: outbound reads against Tenants (the routing policy) and the
//! private inter-node forward link between Tunneller nodes. "Mesh" names the mTLS
//! transport, never a route group.

pub mod forward;
pub mod tenants_client;

pub use forward::{InterNodeForwarder, MtlsForwarder, serve_forward};
pub use tenants_client::{TenantsClient, TenantsResolver};
