//! Wardnet **Tunneller** — the multi-node SNI-passthrough reverse-tunnel edge.
//!
//! A daemon dials `GET /v1/tunnel` (network-scoped JWT) and keeps a WebSocket open;
//! the Tunneller forwards inbound L4 TLS connections arriving at its SNI demuxer
//! down that tunnel, so the daemon terminates its own TLS and its private key never
//! leaves the device. The service is **multi-node from the ground up**: each node
//! owns an in-memory per-node registry, and a regional Postgres `tunnel_routes`
//! table maps `slug → node_addr` so a connection landing on the wrong node is
//! forwarded over a private mTLS link to the node that owns the tunnel
//! (`docs/adr/0004`).
//!
//! Identity is JWT-only (the global identity DB lives in Tenants); the routing
//! policy resolves the daemon's `net` claim to a vanity slug and checks the tenant
//! subscription via mesh-mTLS reads against Tenants.

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod mesh;
pub mod reconcile;
pub mod repository;
pub mod router;
pub mod sni;
pub mod state;
pub mod tunnel;

#[doc(hidden)]
pub mod test_helpers;
