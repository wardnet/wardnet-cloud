//! Data-access layer for the regional Tunneller DB (the `tunnel_routes` map).

pub mod routes;

pub use routes::{PgTunnelRouteRepository, TunnelRoute, TunnelRouteRepository};

#[cfg(test)]
mod tests;
