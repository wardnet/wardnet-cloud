use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use wardnet_common::contract::{ProvisioningState, SubscriptionStatus};

use super::{abort_reaper_tick, should_abort, ttl_reaper_tick};
use crate::mesh::TenantsResolver;
use crate::repository::{TunnelRoute, TunnelRouteRepository};
use crate::test_helpers::{InMemoryRoutes, MockTenants, TEST_NODE_ADDR, network_view, tenant_view};
use crate::tunnel::TunnelRegistry;

const NET: &str = "net-1";
const TENANT: &str = "tenant-1";
const SLUG: &str = "alice";

// ── should_abort decision table ────────────────────────────────────────────────

#[test]
fn keeps_active_network_and_subscription() {
    let net = network_view(NET, SLUG, TENANT, ProvisioningState::Active);
    let ten = tenant_view(TENANT, SubscriptionStatus::Active);
    assert!(!should_abort(Some(&net), Some(&ten)));
}

#[test]
fn aborts_when_network_missing() {
    let ten = tenant_view(TENANT, SubscriptionStatus::Active);
    assert!(should_abort(None, Some(&ten)));
}

#[test]
fn aborts_when_network_deprovisioning() {
    let net = network_view(NET, SLUG, TENANT, ProvisioningState::Deprovisioning);
    let ten = tenant_view(TENANT, SubscriptionStatus::Active);
    assert!(should_abort(Some(&net), Some(&ten)));
}

#[test]
fn aborts_when_tenant_missing() {
    let net = network_view(NET, SLUG, TENANT, ProvisioningState::Active);
    assert!(should_abort(Some(&net), None));
}

#[test]
fn aborts_when_subscription_inactive() {
    let net = network_view(NET, SLUG, TENANT, ProvisioningState::Active);
    let ten = tenant_view(TENANT, SubscriptionStatus::Canceled);
    assert!(should_abort(Some(&net), Some(&ten)));
}

// ── abort_reaper_tick ──────────────────────────────────────────────────────────

/// Wire a live tunnel: a `tunnel_routes` row owned by this node + a registry entry.
async fn live_tunnel() -> (
    Arc<TunnelRegistry>,
    Arc<dyn TunnelRouteRepository>,
    InMemoryRoutes,
    crate::tunnel::Registration,
) {
    let registry = Arc::new(TunnelRegistry::new());
    let routes_concrete = InMemoryRoutes::new();
    routes_concrete
        .upsert(SLUG, TEST_NODE_ADDR, NET, TENANT)
        .await
        .unwrap();
    let registration = registry.register(SLUG);
    let routes: Arc<dyn TunnelRouteRepository> = Arc::new(routes_concrete.clone());
    (registry, routes, routes_concrete, registration)
}

#[tokio::test]
async fn tick_aborts_deprovisioning_tunnel() {
    let (registry, routes, routes_concrete, registration) = live_tunnel().await;
    let tenants = MockTenants::new();
    tenants.seed_network(network_view(
        NET,
        SLUG,
        TENANT,
        ProvisioningState::Deprovisioning,
    ));
    tenants.seed_tenant(tenant_view(TENANT, SubscriptionStatus::Active));
    let tenants: Arc<dyn TenantsResolver> = Arc::new(tenants);

    abort_reaper_tick(&registry, &routes, &tenants, TEST_NODE_ADDR).await;

    assert!(!registry.is_connected(SLUG), "tunnel should be aborted");
    assert!(registration.abort.is_cancelled());
    assert!(
        routes_concrete.get(SLUG).is_none(),
        "route should be deleted"
    );
}

#[tokio::test]
async fn tick_keeps_active_tunnel_and_refreshes() {
    let (registry, routes, routes_concrete, _registration) = live_tunnel().await;
    let tenants = MockTenants::new();
    tenants.seed_network(network_view(NET, SLUG, TENANT, ProvisioningState::Active));
    tenants.seed_tenant(tenant_view(TENANT, SubscriptionStatus::Active));
    let tenants: Arc<dyn TenantsResolver> = Arc::new(tenants);

    abort_reaper_tick(&registry, &routes, &tenants, TEST_NODE_ADDR).await;

    assert!(registry.is_connected(SLUG), "tunnel should be kept");
    assert!(routes_concrete.get(SLUG).is_some(), "route should remain");
}

#[tokio::test]
async fn tick_keeps_tunnel_on_transient_read_failure() {
    let (registry, routes, routes_concrete, _registration) = live_tunnel().await;
    let tenants = MockTenants::new();
    tenants.fail_reads(); // both reads error → must NOT abort
    let tenants: Arc<dyn TenantsResolver> = Arc::new(tenants);

    abort_reaper_tick(&registry, &routes, &tenants, TEST_NODE_ADDR).await;

    assert!(
        registry.is_connected(SLUG),
        "transient failure must not abort"
    );
    assert!(routes_concrete.get(SLUG).is_some());
}

// ── ttl_reaper_tick ────────────────────────────────────────────────────────────

#[tokio::test]
async fn ttl_tick_purges_only_stale_rows() {
    let routes_concrete = InMemoryRoutes::new();
    // A fresh row owned by this node…
    routes_concrete
        .upsert("fresh", TEST_NODE_ADDR, NET, TENANT)
        .await
        .unwrap();
    // …and a stale row from a (crashed) peer node.
    routes_concrete.seed(TunnelRoute {
        slug: "stale".to_string(),
        node_addr: "dead-node:9444".to_string(),
        network_id: NET.to_string(),
        tenant_id: TENANT.to_string(),
        last_seen: Utc::now() - chrono::Duration::hours(1),
    });
    let routes: Arc<dyn TunnelRouteRepository> = Arc::new(routes_concrete.clone());

    ttl_reaper_tick(&routes, Duration::from_secs(100)).await;

    assert!(routes_concrete.get("fresh").is_some(), "fresh row kept");
    assert!(routes_concrete.get("stale").is_none(), "stale row purged");
}
