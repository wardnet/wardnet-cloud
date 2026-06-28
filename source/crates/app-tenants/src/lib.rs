//! Composition-root library for the **wardnet-tenants** deployable.
//!
//! This is the *only* crate that depends on all three aggregate crates (`tenants` +
//! `subscriptions` + `billing`), so the cross-aggregate glue lives here: the merged
//! [`db`] migrator and the [`reconcile`] safety net. The thin `main.rs` bin composes
//! this lib into a process. The full-wiring integration-test `Harness` lives in
//! `tests/common/mod.rs` (a shared test fixture, per the `tests/` convention) — it is
//! deliberately *not* part of the production library surface.

pub mod db;

use wardnet_subscriptions::SubscriptionService;
use wardnet_tenants::service::TenantsService;

/// Reconcile desired state across the tenant + license aggregates — the safety net for
/// any dropped domain event. This spans two aggregates, so it lives at the composition
/// root (not inside either service — ADR-0010). For every live tenant: open a missing
/// trial (only when the tenant has *no* subscription history, so a reaped trial is
/// never resurrected); and if the tenant still has no current subscription, deprovision
/// its networks. Idempotent.
///
/// # Errors
/// Propagates a repository / aggregate failure from either side.
pub async fn reconcile(
    service: &TenantsService,
    subscriptions: &SubscriptionService,
) -> anyhow::Result<()> {
    for tenant_id in service.list_live_tenant_ids().await? {
        if subscriptions.current(&tenant_id).await?.is_some() {
            continue;
        }
        if !subscriptions.create_trial(&tenant_id).await? {
            service.deprovision_networks_for(&tenant_id).await?;
        }
    }
    Ok(())
}
