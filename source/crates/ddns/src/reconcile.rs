//! The reconcile loops — a regional controller over the desired-state work queue.
//!
//! Two pull-loops drive Cloudflare toward the state Tenants owns (`docs/adr/0001`):
//!
//! - the [`provisioner`] (short interval): drains `provisioning` networks and, for
//!   each one that has reported an IP, publishes the A record and reports `active`.
//!   A network with no IP yet is **skipped** until a later tick.
//! - the [`reaper`] (long interval, jittered): drains `deprovisioning` networks,
//!   tears the DNS record down, and reports `deprovisioned` (which deletes the row).
//!
//! Both follow a strict **never-crash** discipline: per-item failures and report
//! (PATCH) failures are *logged, never propagated* — the next tick retries — and a
//! failure to even fetch a page ends only that tick. The loops never panic or
//! abort the process.

use std::sync::Arc;
use std::time::Duration;

use crate::repository::OperationalRepository;
use crate::service::DdnsService;
use crate::work_queue::WorkQueue;

/// Cursor page size for a reconcile drain.
const PAGE_LIMIT: i64 = 100;

/// Run the provisioner loop forever, ticking every `interval`.
pub async fn provisioner(
    work: Arc<dyn WorkQueue>,
    ddns: Arc<DdnsService>,
    op: Arc<dyn OperationalRepository>,
    region: String,
    subdomain_parent: String,
    interval: Duration,
) {
    // Bounded-cardinality domain metric: networks fully provisioned (A record
    // published + transitioned to active). No per-network labels — plan §5a. Built
    // once for the lifetime of the loop, not rebuilt per tick.
    let provisioned = opentelemetry::global::meter(wardnet_common::telemetry::SCOPE)
        .u64_counter("ddns.networks.provisioned")
        .with_description("Networks the provisioner published an A record for and activated.")
        .build();

    loop {
        provisioner_tick(&work, &ddns, &op, &region, &subdomain_parent, &provisioned).await;
        tokio::time::sleep(interval).await;
    }
}

/// One provisioner pass: drain every `provisioning` page for this region.
async fn provisioner_tick(
    work: &Arc<dyn WorkQueue>,
    ddns: &Arc<DdnsService>,
    op: &Arc<dyn OperationalRepository>,
    region: &str,
    subdomain_parent: &str,
    provisioned: &opentelemetry::metrics::Counter<u64>,
) {
    let mut after: Option<String> = None;
    loop {
        let page = match work
            .list("provisioning", region, after.as_deref(), PAGE_LIMIT)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                tracing::warn!(error = %e, "provisioner: failed to fetch work-queue page; retry next tick");
                return;
            }
        };
        if page.is_empty() {
            return;
        }
        let full = page.len() == usize::try_from(PAGE_LIMIT).unwrap_or(usize::MAX);
        for net in &page {
            after = Some(net.id.clone());

            // provisioning→active fires only once an IP has been reported.
            let ip = match op.find_by_id(&net.id).await {
                Ok(Some(o)) => o.ip,
                Ok(None) => None,
                Err(e) => {
                    tracing::error!(network_id = %net.id, error = %e, "provisioner: operational read failed; retry next tick");
                    continue;
                }
            };
            let Some(ip) = ip else {
                tracing::debug!(network_id = %net.id, "provisioner: no IP reported yet; skipping");
                continue;
            };

            let fqdn = format!("{}.{}", net.slug, subdomain_parent);
            if let Err(e) = ddns.provision(&net.id, &fqdn, &ip).await {
                tracing::error!(network_id = %net.id, error = %e, "provisioner: publish failed; retry next tick");
                continue;
            }
            if let Err(e) = work.transition(&net.id, "active").await {
                tracing::error!(network_id = %net.id, error = %e, "provisioner: report active failed; retry next tick");
            } else {
                provisioned.add(1, &[]);
            }
        }
        if !full {
            return;
        }
    }
}

/// Run the reaper loop forever, ticking every `interval` plus up to `jitter_secs`
/// of random jitter (so replicas in a region don't all reap on the same beat).
///
/// Unlike the provisioner, the reaper needs no operational repository handle: it
/// drives teardown purely off the work queue, and `DdnsService::delete_records`
/// self-reads the operational row.
pub async fn reaper(
    work: Arc<dyn WorkQueue>,
    ddns: Arc<DdnsService>,
    region: String,
    interval: Duration,
    jitter_secs: u64,
) {
    loop {
        reaper_tick(&work, &ddns, &region).await;
        let jitter = if jitter_secs == 0 {
            0
        } else {
            rand::random::<u64>() % (jitter_secs + 1)
        };
        tokio::time::sleep(interval + Duration::from_secs(jitter)).await;
    }
}

/// One reaper pass: drain every `deprovisioning` page for this region.
async fn reaper_tick(work: &Arc<dyn WorkQueue>, ddns: &Arc<DdnsService>, region: &str) {
    let mut after: Option<String> = None;
    loop {
        let page = match work
            .list("deprovisioning", region, after.as_deref(), PAGE_LIMIT)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                tracing::warn!(error = %e, "reaper: failed to fetch work-queue page; retry next tick");
                return;
            }
        };
        if page.is_empty() {
            return;
        }
        let full = page.len() == usize::try_from(PAGE_LIMIT).unwrap_or(usize::MAX);
        for net in &page {
            after = Some(net.id.clone());

            if let Err(e) = ddns.delete_records(&net.id).await {
                tracing::error!(network_id = %net.id, error = %e, "reaper: DNS teardown failed; retry next tick");
                continue;
            }
            if let Err(e) = work.transition(&net.id, "deprovisioned").await {
                tracing::error!(network_id = %net.id, error = %e, "reaper: report deprovisioned failed; retry next tick");
            }
        }
        if !full {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
