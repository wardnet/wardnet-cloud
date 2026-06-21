//! The desired-state **work queue** the reconcile loops drain.
//!
//! Tenants owns desired state and exposes it over the mesh-mTLS plane as
//! `GET/PATCH /v1/networks` (see `docs/adr/0001`). This module is the *consumer*
//! side: a [`WorkQueue`] trait (the test seam the loops depend on) plus its
//! Tenants-backed implementation, [`TenantsWorkQueue`].
//!
//! "Mesh" is the mTLS **transport** ([`MeshClient`]), injected in — it does not
//! name this module or the impl, which are named for the *contract* (`WorkQueue`)
//! and the *backing service* (`TenantsWorkQueue`, cf. `PgOperationalRepository`).

use std::sync::Arc;

use async_trait::async_trait;

// `NetworkView` is the shared contract DTO; re-exported so the reconcile loops and
// their tests keep referring to it via `crate::work_queue::NetworkView`.
pub use wardnet_common::contract::NetworkView;
use wardnet_common::contract::{ReconcileQuery, TransitionRequest};
use wardnet_common::mtls::MeshClient;

/// The desired-state work queue the provisioner/reaper drain and report back to.
///
/// The trait is the unit-test seam: the loops depend on `Arc<dyn WorkQueue>`, so
/// they can run against a mock with no live mTLS.
#[async_trait]
pub trait WorkQueue: Send + Sync {
    /// Fetch a cursor page of networks in `state` for `region`, after `after_id`
    /// (exclusive), at most `limit`.
    async fn list(
        &self,
        state: &str,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<NetworkView>>;

    /// Report a network's reconciled state back to Tenants (`active` once the A
    /// record is published, `deprovisioned` once it is torn down).
    async fn transition(&self, id: &str, target: &str) -> anyhow::Result<()>;
}

/// [`WorkQueue`] backed by the Tenants mesh work-queue over mutual TLS.
///
/// Holds a **static** [`MeshClient`] (cert rotation is deferred). The query is
/// built with the camelCase keys Tenants expects; the PATCH body is
/// `{"provisioningState": target}`; a `204 No Content` is treated as success.
pub struct TenantsWorkQueue {
    mesh: Arc<MeshClient>,
    base_url: String,
}

impl TenantsWorkQueue {
    /// Build the client. `base_url` is the Tenants mesh listener base (e.g.
    /// `https://tenants.mesh:9443`), with no trailing slash.
    #[must_use]
    pub fn new(mesh: Arc<MeshClient>, base_url: String) -> Self {
        let mut base_url = base_url;
        base_url.truncate(base_url.trim_end_matches('/').len());
        Self { mesh, base_url }
    }
}

#[async_trait]
impl WorkQueue for TenantsWorkQueue {
    #[tracing::instrument(skip(self), fields(provisioning_state = state, region))]
    async fn list(
        &self,
        state: &str,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<NetworkView>> {
        let url = format!("{}/v1/networks", self.base_url);
        let query = ReconcileQuery {
            provisioning_state: state.to_string(),
            region: region.to_string(),
            after_id: after_id.map(str::to_string),
            limit: Some(limit),
        };

        // Build → inject W3C trace context → execute, so Tenants continues this trace.
        let client = self.mesh.current();
        let request = client.get(&url).query(&query).build()?;
        let request = wardnet_common::telemetry::inject_trace_context(request);
        let resp = client.execute(request).await?.error_for_status()?;
        let networks = resp.json::<Vec<NetworkView>>().await?;
        Ok(networks)
    }

    #[tracing::instrument(skip(self))]
    async fn transition(&self, id: &str, target: &str) -> anyhow::Result<()> {
        let url = format!("{}/v1/networks/{id}", self.base_url);
        let body = TransitionRequest {
            provisioning_state: target.to_string(),
        };
        let client = self.mesh.current();
        let request = client.patch(&url).json(&body).build()?;
        let request = wardnet_common::telemetry::inject_trace_context(request);
        let resp = client.execute(request).await?.error_for_status()?;
        let status = resp.status();
        if status != reqwest::StatusCode::NO_CONTENT {
            anyhow::bail!("unexpected status {status} transitioning network {id} to {target}");
        }
        Ok(())
    }
}
