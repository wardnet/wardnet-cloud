//! The Tenants mesh **client** — the read side of the routing policy.
//!
//! The Tunneller resolves a daemon's `net` claim (a network UUID) to the vanity
//! slug, and checks the owning tenant's subscription, by reading the full Network
//! and Tenant resources over mesh mTLS (`GET /v1/networks/{id}`, `GET
//! /v1/tenants/{id}`). The shared response DTOs are [`NetworkView`] / [`TenantView`]
//! (`wardnet_common::contract`); a `404` reads as `None`.
//!
//! [`TenantsResolver`] is the test seam — the endpoint and the abort reaper depend
//! on `Arc<dyn TenantsResolver>`, so they run against a mock with no live mTLS.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

use wardnet_common::contract::{NetworkView, TenantView};
use wardnet_common::mtls::MeshClient;

/// Reads of the Tenants service the Tunneller's routing policy needs.
#[async_trait]
pub trait TenantsResolver: Send + Sync {
    /// Fetch the full Network resource, or `None` if Tenants returns `404`.
    async fn get_network(&self, id: &str) -> anyhow::Result<Option<NetworkView>>;
    /// Fetch the full Tenant resource, or `None` if Tenants returns `404`.
    async fn get_tenant(&self, id: &str) -> anyhow::Result<Option<TenantView>>;
}

/// [`TenantsResolver`] backed by the Tenants mesh listener over mutual TLS.
///
/// Holds a **static** [`MeshClient`] (cert rotation is deferred). No caching: a
/// tunnel channel lives for days, so one lookup at establishment is negligible.
pub struct TenantsClient {
    mesh: Arc<MeshClient>,
    base_url: String,
}

impl TenantsClient {
    /// Build the client. `base_url` is the Tenants mesh listener base (e.g.
    /// `https://tenants.mesh:9443`), with no trailing slash.
    #[must_use]
    pub fn new(mesh: Arc<MeshClient>, base_url: String) -> Self {
        let mut base_url = base_url;
        base_url.truncate(base_url.trim_end_matches('/').len());
        Self { mesh, base_url }
    }

    /// `GET {base}{path}` over mTLS, mapping `200 → Some`, `404 → None`.
    #[tracing::instrument(skip(self))]
    async fn get_resource<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<Option<T>> {
        let url = format!("{}{path}", self.base_url);
        // Build → inject W3C trace context → execute, so Tenants continues this trace.
        let client = self.mesh.current();
        let request = client.get(&url).build()?;
        let request = wardnet_common::telemetry::inject_trace_context(request);
        let resp = client.execute(request).await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json::<T>().await?)),
            StatusCode::NOT_FOUND => Ok(None),
            status => {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Tenants GET {path} returned {status}: {body}")
            }
        }
    }
}

#[async_trait]
impl TenantsResolver for TenantsClient {
    async fn get_network(&self, id: &str) -> anyhow::Result<Option<NetworkView>> {
        self.get_resource(&format!("/v1/networks/{id}")).await
    }

    async fn get_tenant(&self, id: &str) -> anyhow::Result<Option<TenantView>> {
        self.get_resource(&format!("/v1/tenants/{id}")).await
    }
}
