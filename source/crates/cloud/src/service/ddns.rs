//! The DDNS service — regional DNS operational plane.
//!
//! Owns the regional [`OperationalRepository`] **and** the [`DnsProvider`], so it
//! is the single owner of "a Cloudflare record write plus its persistence". Every
//! method reads the install's current operational row **fresh** (never a stale
//! auth-time snapshot) and persists the result, so sequential calls are always
//! consistent. The ACME replace-set persists with a compare-and-set so a
//! concurrent writer is detected (returns [`DdnsError::Conflict`]) rather than
//! silently clobbered.

use std::sync::Arc;

use chrono::Utc;

use crate::repository::OperationalRepository;
use wardnet_common::dns_provider::DnsProvider;

/// Domain error for [`DdnsService`]. Transport-neutral; mapped to `ApiError` at
/// the API layer (`From` in `crate::error`).
#[derive(Debug, thiserror::Error)]
pub enum DdnsError {
    /// A concurrent ACME write changed the stored record set underneath this one
    /// (the compare-and-set missed). The caller should retry.
    #[error("{0}")]
    Conflict(String),
    /// A provider or repository failure.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Regional DNS operational service.
pub struct DdnsService {
    operational: Arc<dyn OperationalRepository>,
    dns: Arc<dyn DnsProvider>,
}

impl DdnsService {
    /// Wire the service over its operational repository and DNS provider.
    #[must_use]
    pub fn new(operational: Arc<dyn OperationalRepository>, dns: Arc<dyn DnsProvider>) -> Self {
        Self { operational, dns }
    }

    /// Publish `ip` for `install_id` at `fqdn`: upsert the Cloudflare A record
    /// (updating in place if one already exists) and persist the result.
    ///
    /// # Errors
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn publish_ip(
        &self,
        install_id: &str,
        fqdn: &str,
        ip: &str,
    ) -> Result<(), DdnsError> {
        let existing = self.operational.find_by_id(install_id).await?;
        let existing_a = existing.as_ref().and_then(|o| o.cf_a_record_id.as_deref());

        let record_id = self
            .dns
            .upsert_a_record(fqdn, ip, existing_a)
            .await
            .map_err(|e| {
                tracing::error!(install_id, error = %e, "Cloudflare A-record upsert failed");
                e
            })?;

        self.operational
            .upsert_ip(install_id, ip, &record_id, Utc::now())
            .await?;
        tracing::info!(install_id, ip, fqdn, "IP record updated");
        Ok(())
    }

    /// Set the ACME DNS-01 challenge for `install_id` at `fqdn`: delete the prior
    /// challenge's stale TXT records, create one per value, and persist the new IDs
    /// with a compare-and-set against the freshly-read prior set.
    ///
    /// A per-user wildcard cert authorises two SANs through the same
    /// `_acme-challenge` name, so `values` typically carries two co-existing TXT
    /// records.
    ///
    /// # Errors
    /// [`DdnsError::Conflict`] if a concurrent ACME write won the CAS;
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn set_acme_challenge(
        &self,
        install_id: &str,
        fqdn: &str,
        values: &[String],
    ) -> Result<(), DdnsError> {
        let prior = self.current_acme_ids(install_id).await?;

        // Delete the prior challenge's stale records first. A failure leaves the
        // stored IDs untouched (we never reached the persist), so the next call
        // retries the delete.
        self.delete_records_or_err(install_id, &prior, "delete (stale)")
            .await?;

        // Create the new TXT records. On a partial failure, best-effort delete what
        // we created and clear the stored IDs (the old ones are already gone), then
        // surface the ORIGINAL provider error — the clear is bookkeeping and must
        // never mask the real cause.
        let mut new_ids = Vec::with_capacity(values.len());
        for value in values {
            match self.dns.upsert_txt_record(fqdn, value, None).await {
                Ok(record_id) => new_ids.push(record_id),
                Err(e) => {
                    self.cleanup_created(install_id, &new_ids).await;
                    if let Err(clear_err) = self
                        .operational
                        .cas_acme_records(install_id, &prior, &[], Utc::now())
                        .await
                    {
                        tracing::error!(install_id, error = %clear_err, "failed to clear ACME IDs after a create failure");
                    }
                    tracing::error!(install_id, error = %e, "Cloudflare ACME TXT create failed");
                    return Err(DdnsError::Internal(e));
                }
            }
        }

        self.cas_or_conflict(install_id, &prior, &new_ids).await?;
        tracing::info!(
            install_id,
            fqdn,
            count = new_ids.len(),
            "ACME TXT records set"
        );
        Ok(())
    }

    /// Clear the ACME challenge for `install_id`: delete every live TXT record and
    /// clear the stored IDs. Idempotent — a no-op when none is live.
    ///
    /// # Errors
    /// [`DdnsError::Conflict`] on a CAS miss; [`DdnsError::Internal`] otherwise.
    pub async fn clear_acme_challenge(&self, install_id: &str) -> Result<(), DdnsError> {
        let prior = self.current_acme_ids(install_id).await?;
        if prior.is_empty() {
            return Ok(());
        }
        self.delete_records_or_err(install_id, &prior, "delete")
            .await?;
        self.cas_or_conflict(install_id, &prior, &[]).await?;
        tracing::info!(install_id, count = prior.len(), "ACME TXT records deleted");
        Ok(())
    }

    /// Tear down all of an install's DNS state (deregistration): delete the A
    /// record and any live ACME TXT records, then drop the operational row.
    /// Idempotent — a no-op when the install has no operational row.
    ///
    /// # Errors
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn delete_records(&self, install_id: &str) -> Result<(), DdnsError> {
        let Some(op) = self.operational.find_by_id(install_id).await? else {
            return Ok(());
        };

        if let Some(record_id) = &op.cf_a_record_id {
            self.dns.delete_record(record_id).await.map_err(|e| {
                tracing::error!(install_id, error = %e, "Cloudflare A-record delete failed on deregister");
                e
            })?;
        }
        for record_id in &op.cf_acme_record_ids {
            self.dns.delete_record(record_id).await.map_err(|e| {
                tracing::error!(install_id, error = %e, "Cloudflare ACME TXT delete failed on deregister");
                e
            })?;
        }
        self.operational.delete(install_id).await?;
        Ok(())
    }

    // ── private ────────────────────────────────────────────────────────────────

    /// The install's currently-stored ACME record IDs (empty when no row exists).
    async fn current_acme_ids(&self, install_id: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .operational
            .find_by_id(install_id)
            .await?
            .map(|o| o.cf_acme_record_ids)
            .unwrap_or_default())
    }

    /// Best-effort delete of records created during a failed `set_acme_challenge`.
    async fn cleanup_created(&self, install_id: &str, created: &[String]) {
        for record_id in created {
            if let Err(e) = self.dns.delete_record(record_id).await {
                tracing::warn!(
                    install_id, record_id = %record_id, error = %e,
                    "ACME TXT cleanup delete failed after a partial create; record may be orphaned"
                );
            }
        }
    }

    /// Delete every record in `ids`, surfacing the first provider error. A failure
    /// here leaves the stored IDs untouched (no persist has run), so the next call
    /// retries the delete.
    async fn delete_records_or_err(
        &self,
        install_id: &str,
        ids: &[String],
        op: &str,
    ) -> Result<(), DdnsError> {
        for record_id in ids {
            self.dns.delete_record(record_id).await.map_err(|e| {
                tracing::error!(install_id, op, error = %e, "Cloudflare ACME TXT delete failed");
                DdnsError::Internal(e)
            })?;
        }
        Ok(())
    }

    /// Persist `new_ids` via compare-and-set against `prior`, turning a CAS miss
    /// (a concurrent ACME write changed the stored set after our fresh read) into a
    /// [`DdnsError::Conflict`] so the daemon retries cleanly.
    async fn cas_or_conflict(
        &self,
        install_id: &str,
        prior: &[String],
        new_ids: &[String],
    ) -> Result<(), DdnsError> {
        if self
            .operational
            .cas_acme_records(install_id, prior, new_ids, Utc::now())
            .await?
        {
            return Ok(());
        }
        tracing::warn!(
            install_id,
            "ACME record CAS miss — concurrent challenge write; created records may be orphaned"
        );
        Err(DdnsError::Conflict(
            "a concurrent ACME challenge update was in flight; retry".to_string(),
        ))
    }
}
