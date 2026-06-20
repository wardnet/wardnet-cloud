//! The DDNS service — regional DNS operational plane.
//!
//! Owns the regional [`OperationalRepository`] **and** the [`DnsProvider`], so it
//! is the single owner of "a Cloudflare record write plus its persistence". Every
//! method reads the network's current operational row **fresh** (never a stale
//! snapshot) and persists the result.
//!
//! The write model is **hybrid** (see `docs/adr/0003`): the **provisioner** is the
//! sole *creator* of the A record (it alone sees the slug→FQDN and pulls live
//! desired state), while **report-IP** only ever *updates the record in place* —
//! it never creates one, so it cannot resurrect a record the reaper just deleted.
//! Provisioning tolerates N regional replicas via an **adopt-or-create + CAS**
//! claim. The ACME replace-set persists with a compare-and-set so a concurrent
//! writer is detected (returns [`DdnsError::Conflict`]) rather than clobbered.

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

    /// Report the daemon's current `ip` for `network_id`.
    ///
    /// Updates the A record **in place** only when one has already been published
    /// (the provisioner stored its `fqdn` + `cf_a_record_id`); it never *creates*
    /// a record. Either way it stores the reported IP. So a report arriving after
    /// the reaper deleted the record cannot resurrect it — it just re-stores the IP
    /// into a (possibly fresh) row, which is harmless and bounded by the JWT's
    /// short TTL.
    ///
    /// # Errors
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn report_ip(&self, network_id: &str, ip: &str) -> Result<(), DdnsError> {
        let op = self.operational.find_by_id(network_id).await?;
        if let Some(op) = &op
            && let (Some(record_id), Some(fqdn)) =
                (op.cf_a_record_id.as_deref(), op.fqdn.as_deref())
        {
            self.dns
                .upsert_a_record(fqdn, ip, Some(record_id))
                .await
                .map_err(|e| {
                    tracing::error!(network_id, error = %e, "Cloudflare A-record update failed");
                    e
                })?;
        }

        self.operational
            .record_ip(network_id, ip, Utc::now())
            .await?;
        tracing::info!(network_id, ip, "IP reported");
        Ok(())
    }

    /// Publish the A record for a `provisioning` network at `fqdn` with `ip`, the
    /// provisioner's sole job. **Adopt-or-create + CAS claim**, safe across N
    /// regional replicas:
    ///
    /// 1. Adopt an existing A record for `fqdn` (update it in place) if one is
    ///    found, else create a fresh one.
    /// 2. CAS-store the record id (only if none is stored yet).
    /// 3. If the CAS lost to a peer, best-effort delete the record we hold —
    ///    **unless** it is the one the winner stored (we adopted the winner's
    ///    record), so we drop only a true duplicate and keep the live record.
    ///
    /// Idempotent: a network already claimed by this region re-adopts and loses
    /// the CAS, leaving the live record untouched.
    ///
    /// # Errors
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn provision(&self, network_id: &str, fqdn: &str, ip: &str) -> Result<(), DdnsError> {
        let existing = self.dns.find_a_record(fqdn).await?;
        let record_id = self
            .dns
            .upsert_a_record(fqdn, ip, existing.as_deref())
            .await
            .map_err(|e| {
                tracing::error!(network_id, error = %e, "Cloudflare A-record publish failed");
                e
            })?;

        let won = self
            .operational
            .claim_a_record(network_id, fqdn, &record_id, Utc::now())
            .await?;
        if !won {
            // A peer replica already claimed this network. Drop the record we hold
            // only if it is NOT the one the winner stored — otherwise we adopted the
            // winner's live record and must keep it.
            let winner = self
                .operational
                .find_by_id(network_id)
                .await?
                .and_then(|o| o.cf_a_record_id);
            if winner.as_deref() != Some(record_id.as_str())
                && let Err(e) = self.dns.delete_record(&record_id).await
            {
                tracing::warn!(
                    network_id, record_id = %record_id, error = %e,
                    "failed to delete duplicate A record after losing the claim; may be orphaned"
                );
            }
            tracing::debug!(network_id, "A-record claim lost to a peer replica (no-op)");
            return Ok(());
        }

        tracing::info!(network_id, fqdn, ip, "A record published");
        Ok(())
    }

    /// The FQDN the provisioner published this network's A record under, or `None`
    /// if it has not been provisioned yet (no row, or no `fqdn` stored). The ACME
    /// endpoint uses this to derive `_acme-challenge.<fqdn>` — a daemon cannot set a
    /// challenge before its network is active.
    ///
    /// # Errors
    /// [`DdnsError::Internal`] on a repository failure.
    pub async fn network_fqdn(&self, network_id: &str) -> Result<Option<String>, DdnsError> {
        Ok(self
            .operational
            .find_by_id(network_id)
            .await?
            .and_then(|o| o.fqdn))
    }

    /// Set the ACME DNS-01 challenge for `network_id` at `fqdn`: delete the prior
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
        network_id: &str,
        fqdn: &str,
        values: &[String],
    ) -> Result<(), DdnsError> {
        let prior = self.current_acme_ids(network_id).await?;

        // Delete the prior challenge's stale records first. A failure leaves the
        // stored IDs untouched (we never reached the persist), so the next call
        // retries the delete.
        self.delete_records_or_err(network_id, &prior, "delete (stale)")
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
                    self.cleanup_created(network_id, &new_ids).await;
                    if let Err(clear_err) = self
                        .operational
                        .cas_acme_records(network_id, &prior, &[], Utc::now())
                        .await
                    {
                        tracing::error!(network_id, error = %clear_err, "failed to clear ACME IDs after a create failure");
                    }
                    tracing::error!(network_id, error = %e, "Cloudflare ACME TXT create failed");
                    return Err(DdnsError::Internal(e));
                }
            }
        }

        self.cas_or_conflict(network_id, &prior, &new_ids).await?;
        tracing::info!(
            network_id,
            fqdn,
            count = new_ids.len(),
            "ACME TXT records set"
        );
        Ok(())
    }

    /// Clear the ACME challenge for `network_id`: delete every live TXT record and
    /// clear the stored IDs. Idempotent — a no-op when none is live.
    ///
    /// # Errors
    /// [`DdnsError::Conflict`] if a concurrent ACME write won the CAS;
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn clear_acme_challenge(&self, network_id: &str) -> Result<(), DdnsError> {
        let prior = self.current_acme_ids(network_id).await?;
        if prior.is_empty() {
            return Ok(());
        }

        self.delete_records_or_err(network_id, &prior, "delete")
            .await?;
        self.cas_or_conflict(network_id, &prior, &[]).await?;
        tracing::info!(network_id, count = prior.len(), "ACME TXT records deleted");
        Ok(())
    }

    /// Tear down all of a network's DNS state (the reaper): delete the A record and
    /// any live ACME TXT records, then drop the operational row. Idempotent — a
    /// no-op when the network has no operational row (Cloudflare delete treats a
    /// 404 as success, so re-running is safe).
    ///
    /// # Errors
    /// [`DdnsError::Internal`] on a provider or repository failure.
    pub async fn delete_records(&self, network_id: &str) -> Result<(), DdnsError> {
        let Some(op) = self.operational.find_by_id(network_id).await? else {
            return Ok(());
        };

        if let Some(record_id) = &op.cf_a_record_id {
            self.dns.delete_record(record_id).await.map_err(|e| {
                tracing::error!(network_id, error = %e, "Cloudflare A-record delete failed on reap");
                e
            })?;
        }
        for record_id in &op.cf_acme_record_ids {
            self.dns.delete_record(record_id).await.map_err(|e| {
                tracing::error!(network_id, error = %e, "Cloudflare ACME TXT delete failed on reap");
                e
            })?;
        }
        self.operational.delete(network_id).await?;
        Ok(())
    }

    // ── private ────────────────────────────────────────────────────────────────

    /// The network's currently-stored ACME record IDs (empty when no row exists).
    async fn current_acme_ids(&self, network_id: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .operational
            .find_by_id(network_id)
            .await?
            .map(|o| o.cf_acme_record_ids)
            .unwrap_or_default())
    }

    /// Best-effort delete of records created during a failed `set_acme_challenge`.
    async fn cleanup_created(&self, network_id: &str, created: &[String]) {
        for record_id in created {
            if let Err(e) = self.dns.delete_record(record_id).await {
                tracing::warn!(
                    network_id, record_id = %record_id, error = %e,
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
        network_id: &str,
        ids: &[String],
        op: &str,
    ) -> Result<(), DdnsError> {
        for record_id in ids {
            self.dns.delete_record(record_id).await.map_err(|e| {
                tracing::error!(network_id, op, error = %e, "Cloudflare ACME TXT delete failed");
                DdnsError::Internal(e)
            })?;
        }
        Ok(())
    }

    /// Persist `new_ids` via compare-and-set against `prior`, turning a CAS miss
    /// (a concurrent ACME write changed the stored set after the read) into a
    /// [`DdnsError::Conflict`] so the daemon retries cleanly.
    async fn cas_or_conflict(
        &self,
        network_id: &str,
        prior: &[String],
        new_ids: &[String],
    ) -> Result<(), DdnsError> {
        if self
            .operational
            .cas_acme_records(network_id, prior, new_ids, Utc::now())
            .await?
        {
            return Ok(());
        }
        tracing::warn!(
            network_id,
            "ACME record CAS miss — concurrent challenge write; created records may be orphaned"
        );
        Err(DdnsError::Conflict(
            "a concurrent ACME challenge update was in flight; retry".to_string(),
        ))
    }
}
