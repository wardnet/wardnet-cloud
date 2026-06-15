//! Background reaper for expired ACME HTTP-01 challenge tokens.
//!
//! The former name-reservation sweep is gone: after the identity collapse
//! (#610 3a-ii) registration is a single global-DB transaction, so there is no
//! `reserved` intermediate state to reap and no cross-database orphan to clean.
//! What remains is reaping expired `acme_http_challenge` tokens so a failed cert
//! order cannot strand one (mirroring the daemon's "always clear the challenge"
//! discipline).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::repository::TlsRepository;

/// How often the sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_mins(1);

/// Background loop that reaps expired ACME HTTP-01 challenge tokens every
/// [`SWEEP_INTERVAL`]. Never returns; spawn it as a detached task. A failed pass
/// is logged and retried on the next tick.
pub async fn run(tls: Arc<dyn TlsRepository>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        match tls.delete_expired_challenges(Utc::now()).await {
            Ok(n) if n > 0 => tracing::debug!(count = n, "reaped expired ACME challenge tokens"),
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "failed to reap expired ACME challenges"),
        }
    }
}
