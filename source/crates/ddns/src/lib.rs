//! Wardnet DDNS — the regional DNS reconciler.
//!
//! A stateless controller that drives Cloudflare toward the desired state Tenants
//! owns (see `docs/adr/0001`). Two pull-loops reconcile a mesh **work-queue**
//! ([`work_queue`]): a short-interval **provisioner** (`provisioning → active`,
//! publishing the A record) and a long-interval **reaper** (`deprovisioning →`
//! row-deletion, tearing the record down). It also serves daemon-facing
//! **report-IP** and **ACME DNS-01** endpoints over the public, nginx-fronted API.
//!
//! The hybrid write model — provisioner is the sole *creator*, report-IP only ever
//! *updates in place* — is recorded in `docs/adr/0003`.

pub mod api;
pub mod cloudflare;
pub mod config;
pub mod db;
pub mod error;
pub mod reconcile;
pub mod repository;
pub mod service;
pub mod state;
pub mod work_queue;

// Mocks + fixtures shared by unit and integration tests. Doc-hidden and not
// `cfg(test)` so the integration tests in `tests/` can reach it too; carries no
// extra production dependencies. (A dedicated `wardnet-test-support` crate is the
// eventual home — see PLAN-INITIATIVE follow-ups.)
#[doc(hidden)]
pub mod test_helpers;
