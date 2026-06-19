//! Shared test fixtures: deterministic JWT/daemon keypairs, in-memory mock
//! repositories + DNS provider + work queue, and an [`AppState`] builder for the
//! integration tests in `tests/`.
//!
//! Doc-hidden and **not** `cfg(test)` so the integration tests (a separate crate)
//! can reach these too; it carries no extra production dependencies. (A dedicated
//! `wardnet-test-support` crate is the eventual home.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;

use wardnet_common::dns_provider::DnsProvider;
use wardnet_common::token::{Signer, Verifier};

use crate::config::Config;
use crate::repository::operational::{Operational, OperationalRepository};
use crate::service::DdnsService;
use crate::state::AppState;
use crate::work_queue::{NetworkView, WorkQueue};

// ── Key material ────────────────────────────────────────────────────────────────

/// A deterministic `EdDSA` JWT keypair as `(private_pkcs8_pem, public_spki_pem)`,
/// derived from `seed`.
#[must_use]
pub fn jwt_keypair_pem(seed: u8) -> (String, String) {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let private_pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode JWT private key PEM")
        .to_string();
    let public_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode JWT public key PEM");
    (private_pem, public_pem)
}

/// A deterministic daemon request-signing keypair plus the base64 `cnf` of its
/// public key, derived from `seed`.
#[must_use]
pub fn daemon_keypair(seed: u8) -> (SigningKey, String) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let cnf = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
    (key, cnf)
}

/// A `Signer` over the seed keypair — lets tests mint JWTs the built [`AppState`]'s
/// verifier accepts.
#[must_use]
pub fn test_signer(seed: u8) -> Signer {
    Signer::from_pem(jwt_keypair_pem(seed).0.as_bytes(), None).unwrap()
}

// ── In-memory operational repository ─────────────────────────────────────────────

/// In-memory [`OperationalRepository`] mirroring the SQL CAS semantics. `Clone`
/// shares the same backing store (so a handle kept for assertions sees the
/// service's writes).
#[derive(Clone, Default)]
pub struct InMemoryOperational {
    rows: Arc<Mutex<HashMap<String, Operational>>>,
    /// When set, the next `cas_acme_records` returns `false` (simulates a
    /// concurrent ACME writer winning the CAS), then resets.
    force_acme_cas_miss: Arc<std::sync::atomic::AtomicBool>,
}

impl InMemoryOperational {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a single forced `cas_acme_records` miss on the next call.
    pub fn force_next_acme_cas_miss(&self) {
        self.force_acme_cas_miss
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Seed a row that already has an A-record claim (simulates a peer replica
    /// having won the claim before this service runs `provision`).
    pub fn seed_claimed(&self, network_id: &str, fqdn: &str, record_id: &str) {
        self.rows.lock().unwrap().insert(
            network_id.to_string(),
            Operational {
                network_id: network_id.to_string(),
                ip: None,
                fqdn: Some(fqdn.to_string()),
                cf_a_record_id: Some(record_id.to_string()),
                cf_acme_record_ids: Vec::new(),
                updated_at: Utc::now(),
            },
        );
    }

    /// Read a row for assertions.
    #[must_use]
    pub fn get(&self, network_id: &str) -> Option<Operational> {
        self.rows.lock().unwrap().get(network_id).cloned()
    }
}

#[async_trait]
impl OperationalRepository for InMemoryOperational {
    async fn find_by_id(&self, network_id: &str) -> anyhow::Result<Option<Operational>> {
        Ok(self.rows.lock().unwrap().get(network_id).cloned())
    }

    async fn record_ip(
        &self,
        network_id: &str,
        ip: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut data = self.rows.lock().unwrap();
        data.entry(network_id.to_string())
            .and_modify(|o| {
                o.ip = Some(ip.to_string());
                o.updated_at = now;
            })
            .or_insert_with(|| Operational {
                network_id: network_id.to_string(),
                ip: Some(ip.to_string()),
                fqdn: None,
                cf_a_record_id: None,
                cf_acme_record_ids: Vec::new(),
                updated_at: now,
            });
        Ok(())
    }

    async fn claim_a_record(
        &self,
        network_id: &str,
        fqdn: &str,
        record_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let mut data = self.rows.lock().unwrap();
        match data.get_mut(network_id) {
            Some(o) if o.cf_a_record_id.is_none() => {
                o.fqdn = Some(fqdn.to_string());
                o.cf_a_record_id = Some(record_id.to_string());
                o.updated_at = now;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn cas_acme_records(
        &self,
        network_id: &str,
        expected: &[String],
        new_ids: &[String],
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        if self
            .force_acme_cas_miss
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(false);
        }
        let mut data = self.rows.lock().unwrap();
        if expected.is_empty() {
            match data.get_mut(network_id) {
                Some(o) if o.cf_acme_record_ids.is_empty() => {
                    o.cf_acme_record_ids = new_ids.to_vec();
                    o.updated_at = now;
                    Ok(true)
                }
                Some(_) => Ok(false),
                None => {
                    data.insert(
                        network_id.to_string(),
                        Operational {
                            network_id: network_id.to_string(),
                            ip: None,
                            fqdn: None,
                            cf_a_record_id: None,
                            cf_acme_record_ids: new_ids.to_vec(),
                            updated_at: now,
                        },
                    );
                    Ok(true)
                }
            }
        } else {
            match data.get_mut(network_id) {
                Some(o) if o.cf_acme_record_ids == expected => {
                    o.cf_acme_record_ids = new_ids.to_vec();
                    o.updated_at = now;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }

    async fn delete(&self, network_id: &str) -> anyhow::Result<()> {
        self.rows.lock().unwrap().remove(network_id);
        Ok(())
    }
}

// ── Mock DNS provider (simulates a Cloudflare zone) ───────────────────────────────

#[derive(Default)]
struct DnsState {
    /// `record_id` → (kind `'A'`|`'T'`, fqdn)
    records: HashMap<String, (char, String)>,
    next: u64,
    a_creates: usize,
    a_updates: usize,
    deleted: Vec<String>,
}

/// In-memory [`DnsProvider`] that simulates a Cloudflare zone and records call
/// counts for assertions. `Clone` shares the same backing state.
#[derive(Clone, Default)]
pub struct MockDnsProvider(Arc<Mutex<DnsState>>);

impl MockDnsProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of A records currently live in the simulated zone.
    #[must_use]
    pub fn a_record_count(&self) -> usize {
        self.0
            .lock()
            .unwrap()
            .records
            .values()
            .filter(|(k, _)| *k == 'A')
            .count()
    }

    /// How many A-record *creates* (POST) have happened.
    #[must_use]
    pub fn a_creates(&self) -> usize {
        self.0.lock().unwrap().a_creates
    }

    /// How many A-record *updates* (PUT) have happened.
    #[must_use]
    pub fn a_updates(&self) -> usize {
        self.0.lock().unwrap().a_updates
    }

    /// Record ids that have been deleted.
    #[must_use]
    pub fn deleted(&self) -> Vec<String> {
        self.0.lock().unwrap().deleted.clone()
    }
}

#[async_trait]
impl DnsProvider for MockDnsProvider {
    async fn upsert_a_record(
        &self,
        fqdn: &str,
        _ip: &str,
        existing_record_id: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut st = self.0.lock().unwrap();
        if let Some(id) = existing_record_id {
            st.a_updates += 1;
            st.records.insert(id.to_string(), ('A', fqdn.to_string()));
            Ok(id.to_string())
        } else {
            st.next += 1;
            let id = format!("a-{}", st.next);
            st.a_creates += 1;
            st.records.insert(id.clone(), ('A', fqdn.to_string()));
            Ok(id)
        }
    }

    async fn upsert_txt_record(
        &self,
        fqdn: &str,
        _content: &str,
        existing_record_id: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut st = self.0.lock().unwrap();
        if let Some(id) = existing_record_id {
            st.records.insert(id.to_string(), ('T', fqdn.to_string()));
            Ok(id.to_string())
        } else {
            st.next += 1;
            let id = format!("t-{}", st.next);
            st.records.insert(id.clone(), ('T', fqdn.to_string()));
            Ok(id)
        }
    }

    async fn delete_record(&self, record_id: &str) -> anyhow::Result<()> {
        let mut st = self.0.lock().unwrap();
        st.records.remove(record_id);
        st.deleted.push(record_id.to_string());
        Ok(())
    }

    async fn find_a_record(&self, fqdn: &str) -> anyhow::Result<Option<String>> {
        let st = self.0.lock().unwrap();
        Ok(st
            .records
            .iter()
            .find(|(_, (k, f))| *k == 'A' && f == fqdn)
            .map(|(id, _)| id.clone()))
    }
}

// ── Mock work queue ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct QueueState {
    networks: Vec<NetworkView>,
    transitions: Vec<(String, String)>,
    fail_transition: bool,
}

/// In-memory [`WorkQueue`]. `Clone` shares the same backing state.
#[derive(Clone, Default)]
pub struct MockWorkQueue(Arc<Mutex<QueueState>>);

impl MockWorkQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a network onto the queue.
    pub fn seed(&self, view: NetworkView) {
        self.0.lock().unwrap().networks.push(view);
    }

    /// Make every `transition` call fail (PATCH-failure test).
    pub fn fail_transitions(&self) {
        self.0.lock().unwrap().fail_transition = true;
    }

    /// The `(id, target)` transitions that were reported.
    #[must_use]
    pub fn transitions(&self) -> Vec<(String, String)> {
        self.0.lock().unwrap().transitions.clone()
    }
}

#[async_trait]
impl WorkQueue for MockWorkQueue {
    async fn list(
        &self,
        state: &str,
        region: &str,
        after_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<NetworkView>> {
        let st = self.0.lock().unwrap();
        let mut matching: Vec<NetworkView> = st
            .networks
            .iter()
            .filter(|n| n.provisioning_state.as_str() == state && n.region == region)
            .filter(|n| after_id.is_none_or(|a| n.id.as_str() > a))
            .cloned()
            .collect();
        matching.sort_by(|a, b| a.id.cmp(&b.id));
        matching.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(matching)
    }

    async fn transition(&self, id: &str, target: &str) -> anyhow::Result<()> {
        let mut st = self.0.lock().unwrap();
        if st.fail_transition {
            anyhow::bail!("simulated transition failure");
        }
        st.transitions.push((id.to_string(), target.to_string()));
        // Drop the network from the queue (Tenants would move/delete it).
        st.networks.retain(|n| n.id != id);
        Ok(())
    }
}

// ── Config + AppState ─────────────────────────────────────────────────────────────

/// A throwaway [`Config`] (no real listeners/PEM are opened in mock-backed tests).
#[must_use]
pub fn test_config() -> Config {
    Config {
        database_url: "postgres://ignored".to_string(),
        cloudflare_api_token: "ignored".to_string(),
        cloudflare_zone_id: "ignored".to_string(),
        cloudflare_api_base: None,
        subdomain_parent: "my.wardnet.services".to_string(),
        region: "use1".to_string(),
        api_listen_addr: "127.0.0.1:0".to_string(),
        mesh_base_url: "https://tenants.mesh:9443".to_string(),
        trust_bundle_path: "/dev/null".to_string(),
        leaf_cert_path: "/dev/null".to_string(),
        leaf_key_path: "/dev/null".to_string(),
        provisioner_interval_secs: 10,
        reaper_interval_secs: 300,
        reaper_jitter_secs: 0,
    }
}

/// Build an [`AppState`] backed by the given mocks, with a verifier over `seed`'s
/// keypair (so `test_signer(seed)`-minted tokens are accepted).
#[must_use]
pub fn build_state(seed: u8, op: InMemoryOperational, dns: MockDnsProvider) -> AppState {
    let service = Arc::new(DdnsService::new(Arc::new(op), Arc::new(dns)));
    let verifier = Verifier::from_pem(jwt_keypair_pem(seed).1.as_bytes(), "ddns").unwrap();
    AppState::new(test_config(), service, verifier)
}
