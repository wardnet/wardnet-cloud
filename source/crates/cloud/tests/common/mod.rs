#![allow(dead_code)]

//! Shared test helpers for the cloud (DDNS + Tunneller) integration suite.
//!
//! Holds the mock operational repository and mock DNS provider (the traits this
//! crate owns / consumes), plus the deterministic JWT keypair helper. Cloud auth
//! is **JWT-only** — there is no identity DB here — so there is no identity mock;
//! the keypair helper duplicates the crate-internal one (integration tests cannot
//! cross the `cfg(test)` boundary).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use wardnet_cloud::repository::{Operational, OperationalRepository};
use wardnet_common::dns_provider::DnsProvider;

// ── Shared helpers ───────────────────────────────────────────────────────────

/// A deterministic `EdDSA` JWT keypair as `(private_pkcs8_pem, public_spki_pem)`,
/// derived from `seed`. Mirrors the crate-internal `test_helpers::jwt_keypair_pem`
/// (which integration tests cannot reach across the `cfg(test)` boundary).
#[must_use]
pub fn jwt_keypair_pem(seed: u8) -> (String, String) {
    use ed25519_dalek::SigningKey;
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

// ── Mock operational repository (regional DB) ────────────────────────────────

pub struct MockOperationalRepository {
    rows: Mutex<HashMap<String, Operational>>,
}

impl MockOperationalRepository {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockOperationalRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OperationalRepository for MockOperationalRepository {
    async fn find_by_id(&self, install_id: &str) -> anyhow::Result<Option<Operational>> {
        Ok(self.rows.lock().unwrap().get(install_id).cloned())
    }

    async fn upsert_ip(
        &self,
        install_id: &str,
        ip: &str,
        cf_a_record_id: &str,
        updated_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let mut map = self.rows.lock().unwrap();
        let row = map
            .entry(install_id.to_string())
            .or_insert_with(|| Operational {
                install_id: install_id.to_string(),
                ip: None,
                cf_a_record_id: None,
                cf_acme_record_ids: Vec::new(),
                updated_at,
            });
        row.ip = Some(ip.to_string());
        row.cf_a_record_id = Some(cf_a_record_id.to_string());
        row.updated_at = updated_at;
        Ok(())
    }

    async fn cas_acme_records(
        &self,
        install_id: &str,
        expected: &[String],
        new_ids: &[String],
        updated_at: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        let mut map = self.rows.lock().unwrap();
        match map.get_mut(install_id) {
            Some(row) => {
                if row.cf_acme_record_ids == expected {
                    row.cf_acme_record_ids = new_ids.to_vec();
                    row.updated_at = updated_at;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            None if expected.is_empty() => {
                map.insert(
                    install_id.to_string(),
                    Operational {
                        install_id: install_id.to_string(),
                        ip: None,
                        cf_a_record_id: None,
                        cf_acme_record_ids: new_ids.to_vec(),
                        updated_at,
                    },
                );
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete(&self, install_id: &str) -> anyhow::Result<()> {
        self.rows.lock().unwrap().remove(install_id);
        Ok(())
    }
}

// ── Mock DNS provider ────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DnsCall {
    UpsertA,
    UpsertTxt,
    DeleteRecord,
}

pub struct MockDnsProvider {
    calls: Mutex<Vec<DnsCall>>,
    error: Option<String>,
}

impl MockDnsProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            error: None,
        }
    }

    #[must_use]
    pub fn with_error(msg: &str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            error: Some(msg.to_string()),
        }
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Default for MockDnsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsProvider for MockDnsProvider {
    async fn upsert_a_record(
        &self,
        fqdn: &str,
        _ip: &str,
        _existing_record_id: Option<&str>,
    ) -> anyhow::Result<String> {
        if let Some(e) = &self.error {
            return Err(anyhow::anyhow!("{e}"));
        }
        self.calls.lock().unwrap().push(DnsCall::UpsertA);
        Ok(format!("cf-a-{fqdn}"))
    }

    async fn upsert_txt_record(
        &self,
        fqdn: &str,
        _content: &str,
        _existing_record_id: Option<&str>,
    ) -> anyhow::Result<String> {
        if let Some(e) = &self.error {
            return Err(anyhow::anyhow!("{e}"));
        }
        self.calls.lock().unwrap().push(DnsCall::UpsertTxt);
        Ok(format!("cf-txt-{fqdn}"))
    }

    async fn delete_record(&self, _record_id: &str) -> anyhow::Result<()> {
        if let Some(e) = &self.error {
            return Err(anyhow::anyhow!("{e}"));
        }
        self.calls.lock().unwrap().push(DnsCall::DeleteRecord);
        Ok(())
    }
}
