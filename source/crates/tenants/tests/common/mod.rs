#![allow(dead_code)]

//! Shared test helpers for the Tenants integration suite.
//!
//! Holds the mock identity + challenge repositories (the two traits Tenants owns),
//! the deterministic JWT keypair helper, and the request-signing helpers the
//! full-stack API tests use. The `jwt_keypair_pem` helper duplicates the
//! crate-internal `test_helpers::jwt_keypair_pem` — integration tests are compiled
//! as a separate crate and cannot reach across the `cfg(test)` boundary, so this
//! duplication is the established pattern.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use wardnet_tenants::repository::{
    ChallengeRepository, Identity, IdentityRepository, RegisterOutcome, RegistrationChallenge,
    Status,
};

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

/// The `registration_challenges` table — shared between the identity and challenge
/// mocks so the identity mock's atomic `register` (which burns the challenge in the
/// same transaction as the PG impl) sees the same rows the challenge mock issued.
pub type ChallengeStore = Arc<Mutex<HashMap<String, RegistrationChallenge>>>;

// ── Mock identity repository (global Tenants DB) ─────────────────────────────

pub struct MockIdentityRepository {
    identities: Mutex<HashMap<String, Identity>>,
    log: Mutex<Vec<(String, DateTime<Utc>)>>,
    challenges: ChallengeStore,
    /// When true, `register` fails after burning the challenge — exercises the
    /// atomic rollback (the burn is undone).
    fail_register: bool,
}

impl MockIdentityRepository {
    #[must_use]
    pub fn new(challenges: ChallengeStore) -> Self {
        Self {
            identities: Mutex::new(HashMap::new()),
            log: Mutex::new(Vec::new()),
            challenges,
            fail_register: false,
        }
    }

    /// An identity repo whose `register` always fails (after burning) — to assert
    /// the transaction rolls the burn back.
    #[must_use]
    pub fn failing_register(challenges: ChallengeStore) -> Self {
        Self {
            fail_register: true,
            ..Self::new(challenges)
        }
    }

    fn unburn(&self, challenge_id: &str) {
        if let Some(c) = self.challenges.lock().unwrap().get_mut(challenge_id) {
            c.used_at = None;
        }
    }

    /// Seed an identity directly (test fixture), bypassing the challenge-gated
    /// `register` — for tests that need a pre-existing authenticated install.
    pub fn seed(&self, identity: Identity) {
        self.identities
            .lock()
            .unwrap()
            .insert(identity.id.clone(), identity);
    }
}

#[async_trait]
impl IdentityRepository for MockIdentityRepository {
    async fn register(
        &self,
        identity: &Identity,
        challenge_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<RegisterOutcome> {
        // Burn the challenge (atomic with the insert below).
        {
            let mut ch = self.challenges.lock().unwrap();
            match ch.get_mut(challenge_id) {
                Some(c) if c.used_at.is_none() => c.used_at = Some(now),
                _ => return Ok(RegisterOutcome::ChallengeAlreadyUsed),
            }
        }

        if self.fail_register {
            self.unburn(challenge_id);
            anyhow::bail!("simulated register failure");
        }

        let mut ids = self.identities.lock().unwrap();
        if ids.values().any(|i| i.name == identity.name) {
            drop(ids);
            self.unburn(challenge_id); // name clash rolls back the burn
            return Ok(RegisterOutcome::NameTaken);
        }
        ids.insert(identity.id.clone(), identity.clone());
        Ok(RegisterOutcome::Registered)
    }

    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<Identity>> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .get(id)
            .filter(|i| i.status == Status::Active)
            .cloned())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> anyhow::Result<Option<Identity>> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .values()
            .find(|i| i.token_hash == token_hash && i.status == Status::Active)
            .cloned())
    }

    async fn is_name_taken(&self, name: &str) -> anyhow::Result<bool> {
        // The name allocation survives a tombstone, so any-status match.
        Ok(self
            .identities
            .lock()
            .unwrap()
            .values()
            .any(|i| i.name == name))
    }

    async fn tombstone(&self, id: &str, _now: DateTime<Utc>) -> anyhow::Result<()> {
        if let Some(i) = self.identities.lock().unwrap().get_mut(id) {
            i.status = Status::Deregistered;
        }
        Ok(())
    }

    async fn find_inactive(&self, ids: &[String]) -> anyhow::Result<Vec<String>> {
        let map = self.identities.lock().unwrap();
        Ok(ids
            .iter()
            .filter(|id| map.get(*id).is_none_or(|i| i.status != Status::Active))
            .cloned()
            .collect())
    }

    async fn count_registrations_from_ip(
        &self,
        remote_ip: &str,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64> {
        let log = self.log.lock().unwrap();
        let count = log
            .iter()
            .filter(|(ip, created_at)| ip == remote_ip && *created_at > since)
            .count();
        Ok(i64::try_from(count).unwrap_or(i64::MAX))
    }

    async fn log_registration(
        &self,
        remote_ip: &str,
        created_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        self.log
            .lock()
            .unwrap()
            .push((remote_ip.to_string(), created_at));
        Ok(())
    }
}

// ── Mock challenge repository ────────────────────────────────────────────────

pub struct MockChallengeRepository {
    challenges: ChallengeStore,
}

impl MockChallengeRepository {
    #[must_use]
    pub fn new(challenges: ChallengeStore) -> Self {
        Self { challenges }
    }
}

#[async_trait]
impl ChallengeRepository for MockChallengeRepository {
    async fn insert(&self, challenge: &RegistrationChallenge) -> anyhow::Result<()> {
        self.challenges
            .lock()
            .unwrap()
            .insert(challenge.id.clone(), challenge.clone());
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> anyhow::Result<Option<RegistrationChallenge>> {
        Ok(self.challenges.lock().unwrap().get(id).cloned())
    }

    async fn count_from_ip(&self, remote_ip: &str, since: DateTime<Utc>) -> anyhow::Result<i64> {
        let map = self.challenges.lock().unwrap();
        let count = map
            .values()
            .filter(|c| c.remote_ip == remote_ip && c.created_at > since)
            .count();
        Ok(i64::try_from(count).unwrap_or(i64::MAX))
    }
}
