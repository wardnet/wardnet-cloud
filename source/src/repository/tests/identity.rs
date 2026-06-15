use chrono::Utc;

use crate::db::DbPools;
use crate::repository::ChallengeRepository;
use crate::repository::challenge::{PgChallengeRepository, RegistrationChallenge};
use crate::repository::identity::{
    Identity, IdentityRepository, PgIdentityRepository, RegisterOutcome, Status,
};
use crate::test_helpers::test_pool_global;

const TEST_PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// `new()` is a trivial one-liner; call it once without `Postgres` so it shows covered.
#[tokio::test]
async fn new_from_lazy_pool() {
    let pool =
        sqlx::PgPool::connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/dummy").unwrap();
    let _ = PgIdentityRepository::new(pool);
}

async fn repos() -> (PgIdentityRepository, PgChallengeRepository) {
    let pool = test_pool_global().await;
    (
        PgIdentityRepository::new_pools(DbPools::single(pool.clone())),
        PgChallengeRepository::new_pools(DbPools::single(pool)),
    )
}

fn sample_identity(id: &str, name: &str) -> Identity {
    Identity {
        id: id.to_string(),
        name: name.to_string(),
        region: "use1".to_string(),
        public_key: TEST_PUBLIC_KEY.to_string(),
        pub_key_bytes: [0u8; 32],
        token_hash: format!("hash_{id}"),
        status: Status::Active,
        created_at: Utc::now(),
    }
}

async fn seed_challenge(challenges: &PgChallengeRepository, id: &str) {
    let now = Utc::now();
    challenges
        .insert(&RegistrationChallenge {
            id: id.to_string(),
            nonce: "00".repeat(32),
            difficulty: 1,
            remote_ip: "203.0.113.1".to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            used_at: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn register_inserts_identity_and_burns_challenge() {
    let (identity, challenges) = repos().await;
    seed_challenge(&challenges, "ch-1").await;

    let outcome = identity
        .register(
            &sample_identity("id-1", "happy-einstein"),
            "ch-1",
            Utc::now(),
        )
        .await
        .unwrap();
    assert_eq!(outcome, RegisterOutcome::Registered);

    let found = identity.find_by_id("id-1").await.unwrap().expect("exists");
    assert_eq!(found.name, "happy-einstein");
    // The challenge is now burned.
    let again = identity
        .register(&sample_identity("id-2", "brave-newton"), "ch-1", Utc::now())
        .await
        .unwrap();
    assert_eq!(again, RegisterOutcome::ChallengeAlreadyUsed);
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn register_name_clash_does_not_burn_challenge() {
    let (identity, challenges) = repos().await;
    seed_challenge(&challenges, "ch-a").await;
    seed_challenge(&challenges, "ch-b").await;

    identity
        .register(&sample_identity("id-a", "taken-name"), "ch-a", Utc::now())
        .await
        .unwrap();

    // A different challenge, same name → NameTaken, and ch-b stays usable.
    let clash = identity
        .register(&sample_identity("id-b", "taken-name"), "ch-b", Utc::now())
        .await
        .unwrap();
    assert_eq!(clash, RegisterOutcome::NameTaken);

    let retry = identity
        .register(&sample_identity("id-b", "free-name"), "ch-b", Utc::now())
        .await
        .unwrap();
    assert_eq!(
        retry,
        RegisterOutcome::Registered,
        "the challenge must survive a name clash (invariant #3)"
    );
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn find_by_token_hash_and_is_name_taken() {
    let (identity, challenges) = repos().await;
    seed_challenge(&challenges, "ch-t").await;
    identity
        .register(&sample_identity("id-t", "node-t"), "ch-t", Utc::now())
        .await
        .unwrap();

    assert!(identity.is_name_taken("node-t").await.unwrap());
    assert!(!identity.is_name_taken("nobody").await.unwrap());
    let found = identity
        .find_by_token_hash("hash_id-t")
        .await
        .unwrap()
        .expect("exists");
    assert_eq!(found.id, "id-t");
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn concurrent_register_same_challenge_has_one_winner() {
    use std::sync::Arc;

    // Two registrations racing on the SAME challenge (different names) must not
    // both succeed — the row lock on `UPDATE ... WHERE used_at IS NULL` serialises
    // the burn, so a stolen PoW cannot be double-spent.
    let pool = test_pool_global().await;
    let identity = Arc::new(PgIdentityRepository::new_pools(DbPools::single(
        pool.clone(),
    )));
    let challenges = PgChallengeRepository::new_pools(DbPools::single(pool));
    seed_challenge(&challenges, "ch-race").await;

    let a = {
        let id = Arc::clone(&identity);
        tokio::spawn(async move {
            id.register(&sample_identity("race-a", "name-a"), "ch-race", Utc::now())
                .await
                .unwrap()
        })
    };
    let b = {
        let id = Arc::clone(&identity);
        tokio::spawn(async move {
            id.register(&sample_identity("race-b", "name-b"), "ch-race", Utc::now())
                .await
                .unwrap()
        })
    };
    let outcomes = [a.await.unwrap(), b.await.unwrap()];

    let registered = outcomes
        .iter()
        .filter(|o| **o == RegisterOutcome::Registered)
        .count();
    let already_used = outcomes
        .iter()
        .filter(|o| **o == RegisterOutcome::ChallengeAlreadyUsed)
        .count();
    assert_eq!(
        registered, 1,
        "exactly one registration may win the challenge"
    );
    assert_eq!(already_used, 1, "the loser must see ChallengeAlreadyUsed");
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn tombstone_deregisters_but_keeps_the_name() {
    let (identity, challenges) = repos().await;
    seed_challenge(&challenges, "ch-d").await;
    identity
        .register(&sample_identity("id-d", "node-d"), "ch-d", Utc::now())
        .await
        .unwrap();

    identity.tombstone("id-d", Utc::now()).await.unwrap();

    // No longer active: cannot be found (the find filters status='active')…
    assert!(identity.find_by_id("id-d").await.unwrap().is_none());
    assert!(
        identity
            .find_by_token_hash("hash_id-d")
            .await
            .unwrap()
            .is_none(),
        "a tombstoned install must not authenticate"
    );
    // …but the row (and its name allocation) survives.
    assert!(
        identity.is_name_taken("node-d").await.unwrap(),
        "the name stays allocated after a tombstone"
    );

    // Idempotent — a second tombstone is a no-op (the WHERE status='active' guard).
    identity.tombstone("id-d", Utc::now()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d)"]
async fn find_inactive_returns_tombstoned_and_absent() {
    let (identity, challenges) = repos().await;
    seed_challenge(&challenges, "ch-act").await;
    seed_challenge(&challenges, "ch-dead").await;
    identity
        .register(
            &sample_identity("id-active", "name-active"),
            "ch-act",
            Utc::now(),
        )
        .await
        .unwrap();
    identity
        .register(
            &sample_identity("id-dead", "name-dead"),
            "ch-dead",
            Utc::now(),
        )
        .await
        .unwrap();
    identity.tombstone("id-dead", Utc::now()).await.unwrap();

    let inactive = identity
        .find_inactive(&[
            "id-active".to_string(),
            "id-dead".to_string(),
            "id-absent".to_string(),
        ])
        .await
        .unwrap();

    assert!(
        !inactive.contains(&"id-active".to_string()),
        "active must be excluded"
    );
    assert!(
        inactive.contains(&"id-dead".to_string()),
        "tombstoned must be inactive"
    );
    assert!(
        inactive.contains(&"id-absent".to_string()),
        "never-registered must be inactive"
    );
    assert_eq!(inactive.len(), 2);
}
