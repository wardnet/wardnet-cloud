//! End-to-end tombstone flow over **real** SPIFFE mesh mTLS.
//!
//! `#[ignore]`d by default — it needs the docker-compose topology up (real
//! `tenants` + `ddns` containers, two Postgres instances, and a wiremock mocking
//! the Cloudflare API). Bring it up and run it with the `source/Makefile` targets:
//!
//! ```sh
//! make e2e-all          # gen certs → build+up → run this test → tear down
//! # or, against an already-running stack:
//! make e2e-test
//! ```
//!
//! What it proves end-to-end, exercising the WS-E mesh plane for real:
//!
//! 1. The **DDNS provisioner** drains Tenants' work-queue *over SPIFFE mesh mTLS*,
//!    publishes the A record (to the wiremock Cloudflare), and transitions the
//!    network to `active` — i.e. the SPIFFE handshake + `GET`/`PATCH /v1/networks`
//!    round-trip between two real binaries with xtask-minted leaves succeeds.
//! 2. A **USER `DELETE /v1/tenants/{id}`** tombstones the account and cascades its
//!    networks to `deprovisioning`.
//! 3. The **DDNS reaper** tears the record down and reports `deprovisioned`
//!    (deleting the network row), after which the **Tenants sweep** deletes the
//!    now-network-less tombstoned tenant.
//!
//! The control-plane API is fronted by nginx + PROXY protocol v1 in production
//! (invariant #13), so the single `DELETE` call here is driven over a raw TCP
//! socket with a PROXY v1 preamble rather than a plain HTTP client. Tenant/network
//! and operational-IP state are seeded directly via SQL (re-testing the daemon
//! enrollment flow is the job of the unit/api tests, not this harness).

use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::Row as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use wardnet_common::token::{ClaimsSpec, PrincipalType, Signer};

/// How long to wait for each asynchronous reconcile step before failing.
const POLL_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::test]
#[ignore = "requires the docker-compose mesh harness (make e2e-all)"]
async fn tombstone_flow_over_real_mesh_mtls() {
    let tenants_api = env_or("E2E_TENANTS_API", "127.0.0.1:18080");
    let global_db = env_or(
        "E2E_GLOBAL_DB",
        "postgres://postgres:postgres@127.0.0.1:15432/postgres",
    );
    let regional_db = env_or(
        "E2E_REGIONAL_DB",
        "postgres://postgres:postgres@127.0.0.1:15433/postgres",
    );
    let jwt_signing_key_path = env_or("E2E_JWT_SIGNING_KEY", "certs/jwt-signing.pem");
    let subdomain_parent = env_or("E2E_SUBDOMAIN_PARENT", "e2e.wardnet.test");
    let region = env_or("E2E_REGION", "use1");

    let global = connect_with_retry(&global_db).await;
    let regional = connect_with_retry(&regional_db).await;

    // The services own their schemas (sqlx::migrate! at boot), so wait for their
    // tables to exist before seeding — the containers may still be starting.
    await_table(&global, "tenants").await;
    await_table(&regional, "operational").await;

    // Unique ids so reruns against a persistent stack don't collide.
    let suffix = unique_suffix(&global).await;
    let tenant_id = format!("ten-e2e-{suffix}");
    let network_id = format!("net-e2e-{suffix}");
    let slug = format!("e2e-{suffix}");
    let email = format!("e2e-{suffix}@example.com");

    // ── Seed desired state: a live tenant with a provisioning network ───────────
    sqlx::query(
        "INSERT INTO tenants (id, email, entitlement, subscription_status, created_at) \
         VALUES ($1, $2, $3::jsonb, 'active', now())",
    )
    .bind(&tenant_id)
    .bind(&email)
    .bind(r#"{"max_networks":1,"max_daemons":1}"#)
    .execute(&global)
    .await
    .expect("seed tenant");

    sqlx::query(
        "INSERT INTO networks \
           (id, tenant_id, slug, display_name, region, provisioning_state, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, 'provisioning', now(), now())",
    )
    .bind(&network_id)
    .bind(&tenant_id)
    .bind(&slug)
    .bind("E2E Network")
    .bind(&region)
    .execute(&global)
    .await
    .expect("seed network");

    // Seed the regional operational IP row — the provisioner only publishes (and
    // flips the network to `active`) once an IP has been reported.
    sqlx::query(
        "INSERT INTO operational (network_id, ip, updated_at) VALUES ($1, '203.0.113.7', now())",
    )
    .bind(&network_id)
    .execute(&regional)
    .await
    .expect("seed operational ip");

    // ── 1. Provisioner flips the network active over real mesh mTLS ─────────────
    await_until("network → active", || async {
        network_state(&global, &network_id).await.as_deref() == Some("active")
    })
    .await;

    // ── 2. USER DELETE tenant (tombstone + cascade) ─────────────────────────────
    let token = mint_user_token(&jwt_signing_key_path, &tenant_id);
    let status = delete_tenant(&tenants_api, &tenant_id, &token).await;
    assert_eq!(
        status, 202,
        "DELETE /v1/tenants/{tenant_id} should return 202"
    );

    // The cascade marks the network deprovisioning (the reaper may already be
    // tearing it down, so accept either deprovisioning or already-gone).
    await_until("network → deprovisioning or gone", || async {
        matches!(
            network_state(&global, &network_id).await.as_deref(),
            Some("deprovisioning") | None
        )
    })
    .await;

    // ── 3. Reaper deletes the network, then the sweep deletes the tenant ────────
    await_until("network row gone (reaper)", || async {
        network_state(&global, &network_id).await.is_none()
    })
    .await;

    await_until("tenant row swept", || async {
        !tenant_exists(&global, &tenant_id).await
    })
    .await;

    let _ = subdomain_parent; // documented seam: fqdn = <slug>.<subdomain_parent>
}

/// Connect to Postgres, retrying briefly while the container finishes booting.
async fn connect_with_retry(url: &str) -> PgPool {
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        match PgPool::connect(url).await {
            Ok(pool) => return pool,
            Err(e) if Instant::now() < deadline => {
                eprintln!("waiting for Postgres at {url}: {e}");
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Err(e) => panic!("connect to {url}: {e}"),
        }
    }
}

/// Poll until `table` exists (a service has run its migrations) or time out.
async fn await_table(pool: &PgPool, table: &str) {
    let qualified = format!("public.{table}");
    await_until(&format!("table {table} present"), || {
        let qualified = qualified.clone();
        async move {
            sqlx::query("SELECT to_regclass($1::text) IS NOT NULL AS present")
                .bind(&qualified)
                .fetch_one(pool)
                .await
                .is_ok_and(|r| r.get::<bool, _>("present"))
        }
    })
    .await;
}

/// A short unique-ish suffix derived from the DB's transaction id (monotonic,
/// avoids needing a clock or RNG dependency in the test).
async fn unique_suffix(pool: &PgPool) -> String {
    let row = sqlx::query("SELECT txid_current()::text AS id")
        .fetch_one(pool)
        .await
        .expect("txid_current");
    row.get::<String, _>("id")
}

async fn network_state(pool: &PgPool, network_id: &str) -> Option<String> {
    sqlx::query("SELECT provisioning_state FROM networks WHERE id = $1")
        .bind(network_id)
        .fetch_optional(pool)
        .await
        .expect("query network state")
        .map(|r| r.get::<String, _>("provisioning_state"))
}

async fn tenant_exists(pool: &PgPool, tenant_id: &str) -> bool {
    sqlx::query("SELECT 1 AS one FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .expect("query tenant")
        .is_some()
}

fn mint_user_token(signing_key_path: &str, tenant_id: &str) -> String {
    let pem = std::fs::read(signing_key_path)
        .unwrap_or_else(|e| panic!("read JWT signing key {signing_key_path}: {e}"));
    let signer = Signer::from_pem(&pem, None).expect("build signer");
    let now = chrono::Utc::now().timestamp();
    signer
        .sign(
            &ClaimsSpec {
                tenant_id,
                principal_type: PrincipalType::User,
                subject: "e2e-user",
                network: None,
                cnf_ed25519_b64: None,
            },
            now,
            300,
        )
        .expect("sign user token")
}

/// Issue `DELETE /v1/tenants/{id}` over a raw socket, prefixed with a PROXY v1
/// header (the API listener requires one, per invariant #13). Returns the HTTP
/// status code.
async fn delete_tenant(api_addr: &str, tenant_id: &str, bearer: &str) -> u16 {
    let mut stream = TcpStream::connect(api_addr)
        .await
        .unwrap_or_else(|e| panic!("connect to tenants API {api_addr}: {e}"));

    let request = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 12345 80\r\n\
         DELETE /v1/tenants/{tenant_id} HTTP/1.1\r\n\
         Host: tenants\r\n\
         Authorization: Bearer {bearer}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write DELETE request");
    stream.flush().await.expect("flush");

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .expect("read DELETE response");
    let head = String::from_utf8_lossy(&buf);
    parse_status_code(&head).unwrap_or_else(|| {
        panic!(
            "no HTTP status in response: {}",
            head.lines().next().unwrap_or("")
        )
    })
}

/// Pull the numeric status out of an `HTTP/1.1 <code> <reason>` status line.
fn parse_status_code(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Poll `cond` until it returns true or [`POLL_TIMEOUT`] elapses.
async fn await_until<F, Fut>(label: &str, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if cond().await {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {POLL_TIMEOUT:?} waiting for: {label}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
