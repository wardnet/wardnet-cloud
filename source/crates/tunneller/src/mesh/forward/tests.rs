//! Unit tests for the forward acceptor's scope-direction rule (ADR-0005) and the
//! `{slug, dest_port}` preamble codec. The mTLS handshake itself is exercised end-to-end
//! in `tests/mesh_mtls.rs`; here we pin the authorization predicate and the defensive
//! preamble bounds that a handshake-valid-but-malformed peer could otherwise exploit.

use wardnet_common::mtls::SpiffeId;

use super::{peer_allowed_on_forward, read_preamble, write_preamble};

fn peer(service: &str, scope: &str) -> SpiffeId {
    SpiffeId {
        trust_domain: "wardnet.test".to_string(),
        env: "dev".to_string(),
        scope: scope.to_string(),
        service: service.to_string(),
    }
}

#[test]
fn forward_admits_same_service_same_scope_peer() {
    assert!(peer_allowed_on_forward(&peer("tunneller", "use1"), "use1"));
}

#[test]
fn forward_rejects_non_tunneller_service() {
    // A bundle-valid `ddns`/`tenants` leaf must not reach the forward plane — it is
    // same-service-only, even within the right region.
    assert!(!peer_allowed_on_forward(&peer("ddns", "use1"), "use1"));
    assert!(!peer_allowed_on_forward(&peer("tenants", "use1"), "use1"));
}

#[test]
fn forward_rejects_cross_region_scope() {
    // A `tunneller` from another region is bundle-blocked in production; the rule is the
    // belt-and-braces second check, so it must reject a different scope.
    assert!(!peer_allowed_on_forward(&peer("tunneller", "use2"), "use1"));
    assert!(!peer_allowed_on_forward(
        &peer("tunneller", "global"),
        "use1"
    ));
}

#[tokio::test]
async fn preamble_round_trips() {
    let mut buf = Vec::new();
    write_preamble(&mut buf, "alice", 443).await.unwrap();
    let mut cursor = buf.as_slice();
    let (slug, port) = read_preamble(&mut cursor).await.unwrap();
    assert_eq!(slug, "alice");
    assert_eq!(port, 443);
}

#[tokio::test]
async fn write_preamble_rejects_oversized_slug() {
    let mut buf = Vec::new();
    let too_long = "a".repeat(65); // MAX_SLUG_LEN is 64
    assert!(write_preamble(&mut buf, &too_long, 443).await.is_err());
}

#[tokio::test]
async fn read_preamble_rejects_zero_length_slug() {
    // A length prefix of 0 is a malformed preamble — reject rather than read an empty slug.
    let bytes = [0u8, 0u8];
    let mut cursor = &bytes[..];
    assert!(read_preamble(&mut cursor).await.is_err());
}

#[tokio::test]
async fn read_preamble_rejects_truncated_stream() {
    // Claims a 5-byte slug but only 2 bytes follow → the stream ends early.
    let bytes = [0u8, 5u8, b'a', b'b'];
    let mut cursor = &bytes[..];
    assert!(read_preamble(&mut cursor).await.is_err());
}

#[tokio::test]
async fn read_preamble_rejects_non_utf8_slug() {
    // len=2, two invalid-UTF-8 bytes, then a port → the slug decode must fail closed.
    let bytes = [0u8, 2u8, 0xff, 0xfe, 0x01, 0xbb];
    let mut cursor = &bytes[..];
    assert!(read_preamble(&mut cursor).await.is_err());
}
