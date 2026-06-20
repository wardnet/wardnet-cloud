use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::router::TunnelRouter;

use super::{extract_slug, parse_sni, route};

const TEST_SUFFIX: &str = ".my.wardnet.services";

/// A [`TunnelRouter`] that records the `(slug, dest_port)` of every routed stream
/// (and drops the stream itself).
#[derive(Default)]
struct RecordingRouter(Mutex<Vec<(String, u16)>>);

impl RecordingRouter {
    fn routed(&self) -> Vec<(String, u16)> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait]
impl TunnelRouter for RecordingRouter {
    async fn route(&self, slug: &str, _stream: TcpStream, dest_port: u16) {
        self.0.lock().unwrap().push((slug.to_string(), dest_port));
    }
}

/// A PROXY protocol v1 header line (what nginx prepends on `:8443`/`:8853`).
fn proxy_header() -> Vec<u8> {
    b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n".to_vec()
}

/// A minimal TLS 1.2 `ClientHello` with the given SNI, assembled by hand.
fn make_client_hello(sni: &str) -> Vec<u8> {
    let name_bytes = sni.as_bytes();
    let name_len = u16::try_from(name_bytes.len()).unwrap();
    let list_len = name_len + 3;
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&list_len.to_be_bytes());
    sni_ext.push(0x00); // host_name type
    sni_ext.extend_from_slice(&name_len.to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);

    let sni_ext_len = u16::try_from(sni_ext.len()).unwrap();
    let mut exts = Vec::new();
    exts.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI extension type
    exts.extend_from_slice(&sni_ext_len.to_be_bytes());
    exts.extend_from_slice(&sni_ext);

    let exts_len = u16::try_from(exts.len()).unwrap();
    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2 version
    hello.extend_from_slice(&[0u8; 32]); // random
    hello.push(0x00); // session_id_len
    hello.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites_len
    hello.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
    hello.push(0x01); // compression_methods_len
    hello.push(0x00); // null compression
    hello.extend_from_slice(&exts_len.to_be_bytes());
    hello.extend_from_slice(&exts);

    let hello_len = u32::try_from(hello.len()).unwrap();
    let mut hs = vec![
        0x01u8,
        ((hello_len >> 16) & 0xff) as u8,
        ((hello_len >> 8) & 0xff) as u8,
        (hello_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&hello);

    let hs_len = u16::try_from(hs.len()).unwrap();
    let mut record = Vec::new();
    record.push(0x16); // handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&hs_len.to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// Accept one server-side connection on a fresh listener, returning it with its
/// peer address, after the client has written `to_send`.
async fn one_shot(to_send: Vec<u8>) -> (TcpStream, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    client.write_all(&to_send).await.unwrap();
    client.flush().await.unwrap();
    drop(client);
    (server, peer)
}

// ── parse_sni ───────────────────────────────────────────────────────────────

#[test]
fn parse_sni_extracts_hostname() {
    let buf = make_client_hello("happy-einstein.my.wardnet.services");
    assert_eq!(
        parse_sni(&buf).as_deref(),
        Some("happy-einstein.my.wardnet.services")
    );
}

#[test]
fn parse_sni_returns_none_for_empty_buffer() {
    assert!(parse_sni(&[]).is_none());
}

#[test]
fn parse_sni_returns_none_for_non_handshake() {
    let mut buf = make_client_hello("test.example.com");
    buf[0] = 0x17;
    assert!(parse_sni(&buf).is_none());
}

#[test]
fn parse_sni_returns_none_for_truncated_buffer() {
    let buf = make_client_hello("test.example.com");
    assert!(parse_sni(&buf[..10]).is_none());
}

// ── extract_slug ──────────────────────────────────────────────────────────────

#[test]
fn extract_slug_simple() {
    assert_eq!(
        extract_slug("happy-einstein.my.wardnet.services", TEST_SUFFIX),
        Some("happy-einstein")
    );
}

#[test]
fn extract_slug_per_service_host() {
    assert_eq!(
        extract_slug("jellyfin.alice.my.wardnet.services", TEST_SUFFIX),
        Some("alice")
    );
}

#[test]
fn extract_slug_rejects_empty_label() {
    assert!(extract_slug("foo..my.wardnet.services", TEST_SUFFIX).is_none());
}

#[test]
fn extract_slug_rejects_invalid_vanity() {
    assert!(extract_slug("ab.my.wardnet.services", TEST_SUFFIX).is_none());
}

#[test]
fn extract_slug_rejects_wrong_parent() {
    assert!(extract_slug("foo.other.network", TEST_SUFFIX).is_none());
}

#[test]
fn extract_slug_rejects_bare_parent() {
    assert!(extract_slug("my.wardnet.services", TEST_SUFFIX).is_none());
}

// ── route → router hand-off ─────────────────────────────────────────────────────

#[tokio::test]
async fn route_drops_connection_when_no_sni() {
    let rec = Arc::new(RecordingRouter::default());
    let router: Arc<dyn TunnelRouter> = rec.clone();

    let mut bytes = proxy_header();
    bytes.extend_from_slice(b"not-tls-data");
    let (server, peer) = one_shot(bytes).await;

    route(server, peer, TEST_SUFFIX, &router, 853)
        .await
        .unwrap();
    assert!(rec.routed().is_empty());
}

#[tokio::test]
async fn route_drops_connection_for_unroutable_sni() {
    let rec = Arc::new(RecordingRouter::default());
    let router: Arc<dyn TunnelRouter> = rec.clone();

    let mut bytes = proxy_header();
    bytes.extend_from_slice(&make_client_hello("unrelated.example.com"));
    let (server, peer) = one_shot(bytes).await;

    route(server, peer, TEST_SUFFIX, &router, 853)
        .await
        .unwrap();
    assert!(rec.routed().is_empty());
}

#[tokio::test]
async fn route_hands_tenant_to_router_dot_port() {
    let rec = Arc::new(RecordingRouter::default());
    let router: Arc<dyn TunnelRouter> = rec.clone();

    let mut bytes = proxy_header();
    bytes.extend_from_slice(&make_client_hello("alice.my.wardnet.services"));
    let (server, peer) = one_shot(bytes).await;

    route(server, peer, TEST_SUFFIX, &router, 853)
        .await
        .unwrap();
    assert_eq!(rec.routed(), vec![("alice".to_string(), 853)]);
}

#[tokio::test]
async fn route_hands_tenant_to_router_https_port() {
    let rec = Arc::new(RecordingRouter::default());
    let router: Arc<dyn TunnelRouter> = rec.clone();

    let mut bytes = proxy_header();
    bytes.extend_from_slice(&make_client_hello("alice.my.wardnet.services"));
    let (server, peer) = one_shot(bytes).await;

    route(server, peer, TEST_SUFFIX, &router, 443)
        .await
        .unwrap();
    assert_eq!(rec.routed(), vec![("alice".to_string(), 443)]);
}
