use std::net::SocketAddr;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::{Inspected, parse_v1, read_optional, read_required};

#[test]
fn parse_tcp4() {
    let addr = parse_v1(b"PROXY TCP4 1.2.3.4 5.6.7.8 1111 443\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(addr, "1.2.3.4:1111".parse::<SocketAddr>().unwrap());
}

#[test]
fn parse_tcp6() {
    let addr = parse_v1(b"PROXY TCP6 2001:db8::1 2001:db8::2 4040 443\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(addr, "[2001:db8::1]:4040".parse::<SocketAddr>().unwrap());
}

#[test]
fn parse_unknown_yields_no_addr() {
    assert_eq!(parse_v1(b"PROXY UNKNOWN\r\n").unwrap(), None);
}

#[test]
fn parse_rejects_non_crlf() {
    assert!(parse_v1(b"PROXY TCP4 1.2.3.4 5.6.7.8 1111 443").is_err());
}

#[test]
fn parse_rejects_garbage() {
    assert!(parse_v1(b"GET / HTTP/1.1\r\n").is_err());
}

/// `read_required` consumes **exactly** the header line — the bytes that follow
/// (here a fake TLS `ClientHello`) must be readable untouched afterwards.
#[tokio::test]
async fn read_required_does_not_over_read() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let payload = b"\x16\x03\x01\x00\x05HELLO"; // bytes after the header
    let client = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PROXY TCP4 9.9.9.9 1.1.1.1 5555 443\r\n")
            .await
            .unwrap();
        s.write_all(payload).await.unwrap();
        s.flush().await.unwrap();
        // keep the connection open until the server has read
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let (mut srv, _) = listener.accept().await.unwrap();
    let client_addr = read_required(&mut srv).await.unwrap().unwrap();
    assert_eq!(client_addr, "9.9.9.9:5555".parse::<SocketAddr>().unwrap());

    let mut rest = vec![0u8; payload.len()];
    srv.read_exact(&mut rest).await.unwrap();
    assert_eq!(&rest, payload, "ClientHello bytes must survive intact");

    client.await.unwrap();
}

/// `read_optional` returns `Direct` (consuming nothing) for a connection with no
/// PROXY header — the direct/local health-probe case.
#[tokio::test]
async fn read_optional_direct_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let payload = b"GET /health HTTP/1.1\r\n\r\n";
    let client = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(payload).await.unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let (mut srv, _) = listener.accept().await.unwrap();
    assert_eq!(read_optional(&mut srv).await.unwrap(), Inspected::Direct);

    // nothing was consumed — the request line is still there
    let mut rest = vec![0u8; payload.len()];
    srv.read_exact(&mut rest).await.unwrap();
    assert_eq!(&rest, payload);

    client.await.unwrap();
}

/// `read_optional` parses and consumes a present header.
#[tokio::test]
async fn read_optional_with_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = tokio::spawn(async move {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PROXY TCP4 8.8.8.8 1.1.1.1 6000 80\r\nGET / HTTP/1.1\r\n")
            .await
            .unwrap();
        s.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let (mut srv, _) = listener.accept().await.unwrap();
    match read_optional(&mut srv).await.unwrap() {
        Inspected::Header(Some(a)) => {
            assert_eq!(a, "8.8.8.8:6000".parse::<SocketAddr>().unwrap());
        }
        other => panic!("expected parsed header, got {other:?}"),
    }
    client.await.unwrap();
}

// ── client_ip ─────────────────────────────────────────────────────────────────

mod client_ip {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::http::{HeaderMap, HeaderValue};

    use crate::proxy_protocol::client_ip;

    fn loopback_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    fn external_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345)
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn xff_trusted_from_loopback() {
        let ip = client_ip(&xff("203.0.114.5"), loopback_addr());
        assert_eq!(ip, "203.0.114.5");
    }

    #[test]
    fn xff_leftmost_value_from_loopback() {
        let ip = client_ip(&xff("10.0.0.1, 1.2.3.4"), loopback_addr());
        // Leftmost entry is chosen (the client as seen by the first proxy)
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn xff_ignored_from_external_peer() {
        // A directly connected client cannot forge its IP via X-Forwarded-For.
        let ip = client_ip(&xff("9.9.9.9"), external_addr());
        assert_eq!(ip, "1.2.3.4", "should use TCP peer, not XFF header");
    }

    #[test]
    fn no_xff_uses_peer_ip() {
        let ip = client_ip(&HeaderMap::new(), loopback_addr());
        assert_eq!(ip, "127.0.0.1");
    }

    /// Behind the L4 proxy the listener injects the PROXY-supplied client address as
    /// `ConnectInfo` (a non-loopback peer), so two distinct real clients key the
    /// per-IP rate limit independently and neither can spoof the other via a forged
    /// `X-Forwarded-For`. This is the property that keeps the registration limits
    /// per-client rather than collapsing to the proxy's single address.
    #[test]
    fn proxy_supplied_ips_are_independent_and_unspoofable() {
        let client_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51000);
        let client_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 51000);

        // Each real client keys on its own (proxy-supplied) address …
        let key_a = client_ip(&HeaderMap::new(), client_a);
        let key_b = client_ip(&HeaderMap::new(), client_b);
        assert_eq!(key_a, "203.0.113.7");
        assert_eq!(key_b, "198.51.100.9");
        assert_ne!(
            key_a, key_b,
            "distinct clients must get distinct rate-limit keys"
        );

        // … and a forged X-Forwarded-For cannot collapse them onto one budget.
        assert_eq!(client_ip(&xff("203.0.113.7"), client_b), "198.51.100.9");
    }
}
