//! Unit tests for the reserved-IPv4 guard.

use super::is_reserved_ipv4;

#[test]
fn public_addresses_allowed() {
    for addr in ["1.2.3.4", "8.8.8.8", "203.0.114.1"] {
        let ip: std::net::Ipv4Addr = addr.parse().unwrap();
        assert!(!is_reserved_ipv4(ip), "{addr} should be allowed");
    }
}

#[test]
fn private_and_reserved_addresses_rejected() {
    for addr in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "255.255.255.255",
        "192.0.2.1",
        "203.0.113.1",
        "0.0.0.0",
        "100.64.0.1",      // CGN shared address space
        "224.0.0.1",       // multicast
        "239.255.255.255", // multicast
        "240.0.0.1",       // reserved / future use
    ] {
        let ip: std::net::Ipv4Addr = addr.parse().unwrap();
        assert!(is_reserved_ipv4(ip), "{addr} should be rejected");
    }
}
