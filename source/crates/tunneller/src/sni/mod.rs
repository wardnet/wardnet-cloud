//! SNI-demuxing passthrough front.
//!
//! Behind the transparent L4 proxy the node owns two passthrough listeners:
//! - **`:8443`** (`dest_port = 443`) — peeks the TLS `ClientHello` SNI and passes
//!   the still-encrypted stream through to the tenant's reverse tunnel on port 443.
//! - **`:8853`** (`dest_port = 853`) — DNS-over-TLS passthrough to the tenant
//!   tunnel on port 853.
//!
//! The node **never terminates** tenant TLS: it is a pure L4 forwarder, so the
//! connection carries the *daemon's* certificate end-to-end. Every connection is
//! fronted by a PROXY protocol v1 header (nginx) which is consumed first to recover
//! the real client address; because exactly the header line is consumed, the
//! subsequent non-consuming [`TcpStream::peek`] still sees the `ClientHello`.
//!
//! The demuxer hands the recovered slug + stream to a [`TunnelRouter`] — it never
//! looks up the registry directly, so cross-node routing is transparent to it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::Instrument as _;

use crate::router::TunnelRouter;
use wardnet_common::proxy_protocol;
use wardnet_common::validation::is_valid_name;

/// Maximum bytes to peek for SNI extraction.
const PEEK_SIZE: usize = 1024;
/// Maximum concurrent in-flight SNI routing tasks (accept-storm guard).
const MAX_CONCURRENT_SNI: usize = 4096;
/// Timeout for reading the PROXY header + TLS `ClientHello`.
const PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Run an SNI-demuxing passthrough listener that routes every tenant connection to
/// its reverse tunnel on `dest_port` (443 for HTTPS, 853 for `DoT`).
///
/// # Errors
/// Returns an error if the listener cannot be bound.
pub async fn run(
    addr: &str,
    subdomain_parent: &str,
    router: Arc<dyn TunnelRouter>,
    dest_port: u16,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr, port = dest_port, "SNI passthrough listening");

    let subdomain_dot_suffix: Arc<str> = Arc::from(format!(".{subdomain_parent}"));
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SNI));

    loop {
        let (stream, peer) = listener.accept().await?;
        let router = Arc::clone(&router);
        let suffix = Arc::clone(&subdomain_dot_suffix);
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed");
        let span = tracing::debug_span!("sni.route", %peer);
        tokio::spawn(
            async move {
                let _permit = permit;
                if let Err(e) = route(stream, peer, &suffix, &router, dest_port).await {
                    tracing::debug!(error = %e, "SNI demux error");
                }
            }
            .instrument(span),
        );
    }
}

async fn route(
    mut stream: TcpStream,
    peer: SocketAddr,
    subdomain_dot_suffix: &str,
    router: &Arc<dyn TunnelRouter>,
    dest_port: u16,
) -> anyhow::Result<()> {
    // 1. Consume the PROXY v1 header to recover the real client address.
    let _client_addr =
        tokio::time::timeout(PEEK_TIMEOUT, proxy_protocol::read_required(&mut stream))
            .await
            .map_err(|_| anyhow::anyhow!("PROXY header read timeout"))??
            .unwrap_or(peer);

    // 2. Peek the ClientHello (non-consuming) for the SNI.
    let mut peek_buf = vec![0u8; PEEK_SIZE];
    let n = tokio::time::timeout(PEEK_TIMEOUT, stream.peek(&mut peek_buf))
        .await
        .map_err(|_| anyhow::anyhow!("peek timeout"))??;
    let sni = parse_sni(&peek_buf[..n]);

    match sni.as_deref() {
        // A tenant host → hand the encrypted stream to the router.
        Some(host) => {
            if let Some(slug) = extract_slug(host, subdomain_dot_suffix) {
                router.route(slug, stream, dest_port).await;
            } else {
                tracing::debug!(peer = %peer, sni = host, "unroutable SNI, dropping");
            }
        }
        None => {
            tracing::debug!(peer = %peer, "no SNI in ClientHello, dropping");
        }
    }

    Ok(())
}

/// Extract the vanity **slug** (tunnel routing key) from an SNI hostname.
///
/// The slug is the **rightmost label before the suffix**, so both the apex vanity
/// host and any per-service subdomain route to the same tunnel:
/// - `"alice.my.wardnet.services"` with suffix `".my.wardnet.services"` →
///   `Some("alice")`
/// - `"jellyfin.alice.my.wardnet.services"` → `Some("alice")`
///
/// Returns `None` when the hostname does not end with the suffix, or when the
/// extracted slug is not a name registration could ever have produced.
fn extract_slug<'a>(hostname: &'a str, subdomain_dot_suffix: &str) -> Option<&'a str> {
    let prefix = hostname.strip_suffix(subdomain_dot_suffix)?;
    let slug = prefix.rsplit('.').next()?;
    is_valid_name(slug).then_some(slug)
}

/// Parse the SNI hostname from the first bytes of a TLS `ClientHello`.
///
/// Uses only the bytes already available via [`TcpStream::peek`]; returns `None`
/// if the buffer is too short, the record is not a `ClientHello`, or the SNI
/// extension is absent.
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    // TLS record: content_type(1) + version(2) + length(2)
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != 0x16 {
        // Not a handshake record.
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let hs = &buf[5..5 + record_len];

    // Handshake: msg_type(1) + length(3)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_body_len = (u32::from_be_bytes([0, hs[1], hs[2], hs[3]])) as usize;
    if hs.len() < 4 + hs_body_len {
        return None;
    }
    let hello = &hs[4..4 + hs_body_len];

    // ClientHello: version(2) + random(32) + session_id_len(1)
    if hello.len() < 35 {
        return None;
    }
    let mut pos = 35 + hello[34] as usize; // skip session_id

    // cipher_suites_len(2) + cipher_suites
    if hello.len() < pos + 2 {
        return None;
    }
    pos += 2 + u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;

    // compression_methods_len(1) + methods
    if hello.len() < pos + 1 {
        return None;
    }
    pos += 1 + hello[pos] as usize;

    // extensions_len(2)
    if hello.len() < pos + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    if hello.len() < pos + ext_len {
        return None;
    }
    let exts = &hello[pos..pos + ext_len];
    let mut i = 0;

    while i + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let elen = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        i += 4;
        if i + elen > exts.len() {
            break;
        }
        if ext_type == 0x0000 {
            // SNI extension: list_len(2) + entry_type(1) + name_len(2) + name
            let sni_data = &exts[i..i + elen];
            if sni_data.len() < 5 || sni_data[2] != 0x00 {
                return None;
            }
            let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
            if sni_data.len() < 5 + name_len {
                return None;
            }
            return std::str::from_utf8(&sni_data[5..5 + name_len])
                .ok()
                .map(str::to_string);
        }
        i += elen;
    }

    None
}

#[cfg(test)]
mod tests;
