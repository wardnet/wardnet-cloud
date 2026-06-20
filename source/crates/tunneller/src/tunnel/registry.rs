use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;

/// A byte stream that can be spliced into a tunnel. Two concrete kinds flow in:
/// a **local** client `TcpStream` (from this node's SNI demuxer) and the **remote**
/// mTLS stream of a peer node's inter-node forward — both erased to this trait so
/// the tunnel handler is agnostic to where the connection entered the mesh.
pub trait TunnelStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> TunnelStream for T {}

/// An inbound connection handed off to a tunnel handler for splicing to its Pi.
pub struct ForwardRequest {
    /// The accepted stream (the TLS `ClientHello` is still unread in its buffer).
    pub stream: Box<dyn TunnelStream>,
    /// Destination port the Pi should connect to locally (443 or 853).
    pub dest_port: u16,
}

/// Result of attempting to forward an inbound connection to a registered tunnel.
pub enum ForwardResult {
    /// The connection was accepted and queued for the Pi.
    Accepted,
    /// No tunnel is registered locally for the requested slug.
    NotConnected,
    /// A tunnel is registered but its receive buffer is full; connection dropped.
    BufferFull,
}

/// The handle a tunnel handler holds for its registration.
pub struct Registration {
    /// Inbound connections destined for this tunnel.
    pub rx: mpsc::Receiver<ForwardRequest>,
    /// Fires when the tunnel is aborted (decommission) or displaced by a reconnect.
    pub abort: CancellationToken,
    /// Monotonic id used to make a superseded handler's cleanup a no-op.
    pub generation: u64,
}

struct Entry {
    tx: mpsc::Sender<ForwardRequest>,
    abort: CancellationToken,
    generation: u64,
}

/// Thread-safe per-node map from vanity **slug** → active tunnel.
///
/// Registration is keyed solely on the slug (the SNI routing key); the daemon's
/// identity is not part of the key. The map is in-memory and **per-node** — it is
/// never persisted, so after a node restart all Pis simply reconnect. The
/// cross-node ownership hint lives in the `tunnel_routes` table.
pub struct TunnelRegistry {
    by_slug: DashMap<String, Entry>,
    next_gen: AtomicU64,
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self {
            by_slug: DashMap::new(),
            next_gen: AtomicU64::new(0),
        }
    }
}

impl TunnelRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tunnel for `slug`, returning its inbound receiver, an abort token,
    /// and the registration generation.
    ///
    /// A pre-existing registration for the same slug (a reconnect) is replaced and
    /// **aborted** — its token is cancelled so the displaced handler tears down.
    #[must_use]
    pub fn register(&self, slug: &str) -> Registration {
        let generation = self.next_gen.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(64);
        let abort = CancellationToken::new();
        if let Some(old) = self.by_slug.insert(
            slug.to_string(),
            Entry {
                tx,
                abort: abort.clone(),
                generation,
            },
        ) {
            old.abort.cancel();
        }
        Registration {
            rx,
            abort,
            generation,
        }
    }

    /// Remove the registration for `slug` **iff** `generation` still owns it, returning
    /// whether a row was removed. A reconnect under the same slug bumps the
    /// generation, so a superseded handler's cleanup is a no-op (it must not evict
    /// the live tunnel).
    pub fn unregister(&self, slug: &str, generation: u64) -> bool {
        self.by_slug
            .remove_if(slug, |_, e| e.generation == generation)
            .is_some()
    }

    /// Abort the tunnel for `slug` (decommission): cancel its token and drop the
    /// registration. Returns `true` if a tunnel was registered.
    pub fn abort(&self, slug: &str) -> bool {
        if let Some((_, e)) = self.by_slug.remove(slug) {
            e.abort.cancel();
            true
        } else {
            false
        }
    }

    /// Forward an inbound connection to the tunnel registered under `slug`.
    ///
    /// Non-blocking so the SNI/forward accept loops are never stalled by a slow Pi.
    pub fn forward(&self, slug: &str, req: ForwardRequest) -> ForwardResult {
        // Clone the sender while the DashMap ref is held, then drop it before send.
        let tx = self.by_slug.get(slug).map(|r| r.value().tx.clone());
        match tx {
            None => ForwardResult::NotConnected,
            Some(tx) => match tx.try_send(req) {
                Ok(()) => ForwardResult::Accepted,
                Err(TrySendError::Full(_)) => ForwardResult::BufferFull,
                Err(TrySendError::Closed(_)) => ForwardResult::NotConnected,
            },
        }
    }

    /// Return `true` when a tunnel is currently registered locally for `slug`.
    #[must_use]
    pub fn is_connected(&self, slug: &str) -> bool {
        self.by_slug.contains_key(slug)
    }

    /// The number of tunnels currently registered on this node. Backs the
    /// `tunneller.active_tunnels` observability gauge (a bounded scalar — no labels).
    #[must_use]
    pub fn active_count(&self) -> u64 {
        u64::try_from(self.by_slug.len()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests;
