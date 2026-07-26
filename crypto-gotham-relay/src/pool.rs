// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Connection pool for outbound QUIC + Noise XK.
//!
//! Without this, every `forward_packet` call paid the full cost of:
//! - QUIC handshake (~1 RTT)
//! - Noise XK handshake (3 messages = ~1.5 RTT)
//!
//! At ≈ 1 packet per second per active conversation and ≈ 200 ms one-way
//! latency, that's a 60-80% transport overhead. The pool reuses each
//! `(addr, peer_pubkey)` connection across many packets, amortizing the
//! handshake to a one-time cost.
//!
//! ## Design
//!
//! `ConnectionPool` holds a `Mutex<HashMap<(SocketAddr, [u8; 32]),
//! Arc<PooledConnection>>>`. Each `PooledConnection` owns:
//! - the live `quinn::Connection`
//! - a `Mutex<SendStream>` (Noise frames serialize on one bi-stream)
//! - a `Mutex<TransportState>` (Noise nonce counters advance per send)
//! - a `Mutex<Instant>` last-used time (for eviction)
//!
//! ## Eviction
//!
//! v0.1: simple "oldest-out" when `max_size` reached. v0.2 will add a
//! background sweep that proactively evicts entries idle > `idle_ttl`,
//! and an LRU touch on every hit.
//!
//! ## Failure handling
//!
//! If sending on a pooled connection fails (e.g. peer closed, network
//! blip), the entry is removed and the next `send` re-establishes
//! transparently. Callers see at most one extra-latency event per
//! peer-down incident.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use snow::TransportState;
use tokio::sync::Mutex;
use tracing::debug;

use crate::transport::{noise_initiator_handshake, write_noise_frame, TransportError};

/// Default max pool size (entries).
pub const DEFAULT_MAX_SIZE: usize = 128;

/// Default idle TTL after which an entry is eligible for proactive
/// eviction (v0.1 only enforces this lazily on `send` retry).
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(300);

type PoolKey = (SocketAddr, [u8; 32]);

/// One reusable QUIC + Noise XK connection.
struct PooledConnection {
    #[allow(dead_code)] // kept alive so the stream stays valid
    conn: Connection,
    send: Mutex<SendStream>,
    // Read half of the bi-stream. We never read from it in v0.1, but dropping
    // it would half-close the stream — so we keep it owned by the pooled
    // connection and let it drop together with `conn` (no leak).
    #[allow(dead_code)]
    recv: RecvStream,
    noise: Mutex<TransportState>,
    last_used: Mutex<Instant>,
}

impl PooledConnection {
    /// Encrypt + write one Gotham packet on this connection.
    async fn send_packet(&self, packet: &[u8]) -> Result<(), TransportError> {
        let mut noise = self.noise.lock().await;
        let mut send = self.send.lock().await;
        write_noise_frame(&mut noise, &mut send, packet).await?;
        *self.last_used.lock().await = Instant::now();
        Ok(())
    }
}

/// Outbound connection pool keyed by `(addr, peer X25519 pubkey)`.
pub struct ConnectionPool {
    endpoint: Endpoint,
    my_sk: [u8; 32],
    pool: Mutex<HashMap<PoolKey, Arc<PooledConnection>>>,
    max_size: usize,
    /// RFC B3: live inbound rendezvous tunnels this relay hosts (empty unless it
    /// serves as a rendezvous point). Threaded through the pool so the mixnet
    /// forwarder can PUSH a `VIA_RENDEZVOUS` packet to a hosted CGNAT relay
    /// instead of dialing it — same "outbound send" abstraction, different wire.
    rendezvous: crate::rendezvous::RendezvousTable,
}

impl ConnectionPool {
    /// Create a new empty pool. `my_sk` is the local relay/client's
    /// X25519 static identity used as the initiator side of every
    /// Noise XK handshake. `endpoint` is a QUIC client endpoint
    /// (typically from [`crate::transport::build_client_endpoint`]).
    #[must_use]
    pub fn new(endpoint: Endpoint, my_sk: [u8; 32]) -> Self {
        Self {
            endpoint,
            my_sk,
            pool: Mutex::new(HashMap::new()),
            max_size: DEFAULT_MAX_SIZE,
            rendezvous: crate::rendezvous::RendezvousTable::new(),
        }
    }

    /// The RFC B3 rendezvous table shared by this relay's accept loop (which
    /// registers hosted CGNAT relays' tunnels) and its forwarder (which pushes
    /// `VIA_RENDEZVOUS` packets down them).
    #[must_use]
    pub fn rendezvous(&self) -> &crate::rendezvous::RendezvousTable {
        &self.rendezvous
    }

    /// Customize the pool's max entry count.
    #[must_use]
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.max(1);
        self
    }

    /// How many pooled connections are currently live.
    pub async fn len(&self) -> usize {
        self.pool.lock().await.len()
    }

    /// True if the pool has no entries.
    pub async fn is_empty(&self) -> bool {
        self.pool.lock().await.is_empty()
    }

    /// Send one Gotham packet to `(addr, peer_pk)`, reusing an existing
    /// connection if one is available. On failure (connection dead /
    /// peer closed) the entry is removed and a fresh connection
    /// established for the retry.
    pub async fn send(
        &self,
        addr: SocketAddr,
        peer_pk: [u8; 32],
        packet: &[u8],
    ) -> Result<(), TransportError> {
        let key: PoolKey = (addr, peer_pk);

        // 1. Try the cached connection (if any).
        let cached = {
            let pool = self.pool.lock().await;
            pool.get(&key).cloned()
        };
        if let Some(conn) = cached {
            match conn.send_packet(packet).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    // Drop the dead entry; fall through to fresh-open.
                    self.pool.lock().await.remove(&key);
                    debug!("pool: evicted dead connection on send failure");
                }
            }
        }

        // 2. Establish a fresh connection.
        let pooled = self.open_new(addr, peer_pk).await?;
        pooled.send_packet(packet).await?;

        // 3. Insert into the pool, evicting the oldest entry if at cap.
        let mut pool = self.pool.lock().await;
        if pool.len() >= self.max_size {
            self.evict_oldest_locked(&mut pool).await;
        }
        pool.insert(key, pooled);
        Ok(())
    }

    /// Evict the entry with the oldest `last_used` timestamp. Must be
    /// called while holding the pool lock.
    async fn evict_oldest_locked(&self, pool: &mut HashMap<PoolKey, Arc<PooledConnection>>) {
        // We can't hold per-entry Mutexes across the iteration, so we
        // snapshot the (key, last_used) pairs first.
        let mut oldest: Option<(PoolKey, Instant)> = None;
        for (k, v) in pool.iter() {
            let ts = *v.last_used.lock().await;
            match oldest {
                None => oldest = Some((*k, ts)),
                Some((_, prev_ts)) if ts < prev_ts => oldest = Some((*k, ts)),
                _ => {}
            }
        }
        if let Some((k, _)) = oldest {
            pool.remove(&k);
            debug!("pool: evicted oldest entry to make room");
        }
    }

    async fn open_new(
        &self,
        addr: SocketAddr,
        peer_pk: [u8; 32],
    ) -> Result<Arc<PooledConnection>, TransportError> {
        let conn = self.endpoint.connect(addr, "gotham-relay.local")?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let noise = noise_initiator_handshake(&self.my_sk, &peer_pk, &mut send, &mut recv).await?;
        // We don't expect peer-to-client data on this bi-stream in v0.1, but we
        // keep `recv` alive (drop would half-close the bi-stream). It is owned
        // by the PooledConnection and dropped with it — no mem::forget leak.
        Ok(Arc::new(PooledConnection {
            conn,
            send: Mutex::new(send),
            recv,
            noise: Mutex::new(noise),
            last_used: Mutex::new(Instant::now()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::header::{
        derive_route_secrets, flag, mode, wrap_header, RoutingRecord, HEADER_LEN, TRAILER_LEN,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::net::SocketAddrV4;
    use std::sync::Once;
    use tokio::sync::mpsc;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::process::Relay;
    use crate::transport::{
        build_client_endpoint, build_server_endpoint, serve_connection, DeliveryHandler,
    };

    static CRYPTO: Once = Once::new();
    fn init() {
        CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn clamped_sk(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    /// Spawn a 1-hop relay that delivers to the supplied mpsc.
    async fn spawn_relay(sk: [u8; 32], tx: mpsc::UnboundedSender<Vec<u8>>) -> SocketAddrV4 {
        let handler: DeliveryHandler = Arc::new(move |payload| {
            let _ = tx.send(payload);
        });
        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Relay::new(sk, 1000, Duration::from_secs(60), 0);
        let relay = Arc::new(Mutex::new(relay));
        let pool = Arc::new(ConnectionPool::new(client, sk));
        tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let relay = Arc::clone(&relay);
                let pool = Arc::clone(&pool);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, Some(handler)).await;
                    }
                });
            }
        });
        match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("v4 expected"),
        }
    }

    /// Build a 1-hop deliver-local packet with `marker` prefixing the payload.
    fn build_1hop_packet(rng: &mut ChaCha20Rng, relay_sk: [u8; 32], marker: &[u8]) -> Vec<u8> {
        let pks = [PublicKey::from(&StaticSecret::from(relay_sk)).to_bytes()];
        let (alphas, sub_keys) = derive_route_secrets(rng, &pks).unwrap();
        let records = vec![RoutingRecord {
            flag: flag::IS_LAST_HOP,
            ..RoutingRecord::default()
        }];
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header =
            wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer).unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        packet[HEADER_LEN..HEADER_LEN + marker.len()].copy_from_slice(marker);
        // Apply the (single) sender LIONESS layer so the 1-hop relay peels back
        // to `marker` — mirrors `GothamClient::ship_path`.
        crypto_gotham::lioness::encrypt(&sub_keys[0].k_payload, &mut packet[HEADER_LEN..]);
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_reuses_connection_for_repeated_sends() {
        init();
        let mut r = ChaCha20Rng::seed_from_u64(0x00C0_FFEE_BABE);
        let sk = clamped_sk(&mut r);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let addr = spawn_relay(sk, tx).await;
        let peer_pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();

        let endpoint = build_client_endpoint().unwrap();
        let my_sk = clamped_sk(&mut r);
        let pool = ConnectionPool::new(endpoint, my_sk);

        assert!(pool.is_empty().await);

        // First send → opens new connection.
        let p1 = build_1hop_packet(&mut r, sk, b"first-via-pool");
        pool.send(SocketAddr::V4(addr), peer_pk, &p1)
            .await
            .expect("first send");
        assert_eq!(pool.len().await, 1);

        // Second send to same peer → reuses connection (no new entry).
        let p2 = build_1hop_packet(&mut r, sk, b"second-via-pool");
        pool.send(SocketAddr::V4(addr), peer_pk, &p2)
            .await
            .expect("second send");
        assert_eq!(pool.len().await, 1, "pool should reuse, not grow");

        // Both deliveries should arrive.
        let mut got_first = false;
        let mut got_second = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline && !(got_first && got_second) {
            if let Ok(Some(payload)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await
            {
                if payload[..b"first-via-pool".len()] == b"first-via-pool"[..] {
                    got_first = true;
                } else if payload[..b"second-via-pool".len()] == b"second-via-pool"[..] {
                    got_second = true;
                }
            }
        }
        assert!(got_first, "first marker never arrived");
        assert!(got_second, "second marker never arrived");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_separate_entries_per_peer() {
        init();
        let mut r = ChaCha20Rng::seed_from_u64(0xC0DEC0DE);
        let sk1 = clamped_sk(&mut r);
        let sk2 = clamped_sk(&mut r);
        let (tx1, _rx1) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx2, _rx2) = mpsc::unbounded_channel::<Vec<u8>>();
        let addr1 = spawn_relay(sk1, tx1).await;
        let addr2 = spawn_relay(sk2, tx2).await;
        let pk1 = PublicKey::from(&StaticSecret::from(sk1)).to_bytes();
        let pk2 = PublicKey::from(&StaticSecret::from(sk2)).to_bytes();

        let endpoint = build_client_endpoint().unwrap();
        let my_sk = clamped_sk(&mut r);
        let pool = ConnectionPool::new(endpoint, my_sk);

        let p1 = build_1hop_packet(&mut r, sk1, b"to-relay-1");
        let p2 = build_1hop_packet(&mut r, sk2, b"to-relay-2");
        pool.send(SocketAddr::V4(addr1), pk1, &p1).await.unwrap();
        pool.send(SocketAddr::V4(addr2), pk2, &p2).await.unwrap();
        assert_eq!(
            pool.len().await,
            2,
            "expected separate pool entries per peer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_enforces_max_size() {
        init();
        let mut r = ChaCha20Rng::seed_from_u64(0xABCD0F0F);
        // Spawn 3 distinct relays so the pool would naturally hold 3 entries.
        let sk_a = clamped_sk(&mut r);
        let sk_b = clamped_sk(&mut r);
        let sk_c = clamped_sk(&mut r);
        let (tx_a, _) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_b, _) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_c, _) = mpsc::unbounded_channel::<Vec<u8>>();
        let addr_a = spawn_relay(sk_a, tx_a).await;
        let addr_b = spawn_relay(sk_b, tx_b).await;
        let addr_c = spawn_relay(sk_c, tx_c).await;
        let pk_a = PublicKey::from(&StaticSecret::from(sk_a)).to_bytes();
        let pk_b = PublicKey::from(&StaticSecret::from(sk_b)).to_bytes();
        let pk_c = PublicKey::from(&StaticSecret::from(sk_c)).to_bytes();

        let endpoint = build_client_endpoint().unwrap();
        let my_sk = clamped_sk(&mut r);
        let pool = ConnectionPool::new(endpoint, my_sk).with_max_size(2);

        let pa = build_1hop_packet(&mut r, sk_a, b"a");
        let pb = build_1hop_packet(&mut r, sk_b, b"b");
        let pc = build_1hop_packet(&mut r, sk_c, b"c");

        pool.send(SocketAddr::V4(addr_a), pk_a, &pa).await.unwrap();
        // Sleep a hair so timestamps differ.
        tokio::time::sleep(Duration::from_millis(10)).await;
        pool.send(SocketAddr::V4(addr_b), pk_b, &pb).await.unwrap();
        assert_eq!(pool.len().await, 2);
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Sending to a 3rd peer should evict the oldest (a).
        pool.send(SocketAddr::V4(addr_c), pk_c, &pc).await.unwrap();
        assert_eq!(pool.len().await, 2, "max size must be enforced");
    }
}
