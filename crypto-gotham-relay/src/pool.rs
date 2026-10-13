// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use snow::TransportState;
use tokio::sync::Mutex;
use tracing::debug;

use crate::transport::{noise_initiator_handshake, write_noise_frame, TransportError};

pub const DEFAULT_MAX_SIZE: usize = 128;

pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(300);

type PoolKey = (SocketAddr, [u8; 32]);

struct PooledConnection {
    #[allow(dead_code)]
    conn: Connection,
    send: Mutex<SendStream>,
    #[allow(dead_code)]
    recv: RecvStream,
    noise: Mutex<TransportState>,
    last_used: Mutex<Instant>,
}

impl PooledConnection {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), TransportError> {
        let mut noise = self.noise.lock().await;
        let mut send = self.send.lock().await;
        write_noise_frame(&mut noise, &mut send, packet).await?;
        *self.last_used.lock().await = Instant::now();
        Ok(())
    }
}

pub struct ConnectionPool {
    endpoint: Endpoint,
    my_sk: [u8; 32],
    pool: Mutex<HashMap<PoolKey, Arc<PooledConnection>>>,
    max_size: usize,
    rendezvous: crate::rendezvous::RendezvousTable,
}

impl ConnectionPool {
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

    #[must_use]
    pub fn rendezvous(&self) -> &crate::rendezvous::RendezvousTable {
        &self.rendezvous
    }

    #[must_use]
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size.max(1);
        self
    }

    pub async fn len(&self) -> usize {
        self.pool.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.pool.lock().await.is_empty()
    }

    pub async fn send(
        &self,
        addr: SocketAddr,
        peer_pk: [u8; 32],
        packet: &[u8],
    ) -> Result<(), TransportError> {
        let key: PoolKey = (addr, peer_pk);

        let cached = {
            let pool = self.pool.lock().await;
            pool.get(&key).cloned()
        };
        if let Some(conn) = cached {
            match conn.send_packet(packet).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    self.pool.lock().await.remove(&key);
                    debug!("pool: evicted dead connection on send failure");
                }
            }
        }

        let pooled = self.open_new(addr, peer_pk).await?;
        pooled.send_packet(packet).await?;

        let mut pool = self.pool.lock().await;
        if pool.len() >= self.max_size {
            self.evict_oldest_locked(&mut pool).await;
        }
        pool.insert(key, pooled);
        Ok(())
    }

    async fn evict_oldest_locked(&self, pool: &mut HashMap<PoolKey, Arc<PooledConnection>>) {
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

        let p1 = build_1hop_packet(&mut r, sk, b"first-via-pool");
        pool.send(SocketAddr::V4(addr), peer_pk, &p1)
            .await
            .expect("first send");
        assert_eq!(pool.len().await, 1);

        let p2 = build_1hop_packet(&mut r, sk, b"second-via-pool");
        pool.send(SocketAddr::V4(addr), peer_pk, &p2)
            .await
            .expect("second send");
        assert_eq!(pool.len().await, 1, "pool should reuse, not grow");

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
        tokio::time::sleep(Duration::from_millis(10)).await;
        pool.send(SocketAddr::V4(addr_b), pk_b, &pb).await.unwrap();
        assert_eq!(pool.len().await, 2);
        tokio::time::sleep(Duration::from_millis(10)).await;
        pool.send(SocketAddr::V4(addr_c), pk_c, &pc).await.unwrap();
        assert_eq!(pool.len().await, 2, "max size must be enforced");
    }
}
