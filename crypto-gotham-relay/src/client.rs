// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::net::SocketAddr;

use crypto_gotham::directory::{PathSelector, RelayDescriptor, SelectedPath};
use crypto_gotham::header::{
    derive_route_secrets, flag, mode, wrap_header, RoutingRecord, HEADER_LEN, TRAILER_LEN,
};
use crypto_gotham::PACKET_SIZE;
use quinn::Endpoint;
use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::delay::PoissonScheduler;
use crate::transport::{build_client_endpoint, forward_packet, TransportError};

pub const MAX_PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_LEN;

const SENDER_MEAN_DELAY_MICROS: u64 = 500_000;

fn sender_hop_delay_micros<R: RngCore + ?Sized>(sched: &PoissonScheduler, rng: &mut R) -> u32 {
    let micros = sched.next_delay(rng).as_micros().min(u32::MAX as u128) as u32;
    micros.max(1)
}

pub fn hop_count_for_mode(m: u8) -> Option<usize> {
    match m {
        mode::LOW_LATENCY => Some(3),
        mode::BALANCED => Some(4),
        mode::PARANOID => Some(5),
        _ => None,
    }
}

#[derive(ZeroizeOnDrop)]
pub struct GothamClient {
    #[zeroize(skip)]
    endpoint: Endpoint,
    #[zeroize(skip)]
    mean_hop_delay_micros: u64,
    #[zeroize(skip)]
    entry_guards: Vec<String>,
}

impl GothamClient {
    fn fresh_handshake_key() -> zeroize::Zeroizing<[u8; 32]> {
        let mut sk = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut sk[..]);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    pub fn new<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self, TransportError> {
        let endpoint = build_client_endpoint()?;
        Ok(Self {
            endpoint,
            mean_hop_delay_micros: SENDER_MEAN_DELAY_MICROS,
            entry_guards: Vec::new(),
        })
    }

    #[must_use]
    pub fn with_hop_delay(mut self, mean_micros: u64) -> Self {
        self.mean_hop_delay_micros = mean_micros.max(1_000);
        self
    }

    #[must_use]
    pub fn with_entry_guards(mut self, guards: Vec<String>) -> Self {
        self.entry_guards = guards;
        self
    }

    pub async fn send<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        relays: &[RelayDescriptor],
        hop_count: usize,
        payload: &[u8],
    ) -> Result<(), ClientError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ClientError::PayloadTooLarge);
        }
        if !(3..=5).contains(&hop_count) {
            return Err(ClientError::BadHopCount);
        }

        let path = PathSelector::new(relays)
            .with_guards(&self.entry_guards)
            .pick(rng, hop_count)
            .map_err(|_| ClientError::PathSelection)?;
        self.ship_path(rng, &path, payload).await
    }

    pub async fn send_to_exit<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        relays: &[RelayDescriptor],
        hop_count: usize,
        exit: &RelayDescriptor,
        payload: &[u8],
    ) -> Result<(), ClientError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ClientError::PayloadTooLarge);
        }
        if !(3..=5).contains(&hop_count) {
            return Err(ClientError::BadHopCount);
        }
        let path = PathSelector::new(relays)
            .with_guards(&self.entry_guards)
            .pick_to_exit(rng, hop_count, exit)
            .map_err(|_| ClientError::PathSelection)?;
        self.ship_path(rng, &path, payload).await
    }

    async fn ship_path<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        path: &SelectedPath<'_>,
        payload: &[u8],
    ) -> Result<(), ClientError> {
        let recipient_pks: Vec<[u8; 32]> = path
            .hops
            .iter()
            .map(|r| r.kem_pubkey_bytes())
            .collect::<crypto_gotham::Result<Vec<_>>>()
            .map_err(|_| ClientError::BadDirectory("relay kem pubkey malformed"))?;
        let (alphas, sub_keys) =
            derive_route_secrets(rng, &recipient_pks).map_err(|_| ClientError::Crypto)?;

        let n = path.hops.len();
        let delay_sched = PoissonScheduler::new(self.mean_hop_delay_micros);
        let mut records: Vec<RoutingRecord> = Vec::with_capacity(n);
        for i in 0..n {
            let mut rec = RoutingRecord::default();
            if i + 1 < n {
                let next = path.hops[i + 1];
                rec.next_node_id = next
                    .kem_pubkey_bytes()
                    .map_err(|_| ClientError::BadDirectory("next node id"))?;
                if next.rendezvous.is_some() {
                    rec.flag = flag::VIA_RENDEZVOUS;
                } else {
                    rec.next_ipv4 = next
                        .ipv4_octets()
                        .map_err(|_| ClientError::BadDirectory("non-ipv4 next addr"))?;
                    rec.next_port = next
                        .port()
                        .map_err(|_| ClientError::BadDirectory("bad next port"))?;
                }
            } else {
                rec.flag = flag::IS_LAST_HOP;
            }
            rec.delay_micros = sender_hop_delay_micros(&delay_sched, rng);
            records.push(rec);
        }

        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header = wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer)
            .map_err(|_| ClientError::Crypto)?;

        let mut packet = vec![0u8; PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        packet[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);

        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }

        let entry = path.hops[0];
        let entry_addr: SocketAddr = entry
            .addr
            .parse()
            .map_err(|_| ClientError::BadDirectory("entry addr parse"))?;
        let entry_pk = entry
            .kem_pubkey_bytes()
            .map_err(|_| ClientError::BadDirectory("entry kem pk"))?;

        let handshake_sk = Self::fresh_handshake_key();
        forward_packet(
            &self.endpoint,
            entry_addr,
            &entry_pk,
            &handshake_sk,
            &packet,
        )
        .await
        .map_err(ClientError::Transport)?;

        let _ = sub_keys;
        Ok(())
    }

    pub async fn send_sealed<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        relays: &[RelayDescriptor],
        hop_count: usize,
        recipient_pk: &[u8; 32],
        sender_pk: &[u8; 32],
        body: &[u8],
    ) -> Result<(), ClientError> {
        let framed = Self::seal_and_frame(rng, recipient_pk, sender_pk, body)?;
        self.send(rng, relays, hop_count, &framed).await
    }

    pub fn seal_and_frame<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_pk: &[u8; 32],
        sender_pk: &[u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let envelope = crypto_gotham::sealed::seal(rng, recipient_pk, sender_pk, body)
            .map_err(|_| ClientError::Crypto)?;
        let mut framed = Vec::with_capacity(4 + envelope.len());
        framed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        framed.extend_from_slice(&envelope);
        if framed.len() > MAX_PAYLOAD_SIZE {
            return Err(ClientError::PayloadTooLarge);
        }
        Ok(framed)
    }

    pub async fn send_sealed_to_exit<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        relays: &[RelayDescriptor],
        hop_count: usize,
        exit: &RelayDescriptor,
        sender_pk: &[u8; 32],
        body: &[u8],
    ) -> Result<(), ClientError> {
        let framed = Self::frame_sealed_for_exit(rng, exit, sender_pk, body)?;
        self.send_to_exit(rng, relays, hop_count, exit, &framed)
            .await
    }

    pub fn frame_sealed_for_exit<R: CryptoRng + RngCore>(
        rng: &mut R,
        exit: &RelayDescriptor,
        sender_pk: &[u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let exit_kem = exit
            .kem_pubkey_bytes()
            .map_err(|_| ClientError::BadDirectory("exit kem pk"))?;
        let envelope = crypto_gotham::sealed::seal(rng, &exit_kem, sender_pk, body)
            .map_err(|_| ClientError::Crypto)?;
        let mut framed = Vec::with_capacity(4 + envelope.len());
        framed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        framed.extend_from_slice(&envelope);
        if framed.len() > MAX_PAYLOAD_SIZE {
            return Err(ClientError::PayloadTooLarge);
        }
        Ok(framed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("payload exceeds {MAX_PAYLOAD_SIZE} bytes")]
    PayloadTooLarge,
    #[error("hop_count must be in 3..=5")]
    BadHopCount,
    #[error("path selection failed (insufficient diversity in directory)")]
    PathSelection,
    #[error("directory: {0}")]
    BadDirectory(&'static str),
    #[error("crypto operation failed")]
    Crypto,
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::directory::{RelayDescriptor, RelayTier};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::net::SocketAddrV4;
    use std::sync::{Arc, Once};
    use std::time::Duration;
    use tokio::sync::Mutex;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::pool::ConnectionPool;
    use crate::process::Relay;
    use crate::transport::{build_server_endpoint, serve_connection};

    static CRYPTO: Once = Once::new();
    fn init() {
        CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xDEADCAFE)
    }

    async fn spawn_relay(sk: [u8; 32]) -> SocketAddrV4 {
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
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, None).await;
                    }
                });
            }
        });
        match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("expected v4"),
        }
    }

    fn clamped_sk(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    fn descriptor_from(
        sk: [u8; 32],
        addr: SocketAddrV4,
        tier: RelayTier,
        op: &str,
    ) -> RelayDescriptor {
        let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        RelayDescriptor {
            id_pubkey_hex: hex::encode(pk),
            kem_pubkey_hex: hex::encode(pk),
            addr: addr.to_string(),
            tier,
            country: Some("FR".into()),
            asn: None,
            operator: Some(op.into()),
            uptime_pct: Some(99.9),
            mailbox: false,
            rendezvous: None,
            rendezvous_capable: false,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn client_sends_through_3_hop_path() {
        init();
        let mut r = rng();

        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_exit = clamped_sk(&mut r);
        let addr_entry = spawn_relay(sk_entry).await;
        let addr_mix = spawn_relay(sk_mix).await;
        let addr_exit = spawn_relay(sk_exit).await;

        let relays = vec![
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry, "op-A"),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix, "op-B"),
            descriptor_from(sk_exit, addr_exit, RelayTier::Exit, "op-C"),
        ];

        let payload = b"hello from gotham client v0.1";

        let client = GothamClient::new(&mut r).unwrap();
        client
            .send(&mut r, &relays, 3, payload)
            .await
            .expect("send");

        tokio::time::sleep(Duration::from_millis(800)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_rejects_oversized_payload() {
        init();
        let mut r = rng();
        let client = GothamClient::new(&mut r).unwrap();
        let oversized = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let err = client.send(&mut r, &[], 3, &oversized).await.unwrap_err();
        assert!(matches!(err, ClientError::PayloadTooLarge));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_rejects_bad_hop_count() {
        init();
        let mut r = rng();
        let client = GothamClient::new(&mut r).unwrap();
        let err = client.send(&mut r, &[], 2, b"x").await.unwrap_err();
        assert!(matches!(err, ClientError::BadHopCount));
        let err = client.send(&mut r, &[], 6, b"x").await.unwrap_err();
        assert!(matches!(err, ClientError::BadHopCount));
    }

    #[test]
    fn sender_hop_delays_are_exponentially_distributed() {
        let sched = PoissonScheduler::new(SENDER_MEAN_DELAY_MICROS);
        let mut rng = ChaCha20Rng::seed_from_u64(0x0090_1550);
        let n = 50_000usize;
        let (mut sum, mut sum_sq) = (0.0f64, 0.0f64);
        let mut min_seen = u32::MAX;
        for _ in 0..n {
            let micros = sender_hop_delay_micros(&sched, &mut rng);
            min_seen = min_seen.min(micros);
            let x = f64::from(micros);
            sum += x;
            sum_sq += x * x;
        }
        let mean = sum / n as f64;
        let var = (sum_sq / n as f64) - mean * mean;
        let cv = var.sqrt() / mean;

        let mean_err =
            (mean - SENDER_MEAN_DELAY_MICROS as f64).abs() / SENDER_MEAN_DELAY_MICROS as f64;
        assert!(
            mean_err < 0.05,
            "sample mean {mean:.0}µs differs from configured {SENDER_MEAN_DELAY_MICROS}µs by {:.2}%",
            mean_err * 100.0
        );
        assert!(
            (0.9..=1.1).contains(&cv),
            "coefficient of variation {cv:.3} is not ~1 — delays are not exponential"
        );
        assert!(
            min_seen >= 1,
            "0 is reserved for 'unset'; sender must emit ≥1µs"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_rejects_empty_directory() {
        init();
        let mut r = rng();
        let client = GothamClient::new(&mut r).unwrap();
        let err = client.send(&mut r, &[], 3, b"x").await.unwrap_err();
        assert!(matches!(err, ClientError::PathSelection));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sealed_send_round_trips_through_3_hop_path() {
        init();
        let mut r = rng();

        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_exit = clamped_sk(&mut r);

        let addr_entry = spawn_relay(sk_entry).await;
        let addr_mix = spawn_relay(sk_mix).await;

        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<([u8; 32], Vec<u8>)>();
        let handler =
            crate::transport::make_unsealing_delivery_handler(recipient_sk, move |sender, body| {
                let _ = tx.send((sender, body));
            });
        let server_exit =
            crate::transport::build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr_exit = match server_exit.local_addr().unwrap() {
            SocketAddr::V4(v) => v,
            _ => panic!(),
        };
        let client_ep = crate::transport::build_client_endpoint().unwrap();
        let relay_exit = Relay::new(sk_exit, 1000, Duration::from_secs(60), 0);
        let relay_exit = Arc::new(Mutex::new(relay_exit));
        let pool_exit = Arc::new(ConnectionPool::new(client_ep, sk_exit));
        tokio::spawn(async move {
            while let Some(connecting) = server_exit.accept().await {
                let relay = Arc::clone(&relay_exit);
                let pool = Arc::clone(&pool_exit);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk_exit, relay, pool, Some(handler)).await;
                    }
                });
            }
        });

        let relays = vec![
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry, "op-A"),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix, "op-B"),
            descriptor_from(sk_exit, addr_exit, RelayTier::Exit, "op-C"),
        ];

        let body = b"sealed end-to-end through 3 hops".to_vec();

        let client = GothamClient::new(&mut r).unwrap();
        client
            .send_sealed(&mut r, &relays, 3, &recipient_pk, &sender_pk, &body)
            .await
            .expect("send_sealed");

        let (got_sender, got_body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delivery timeout")
            .expect("channel closed");
        assert_eq!(got_sender, sender_pk, "unsealed sender mismatch");
        assert_eq!(&got_body[..body.len()], &body[..]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn signed_directory_testnet_delivers_a_to_b() {
        init();
        let mut r = rng();

        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_exit = clamped_sk(&mut r);
        let authority = ed25519_dalek::SigningKey::generate(&mut r);

        let addr_entry = spawn_relay(sk_entry).await;
        let addr_mix = spawn_relay(sk_mix).await;

        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<([u8; 32], Vec<u8>)>();
        let handler =
            crate::transport::make_unsealing_delivery_handler(recipient_sk, move |sender, body| {
                let _ = tx.send((sender, body));
            });
        let server_exit = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr_exit = match server_exit.local_addr().unwrap() {
            SocketAddr::V4(v) => v,
            _ => panic!("expected v4"),
        };
        let client_ep = crate::transport::build_client_endpoint().unwrap();
        let relay_exit = Arc::new(Mutex::new(Relay::new(
            sk_exit,
            1000,
            Duration::from_secs(60),
            0,
        )));
        let pool_exit = Arc::new(ConnectionPool::new(client_ep, sk_exit));
        tokio::spawn(async move {
            while let Some(connecting) = server_exit.accept().await {
                let relay = Arc::clone(&relay_exit);
                let pool = Arc::clone(&pool_exit);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk_exit, relay, pool, Some(handler)).await;
                    }
                });
            }
        });

        let relays = vec![
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry, "op-A"),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix, "op-B"),
            descriptor_from(sk_exit, addr_exit, RelayTier::Exit, "op-C"),
        ];
        let doc = crypto_gotham::directory::DirectoryDoc::new(relays, Duration::from_secs(3600))
            .expect("build directory doc");
        let signed = crypto_gotham::directory::SignedDirectory::sign(doc, &authority)
            .expect("sign directory");

        let path = std::env::temp_dir().join(format!(
            "gotham_testnet_dir_{}_{}.json",
            std::process::id(),
            r.next_u32()
        ));
        std::fs::write(&path, signed.to_json_pretty().unwrap()).unwrap();
        let raw = std::fs::read(&path).unwrap();
        let loaded = crypto_gotham::directory::SignedDirectory::from_json(&raw)
            .expect("parse signed directory");
        std::fs::remove_file(&path).ok();

        loaded
            .verify(&authority.verifying_key())
            .expect("signed directory must verify against the pinned authority");
        let impostor = ed25519_dalek::SigningKey::generate(&mut r);
        assert!(
            loaded.verify(&impostor.verifying_key()).is_err(),
            "directory must not verify against an unpinned authority"
        );

        let body = b"delivered through a signed 3-relay testnet".to_vec();
        let client = GothamClient::new(&mut r).unwrap();
        client
            .send_sealed(
                &mut r,
                &loaded.doc.relays,
                3,
                &recipient_pk,
                &sender_pk,
                &body,
            )
            .await
            .expect("send_sealed via signed directory");

        let (got_sender, got_body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delivery timeout")
            .expect("channel closed");
        assert_eq!(got_sender, sender_pk, "unsealed sender mismatch");
        assert_eq!(
            &got_body[..body.len()],
            &body[..],
            "recovered body mismatch"
        );
    }

    #[test]
    fn hop_count_for_mode_table() {
        assert_eq!(hop_count_for_mode(mode::LOW_LATENCY), Some(3));
        assert_eq!(hop_count_for_mode(mode::BALANCED), Some(4));
        assert_eq!(hop_count_for_mode(mode::PARANOID), Some(5));
        assert_eq!(hop_count_for_mode(99), None);
    }

    #[test]
    fn every_handshake_key_is_fresh_and_clamped() {
        let a = GothamClient::fresh_handshake_key();
        let b = GothamClient::fresh_handshake_key();
        assert_ne!(*a, *b, "two handshakes must not share a key");

        for k in [&a, &b] {
            assert_eq!(k[0] & 7, 0);
            assert_eq!(k[31] & 128, 0);
            assert_eq!(k[31] & 64, 64);
        }

        let sizes = std::mem::size_of::<GothamClient>();
        assert!(sizes > 0);
    }
}
