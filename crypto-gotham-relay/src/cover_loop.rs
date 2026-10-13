// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::collections::VecDeque;
use std::sync::Arc;

use crypto_gotham::cover::{CoverIntent, CoverMode, CoverScheduler};
use crypto_gotham::directory::RelayDescriptor;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, warn};

use crate::client::GothamClient;

pub const DUMMY_PAYLOAD_SIZE: usize = 32;

fn build_cover_payload<R: CryptoRng + RngCore>(rng: &mut R) -> Vec<u8> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let recipient = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
    let sender = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();

    let mut pick = [0u8; 2];
    rng.fill_bytes(&mut pick);
    let span = COVER_BODY_MAX - COVER_BODY_MIN;
    let len = COVER_BODY_MIN + (u16::from_be_bytes(pick) as usize % span);

    let mut body = vec![0u8; len];
    rng.fill_bytes(&mut body);

    match GothamClient::seal_and_frame(rng, &recipient, &sender, &body) {
        Ok(framed) => framed,
        Err(_) => {
            let mut fallback = vec![0u8; DUMMY_PAYLOAD_SIZE];
            rng.fill_bytes(&mut fallback);
            fallback
        }
    }
}

const COVER_BODY_MIN: usize = 64;
const COVER_BODY_MAX: usize = 1024;

pub type QueuedMessage = (
    Vec<u8>,
    Option<usize>,
    Option<oneshot::Sender<Result<(), String>>>,
);

pub struct QueuedPacket {
    pub payload: Vec<u8>,
    pub hops: Option<usize>,
    pub exit: Option<RelayDescriptor>,
    pub done: Option<oneshot::Sender<Result<(), String>>>,
}

impl From<QueuedMessage> for QueuedPacket {
    fn from((payload, hops, done): QueuedMessage) -> Self {
        Self {
            payload,
            hops,
            exit: None,
            done,
        }
    }
}

pub struct CoverLoopHandle {
    cancel: Option<oneshot::Sender<()>>,
}

impl CoverLoopHandle {
    pub fn stop(mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for CoverLoopHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel.take() {
            let _ = tx.send(());
        }
    }
}

pub fn spawn_cover_loop<F>(
    client: Arc<GothamClient>,
    relays: Arc<Vec<RelayDescriptor>>,
    queue: Arc<Mutex<VecDeque<QueuedPacket>>>,
    base_mode: CoverMode,
    default_hop_count: usize,
    battery_provider: F,
) -> CoverLoopHandle
where
    F: Fn() -> (u8, bool) + Send + 'static,
{
    let (cancel_tx, mut cancel_rx) = oneshot::channel();

    tokio::spawn(async move {
        loop {
            let (battery_pct, charging) = battery_provider();
            let mode = base_mode.battery_adjusted(battery_pct, charging);
            let scheduler = CoverScheduler::new(mode);

            let delay = {
                let mut rng = OsRng;
                scheduler.next_interval(&mut rng)
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = &mut cancel_rx => break,
            }

            let has_real = !queue.lock().await.is_empty();
            let intent = {
                let mut rng = OsRng;
                scheduler.next_intent(&mut rng, has_real)
            };

            match intent {
                CoverIntent::Real => {
                    let popped = queue.lock().await.pop_front();
                    if let Some(QueuedPacket {
                        payload,
                        hops,
                        exit,
                        done,
                    }) = popped
                    {
                        let n = hops.unwrap_or(default_hop_count);
                        let mut rng = OsRng;
                        let result = match &exit {
                            Some(e) => client
                                .send_to_exit(&mut rng, &relays, n, e, &payload)
                                .await
                                .map_err(|e| format!("cover loop deposit send: {e}")),
                            None => client
                                .send(&mut rng, &relays, n, &payload)
                                .await
                                .map_err(|e| format!("cover loop real send: {e}")),
                        };
                        match &result {
                            Ok(()) => debug!(payload_len = payload.len(), "cover loop: real sent"),
                            Err(e) => warn!(error = %e, "cover loop: real send failed"),
                        }
                        if let Some(done) = done {
                            let _ = done.send(result);
                        }
                    }
                }
                CoverIntent::Drop | CoverIntent::Loop => {
                    let mut rng = OsRng;
                    let dummy = build_cover_payload(&mut rng);
                    if let Err(e) = client
                        .send(&mut rng, &relays, default_hop_count, &dummy)
                        .await
                    {
                        debug!(error = ?e, "cover loop: dummy send failed");
                    } else {
                        debug!("cover loop: dummy sent");
                    }
                }
            }
        }
        debug!("cover loop exited");
    });

    CoverLoopHandle {
        cancel: Some(cancel_tx),
    }
}

#[cfg(test)]
mod cover_indistinguishability_tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn real_payload<R: CryptoRng + RngCore>(rng: &mut R, body_len: usize) -> Vec<u8> {
        let recipient = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
        let sender = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
        let mut body = vec![0u8; body_len];
        rng.fill_bytes(&mut body);
        GothamClient::seal_and_frame(rng, &recipient, &sender, &body).unwrap()
    }

    fn looks_well_framed(p: &[u8]) -> bool {
        if p.len() < 4 {
            return false;
        }
        let declared = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        declared == p.len() - 4
    }

    #[test]
    fn a_cover_packet_is_framed_exactly_like_a_real_one() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FF_EE00);

        let mut legacy = vec![0u8; DUMMY_PAYLOAD_SIZE];
        rng.fill_bytes(&mut legacy);
        assert!(
            !looks_well_framed(&legacy),
            "the classifier must actually separate the OLD dummy, or this test \
             is not measuring anything",
        );

        for _ in 0..256 {
            assert!(
                looks_well_framed(&build_cover_payload(&mut rng)),
                "a decoy must carry a valid length prefix, like a real packet",
            );
        }
        for _ in 0..256 {
            assert!(looks_well_framed(&real_payload(&mut rng, 200)));
        }
    }

    #[test]
    fn cover_lengths_overlap_real_lengths_and_are_not_constant() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF_0042);

        let cover: Vec<usize> = (0..512)
            .map(|_| build_cover_payload(&mut rng).len())
            .collect();
        let distinct = cover.iter().collect::<std::collections::HashSet<_>>().len();
        assert!(
            distinct > 100,
            "decoy lengths are effectively constant ({distinct} distinct)",
        );

        let real_small = real_payload(&mut rng, COVER_BODY_MIN).len();
        let real_large = real_payload(&mut rng, COVER_BODY_MAX - 1).len();
        assert!(
            cover.iter().all(|l| *l >= real_small && *l <= real_large),
            "decoy lengths fall outside the real range",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::directory::{RelayDescriptor, RelayTier};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::net::{SocketAddr, SocketAddrV4};
    use std::sync::Once;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::pool::ConnectionPool;
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

    async fn spawn_relay_with_delivery(
        sk: [u8; 32],
        tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> SocketAddrV4 {
        let handler: DeliveryHandler = Arc::new(move |payload: Vec<u8>| {
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

    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cover_loop_dispatches_real_message() {
        init();
        let mut r = ChaCha20Rng::seed_from_u64(0xABCD1234);

        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_exit = clamped_sk(&mut r);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let addr_entry = spawn_relay_with_delivery(sk_entry, tx.clone()).await;
        let addr_mix = spawn_relay_with_delivery(sk_mix, tx.clone()).await;
        let addr_exit = spawn_relay_with_delivery(sk_exit, tx.clone()).await;

        let relays = Arc::new(vec![
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry, "op-A"),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix, "op-B"),
            descriptor_from(sk_exit, addr_exit, RelayTier::Exit, "op-C"),
        ]);

        let client = Arc::new(GothamClient::new(&mut r).unwrap());
        let queue = Arc::new(Mutex::new(VecDeque::<QueuedPacket>::new()));

        let marker = b"COVER-LOOP-TEST-MARKER-1234567890".to_vec();
        queue
            .lock()
            .await
            .push_back((marker.clone(), None, None).into());

        let handle = spawn_cover_loop(
            client,
            Arc::clone(&relays),
            Arc::clone(&queue),
            CoverMode::Paranoid,
            3,
            || (100, true),
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut found = false;
        while tokio::time::Instant::now() < deadline && !found {
            if let Ok(Some(payload)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await
            {
                if payload.len() >= marker.len() && payload[..marker.len()] == marker[..] {
                    found = true;
                }
            }
        }

        handle.stop();
        assert!(found, "marker payload never arrived within 30 s");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cover_loop_stops_cleanly_on_handle_drop() {
        init();
        let mut r = ChaCha20Rng::seed_from_u64(7);
        let client = Arc::new(GothamClient::new(&mut r).unwrap());
        let relays = Arc::new(Vec::<RelayDescriptor>::new());
        let queue = Arc::new(Mutex::new(VecDeque::<QueuedPacket>::new()));
        let handle = spawn_cover_loop(client, relays, queue, CoverMode::Paranoid, 3, || {
            (100, true)
        });
        drop(handle);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[test]
    fn a_queued_packet_carries_its_forced_exit() {
        let plain: QueuedPacket = (vec![1, 2, 3], Some(4), None).into();
        assert!(
            plain.exit.is_none(),
            "an ordinary message must not force an exit"
        );
        assert_eq!(plain.hops, Some(4));

        let deposit = QueuedPacket {
            payload: vec![9; 64],
            hops: Some(3),
            exit: Some(crypto_gotham::directory::RelayDescriptor {
                id_pubkey_hex: "aa".repeat(32),
                kem_pubkey_hex: "bb".repeat(32),
                addr: "203.0.113.7:443".to_string(),
                tier: crypto_gotham::directory::RelayTier::Exit,
                country: None,
                asn: None,
                operator: None,
                uptime_pct: None,
                mailbox: true,
                rendezvous: None,
                rendezvous_capable: false,
            }),
            done: None,
        };
        assert!(deposit.exit.is_some());
        assert!(deposit.exit.unwrap().mailbox);
    }
}
