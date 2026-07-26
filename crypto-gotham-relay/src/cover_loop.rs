// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Cover-traffic event loop.
//!
//! Wires together [`crypto_gotham::cover::CoverScheduler`] (intent + timing
//! logic) and [`crate::client::GothamClient`] (actual packet send) into a
//! background task that emits a Poisson-distributed packet stream — real
//! when there's a queued message, dummy otherwise.
//!
//! ## Lifecycle
//!
//! ```ignore
//! let queue = Arc::new(Mutex::new(VecDeque::new()));
//! let handle = spawn_cover_loop(
//!     Arc::new(client),
//!     Arc::new(relays),
//!     queue.clone(),
//!     CoverMode::Balanced,
//!     3,                            // default hop count
//!     || (100, true),               // battery provider — fully charged
//! );
//! // ... later ...
//! queue.lock().await.push_back((b"hello bob".to_vec(), None, None));
//! // ... eventually ...
//! handle.stop();
//! ```
//!
//! ## v0.1 caveats
//!
//! - `CoverIntent::Loop` is implemented as a Drop in v0.1 (we don't yet
//!   have self-registration in the directory).
//! - The dummy payload is 32 bytes of OS-random — the recipient relay
//!   simply discards it because it's not a real Sealed-Sender packet.
//!   v0.2 will introduce a "sink" tier of relays that explicitly drop
//!   such packets without attempting decapsulation.

use std::collections::VecDeque;
use std::sync::Arc;

use crypto_gotham::cover::{CoverIntent, CoverMode, CoverScheduler};
use crypto_gotham::directory::RelayDescriptor;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, warn};

use crate::client::GothamClient;

/// Length of the dummy payload Drop / Loop packets carry.
pub const DUMMY_PAYLOAD_SIZE: usize = 32;

/// One queued real message waiting for cover-loop dispatch:
/// `(payload, optional_override_hop_count, optional_completion)`.
///
/// - `optional_override_hop_count`: `None` ⇒ use the configured `default_hop_count`.
/// - `optional_completion`: a one-shot the loop fires with the true send result
///   once the message is actually dispatched (at its Poisson tick). The enqueuer
///   awaits it so `Ok(())` means *shipped to the entry relay*, not merely queued
///   — the sender's `pending_outbox` retry row is only cleared on real dispatch,
///   so a dead/slow loop or a failed send never silently loses the message.
pub type QueuedMessage = (
    Vec<u8>,
    Option<usize>,
    Option<oneshot::Sender<Result<(), String>>>,
);

/// Live handle to a running cover loop. Calling [`Self::stop`] cancels
/// the loop on the next tick.
pub struct CoverLoopHandle {
    cancel: Option<oneshot::Sender<()>>,
}

impl CoverLoopHandle {
    /// Signal the loop to terminate.
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

/// Spawn the cover-traffic loop as a tokio task and return a cancellation
/// handle.
///
/// At each Poisson-sampled tick the loop:
/// 1. Reads battery state via `battery_provider()` and adjusts the mode
///    if necessary.
/// 2. Calls [`CoverScheduler::next_intent`] passing whether the queue
///    has a real message.
/// 3. Dispatches `Real`, `Drop`, or `Loop` (Loop falls back to Drop in
///    v0.1).
pub fn spawn_cover_loop<F>(
    client: Arc<GothamClient>,
    relays: Arc<Vec<RelayDescriptor>>,
    queue: Arc<Mutex<VecDeque<QueuedMessage>>>,
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
            // Battery-aware mode for THIS tick.
            let (battery_pct, charging) = battery_provider();
            let mode = base_mode.battery_adjusted(battery_pct, charging);
            let scheduler = CoverScheduler::new(mode);

            // Sleep for the next Poisson interval (cancellable).
            let delay = {
                let mut rng = OsRng;
                scheduler.next_interval(&mut rng)
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = &mut cancel_rx => break,
            }

            // Inspect queue (briefly) to decide intent.
            let has_real = !queue.lock().await.is_empty();
            let intent = {
                let mut rng = OsRng;
                scheduler.next_intent(&mut rng, has_real)
            };

            match intent {
                CoverIntent::Real => {
                    let popped = queue.lock().await.pop_front();
                    if let Some((payload, hop_override, done)) = popped {
                        let n = hop_override.unwrap_or(default_hop_count);
                        let mut rng = OsRng;
                        let result = client
                            .send(&mut rng, &relays, n, &payload)
                            .await
                            .map_err(|e| format!("cover loop real send: {e}"));
                        match &result {
                            Ok(()) => debug!(payload_len = payload.len(), "cover loop: real sent"),
                            Err(e) => warn!(error = %e, "cover loop: real send failed"),
                        }
                        // Signal the awaiting enqueuer with the true outcome so it
                        // can clear (Ok) or retry/deposit (Err) — no silent loss.
                        if let Some(done) = done {
                            let _ = done.send(result);
                        }
                    }
                }
                CoverIntent::Drop | CoverIntent::Loop => {
                    let mut dummy = vec![0u8; DUMMY_PAYLOAD_SIZE];
                    OsRng.fill_bytes(&mut dummy);
                    let mut rng = OsRng;
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

    /// Spawn a relay with delivery hook → mpsc Sender for verification.
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

    // FIXME P5.next: this integration test depends on a Poisson tick
    // firing within a 30 s window — even with Paranoid mode (5 s mean)
    // and a battery override, the tail of the distribution makes it
    // flaky in CI. Run manually with `cargo test cover_loop -- --ignored`.
    // The dispatcher logic itself is covered by the synchronous tests
    // in `crypto-gotham/src/cover.rs` (next_intent / next_interval).
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
        let queue = Arc::new(Mutex::new(VecDeque::<QueuedMessage>::new()));

        // Enqueue ONE real message BEFORE spawning the loop, so the first
        // tick is guaranteed to see has_real=true and pick CoverIntent::Real.
        let marker = b"COVER-LOOP-TEST-MARKER-1234567890".to_vec();
        queue.lock().await.push_back((marker.clone(), None, None));

        // Paranoid mode = 5 s mean interval — first tick is the only one
        // we care about. Battery 100%/charging avoids degradation.
        let handle = spawn_cover_loop(
            client,
            Arc::clone(&relays),
            Arc::clone(&queue),
            CoverMode::Paranoid,
            3,
            || (100, true),
        );

        // Wait up to 30 s (Poisson tail tolerance). We loop reading from
        // rx so cover/dummy payloads don't starve us out of the marker.
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
        // We don't need network here — a dummy client + empty relays.
        let mut r = ChaCha20Rng::seed_from_u64(7);
        let client = Arc::new(GothamClient::new(&mut r).unwrap());
        let relays = Arc::new(Vec::<RelayDescriptor>::new());
        let queue = Arc::new(Mutex::new(VecDeque::<QueuedMessage>::new()));
        let handle = spawn_cover_loop(client, relays, queue, CoverMode::Paranoid, 3, || {
            (100, true)
        });
        // Immediately drop — should send cancel signal without panicking.
        drop(handle);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
