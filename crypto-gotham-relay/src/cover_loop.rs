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
use rand::{CryptoRng, RngCore};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, warn};

use crate::client::GothamClient;

/// Length of the dummy payload Drop / Loop packets carry.
///
/// Retained for the tests that name it; the cover loop no longer uses a fixed
/// size. See [`build_cover_payload`].
pub const DUMMY_PAYLOAD_SIZE: usize = 32;

/// F-32 — a cover packet must be indistinguishable from a real one at the exit.
///
/// The dummy used to be 32 raw random bytes, while a real payload is a sealed
/// envelope behind a 4-byte big-endian length prefix. The exit relay sees the
/// peeled payload region in clear, so it simply read the first four bytes as a
/// length: for a real packet that length is consistent with what follows, for 32
/// random bytes it essentially never is. That separates cover from real with
/// probability about 1 − 2⁻²¹ — at the one hop where cover traffic is supposed
/// to matter most, since the exit is what learns the recipient.
///
/// Building the dummy through the real sealing path makes the region a
/// well-formed sealed envelope with a valid length prefix. The exit can then
/// only try to unseal it and fail, which is exactly what it already does for a
/// genuine packet not addressed to it — so failure to unseal stops being a
/// distinguisher at all.
fn build_cover_payload<R: CryptoRng + RngCore>(rng: &mut R) -> Vec<u8> {
    use x25519_dalek::{PublicKey, StaticSecret};

    // A throwaway recipient nobody holds the secret for. The envelope is
    // undecryptable by construction, which is what a decoy should be.
    let recipient = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
    let sender = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();

    // Body length drawn across the range a real message occupies, rather than a
    // constant. The Sphinx packet is fixed at 2048 bytes either way, so this
    // costs nothing on the wire; what it buys is that the length prefix inside
    // the peeled region carries the same spread as real traffic.
    let mut pick = [0u8; 2];
    rng.fill_bytes(&mut pick);
    let span = COVER_BODY_MAX - COVER_BODY_MIN;
    let len = COVER_BODY_MIN + (u16::from_be_bytes(pick) as usize % span);

    let mut body = vec![0u8; len];
    rng.fill_bytes(&mut body);

    match GothamClient::seal_and_frame(rng, &recipient, &sender, &body) {
        Ok(framed) => framed,
        Err(_) => {
            // Cannot happen for a body inside the range above, but a cover
            // packet must never be skipped: a gap in the Poisson stream is
            // itself a signal.
            let mut fallback = vec![0u8; DUMMY_PAYLOAD_SIZE];
            rng.fill_bytes(&mut fallback);
            fallback
        }
    }
}

/// Body-length range for a decoy, chosen to cover ordinary chat traffic without
/// approaching the payload ceiling (a decoy that is always maximal is its own
/// distinguisher).
const COVER_BODY_MIN: usize = 64;
const COVER_BODY_MAX: usize = 1024;

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

/// One queued packet, with an optional FORCED EXIT.
///
/// F-39 — the mailbox deposit used to be sent directly, before anything was
/// queued: one immediate, off-cadence emission per message, followed by the
/// Poisson-timed live copy. Sealing the deposit hides the depositor from the
/// host; it does nothing about an observer on the link, who reads the send
/// instant off the packet clock. Routing it through the same emitter as
/// everything else is what makes its timing indistinguishable — which is the
/// whole purpose of having an emitter.
///
/// `exit` forces the last hop (a mailbox host); `None` is an ordinary path.
pub struct QueuedPacket {
    /// Already sealed and framed by the caller.
    pub payload: Vec<u8>,
    /// `None` ⇒ the loop's configured default.
    pub hops: Option<usize>,
    /// `Some` ⇒ dispatch with `send_to_exit`, forcing this last hop.
    pub exit: Option<RelayDescriptor>,
    /// Fired with the true send result at the packet's Poisson tick.
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
                    if let Some(QueuedPacket {
                        payload,
                        hops,
                        exit,
                        done,
                    }) = popped
                    {
                        let n = hops.unwrap_or(default_hop_count);
                        let mut rng = OsRng;
                        // F-39 — a forced exit (a mailbox deposit) rides the
                        // SAME emitter as everything else, so its timing is
                        // not its own signature.
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
                        // Signal the awaiting enqueuer with the true outcome so it
                        // can clear (Ok) or retry/deposit (Err) — no silent loss.
                        if let Some(done) = done {
                            let _ = done.send(result);
                        }
                    }
                }
                // F-55 — `Loop` is emitted as a Drop. A real self-loop would
                // be routed back to us and AWAITED, so its non-return is the
                // signal; this arm sends and forgets, so the loop half of the
                // split detects nothing. See `CoverIntent::Loop`.
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

    /// What an exit relay actually gets to look at: the peeled payload region.
    fn real_payload<R: CryptoRng + RngCore>(rng: &mut R, body_len: usize) -> Vec<u8> {
        let recipient = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
        let sender = PublicKey::from(&StaticSecret::random_from_rng(&mut *rng)).to_bytes();
        let mut body = vec![0u8; body_len];
        rng.fill_bytes(&mut body);
        GothamClient::seal_and_frame(rng, &recipient, &sender, &body).unwrap()
    }

    /// The classifier the finding describes, and the test whose absence let this
    /// through: read the 4-byte big-endian length prefix and check it against
    /// what actually follows. Against a 32-byte random dummy this separated
    /// cover from real with probability about 1 − 2⁻²¹.
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

        // The old shape, kept here to show the classifier really does work —
        // otherwise a passing test proves nothing about the fix.
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

    /// Length must not be a fingerprint either: a decoy of one fixed size is
    /// separable by size alone, without reading a single byte of content.
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

        // And they sit inside the range real traffic occupies, so a threshold on
        // length cannot separate them either.
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
        let queue = Arc::new(Mutex::new(VecDeque::<QueuedPacket>::new()));

        // Enqueue ONE real message BEFORE spawning the loop, so the first
        // tick is guaranteed to see has_real=true and pick CoverIntent::Real.
        let marker = b"COVER-LOOP-TEST-MARKER-1234567890".to_vec();
        queue
            .lock()
            .await
            .push_back((marker.clone(), None, None).into());

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
        let queue = Arc::new(Mutex::new(VecDeque::<QueuedPacket>::new()));
        let handle = spawn_cover_loop(client, relays, queue, CoverMode::Paranoid, 3, || {
            (100, true)
        });
        // Immediately drop — should send cancel signal without panicking.
        drop(handle);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// F-39 — a forced-exit packet (a mailbox deposit) is dispatched by the
    /// loop, on the emitter's cadence, not sent the moment it is built.
    ///
    /// The deposit used to leave immediately, before anything was queued: one
    /// off-cadence emission at the instant of composition, then the
    /// Poisson-timed live copy. Sealing hides the depositor from the HOST and
    /// does nothing about an observer of the link, who only needs the clock.
    #[test]
    fn a_queued_packet_carries_its_forced_exit() {
        let plain: QueuedPacket = (vec![1, 2, 3], Some(4), None).into();
        assert!(
            plain.exit.is_none(),
            "an ordinary message must not force an exit"
        );
        assert_eq!(plain.hops, Some(4));

        // And a deposit is the same queue entry, with the host pinned as the
        // last hop — so it waits for a tick exactly like everything else.
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
