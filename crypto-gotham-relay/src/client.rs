// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! [`GothamClient`] — high-level client that picks a path from a signed
//! directory, builds a Sphinx-wrapped packet, and ships it to the first
//! hop over QUIC + Noise XK.
//!
//! This is the *sender* side of the mixnet. It glues together:
//!
//! - [`crypto_gotham::directory::PathSelector`] for path selection
//! - [`crypto_gotham::header::wrap_header`] for the Sphinx onion
//! - [`crate::transport::forward_packet`] for actual delivery
//!
//! v0.1 caveats:
//! - No connection pooling — each `send` opens a fresh QUIC connection
//!   to the entry hop. Pooling moves to v0.2.
//! - No application-layer payload encryption here. Callers are
//!   responsible for wrapping `payload` in the Crypto E2E layer (X3DH
//!   + Double Ratchet) before calling [`GothamClient::send`].
//! - The client's own X25519 identity is **ephemeral per `GothamClient`**.
//!   For unlinkable sessions, instantiate a new client per outbound
//!   batch (cheap — only one keypair is generated).

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

/// Maximum payload size that fits inside a single Gotham packet.
pub const MAX_PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_LEN;

/// Mean per-hop mix delay the sender encodes, in microseconds. Tracks the
/// BALANCED mode target (20 ms) used by [`GothamClient::send`]. Each hop's
/// actual hold is an independent Exp(λ) draw with this mean (Loopix
/// sender-chosen delays), NOT a constant — a constant would be both a weak
/// mix and a header fingerprint.
const SENDER_MEAN_DELAY_MICROS: u64 = 20_000;

/// Sample one sender-chosen per-hop delay (µs) from Exp(λ), clamped to ≥ 1.
/// `0` is reserved on the wire for "unset" — relays then fall back to their
/// own scheduler (cover traffic / legacy senders), so the sender never
/// emits a literal 0.
fn sender_hop_delay_micros<R: RngCore + ?Sized>(sched: &PoissonScheduler, rng: &mut R) -> u32 {
    let micros = sched.next_delay(rng).as_micros().min(u32::MAX as u128) as u32;
    micros.max(1)
}

/// Anonymity mode → hop count mapping (mirrors `header::mode`).
pub fn hop_count_for_mode(m: u8) -> Option<usize> {
    match m {
        mode::LOW_LATENCY => Some(3),
        mode::BALANCED => Some(4),
        mode::PARANOID => Some(5),
        _ => None,
    }
}

/// A Gotham mixnet client.
///
/// Holds one QUIC client endpoint (reusable across many `send` calls)
/// and one ephemeral X25519 key used as the client's static identity
/// for the per-link Noise XK handshake. The X25519 key is zeroized on
/// drop.
#[derive(ZeroizeOnDrop)]
pub struct GothamClient {
    #[zeroize(skip)]
    endpoint: Endpoint,
    client_sk: [u8; 32],
}

impl GothamClient {
    /// Construct a fresh client with a freshly-generated ephemeral
    /// X25519 identity for the Noise XK handshake.
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, TransportError> {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        // X25519 scalar clamping.
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        let endpoint = build_client_endpoint()?;
        Ok(Self {
            endpoint,
            client_sk: sk,
        })
    }

    /// Send `payload` through a freshly-selected `hop_count`-hop path
    /// drawn from `relays`.
    ///
    /// **Steps:**
    /// 1. Path selection via [`PathSelector::pick`] (diversity-aware)
    /// 2. Derive ephemeral X25519 chain + per-hop sub-keys
    /// 3. Build per-hop routing records
    /// 4. Construct the Sphinx header
    /// 5. Assemble the 2048 B packet (`header || payload || zero-pad`)
    /// 6. Open a QUIC connection to the entry hop and ship one frame
    ///
    /// The supplied `payload` must be at most [`MAX_PAYLOAD_SIZE`] bytes;
    /// shorter payloads are zero-padded to fill the packet.
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

        // Select a diverse random path, then build + ship the onion.
        let path = PathSelector::new(relays)
            .pick(rng, hop_count)
            .map_err(|_| ClientError::PathSelection)?;
        self.ship_path(rng, &path, payload).await
    }

    /// Like [`send`](Self::send), but forces the LAST hop to `exit` (via
    /// [`PathSelector::pick_to_exit`]). Used to route a payload to a specific
    /// relay — e.g. a store-and-forward mailbox host — so a deposit rides the
    /// mixnet and the host never sees the depositor's IP.
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
            .pick_to_exit(rng, hop_count, exit)
            .map_err(|_| ClientError::PathSelection)?;
        self.ship_path(rng, &path, payload).await
    }

    /// Build the Sphinx onion for `path` and ship the 2048 B packet to the
    /// entry hop. Shared by [`send`](Self::send) and
    /// [`send_to_exit`](Self::send_to_exit).
    async fn ship_path<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        path: &SelectedPath<'_>,
        payload: &[u8],
    ) -> Result<(), ClientError> {
        // 2. Per-hop crypto material.
        let recipient_pks: Vec<[u8; 32]> = path
            .hops
            .iter()
            .map(|r| r.kem_pubkey_bytes())
            .collect::<crypto_gotham::Result<Vec<_>>>()
            .map_err(|_| ClientError::BadDirectory("relay kem pubkey malformed"))?;
        let (alphas, sub_keys) =
            derive_route_secrets(rng, &recipient_pks).map_err(|_| ClientError::Crypto)?;

        // 3. Routing records — record[i] points the i-th hop to hop[i+1].
        //    The KEM pubkey is also reused as the "node id" for self-loop
        //    detection at the relay (process.rs checks against its X25519
        //    public key).
        let n = path.hops.len();
        // Sender-chosen Loopix delays: each hop's hold time is an independent
        // Exp(λ) draw (mean = mode target), encoded per record and honored by
        // the relay (see `process.rs`). Built once, sampled per hop.
        let delay_sched = PoissonScheduler::new(SENDER_MEAN_DELAY_MICROS);
        let mut records: Vec<RoutingRecord> = Vec::with_capacity(n);
        for i in 0..n {
            let mut rec = RoutingRecord::default();
            if i + 1 < n {
                let next = path.hops[i + 1];
                rec.next_node_id = next
                    .kem_pubkey_bytes()
                    .map_err(|_| ClientError::BadDirectory("next node id"))?;
                if next.rendezvous.is_some() {
                    // RFC B3: the next hop is a CGNAT relay reachable only via
                    // THIS hop (its rendezvous R). Address it by identity and set
                    // the flag; R pushes it down the tunnel. Leave next_ipv4/port
                    // as the zero sentinel (never dialed).
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

        // 4. Trailer + header.
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header = wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer)
            .map_err(|_| ClientError::Crypto)?;

        // 5. Assemble packet, then onion-wrap the payload region.
        let mut packet = vec![0u8; PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        packet[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);

        // 5b. Per-hop payload onion (LIONESS wide-block PRP). Encrypt the WHOLE
        //     payload region (incl. the zero-padding, so there's no constant
        //     tail to fingerprint) once per hop, innermost first: apply the LAST
        //     hop's layer, then wrap outward so the entry sees the outermost.
        //     Each relay peels exactly its own layer; the exit recovers the
        //     original `payload`. LIONESS is non-malleable, so the payload not
        //     only differs at every hop but can't be tagged-and-tracked.
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }

        // 6. Ship to entry hop. Use the entry's KEM pubkey as the Noise
        //    XK peer key (relay's identity_sk == kem_sk in v0.1).
        let entry = path.hops[0];
        let entry_addr: SocketAddr = entry
            .addr
            .parse()
            .map_err(|_| ClientError::BadDirectory("entry addr parse"))?;
        let entry_pk = entry
            .kem_pubkey_bytes()
            .map_err(|_| ClientError::BadDirectory("entry kem pk"))?;

        forward_packet(
            &self.endpoint,
            entry_addr,
            &entry_pk,
            &self.client_sk,
            &packet,
        )
        .await
        .map_err(ClientError::Transport)?;

        // Zeroize intermediate secret material that left scope but isn't
        // necessarily wiped by Drop.
        let _ = sub_keys; // dropped here; SubKeys impls ZeroizeOnDrop
        Ok(())
    }

    /// Convenience wrapper around [`Self::send`] that first wraps `body`
    /// in a [sealed-sender envelope](crypto_gotham::sealed) for
    /// `recipient_pk`. The exit relay's [`DeliveryHandler`] (typically
    /// built via
    /// [`crate::transport::make_unsealing_delivery_handler`]) will
    /// recover `(sender_pk, body)` on the receiving side.
    ///
    /// `recipient_pk` is the recipient's long-term X25519 public key.
    /// `sender_pk` is the apparent sender identity included inside the
    /// sealed envelope — typically the sender's own X3DH identity key.
    ///
    /// **Payload size note**: the sealed envelope adds 60 B of overhead
    /// on top of `body`, so callers must keep `body.len() ≤
    /// MAX_PAYLOAD_SIZE - 60`.
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

    /// Seal `body` for `recipient_pk` and frame it (a 4 B big-endian length
    /// prefix ahead of the envelope) into exactly the payload bytes
    /// [`send`](Self::send) / the mixnet will carry. Split out of
    /// [`send_sealed`](Self::send_sealed) so a caller that dispatches through a
    /// queue (e.g. the cover-traffic loop, to hide send timing) can pre-build
    /// the payload and hand it to `send`.
    pub fn seal_and_frame<R: CryptoRng + RngCore>(
        rng: &mut R,
        recipient_pk: &[u8; 32],
        sender_pk: &[u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let envelope = crypto_gotham::sealed::seal(rng, recipient_pk, sender_pk, body)
            .map_err(|_| ClientError::Crypto)?;
        // Frame the variable-length envelope with a 4 B big-endian length
        // prefix so the receiver can find its end inside the zero-padded
        // 1664 B Gotham payload region.
        let mut framed = Vec::with_capacity(4 + envelope.len());
        framed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        framed.extend_from_slice(&envelope);
        if framed.len() > MAX_PAYLOAD_SIZE {
            return Err(ClientError::PayloadTooLarge);
        }
        Ok(framed)
    }

    /// Like [`send_sealed`](Self::send_sealed), but seals `body` for the chosen
    /// `exit` relay's KEM key and forces that relay as the last hop. Used to
    /// deposit into a mailbox host over the mixnet: `body` is a serialized
    /// `MailboxRequest::Deposit`, the host unseals it (with its own key) and
    /// stores the inner envelope — and never learns the depositor's IP.
    ///
    /// Returns [`ClientError::PayloadTooLarge`] if the sealed request doesn't
    /// fit one packet; the caller should then fall back to a direct deposit.
    pub async fn send_sealed_to_exit<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        relays: &[RelayDescriptor],
        hop_count: usize,
        exit: &RelayDescriptor,
        sender_pk: &[u8; 32],
        body: &[u8],
    ) -> Result<(), ClientError> {
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
        self.send_to_exit(rng, relays, hop_count, exit, &framed)
            .await
    }
}

/// Errors specific to the client send pipeline.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// `payload.len() > MAX_PAYLOAD_SIZE`.
    #[error("payload exceeds {MAX_PAYLOAD_SIZE} bytes")]
    PayloadTooLarge,
    /// `hop_count` is outside the supported 3..=5 range.
    #[error("hop_count must be in 3..=5")]
    BadHopCount,
    /// The path selector couldn't find a satisfying diverse path.
    #[error("path selection failed (insufficient diversity in directory)")]
    PathSelection,
    /// A directory descriptor contained malformed data.
    #[error("directory: {0}")]
    BadDirectory(&'static str),
    /// A Sphinx / KEM cryptographic operation failed.
    #[error("crypto operation failed")]
    Crypto,
    /// Underlying QUIC + Noise transport error.
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

    /// Spawn a relay listening on 127.0.0.1:0 with the given static SK.
    /// Returns its bound IPv4 SocketAddr.
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
            // v0.1: id_pubkey == kem_pubkey == X25519 identity.
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

        // Spawn 3 relays: entry + mix + exit.
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

        // Build a small payload (real app would put a Sealed-Sender
        // wrapped Double-Ratchet ciphertext here).
        let payload = b"hello from gotham client v0.1";

        let client = GothamClient::new(&mut r).unwrap();
        client
            .send(&mut r, &relays, 3, payload)
            .await
            .expect("send");

        // Give the chain time to forward + deliver. Success criterion:
        // no error / panic propagated. (Sealed-Sender unwrap hook for
        // assert-on-deliver is P4.next.)
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

    /// Point 8: the sender's per-hop delays must be drawn from Exp(λ), not a
    /// constant. Verified statistically over a large sample:
    ///  - sample mean within 5 % of the configured mean, and
    ///  - coefficient of variation (σ/μ) ≈ 1 — the signature of an
    ///    exponential distribution (a constant would give 0, a uniform ≈0.58).
    ///
    /// This proves the DISTRIBUTION. It does NOT prove the anti-correlation /
    /// unlinkability property that mix delays exist for — that needs real
    /// multi-machine traffic analysis (out of session). See GOTHAM notes.
    #[test]
    fn sender_hop_delays_are_exponentially_distributed() {
        let sched = PoissonScheduler::new(SENDER_MEAN_DELAY_MICROS);
        let mut rng = ChaCha20Rng::seed_from_u64(0x0090_1550); // "POISSO"
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

        // Spawn entry + mix as plain relays (no delivery hook).
        let addr_entry = spawn_relay(sk_entry).await;
        let addr_mix = spawn_relay(sk_mix).await;

        // Recipient identity (separate from any relay key).
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        // Sender identity advertised inside the sealed envelope.
        let sender_pk = clamped_sk(&mut r);

        // Spawn exit relay with an unsealing handler.
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

        // Body the recipient is supposed to recover after unseal.
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
        // The body is followed by zero-padding (we sent through the
        // 1664 B Gotham payload region); compare prefix.
        assert_eq!(&got_body[..body.len()], &body[..]);
    }

    /// Deployable-path proof: build a **signed** relay directory, round-trip
    /// it through disk exactly like a published `directory.json`, verify it
    /// against the pinned authority key (and prove an unpinned authority is
    /// rejected), then route a real sealed message from sender A to a
    /// distinct recipient B through the three relays the *verified*
    /// directory advertises.
    ///
    /// This exercises the full path a real deployment takes —
    /// `sign-directory` → publish → load → verify → route → deliver — the
    /// one link the in-process dev self-loop never covered. Three relays on
    /// independent QUIC sockets stand in for three deployed VPS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn signed_directory_testnet_delivers_a_to_b() {
        init();
        let mut r = rng();

        // Three independent relay identities + a directory-authority key.
        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_exit = clamped_sk(&mut r);
        let authority = ed25519_dalek::SigningKey::generate(&mut r);

        // Entry + mix: plain forwarders on real QUIC sockets.
        let addr_entry = spawn_relay(sk_entry).await;
        let addr_mix = spawn_relay(sk_mix).await;

        // Recipient B (identity distinct from every relay) and sender A.
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);

        // Exit relay with an unsealing delivery handler that hands the
        // recovered (sender, body) to B.
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

        // Build + sign a directory of the three relays — the artifact a
        // `gotham-relay sign-directory` run produces for deployment.
        let relays = vec![
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry, "op-A"),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix, "op-B"),
            descriptor_from(sk_exit, addr_exit, RelayTier::Exit, "op-C"),
        ];
        let doc = crypto_gotham::directory::DirectoryDoc::new(relays, Duration::from_secs(3600))
            .expect("build directory doc");
        let signed = crypto_gotham::directory::SignedDirectory::sign(doc, &authority)
            .expect("sign directory");

        // Round-trip through disk like a published directory.json.
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

        // A consumer MUST verify against the authority key it pinned…
        loaded
            .verify(&authority.verifying_key())
            .expect("signed directory must verify against the pinned authority");
        // …and MUST reject a directory presented under any other authority.
        let impostor = ed25519_dalek::SigningKey::generate(&mut r);
        assert!(
            loaded.verify(&impostor.verifying_key()).is_err(),
            "directory must not verify against an unpinned authority"
        );

        // Route a real sealed message A → B through the relays the verified
        // directory advertises (path is tier-selected, so disk-sort is fine).
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

        // B recovers sender identity + plaintext.
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
}
