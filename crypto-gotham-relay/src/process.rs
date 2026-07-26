// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Stateless packet processor.
//!
//! [`Relay::process`] takes a 2048 B packet and returns one of:
//!
//! - [`ProcessOutcome::Drop`] — silently discard (replay, bad MAC, malformed)
//! - [`ProcessOutcome::Forward`] — forward to the next hop after a Poisson delay
//! - [`ProcessOutcome::DeliverLocal`] — this hop is the recipient
//!
//! No I/O is performed here — the caller (the transport layer in
//! `main.rs`) is responsible for actually sending the bytes. This keeps
//! the relay testable without spinning up sockets.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crypto_gotham::header::{derive_hop_subkeys, unwrap_header, Header, HEADER_LEN, RECORD_LEN};
use crypto_gotham::Error as GothamError;
use rand::{CryptoRng, RngCore};
use tracing::{debug, trace};
use x25519_dalek::{x25519, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::delay::PoissonScheduler;
use crate::rate_limit::RateLimiter;
use crate::replay::{ReplayCache, ReplayCheck};

/// Reason a packet was dropped. Used for *counter* metrics only — the
/// relay never logs per-packet identifiers or peer IPs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// Header MAC failed verification.
    BadMac,
    /// Packet's γ was already seen within the TTL window.
    Replay,
    /// Header could not be parsed (version, hop_count, etc).
    Malformed,
    /// Policy denied the route (e.g. self-loop, unknown next hop).
    PolicyDenied,
    /// Operator-configured rate limit (packets/sec or daily byte quota)
    /// was exceeded — the packet is shed to protect the volunteer's
    /// machine and connection.
    RateLimited,
}

/// Outcome of processing a single packet.
pub enum ProcessOutcome {
    /// Silently drop the packet.
    Drop(DropReason),
    /// Forward to the next hop after `delay`.
    Forward {
        /// Destination socket of the next hop. A zero sentinel (`0.0.0.0:0`)
        /// when `via_rendezvous` is set — the next hop is addressed by identity.
        next_addr: SocketAddrV4,
        /// Identity fingerprint (X25519 pubkey) of the next hop.
        next_node_id: [u8; 32],
        /// Poisson-sampled hold time before transmission.
        delay: Duration,
        /// RFC B3: the next hop is a CGNAT relay reachable only via THIS relay's
        /// rendezvous tunnel — push the packet down that tunnel (keyed by
        /// `next_node_id`) instead of dialing `next_addr`.
        via_rendezvous: bool,
        /// The full 2048 B packet to forward.
        packet: Box<[u8]>,
    },
    /// Local delivery — this hop is the final recipient.
    DeliverLocal {
        /// Poisson-sampled hold time before processing.
        delay: Duration,
        /// The packet's payload (header stripped).
        payload: Box<[u8]>,
    },
}

impl ProcessOutcome {
    /// Convenience: did the packet get dropped?
    #[must_use]
    pub fn is_drop(&self) -> bool {
        matches!(self, ProcessOutcome::Drop(_))
    }
}

/// A Gotham relay's runtime state.
///
/// Holds:
/// - the relay's long-term X25519 identity secret key
/// - the replay cache
/// - the Poisson delay scheduler
///
/// `&mut self` is required for `process` because the replay cache is
/// updated on every fresh packet.
#[derive(ZeroizeOnDrop)]
pub struct Relay {
    #[zeroize(skip)]
    replay_cache: ReplayCache,
    #[zeroize(skip)]
    scheduler: PoissonScheduler,
    #[zeroize(skip)]
    rate_limiter: RateLimiter,
    identity_sk: [u8; 32],
}

impl Relay {
    /// Construct a relay from an existing X25519 secret key.
    ///
    /// `mean_delay_micros = 0` disables the Poisson scheduler (useful in
    /// tests and benchmarks).
    #[must_use]
    pub fn new(
        identity_sk: [u8; 32],
        replay_max_size: usize,
        replay_ttl: Duration,
        mean_delay_micros: u64,
    ) -> Self {
        Self {
            identity_sk,
            replay_cache: ReplayCache::new(replay_max_size, replay_ttl),
            scheduler: PoissonScheduler::new(mean_delay_micros),
            rate_limiter: RateLimiter::unlimited(),
        }
    }

    /// Attach an inbound rate limiter (packets/sec ceiling + rolling daily
    /// wire-byte quota). Either bound may be `0` to disable it; the default
    /// from [`Relay::new`] is fully unlimited. Returns `self` for chaining.
    ///
    /// This is how a volunteer caps the load a relay can place on their
    /// machine and connection — see `docs/gotham/README.md`.
    #[must_use]
    pub fn with_rate_limit(mut self, max_pps: f64, max_bytes_per_day: u64) -> Self {
        self.rate_limiter = RateLimiter::new(max_pps, max_bytes_per_day);
        self
    }

    /// Read-only access to the configured scheduler.
    #[must_use]
    pub fn scheduler(&self) -> &PoissonScheduler {
        &self.scheduler
    }

    /// Current size of the replay cache (for metrics).
    #[must_use]
    pub fn replay_cache_len(&self) -> usize {
        self.replay_cache.len()
    }

    /// Derive the X25519 public key matching this relay's identity.
    #[must_use]
    pub fn identity_public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&StaticSecret::from(self.identity_sk)).to_bytes()
    }

    /// Process one inbound packet.
    ///
    /// `packet_bytes.len()` must equal [`crypto_gotham::PACKET_SIZE`] (2048).
    pub fn process<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        packet_bytes: &[u8],
    ) -> ProcessOutcome {
        if packet_bytes.len() != crypto_gotham::PACKET_SIZE {
            return ProcessOutcome::Drop(DropReason::Malformed);
        }

        // ── 0. Rate limit (cheapest possible flood shedding) ──────────────
        // Checked before any X25519/Sphinx work so a flood costs the
        // operator only a token-bucket comparison, never crypto CPU.
        if !self.rate_limiter.check(packet_bytes.len()).is_allowed() {
            debug!("dropped: rate limited");
            return ProcessOutcome::Drop(DropReason::RateLimited);
        }

        // ── 1. Parse header ───────────────────────────────────────────────
        let header_arr: &[u8; HEADER_LEN] = match packet_bytes[..HEADER_LEN].try_into() {
            Ok(a) => a,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };
        let header = match Header::decode(header_arr) {
            Ok(h) => h,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };

        // ── 2. Derive per-hop sub-keys (X25519 DH) ────────────────────────
        let shared = x25519(self.identity_sk, header.alpha);
        let sub_keys = match derive_hop_subkeys(&shared) {
            Ok(s) => s,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };

        // ── 3. Unwrap FIRST (verifies MAC + decrypts this hop's slot) ─────
        //
        // Authenticate before touching any shared state. γ is the header MAC,
        // and it travels in the clear: anyone who can OBSERVE a packet in flight
        // can copy its γ. If the replay cache were populated before this check,
        // that observer could race a forged packet carrying the stolen γ to the
        // next hop — the forgery would poison the cache, and the genuine packet
        // arriving moments later would be dropped as a "replay". That is
        // targeted, deniable message suppression at zero cost. Inserting only
        // AFTER the MAC verifies means an attacker must already possess a valid
        // packet to occupy a cache slot.
        let outcome = match unwrap_header(&header, &sub_keys) {
            Ok(o) => o,
            Err(GothamError::BadMac) => {
                debug!("dropped: bad MAC");
                return ProcessOutcome::Drop(DropReason::BadMac);
            }
            Err(_) => {
                debug!("dropped: malformed");
                return ProcessOutcome::Drop(DropReason::Malformed);
            }
        };

        // ── 4. Replay check using γ as the unique tag ─────────────────────
        if self.replay_cache.check_and_insert(header.gamma) == ReplayCheck::Replay {
            debug!("dropped: replay");
            return ProcessOutcome::Drop(DropReason::Replay);
        }

        // ── 5. Mix delay ──────────────────────────────────────────────────
        // Honor the sender-chosen per-hop delay (Loopix sender-chosen delays:
        // the sender samples each hold from Exp(λ) and encodes it). A `0`
        // record leaves it unset — fall back to this relay's own Poisson
        // scheduler (cover traffic, or legacy/0-mean senders).
        // Hard ceiling on the sender-chosen per-hop hold. `delay_micros` rides in
        // the peeled routing record and is fully attacker-controlled; a u32
        // permits ~71 min, long enough that a flood of max-delay packets pins a
        // large number of sleeping forward tasks — each retaining its 2 KB
        // packet — as a memory-amplification DoS. Real Loopix hops sample
        // sub-second holds, so a few-second ceiling preserves legitimate mixing
        // while bounding retained memory to (max_pps × MAX_HOP_DELAY × PACKET).
        const MAX_HOP_DELAY: Duration = Duration::from_secs(30);
        let delay = match outcome.record.delay_micros {
            0 => self.scheduler.next_delay(rng),
            micros => Duration::from_micros(u64::from(micros)).min(MAX_HOP_DELAY),
        };

        // ── 6. Peel THIS hop's payload onion layer (LIONESS) ──────────────
        // The payload region carries one LIONESS layer per hop (applied by the
        // sender). Decrypting our layer both reveals the original bytes for the
        // exit AND — on a forwarded packet — transforms what the next link
        // carries. LIONESS is a non-malleable wide-block PRP, so no operator can
        // byte-match, or tag-and-track, the same flow across two points of the
        // path. Content stays end-to-end encrypted; this defends linkability.
        let mut payload_region = packet_bytes[HEADER_LEN..].to_vec();
        crypto_gotham::lioness::decrypt(&sub_keys.k_payload, &mut payload_region);

        // ── 7. Forward vs deliver decision ────────────────────────────────
        if outcome.record.is_last_hop() {
            trace!(?delay, "deliver-local");
            return ProcessOutcome::DeliverLocal {
                delay,
                payload: payload_region.into_boxed_slice(),
            };
        }

        // Construct the outgoing packet: new header || peeled payload.
        let next_header_bytes = outcome.next_header.encode();
        let mut next_packet = vec![0u8; crypto_gotham::PACKET_SIZE].into_boxed_slice();
        next_packet[..HEADER_LEN].copy_from_slice(&next_header_bytes);
        next_packet[HEADER_LEN..].copy_from_slice(&payload_region);

        let next_addr = SocketAddrV4::new(
            Ipv4Addr::from(outcome.record.next_ipv4),
            outcome.record.next_port,
        );

        // Sanity policy: refuse self-loops.
        let our_pk = self.identity_public_key();
        if outcome.record.next_node_id == our_pk {
            debug!("dropped: self-loop");
            return ProcessOutcome::Drop(DropReason::PolicyDenied);
        }

        // Anonymity hard-rule: never log routing fields (next port/addr).
        trace!(?delay, "forward");
        let _ = RECORD_LEN; // silence unused-import warning when not in test
        ProcessOutcome::Forward {
            next_addr,
            next_node_id: outcome.record.next_node_id,
            delay,
            via_rendezvous: outcome.record.is_via_rendezvous(),
            packet: next_packet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::header::{
        derive_route_secrets, flag, mode, wrap_header, RoutingRecord, TRAILER_LEN,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xFEED_FACE)
    }

    /// Build a Gotham packet through `n` relays.
    fn build_packet_for_relays(
        rng: &mut ChaCha20Rng,
        relay_sks: &[[u8; 32]],
    ) -> (Vec<u8>, Vec<[u8; 32]>) {
        let pks: Vec<[u8; 32]> = relay_sks
            .iter()
            .map(|sk| PublicKey::from(&StaticSecret::from(*sk)).to_bytes())
            .collect();
        let (alphas, sub_keys) = derive_route_secrets(rng, &pks).unwrap();
        let n = relay_sks.len();
        let records: Vec<RoutingRecord> = (0..n)
            .map(|i| RoutingRecord {
                next_ipv4: [10, 0, 0, i as u8 + 1],
                next_port: 9000 + i as u16,
                next_node_id: if i + 1 < n {
                    PublicKey::from(&StaticSecret::from(relay_sks[i + 1])).to_bytes()
                } else {
                    [0xEE; 32] // last hop has dummy next_node_id
                },
                next_gamma: [0; 16],
                delay_micros: 0,
                flag: if i + 1 == n { flag::IS_LAST_HOP } else { 0 },
                _padding: [0; 5],
            })
            .collect();
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header =
            wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer).unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        // Fill payload with some bytes (would normally be sealed-sender + AEAD).
        for (i, byte) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        // Apply the sender-side LIONESS onion (innermost hop first) so the
        // relays peel back to the original fill — mirrors `ship_path`.
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }
        (packet, pks)
    }

    /// The deterministic payload the helper fills before onion-wrapping — what
    /// the exit hop must recover after peeling every layer.
    fn expected_payload() -> Vec<u8> {
        (0..crypto_gotham::PACKET_SIZE - HEADER_LEN)
            .map(|i| (i % 256) as u8)
            .collect()
    }

    #[test]
    fn forwards_a_packet_through_three_hops() {
        let mut rng = rng();
        // Three relays.
        let sks: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
        let (mut packet, _pks) = build_packet_for_relays(&mut rng, &sks);

        // Hop 0
        let mut relay0 = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let r0 = relay0.process(&mut rng, &packet);
        let next0 = match r0 {
            ProcessOutcome::Forward { packet, .. } => packet,
            other => panic!("hop 0: expected Forward, got {:?}", outcome_kind(&other)),
        };
        packet = next0.into_vec();

        // Hop 1
        let mut relay1 = Relay::new(sks[1], 1000, Duration::from_secs(60), 0);
        let r1 = relay1.process(&mut rng, &packet);
        let next1 = match r1 {
            ProcessOutcome::Forward { packet, .. } => packet,
            other => panic!("hop 1: expected Forward, got {:?}", outcome_kind(&other)),
        };
        packet = next1.into_vec();

        // Hop 2 (last)
        let mut relay2 = Relay::new(sks[2], 1000, Duration::from_secs(60), 0);
        let r2 = relay2.process(&mut rng, &packet);
        match r2 {
            ProcessOutcome::DeliverLocal { payload, .. } => {
                assert_eq!(payload.len(), crypto_gotham::PACKET_SIZE - HEADER_LEN);
                // After peeling all three onion layers the exit must recover
                // exactly the bytes the sender wrapped.
                assert_eq!(
                    payload.into_vec(),
                    expected_payload(),
                    "exit did not recover the original payload"
                );
            }
            other => panic!(
                "hop 2: expected DeliverLocal, got {:?}",
                outcome_kind(&other)
            ),
        }
    }

    #[test]
    fn rendezvous_flag_yields_via_rendezvous_forward() {
        // RFC B3: a middle relay R whose peeled record carries VIA_RENDEZVOUS
        // must be told to PUSH by identity (never dial the sentinel address).
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [i as u8 + 40; 32]).collect();
        let pks: Vec<[u8; 32]> = sks
            .iter()
            .map(|sk| PublicKey::from(&StaticSecret::from(*sk)).to_bytes())
            .collect();
        let (alphas, sub_keys) = derive_route_secrets(&mut rng, &pks).unwrap();
        let records = vec![
            RoutingRecord {
                next_ipv4: [0, 0, 0, 0], // sentinel — must NOT be dialed
                next_port: 0,
                next_node_id: pks[1], // N addressed by identity
                next_gamma: [0; 16],
                delay_micros: 0,
                flag: flag::VIA_RENDEZVOUS,
                _padding: [0; 5],
            },
            RoutingRecord {
                next_ipv4: [10, 0, 0, 9],
                next_port: 9000,
                next_node_id: [0xEE; 32],
                next_gamma: [0; 16],
                delay_micros: 0,
                flag: flag::IS_LAST_HOP,
                _padding: [0; 5],
            },
        ];
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header = wrap_header(
            &mut rng,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        for (i, b) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }

        let mut r = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        match r.process(&mut rng, &packet) {
            ProcessOutcome::Forward {
                via_rendezvous,
                next_node_id,
                next_addr,
                ..
            } => {
                assert!(
                    via_rendezvous,
                    "VIA_RENDEZVOUS flag must set via_rendezvous"
                );
                assert_eq!(
                    next_node_id, pks[1],
                    "must address the hosted relay by identity"
                );
                assert_eq!(
                    next_addr,
                    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                    "rendezvous record must carry the zero sentinel address"
                );
            }
            other => panic!("expected Forward, got {:?}", outcome_kind(&other)),
        }
    }

    #[test]
    fn ordinary_forward_is_not_via_rendezvous() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);
        let mut r = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        match r.process(&mut rng, &packet) {
            ProcessOutcome::Forward { via_rendezvous, .. } => {
                assert!(!via_rendezvous, "a normal hop must not be via_rendezvous");
            }
            other => panic!("expected Forward, got {:?}", outcome_kind(&other)),
        }
    }

    #[test]
    fn payload_bytes_differ_at_every_hop() {
        // The anti-correlation property: the same flow's payload region must
        // look different on every link, so an operator on two hops can't
        // byte-match. Only the exit ever sees the cleartext payload.
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
        let (packet, _pks) = build_packet_for_relays(&mut rng, &sks);
        let on_wire_entry = packet[HEADER_LEN..].to_vec();

        let mut relay0 = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let p1 = match relay0.process(&mut rng, &packet) {
            ProcessOutcome::Forward { packet, .. } => packet.into_vec(),
            _ => panic!("hop 0 should forward"),
        };
        let on_wire_mid = p1[HEADER_LEN..].to_vec();

        let mut relay1 = Relay::new(sks[1], 1000, Duration::from_secs(60), 0);
        let p2 = match relay1.process(&mut rng, &p1) {
            ProcessOutcome::Forward { packet, .. } => packet.into_vec(),
            _ => panic!("hop 1 should forward"),
        };
        let on_wire_pre_exit = p2[HEADER_LEN..].to_vec();

        // Every link carries a distinct masking of the payload.
        assert_ne!(on_wire_entry, on_wire_mid);
        assert_ne!(on_wire_mid, on_wire_pre_exit);
        assert_ne!(on_wire_entry, on_wire_pre_exit);
        // And none of the in-transit forms equals the cleartext the exit sees.
        assert_ne!(on_wire_entry, expected_payload());
        assert_ne!(on_wire_pre_exit, expected_payload());

        let mut relay2 = Relay::new(sks[2], 1000, Duration::from_secs(60), 0);
        match relay2.process(&mut rng, &p2) {
            ProcessOutcome::DeliverLocal { payload, .. } => {
                assert_eq!(payload.into_vec(), expected_payload());
            }
            _ => panic!("hop 2 should deliver"),
        }
    }

    #[test]
    fn replayed_packet_is_dropped() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);

        let mut relay = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let r1 = relay.process(&mut rng, &packet);
        assert!(!r1.is_drop(), "first delivery should succeed");

        let r2 = relay.process(&mut rng, &packet);
        assert!(matches!(r2, ProcessOutcome::Drop(DropReason::Replay)));
    }

    /// A forged packet must NOT occupy a replay-cache slot.
    ///
    /// γ is the header MAC and travels in the clear, so a network observer can
    /// copy it from a packet in flight. If the cache were populated before the
    /// MAC check, that observer could race a forgery carrying the stolen γ to
    /// the next hop, poisoning the cache so the GENUINE packet is then dropped
    /// as a "replay" — targeted, deniable message suppression at zero cost.
    #[test]
    fn a_forged_packet_cannot_poison_the_replay_cache() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);

        // The attacker copies the real packet and corrupts it so the MAC fails,
        // keeping γ intact — exactly what an on-path observer can build.
        let mut forged = packet.clone();
        // Corrupt THIS hop's routing record — β slot 0 lives at 36..100, and γ
        // authenticates `meta || α || β[slot_i] || trailer`, so this breaks the
        // MAC while γ itself (356..372) stays bit-for-bit the real one.
        forged[50] ^= 0xff;

        let mut relay = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let bad = relay.process(&mut rng, &forged);
        assert!(bad.is_drop(), "the forgery must be dropped");
        assert_eq!(
            relay.replay_cache_len(),
            0,
            "a packet that failed authentication must not consume a cache slot",
        );

        // The genuine packet, arriving afterwards, must still be delivered.
        let good = relay.process(&mut rng, &packet);
        assert!(
            !good.is_drop(),
            "the genuine packet must survive a forgery that reused its γ",
        );
    }

    #[test]
    fn malformed_size_dropped() {
        let mut rng = rng();
        let mut relay = Relay::new([7u8; 32], 100, Duration::from_secs(60), 0);
        let short = vec![0u8; 1024];
        assert!(matches!(
            relay.process(&mut rng, &short),
            ProcessOutcome::Drop(DropReason::Malformed)
        ));
    }

    #[test]
    fn tampered_mac_dropped() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (mut packet, _) = build_packet_for_relays(&mut rng, &sks);
        // Flip a bit inside γ (offset 356..372 of header).
        packet[360] ^= 0x02;
        let mut relay = Relay::new(sks[0], 100, Duration::from_secs(60), 0);
        assert!(matches!(
            relay.process(&mut rng, &packet),
            ProcessOutcome::Drop(DropReason::BadMac)
        ));
    }

    #[test]
    fn replay_cache_len_observable() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let mut relay = Relay::new(sks[0], 100, Duration::from_secs(60), 0);
        assert_eq!(relay.replay_cache_len(), 0);
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);
        let _ = relay.process(&mut rng, &packet);
        assert_eq!(relay.replay_cache_len(), 1);
    }

    #[test]
    fn rate_limit_sheds_a_flood_before_crypto() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);

        // Tight cap: 5 pps ⇒ burst 10. A 200-packet flood fired in a tight
        // loop (wall clock barely advances → negligible refill) must shed
        // the overflow as RateLimited.
        let mut relay =
            Relay::new(sks[0], 100_000, Duration::from_secs(60), 0).with_rate_limit(5.0, 0);
        let mut rate_limited = 0usize;
        for _ in 0..200 {
            if matches!(
                relay.process(&mut rng, &packet),
                ProcessOutcome::Drop(DropReason::RateLimited)
            ) {
                rate_limited += 1;
            }
        }
        assert!(
            rate_limited > 150,
            "expected the bulk of a 200-packet flood to be rate-limited, got {rate_limited}"
        );
    }

    #[test]
    fn unlimited_relay_never_rate_limits() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);
        // Default relay (no with_rate_limit) must behave exactly as before.
        let mut relay = Relay::new(sks[0], 100_000, Duration::from_secs(60), 0);
        for _ in 0..500 {
            assert!(!matches!(
                relay.process(&mut rng, &packet),
                ProcessOutcome::Drop(DropReason::RateLimited)
            ));
        }
    }

    fn outcome_kind(o: &ProcessOutcome) -> &'static str {
        match o {
            ProcessOutcome::Drop(_) => "Drop",
            ProcessOutcome::Forward { .. } => "Forward",
            ProcessOutcome::DeliverLocal { .. } => "DeliverLocal",
        }
    }
}
