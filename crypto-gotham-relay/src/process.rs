// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crypto_gotham::header::{derive_hop_subkeys, unwrap_header, Header, HEADER_LEN, RECORD_LEN};
use crypto_gotham::Error as GothamError;
use rand::{CryptoRng, RngCore};
use tracing::{debug, trace, warn};
use x25519_dalek::{x25519, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::delay::PoissonScheduler;
use crate::rate_limit::RateLimiter;
use crate::replay::{ReplayCache, ReplayCheck};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DropReason {
    BadMac,
    Replay,
    Malformed,
    PolicyDenied,
    RateLimited,
}

pub enum ProcessOutcome {
    Drop(DropReason),
    Forward {
        next_addr: SocketAddrV4,
        next_node_id: [u8; 32],
        delay: Duration,
        via_rendezvous: bool,
        packet: Box<[u8]>,
    },
    DeliverLocal {
        delay: Duration,
        payload: Box<[u8]>,
    },
}

impl ProcessOutcome {
    #[must_use]
    pub fn is_drop(&self) -> bool {
        matches!(self, ProcessOutcome::Drop(_))
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Relay {
    #[zeroize(skip)]
    replay_cache: ReplayCache,
    #[zeroize(skip)]
    scheduler: PoissonScheduler,
    #[zeroize(skip)]
    rate_limiter: RateLimiter,
    #[zeroize(skip)]
    accept_header_v2: bool,
    #[zeroize(skip)]
    v2_accepted: u64,
    #[zeroize(skip)]
    replay_path: Option<std::path::PathBuf>,
    identity_sk: [u8; 32],
}

impl Relay {
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
            accept_header_v2: true,
            v2_accepted: 0,
            replay_path: None,
        }
    }

    #[must_use]
    pub fn with_replay_persistence(mut self, path: std::path::PathBuf) -> Self {
        match crate::replay::persist::load(&mut self.replay_cache, &path) {
            Ok(n) => tracing::info!(entries = n, path = %path.display(), "replay cache restored"),
            Err(e) => tracing::warn!(
                error = %e,
                path = %path.display(),
                "replay cache could not be read — starting EMPTY, so packets seen \
                 before this restart will be accepted again until the TTL refills",
            ),
        }
        self.replay_path = Some(path);
        self
    }

    pub fn encode_replay(&self) -> Option<(Vec<u8>, std::path::PathBuf)> {
        let path = self.replay_path.clone()?;
        Some((crate::replay::persist::encode(&self.replay_cache), path))
    }

    pub fn persist_replay(&self) -> Option<std::io::Result<usize>> {
        let path = self.replay_path.as_ref()?;
        Some(crate::replay::persist::save(&self.replay_cache, path))
    }

    #[must_use]
    pub fn persists_replay(&self) -> bool {
        self.replay_path.is_some()
    }

    #[must_use]
    pub fn strict_header_v3(mut self) -> Self {
        self.accept_header_v2 = false;
        self
    }

    #[must_use]
    pub fn with_rate_limit(mut self, max_pps: f64, max_bytes_per_day: u64) -> Self {
        self.rate_limiter = RateLimiter::new(max_pps, max_bytes_per_day);
        self
    }

    #[must_use]
    pub fn scheduler(&self) -> &PoissonScheduler {
        &self.scheduler
    }

    #[must_use]
    pub fn replay_cache_len(&self) -> usize {
        self.replay_cache.len()
    }

    #[must_use]
    pub fn identity_public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&StaticSecret::from(self.identity_sk)).to_bytes()
    }

    pub fn process<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        packet_bytes: &[u8],
    ) -> ProcessOutcome {
        if packet_bytes.len() != crypto_gotham::PACKET_SIZE {
            return ProcessOutcome::Drop(DropReason::Malformed);
        }

        if !self.rate_limiter.check(packet_bytes.len()).is_allowed() {
            debug!("dropped: rate limited");
            return ProcessOutcome::Drop(DropReason::RateLimited);
        }

        let header_arr: &[u8; HEADER_LEN] = match packet_bytes[..HEADER_LEN].try_into() {
            Ok(a) => a,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };
        let header = match Header::decode(header_arr) {
            Ok(h) => h,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };

        if header.version == crypto_gotham::header::VERSION_LEGACY {
            if !self.accept_header_v2 {
                debug!("dropped: legacy v2 header refused (strict mode)");
                return ProcessOutcome::Drop(DropReason::Malformed);
            }
            self.v2_accepted = self.v2_accepted.saturating_add(1);
            if self.v2_accepted == 1 || self.v2_accepted.is_multiple_of(10_000) {
                warn!(
                    accepted = self.v2_accepted,
                    "serving LEGACY v2 headers — the F-01 tagging channel is open for these \
                     packets. Pass --strict-header-v3 once the clients you serve have updated."
                );
            }
        }

        let shared = x25519(self.identity_sk, header.alpha);
        let sub_keys = match derive_hop_subkeys(&shared) {
            Ok(s) => s,
            Err(_) => return ProcessOutcome::Drop(DropReason::Malformed),
        };

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

        if self.replay_cache.check_and_insert(header.gamma) == ReplayCheck::Replay {
            debug!("dropped: replay");
            return ProcessOutcome::Drop(DropReason::Replay);
        }

        const MAX_HOP_DELAY: Duration = Duration::from_secs(30);
        let delay = match outcome.record.delay_micros {
            0 => self.scheduler.next_delay(rng),
            micros => Duration::from_micros(u64::from(micros)).min(MAX_HOP_DELAY),
        };

        let mut payload_region = packet_bytes[HEADER_LEN..].to_vec();
        crypto_gotham::lioness::decrypt(&sub_keys.k_payload, &mut payload_region);

        if outcome.record.is_last_hop() {
            trace!(?delay, "deliver-local");
            return ProcessOutcome::DeliverLocal {
                delay,
                payload: payload_region.into_boxed_slice(),
            };
        }

        let next_header_bytes = outcome.next_header.encode();
        let mut next_packet = vec![0u8; crypto_gotham::PACKET_SIZE].into_boxed_slice();
        next_packet[..HEADER_LEN].copy_from_slice(&next_header_bytes);
        next_packet[HEADER_LEN..].copy_from_slice(&payload_region);

        let next_addr = SocketAddrV4::new(
            Ipv4Addr::from(outcome.record.next_ipv4),
            outcome.record.next_port,
        );

        let our_pk = self.identity_public_key();
        if outcome.record.next_node_id == our_pk {
            debug!("dropped: self-loop");
            return ProcessOutcome::Drop(DropReason::PolicyDenied);
        }

        trace!(?delay, "forward");
        let _ = RECORD_LEN;
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
                    [0xEE; 32]
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
        for (i, byte) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }
        (packet, pks)
    }

    fn expected_payload() -> Vec<u8> {
        (0..crypto_gotham::PACKET_SIZE - HEADER_LEN)
            .map(|i| (i % 256) as u8)
            .collect()
    }

    #[test]
    fn forwards_a_packet_through_three_hops() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
        let (mut packet, _pks) = build_packet_for_relays(&mut rng, &sks);

        let mut relay0 = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let r0 = relay0.process(&mut rng, &packet);
        let next0 = match r0 {
            ProcessOutcome::Forward { packet, .. } => packet,
            other => panic!("hop 0: expected Forward, got {:?}", outcome_kind(&other)),
        };
        packet = next0.into_vec();

        let mut relay1 = Relay::new(sks[1], 1000, Duration::from_secs(60), 0);
        let r1 = relay1.process(&mut rng, &packet);
        let next1 = match r1 {
            ProcessOutcome::Forward { packet, .. } => packet,
            other => panic!("hop 1: expected Forward, got {:?}", outcome_kind(&other)),
        };
        packet = next1.into_vec();

        let mut relay2 = Relay::new(sks[2], 1000, Duration::from_secs(60), 0);
        let r2 = relay2.process(&mut rng, &packet);
        match r2 {
            ProcessOutcome::DeliverLocal { payload, .. } => {
                assert_eq!(payload.len(), crypto_gotham::PACKET_SIZE - HEADER_LEN);
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
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [i as u8 + 40; 32]).collect();
        let pks: Vec<[u8; 32]> = sks
            .iter()
            .map(|sk| PublicKey::from(&StaticSecret::from(*sk)).to_bytes())
            .collect();
        let (alphas, sub_keys) = derive_route_secrets(&mut rng, &pks).unwrap();
        let records = vec![
            RoutingRecord {
                next_ipv4: [0, 0, 0, 0],
                next_port: 0,
                next_node_id: pks[1],
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

        assert_ne!(on_wire_entry, on_wire_mid);
        assert_ne!(on_wire_mid, on_wire_pre_exit);
        assert_ne!(on_wire_entry, on_wire_pre_exit);
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

    #[test]
    fn a_forged_packet_cannot_poison_the_replay_cache() {
        let mut rng = rng();
        let sks: Vec<[u8; 32]> = (0..2).map(|i| [(i + 1) as u8; 32]).collect();
        let (packet, _) = build_packet_for_relays(&mut rng, &sks);

        let mut forged = packet.clone();
        forged[50] ^= 0xff;

        let mut relay = Relay::new(sks[0], 1000, Duration::from_secs(60), 0);
        let bad = relay.process(&mut rng, &forged);
        assert!(bad.is_drop(), "the forgery must be dropped");
        assert_eq!(
            relay.replay_cache_len(),
            0,
            "a packet that failed authentication must not consume a cache slot",
        );

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
