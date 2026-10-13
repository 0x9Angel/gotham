// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use poly1305::universal_hash::KeyInit as _;
use poly1305::Poly1305;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::x25519;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const HEADER_LEN: usize = 384;

pub const ALPHA_LEN: usize = 32;

pub const BETA_LEN: usize = 320;

pub const GAMMA_LEN: usize = 16;

pub const TRAILER_LEN: usize = HEADER_LEN - 4 - ALPHA_LEN - BETA_LEN - GAMMA_LEN;
const _: () = assert!(TRAILER_LEN == 12);

pub const RECORD_LEN: usize = 64;

pub const MAX_HOPS: usize = BETA_LEN / RECORD_LEN;
const _: () = assert!(MAX_HOPS == 5);

pub const VERSION: u8 = 3;

pub const VERSION_LEGACY: u8 = 2;

pub mod mode {
    pub const LOW_LATENCY: u8 = 0;
    pub const BALANCED: u8 = 1;
    pub const PARANOID: u8 = 2;
}

const SUBKEY_SALT: &[u8] = b"gotham-hop-v1";
const SUBKEY_INFO: &[u8] = b"gotham:subkeys";

pub mod flag {
    pub const IS_LAST_HOP: u8 = 0b0000_0001;
    pub const DELIVER_LOCAL: u8 = 0b0000_0010;
    pub const VIA_RENDEZVOUS: u8 = 0b0000_0100;
}

#[derive(Clone, Copy, Debug, Zeroize)]
pub struct RoutingRecord {
    pub next_ipv4: [u8; 4],
    pub next_port: u16,
    pub next_node_id: [u8; 32],
    pub next_gamma: [u8; GAMMA_LEN],
    pub delay_micros: u32,
    pub flag: u8,
    pub _padding: [u8; 5],
}

impl Default for RoutingRecord {
    fn default() -> Self {
        Self {
            next_ipv4: [0; 4],
            next_port: 0,
            next_node_id: [0; 32],
            next_gamma: [0; GAMMA_LEN],
            delay_micros: 0,
            flag: 0,
            _padding: [0; 5],
        }
    }
}

impl RoutingRecord {
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[0..4].copy_from_slice(&self.next_ipv4);
        out[4..6].copy_from_slice(&self.next_port.to_be_bytes());
        out[6..38].copy_from_slice(&self.next_node_id);
        out[38..54].copy_from_slice(&self.next_gamma);
        out[54..58].copy_from_slice(&self.delay_micros.to_be_bytes());
        out[58] = self.flag;
        out[59..64].copy_from_slice(&self._padding);
        out
    }

    pub fn decode(bytes: &[u8; RECORD_LEN]) -> Self {
        let mut next_ipv4 = [0u8; 4];
        next_ipv4.copy_from_slice(&bytes[0..4]);
        let next_port = u16::from_be_bytes([bytes[4], bytes[5]]);
        let mut next_node_id = [0u8; 32];
        next_node_id.copy_from_slice(&bytes[6..38]);
        let mut next_gamma = [0u8; GAMMA_LEN];
        next_gamma.copy_from_slice(&bytes[38..54]);
        let delay_micros = u32::from_be_bytes([bytes[54], bytes[55], bytes[56], bytes[57]]);
        let flag = bytes[58];
        let mut _padding = [0u8; 5];
        _padding.copy_from_slice(&bytes[59..64]);
        Self {
            next_ipv4,
            next_port,
            next_node_id,
            next_gamma,
            delay_micros,
            flag,
            _padding,
        }
    }

    #[must_use]
    pub fn is_last_hop(&self) -> bool {
        self.flag & flag::IS_LAST_HOP != 0
    }

    #[must_use]
    pub fn is_via_rendezvous(&self) -> bool {
        self.flag & flag::VIA_RENDEZVOUS != 0
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    pub version: u8,
    pub mode: u8,
    pub hop_count: u8,
    pub hop_index: u8,
    pub alpha: [u8; ALPHA_LEN],
    pub beta: [u8; BETA_LEN],
    pub gamma: [u8; GAMMA_LEN],
    pub trailer: [u8; TRAILER_LEN],
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1] = self.mode;
        out[2] = self.hop_count;
        out[3] = self.hop_index;
        out[4..36].copy_from_slice(&self.alpha);
        out[36..356].copy_from_slice(&self.beta);
        out[356..372].copy_from_slice(&self.gamma);
        out[372..384].copy_from_slice(&self.trailer);
        out
    }

    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        let version = bytes[0];
        if version != VERSION && version != VERSION_LEGACY {
            return Err(Error::Malformed("unsupported header version"));
        }
        let mode = bytes[1];
        let hop_count = bytes[2];
        let hop_index = bytes[3];
        if hop_count == 0 || hop_count as usize > MAX_HOPS {
            return Err(Error::Malformed("hop_count out of range"));
        }
        if hop_index >= hop_count {
            return Err(Error::Malformed("hop_index >= hop_count"));
        }
        let mut alpha = [0u8; ALPHA_LEN];
        alpha.copy_from_slice(&bytes[4..36]);
        let mut beta = [0u8; BETA_LEN];
        beta.copy_from_slice(&bytes[36..356]);
        let mut gamma = [0u8; GAMMA_LEN];
        gamma.copy_from_slice(&bytes[356..372]);
        let mut trailer = [0u8; TRAILER_LEN];
        trailer.copy_from_slice(&bytes[372..384]);
        Ok(Self {
            version,
            mode,
            hop_count,
            hop_index,
            alpha,
            beta,
            gamma,
            trailer,
        })
    }

    fn mac_input_for_slot(&self, slot_idx: usize) -> Vec<u8> {
        let start = slot_idx * RECORD_LEN;
        let slot_bytes: &[u8] = if self.version >= 3 {
            &self.beta[start..]
        } else {
            &self.beta[start..start + RECORD_LEN]
        };
        let mut v = Vec::with_capacity(4 + ALPHA_LEN + slot_bytes.len() + TRAILER_LEN);
        v.push(self.version);
        v.push(self.mode);
        v.push(self.hop_count);
        v.push(slot_idx as u8);
        v.extend_from_slice(&self.alpha);
        v.extend_from_slice(slot_bytes);
        v.extend_from_slice(&self.trailer);
        v
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct HopSubKeys {
    pub k_mac: [u8; 32],
    pub k_header: [u8; 32],
    pub k_payload: [u8; 32],
    pub k_blind: [u8; 32],
    pub k_shuffle: [u8; 32],
}

pub fn derive_hop_subkeys(shared_x: &[u8; 32]) -> Result<HopSubKeys> {
    if shared_x.iter().fold(0u8, |acc, &b| acc | b) == 0 {
        return Err(Error::Crypto(
            "low-order point: all-zero X25519 shared secret",
        ));
    }
    let hk = hkdf::Hkdf::<Sha256>::new(Some(SUBKEY_SALT), shared_x);
    let mut buf = [0u8; 32 * 5];
    hk.expand(SUBKEY_INFO, &mut buf)
        .map_err(|_| Error::Crypto("HKDF expand hop sub-keys"))?;
    let mut sub = HopSubKeys {
        k_mac: [0; 32],
        k_header: [0; 32],
        k_payload: [0; 32],
        k_blind: [0; 32],
        k_shuffle: [0; 32],
    };
    sub.k_mac.copy_from_slice(&buf[0..32]);
    sub.k_header.copy_from_slice(&buf[32..64]);
    sub.k_payload.copy_from_slice(&buf[64..96]);
    sub.k_blind.copy_from_slice(&buf[96..128]);
    sub.k_shuffle.copy_from_slice(&buf[128..160]);
    Ok(sub)
}

fn chacha20_stream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    let mut buf = vec![0u8; len];
    cipher.apply_keystream(&mut buf);
    buf
}

fn poly1305_tag(key: &[u8; 32], data: &[u8]) -> [u8; GAMMA_LEN] {
    let mac = Poly1305::new(key.into()).compute_unpadded(data);
    let mut out = [0u8; GAMMA_LEN];
    out.copy_from_slice(mac.as_slice());
    out
}

fn blind_alpha(alpha: &[u8; ALPHA_LEN], k_blind: &[u8; 32]) -> [u8; ALPHA_LEN] {
    x25519(*k_blind, *alpha)
}

pub fn derive_route_secrets<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient_pks: &[[u8; ALPHA_LEN]],
) -> Result<(Vec<[u8; ALPHA_LEN]>, Vec<HopSubKeys>)> {
    let n = recipient_pks.len();
    if n == 0 || n > MAX_HOPS {
        return Err(Error::Routing("hop count out of range"));
    }
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed[0] &= 248;
    seed[31] &= 127;
    seed[31] |= 64;
    let mut s_curr = Scalar::from_bytes_mod_order(seed);
    seed.zeroize();
    let base = curve25519_dalek::constants::X25519_BASEPOINT;

    let mut alphas = Vec::with_capacity(n);
    let mut sub_keys = Vec::with_capacity(n);
    let mut alpha_point = s_curr * base;

    for (i, pk_bytes) in recipient_pks.iter().enumerate() {
        alphas.push(alpha_point.to_bytes());
        let recipient_point = MontgomeryPoint(*pk_bytes);
        let cofactor_cleared = recipient_point
            .mul_bits_be(core::iter::once(true).chain(core::iter::repeat_n(false, 3)));
        if cofactor_cleared.to_bytes() == [0u8; 32] {
            return Err(Error::Routing("relay key is low-order (small subgroup)"));
        }
        let shared_point = s_curr * recipient_point;
        let mut shared_x = shared_point.to_bytes();
        let sub = derive_hop_subkeys(&shared_x)?;
        shared_x.zeroize();
        if i + 1 < n {
            let mut b_bytes = sub.k_blind;
            b_bytes[0] &= 248;
            b_bytes[31] &= 127;
            b_bytes[31] |= 64;
            let b_scalar = Scalar::from_bytes_mod_order(b_bytes);
            b_bytes.zeroize();
            s_curr *= b_scalar;
            alpha_point *= b_scalar;
        }
        sub_keys.push(sub);
    }
    Ok((alphas, sub_keys))
}

pub fn wrap_header<R: CryptoRng + RngCore>(
    rng: &mut R,
    mode: u8,
    alphas: &[[u8; ALPHA_LEN]],
    sub_keys: &[HopSubKeys],
    records: &[RoutingRecord],
    trailer: [u8; TRAILER_LEN],
) -> Result<Header> {
    let n = sub_keys.len();
    if n == 0 || n > MAX_HOPS {
        return Err(Error::Routing("hop count out of range"));
    }
    if alphas.len() != n || records.len() != n {
        return Err(Error::Routing("alphas / records length mismatch"));
    }

    let shuffles: Vec<Vec<u8>> = sub_keys
        .iter()
        .map(|k| chacha20_stream(&k.k_shuffle, BETA_LEN + TRAILER_LEN))
        .collect();
    let mut prefixes: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut acc = vec![0u8; BETA_LEN + TRAILER_LEN];
    for sh in shuffles.iter().take(n) {
        prefixes.push(acc.clone());
        for (a, s) in acc.iter_mut().zip(sh.iter()) {
            *a ^= *s;
        }
    }

    let mut beta = [0u8; BETA_LEN];
    rng.fill_bytes(&mut beta);

    let mut next_gamma = [0u8; GAMMA_LEN];

    for i in (0..n).rev() {
        let mut record_i = records[i];
        record_i.next_gamma = next_gamma;

        let record_bytes = record_i.encode();
        let stream = chacha20_stream(&sub_keys[i].k_header, RECORD_LEN);
        let offset = i * RECORD_LEN;
        for j in 0..RECORD_LEN {
            beta[offset + j] = record_bytes[j] ^ stream[j] ^ prefixes[i][offset + j];
        }

        let mut seen_beta = beta;
        for (j, b) in seen_beta.iter_mut().enumerate() {
            *b ^= prefixes[i][j];
        }
        let mut seen_trailer = trailer;
        for (j, t) in seen_trailer.iter_mut().enumerate() {
            *t ^= prefixes[i][BETA_LEN + j];
        }
        let candidate = Header {
            version: VERSION,
            mode,
            hop_count: n as u8,
            hop_index: i as u8,
            alpha: alphas[i],
            beta: seen_beta,
            gamma: [0; GAMMA_LEN],
            trailer: seen_trailer,
        };
        next_gamma = poly1305_tag(&sub_keys[i].k_mac, &candidate.mac_input_for_slot(i));
    }

    Ok(Header {
        version: VERSION,
        mode,
        hop_count: n as u8,
        hop_index: 0,
        alpha: alphas[0],
        beta,
        gamma: next_gamma,
        trailer,
    })
}

pub struct UnwrapOutcome {
    pub record: RoutingRecord,
    pub next_header: Header,
}

pub fn unwrap_header(header: &Header, sub_keys: &HopSubKeys) -> Result<UnwrapOutcome> {
    let i = header.hop_index as usize;
    let n = header.hop_count as usize;
    if i >= n || n > MAX_HOPS {
        return Err(Error::Malformed("hop_index/hop_count out of range"));
    }

    let expected = poly1305_tag(&sub_keys.k_mac, &header.mac_input_for_slot(i));
    if !bool::from(expected.ct_eq(&header.gamma)) {
        return Err(Error::BadMac);
    }

    let offset = i * RECORD_LEN;
    let stream = chacha20_stream(&sub_keys.k_header, RECORD_LEN);
    let mut record_bytes = [0u8; RECORD_LEN];
    for j in 0..RECORD_LEN {
        record_bytes[j] = header.beta[offset + j] ^ stream[j];
    }
    let record = RoutingRecord::decode(&record_bytes);

    let next_alpha = blind_alpha(&header.alpha, &sub_keys.k_blind);
    let shuffle = chacha20_stream(&sub_keys.k_shuffle, BETA_LEN + TRAILER_LEN);
    let mut next_beta = header.beta;
    for (j, b) in next_beta.iter_mut().enumerate() {
        *b ^= shuffle[j];
    }
    let mut next_trailer = header.trailer;
    for (j, t) in next_trailer.iter_mut().enumerate() {
        *t ^= shuffle[BETA_LEN + j];
    }
    let next_header = Header {
        version: header.version,
        mode: header.mode,
        hop_count: header.hop_count,
        hop_index: header.hop_index.saturating_add(1),
        alpha: next_alpha,
        beta: next_beta,
        gamma: record.next_gamma,
        trailer: next_trailer,
    };

    Ok(UnwrapOutcome {
        record,
        next_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF)
    }

    fn fake_relays(rng: &mut ChaCha20Rng, n: usize) -> Vec<(StaticSecret, [u8; 32])> {
        (0..n)
            .map(|_| {
                let sk = StaticSecret::random_from_rng(&mut *rng);
                let pk = X25519PublicKey::from(&sk).to_bytes();
                (sk, pk)
            })
            .collect()
    }

    fn sample_record(i: usize, is_last: bool) -> RoutingRecord {
        RoutingRecord {
            next_ipv4: [10, 0, 0, i as u8],
            next_port: 443,
            next_node_id: [(i as u8).wrapping_add(0xA0); 32],
            next_gamma: [0; GAMMA_LEN],
            delay_micros: 20_000,
            flag: if is_last { flag::IS_LAST_HOP } else { 0 },
            _padding: [0; 5],
        }
    }

    #[test]
    fn record_encode_decode_roundtrip() {
        let r = RoutingRecord {
            next_ipv4: [192, 168, 1, 100],
            next_port: 9001,
            next_node_id: [0x42; 32],
            next_gamma: [0xAB; GAMMA_LEN],
            delay_micros: 15_500,
            flag: flag::IS_LAST_HOP,
            _padding: [0; 5],
        };
        let bytes = r.encode();
        let r2 = RoutingRecord::decode(&bytes);
        assert_eq!(r.next_ipv4, r2.next_ipv4);
        assert_eq!(r.next_port, r2.next_port);
        assert_eq!(r.next_node_id, r2.next_node_id);
        assert_eq!(r.next_gamma, r2.next_gamma);
        assert_eq!(r.delay_micros, r2.delay_micros);
        assert_eq!(r.flag, r2.flag);
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        let h = Header {
            version: VERSION,
            mode: mode::BALANCED,
            hop_count: 3,
            hop_index: 1,
            alpha: [0x11; ALPHA_LEN],
            beta: [0x22; BETA_LEN],
            gamma: [0x33; GAMMA_LEN],
            trailer: [0x44; TRAILER_LEN],
        };
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        let h2 = Header::decode(&bytes).unwrap();
        assert_eq!(h.version, h2.version);
        assert_eq!(h.mode, h2.mode);
        assert_eq!(h.hop_count, h2.hop_count);
        assert_eq!(h.hop_index, h2.hop_index);
        assert_eq!(h.alpha, h2.alpha);
        assert_eq!(h.beta, h2.beta);
        assert_eq!(h.gamma, h2.gamma);
        assert_eq!(h.trailer, h2.trailer);
    }

    #[test]
    fn header_decode_rejects_bad_version() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0] = 99;
        assert!(matches!(Header::decode(&bytes), Err(Error::Malformed(_))));
    }

    #[test]
    fn header_decode_rejects_bad_hop_count() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0] = VERSION;
        bytes[2] = 0;
        assert!(matches!(Header::decode(&bytes), Err(Error::Malformed(_))));
        bytes[2] = (MAX_HOPS + 1) as u8;
        assert!(matches!(Header::decode(&bytes), Err(Error::Malformed(_))));
    }

    #[test]
    fn derive_hop_subkeys_rejects_low_order_point() {
        assert!(matches!(
            derive_hop_subkeys(&[0u8; 32]),
            Err(Error::Crypto(_))
        ));

        let shared = x25519([7u8; 32], [0u8; 32]);
        assert_eq!(shared, [0u8; 32], "sanity: low-order point ⇒ all-zero DH");
        assert!(matches!(derive_hop_subkeys(&shared), Err(Error::Crypto(_))));

        assert!(derive_hop_subkeys(&[1u8; 32]).is_ok());
    }

    fn roundtrip_n_hops(n: usize) {
        let mut r = rng();
        let relays = fake_relays(&mut r, n);
        let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();

        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records: Vec<RoutingRecord> = (0..n).map(|i| sample_record(i, i + 1 == n)).collect();
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);

        let mut header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .expect("wrap_header should succeed");

        for (i, ((sk, _pk), expected_record)) in relays.iter().zip(records.iter()).enumerate() {
            let shared = sk.diffie_hellman(&X25519PublicKey::from(header.alpha));
            let hop_sub = derive_hop_subkeys(shared.as_bytes()).unwrap();
            assert_eq!(
                hop_sub.k_mac, sub_keys[i].k_mac,
                "k_mac mismatch at hop {i}"
            );
            assert_eq!(
                hop_sub.k_header, sub_keys[i].k_header,
                "k_header mismatch at hop {i}"
            );

            let outcome = unwrap_header(&header, &hop_sub)
                .unwrap_or_else(|e| panic!("unwrap failed at hop {i}: {e:?}"));

            assert_eq!(outcome.record.next_ipv4, expected_record.next_ipv4);
            assert_eq!(outcome.record.next_port, expected_record.next_port);
            assert_eq!(outcome.record.next_node_id, expected_record.next_node_id);
            assert_eq!(outcome.record.delay_micros, expected_record.delay_micros);
            assert_eq!(outcome.record.flag, expected_record.flag);

            if i + 1 == n {
                assert!(outcome.record.is_last_hop(), "last hop flag missing");
            } else {
                header = outcome.next_header;
            }
        }
    }

    #[test]
    fn every_hop_emits_a_binarily_different_header() {
        for n in 2..=MAX_HOPS {
            let mut r = rng();
            let relays = fake_relays(&mut r, n);
            let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();
            let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
            let records: Vec<RoutingRecord> =
                (0..n).map(|i| sample_record(i, i + 1 == n)).collect();
            let mut trailer = [0u8; TRAILER_LEN];
            r.fill_bytes(&mut trailer);

            let mut header = wrap_header(
                &mut r,
                mode::BALANCED,
                &alphas,
                &sub_keys,
                &records,
                trailer,
            )
            .unwrap();

            let mut seen_beta: Vec<[u8; BETA_LEN]> = Vec::new();
            let mut seen_trailer: Vec<[u8; TRAILER_LEN]> = Vec::new();

            for (i, (sk, _pk)) in relays.iter().enumerate() {
                seen_beta.push(header.beta);
                seen_trailer.push(header.trailer);
                let shared = sk.diffie_hellman(&X25519PublicKey::from(header.alpha));
                let hop_sub = derive_hop_subkeys(shared.as_bytes()).unwrap();
                let outcome = unwrap_header(&header, &hop_sub).unwrap();
                if i + 1 < n {
                    header = outcome.next_header;
                }
            }

            for a in 0..n {
                for b in (a + 1)..n {
                    assert_ne!(
                        seen_beta[a], seen_beta[b],
                        "n={n}: β identical between hop {a} and hop {b} — the packet is \
                         linkable end to end by two colluding relays"
                    );
                    assert_ne!(
                        seen_trailer[a], seen_trailer[b],
                        "n={n}: trailer identical between hop {a} and hop {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn roundtrip_1_hop() {
        roundtrip_n_hops(1);
    }
    #[test]
    fn roundtrip_2_hops() {
        roundtrip_n_hops(2);
    }
    #[test]
    fn roundtrip_3_hops() {
        roundtrip_n_hops(3);
    }
    #[test]
    fn roundtrip_4_hops() {
        roundtrip_n_hops(4);
    }
    #[test]
    fn roundtrip_5_hops() {
        roundtrip_n_hops(5);
    }

    #[test]
    fn unwrap_rejects_tampered_mac() {
        let mut r = rng();
        let relays = fake_relays(&mut r, 3);
        let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();
        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records: Vec<RoutingRecord> = (0..3).map(|i| sample_record(i, i == 2)).collect();
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);
        let mut header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        header.gamma[0] ^= 0x01;
        let (sk, _) = &relays[0];
        let shared = sk.diffie_hellman(&X25519PublicKey::from(header.alpha));
        let hop_sub = derive_hop_subkeys(shared.as_bytes()).unwrap();
        assert!(matches!(
            unwrap_header(&header, &hop_sub),
            Err(Error::BadMac)
        ));
    }

    #[test]
    fn unwrap_rejects_tampered_own_slot() {
        let mut r = rng();
        let relays = fake_relays(&mut r, 3);
        let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();
        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records: Vec<RoutingRecord> = (0..3).map(|i| sample_record(i, i == 2)).collect();
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);
        let mut header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        header.beta[10] ^= 0x40;
        let (sk, _) = &relays[0];
        let shared = sk.diffie_hellman(&X25519PublicKey::from(header.alpha));
        let hop_sub = derive_hop_subkeys(shared.as_bytes()).unwrap();
        assert!(matches!(
            unwrap_header(&header, &hop_sub),
            Err(Error::BadMac)
        ));
    }

    #[test]
    fn cross_slot_tamper_is_caught_at_the_first_honest_hop() {
        let mut r = rng();
        let relays = fake_relays(&mut r, 3);
        let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();
        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records: Vec<RoutingRecord> = (0..3).map(|i| sample_record(i, i == 2)).collect();
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);
        let mut header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        header.beta[2 * RECORD_LEN + 5] ^= 0x40;

        let (sk0, _) = &relays[0];
        let shared0 = sk0.diffie_hellman(&X25519PublicKey::from(header.alpha));
        let hop_sub0 = derive_hop_subkeys(shared0.as_bytes()).unwrap();
        assert!(
            matches!(unwrap_header(&header, &hop_sub0), Err(Error::BadMac)),
            "a tamper in a later slot must be caught by the first hop to see it"
        );
    }

    #[test]
    fn unwrap_rejects_tampered_hop_index() {
        let mut r = rng();
        let relays = fake_relays(&mut r, 3);
        let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();
        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records: Vec<RoutingRecord> = (0..3).map(|i| sample_record(i, i == 2)).collect();
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);
        let mut header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        header.hop_index = 1;
        let (sk, _) = &relays[0];
        let shared = sk.diffie_hellman(&X25519PublicKey::from(header.alpha));
        let hop_sub = derive_hop_subkeys(shared.as_bytes()).unwrap();
        assert!(matches!(
            unwrap_header(&header, &hop_sub),
            Err(Error::BadMac)
        ));
    }

    #[test]
    fn wrap_rejects_wrong_hop_count() {
        let mut r = rng();
        let relays = fake_relays(&mut r, MAX_HOPS + 1);
        let pks: Vec<[u8; 32]> = relays.iter().map(|(_, pk)| *pk).collect();
        let res = derive_route_secrets(&mut r, &pks);
        assert!(res.is_err());
    }

    #[test]
    fn a_low_order_relay_key_is_refused_not_silently_used() {
        const LOW_ORDER: [[u8; 32]; 7] = [
            [0u8; 32],
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ];
        let low_order = LOW_ORDER;

        let mut r = rng();
        let honest = fake_relays(&mut r, 3);
        for (i, bad) in low_order.iter().enumerate() {
            for pos in 0..3 {
                let mut pks: Vec<[u8; 32]> = honest.iter().map(|(_, pk)| *pk).collect();
                pks[pos] = *bad;
                assert!(
                    derive_route_secrets(&mut r, &pks).is_err(),
                    "low-order key #{i} at hop {pos} must be refused"
                );
            }
        }

        let pks: Vec<[u8; 32]> = honest.iter().map(|(_, pk)| *pk).collect();
        assert!(derive_route_secrets(&mut r, &pks).is_ok());
    }
}
