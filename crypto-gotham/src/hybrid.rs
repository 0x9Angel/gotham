// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const X25519_PUBKEY_LEN: usize = 32;

pub const MLKEM_CT_LEN: usize = 1088;

pub const MLKEM_EK_LEN: usize = 1184;

pub const MLKEM_DK_LEN: usize = 2400;

pub const MLKEM_SS_LEN: usize = 32;

pub const X25519_SS_LEN: usize = 32;

pub const HYBRID_SS_LEN: usize = X25519_SS_LEN + MLKEM_SS_LEN;

pub const ALPHA_STAR_LEN: usize = 32;

const HKDF_SALT: &[u8] = b"gotham-hop-v1";

const INFO_K_MAC: &[u8] = b"gotham:k_mac";
const INFO_K_HEADER: &[u8] = b"gotham:k_header";
const INFO_K_PAYLOAD: &[u8] = b"gotham:k_payload";
const INFO_K_BLIND: &[u8] = b"gotham:k_blind";

type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;

#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519: [u8; X25519_PUBKEY_LEN],
    pub mlkem: Box<[u8; MLKEM_EK_LEN]>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub(crate) x25519: [u8; X25519_PUBKEY_LEN],
    pub(crate) mlkem: Box<[u8; MLKEM_DK_LEN]>,
}

#[derive(Clone)]
pub struct HybridCiphertext {
    pub alpha: [u8; X25519_PUBKEY_LEN],
    pub alpha_prime: Box<[u8; MLKEM_CT_LEN]>,
}

impl HybridCiphertext {
    pub fn alpha_star(&self) -> [u8; ALPHA_STAR_LEN] {
        let mut h = Blake3Hasher::new();
        h.update(self.alpha_prime.as_slice());
        let mut out = [0u8; ALPHA_STAR_LEN];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(X25519_PUBKEY_LEN + MLKEM_EK_LEN);
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(self.mlkem.as_slice());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != X25519_PUBKEY_LEN + MLKEM_EK_LEN {
            return Err(Error::Crypto("hybrid public key wrong length"));
        }
        let mut x25519 = [0u8; X25519_PUBKEY_LEN];
        x25519.copy_from_slice(&b[..X25519_PUBKEY_LEN]);
        let mut mlkem = Box::new([0u8; MLKEM_EK_LEN]);
        mlkem.copy_from_slice(&b[X25519_PUBKEY_LEN..]);
        Ok(Self { x25519, mlkem })
    }
}

impl HybridSecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(X25519_PUBKEY_LEN + MLKEM_DK_LEN);
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(self.mlkem.as_slice());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != X25519_PUBKEY_LEN + MLKEM_DK_LEN {
            return Err(Error::Crypto("hybrid secret key wrong length"));
        }
        let mut x25519 = [0u8; X25519_PUBKEY_LEN];
        x25519.copy_from_slice(&b[..X25519_PUBKEY_LEN]);
        let mut mlkem = Box::new([0u8; MLKEM_DK_LEN]);
        mlkem.copy_from_slice(&b[X25519_PUBKEY_LEN..]);
        Ok(Self { x25519, mlkem })
    }
}

impl HybridCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(X25519_PUBKEY_LEN + MLKEM_CT_LEN);
        v.extend_from_slice(&self.alpha);
        v.extend_from_slice(self.alpha_prime.as_slice());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != X25519_PUBKEY_LEN + MLKEM_CT_LEN {
            return Err(Error::Crypto("hybrid ciphertext wrong length"));
        }
        let mut alpha = [0u8; X25519_PUBKEY_LEN];
        alpha.copy_from_slice(&b[..X25519_PUBKEY_LEN]);
        let mut alpha_prime = Box::new([0u8; MLKEM_CT_LEN]);
        alpha_prime.copy_from_slice(&b[X25519_PUBKEY_LEN..]);
        Ok(Self { alpha, alpha_prime })
    }
}

impl HybridShared {
    pub fn as_ikm(&self) -> &[u8; HYBRID_SS_LEN] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridShared(pub(crate) [u8; HYBRID_SS_LEN]);

impl HybridShared {
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubKeys {
    pub k_mac: [u8; 32],
    pub k_header: [u8; 32],
    pub k_payload: [u8; 32],
    pub k_blind: [u8; 32],
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (HybridPublicKey, HybridSecretKey) {
    let x_sk = StaticSecret::random_from_rng(&mut *rng);
    let x_pk = X25519PublicKey::from(&x_sk);
    let x_sk_bytes = x_sk.to_bytes();
    let x_pk_bytes = x_pk.to_bytes();

    let (mlkem_dk, mlkem_ek) = MlKem768::generate(rng);
    let ek_array = mlkem_ek.as_bytes();
    let dk_array = mlkem_dk.as_bytes();

    let mut ek_bytes = Box::new([0u8; MLKEM_EK_LEN]);
    ek_bytes.copy_from_slice(ek_array.as_slice());
    let mut dk_bytes = Box::new([0u8; MLKEM_DK_LEN]);
    dk_bytes.copy_from_slice(dk_array.as_slice());

    let pk = HybridPublicKey {
        x25519: x_pk_bytes,
        mlkem: ek_bytes,
    };
    let sk = HybridSecretKey {
        x25519: x_sk_bytes,
        mlkem: dk_bytes,
    };
    (pk, sk)
}

pub fn encapsulate<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient: &HybridPublicKey,
) -> Result<(HybridCiphertext, HybridShared)> {
    let ephem_sk = EphemeralSecret::random_from_rng(&mut *rng);
    let alpha = X25519PublicKey::from(&ephem_sk).to_bytes();
    let recipient_x = X25519PublicKey::from(recipient.x25519);
    let ss_x = ephem_sk.diffie_hellman(&recipient_x);

    let ek_array_ref: &Array<u8, _> = recipient
        .mlkem
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("ml-kem ek length mismatch"))?;
    let mlkem_ek = MlKemEk::from_bytes(ek_array_ref);
    let (mlkem_ct, mlkem_ss) = mlkem_ek
        .encapsulate(rng)
        .map_err(|_| Error::Crypto("ml-kem encapsulate failed"))?;

    let mut alpha_prime = Box::new([0u8; MLKEM_CT_LEN]);
    alpha_prime.copy_from_slice(mlkem_ct.as_slice());

    let mut shared = [0u8; HYBRID_SS_LEN];
    shared[..X25519_SS_LEN].copy_from_slice(ss_x.as_bytes());
    shared[X25519_SS_LEN..].copy_from_slice(mlkem_ss.as_slice());

    Ok((
        HybridCiphertext { alpha, alpha_prime },
        HybridShared(shared),
    ))
}

pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> Result<HybridShared> {
    let x_sk = StaticSecret::from(sk.x25519);
    let alpha_pk = X25519PublicKey::from(ct.alpha);
    let ss_x = x_sk.diffie_hellman(&alpha_pk);

    let dk_array_ref: &Array<u8, _> = sk
        .mlkem
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("ml-kem dk length mismatch"))?;
    let mlkem_dk = MlKemDk::from_bytes(dk_array_ref);

    let ct_array_ref: &Array<u8, _> = ct
        .alpha_prime
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("ml-kem ct length mismatch"))?;

    let mlkem_ss = mlkem_dk
        .decapsulate(ct_array_ref)
        .map_err(|_| Error::Crypto("ml-kem decapsulate failed"))?;

    let mut shared = [0u8; HYBRID_SS_LEN];
    shared[..X25519_SS_LEN].copy_from_slice(ss_x.as_bytes());
    shared[X25519_SS_LEN..].copy_from_slice(mlkem_ss.as_slice());

    Ok(HybridShared(shared))
}

pub fn derive_subkeys(shared: &HybridShared) -> Result<SubKeys> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared.0);

    let mut k_mac = [0u8; 32];
    let mut k_header = [0u8; 32];
    let mut k_payload = [0u8; 32];
    let mut k_blind = [0u8; 32];

    hk.expand(INFO_K_MAC, &mut k_mac)
        .map_err(|_| Error::Crypto("HKDF expand k_mac"))?;
    hk.expand(INFO_K_HEADER, &mut k_header)
        .map_err(|_| Error::Crypto("HKDF expand k_header"))?;
    hk.expand(INFO_K_PAYLOAD, &mut k_payload)
        .map_err(|_| Error::Crypto("HKDF expand k_payload"))?;
    hk.expand(INFO_K_BLIND, &mut k_blind)
        .map_err(|_| Error::Crypto("HKDF expand k_blind"))?;

    Ok(SubKeys {
        k_mac,
        k_header,
        k_payload,
        k_blind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xDEADBEEF)
    }

    #[test]
    fn keypair_lengths_match_constants() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        assert_eq!(pk.x25519.len(), X25519_PUBKEY_LEN);
        assert_eq!(pk.mlkem.len(), MLKEM_EK_LEN);
        assert_eq!(sk.x25519.len(), X25519_PUBKEY_LEN);
        assert_eq!(sk.mlkem.len(), MLKEM_DK_LEN);
    }

    #[test]
    fn round_trip_recovers_same_shared() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        let (ct, ss_sender) = encapsulate(&mut r, &pk).unwrap();
        let ss_receiver = decapsulate(&sk, &ct).unwrap();
        assert!(
            ss_sender.ct_eq(&ss_receiver),
            "round-trip shared secret mismatch"
        );
    }

    #[test]
    fn ciphertext_components_have_correct_lengths() {
        let mut r = rng();
        let (pk, _sk) = generate_keypair(&mut r);
        let (ct, _ss) = encapsulate(&mut r, &pk).unwrap();
        assert_eq!(ct.alpha.len(), X25519_PUBKEY_LEN);
        assert_eq!(ct.alpha_prime.len(), MLKEM_CT_LEN);
        assert_eq!(ct.alpha_star().len(), ALPHA_STAR_LEN);
    }

    #[test]
    fn alpha_star_commits_to_alpha_prime() {
        let mut r = rng();
        let (pk, _sk) = generate_keypair(&mut r);
        let (ct, _ss) = encapsulate(&mut r, &pk).unwrap();
        let commitment_1 = ct.alpha_star();
        let commitment_2 = ct.alpha_star();
        assert_eq!(commitment_1, commitment_2);
    }

    #[test]
    fn alpha_star_changes_when_alpha_prime_changes() {
        let mut r = rng();
        let (pk, _sk) = generate_keypair(&mut r);
        let (ct1, _) = encapsulate(&mut r, &pk).unwrap();
        let (ct2, _) = encapsulate(&mut r, &pk).unwrap();
        assert_ne!(ct1.alpha_star(), ct2.alpha_star());
    }

    #[test]
    fn two_encapsulations_produce_different_shared_secrets() {
        let mut r = rng();
        let (pk, _sk) = generate_keypair(&mut r);
        let (_, ss1) = encapsulate(&mut r, &pk).unwrap();
        let (_, ss2) = encapsulate(&mut r, &pk).unwrap();
        assert!(
            !ss1.ct_eq(&ss2),
            "two independent encapsulations should not collide"
        );
    }

    #[test]
    fn decapsulate_with_wrong_sk_yields_different_shared() {
        let mut r = rng();
        let (pk_a, _sk_a) = generate_keypair(&mut r);
        let (_pk_b, sk_b) = generate_keypair(&mut r);
        let (ct, ss_sender) = encapsulate(&mut r, &pk_a).unwrap();
        match decapsulate(&sk_b, &ct) {
            Err(_) => {}
            Ok(ss_wrong) => {
                assert!(
                    !ss_sender.ct_eq(&ss_wrong),
                    "wrong-key decap must not produce the sender's secret"
                );
            }
        }
    }

    #[test]
    fn subkeys_are_distinct_for_same_shared() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        let (ct, _) = encapsulate(&mut r, &pk).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        let sub = derive_subkeys(&ss).unwrap();
        assert_ne!(sub.k_mac, sub.k_header);
        assert_ne!(sub.k_mac, sub.k_payload);
        assert_ne!(sub.k_mac, sub.k_blind);
        assert_ne!(sub.k_header, sub.k_payload);
        assert_ne!(sub.k_header, sub.k_blind);
        assert_ne!(sub.k_payload, sub.k_blind);
    }

    #[test]
    fn subkeys_are_deterministic_from_shared() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        let (ct, _) = encapsulate(&mut r, &pk).unwrap();
        let ss1 = decapsulate(&sk, &ct).unwrap();
        let ss2 = decapsulate(&sk, &ct).unwrap();
        let sub1 = derive_subkeys(&ss1).unwrap();
        let sub2 = derive_subkeys(&ss2).unwrap();
        assert_eq!(sub1.k_mac, sub2.k_mac);
        assert_eq!(sub1.k_header, sub2.k_header);
        assert_eq!(sub1.k_payload, sub2.k_payload);
        assert_eq!(sub1.k_blind, sub2.k_blind);
    }

    #[test]
    fn different_shared_secrets_yield_different_subkeys() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        let (ct1, _) = encapsulate(&mut r, &pk).unwrap();
        let (ct2, _) = encapsulate(&mut r, &pk).unwrap();
        let ss1 = decapsulate(&sk, &ct1).unwrap();
        let ss2 = decapsulate(&sk, &ct2).unwrap();
        let s1 = derive_subkeys(&ss1).unwrap();
        let s2 = derive_subkeys(&ss2).unwrap();
        assert_ne!(s1.k_mac, s2.k_mac);
        assert_ne!(s1.k_header, s2.k_header);
        assert_ne!(s1.k_payload, s2.k_payload);
        assert_ne!(s1.k_blind, s2.k_blind);
    }

    #[test]
    fn many_round_trips_succeed() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        for _ in 0..256 {
            let (ct, ss_sender) = encapsulate(&mut r, &pk).unwrap();
            let ss_receiver = decapsulate(&sk, &ct).unwrap();
            assert!(ss_sender.ct_eq(&ss_receiver));
            let sub = derive_subkeys(&ss_receiver).unwrap();
            assert!(sub.k_mac.iter().any(|&b| b != 0));
        }
    }
}
