// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Hybrid KEM combining X25519 (classical) and ML-KEM-768 (post-quantum).
//!
//! ## Construction
//!
//! For each Gotham hop, the sender (or relay-as-sender for re-blinding):
//!
//! 1. Generates an ephemeral X25519 keypair `(esk, α)` and computes
//!    `ss_x = X25519(esk, α_recipient)`.
//! 2. Calls `ML-KEM-768.Encapsulate(pk_recipient)` → `(ct, ss_pq)`.
//! 3. Concatenates `shared = ss_x || ss_pq` (64 bytes) and feeds it into
//!    HKDF-SHA256 to derive four 32-byte sub-keys for the hop:
//!    `k_mac`, `k_header`, `k_payload`, `k_blind`.
//!
//! The recipient inverts this with its long-term X25519 and ML-KEM secret
//! keys. Decapsulation runs in constant time per the FIPS 203 specification
//! and the `x25519-dalek` constant-time guarantees.
//!
//! ## Security rationale
//!
//! Concatenation `ss_x || ss_pq` (rather than XOR) inside HKDF is the
//! "dual-PRF" construction recommended by Bindel et al. (2019) — an
//! adversary must break **both** X25519 and ML-KEM-768 to recover the
//! per-hop key material. If quantum computers eventually break X25519, the
//! ML-KEM half still holds; if a lattice break against ML-KEM is found
//! before then, X25519 still holds. Defence in depth.
//!
//! ## Wire layout (for `crate::header`)
//!
//! - `α` is 32 bytes (X25519 public key) — fits in the Sphinx header.
//! - `α'` is 1088 bytes (ML-KEM-768 ciphertext) — too large for the 384 B
//!   header. The full ciphertext lives at the prefix of the payload field
//!   (inside the outer AEAD layer), and the header carries a 32-byte
//!   BLAKE3 commitment `α* = BLAKE3(α')`. See `docs/gotham/README.md` §3.

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

// ─── Constants ──────────────────────────────────────────────────────────────

/// Length of an X25519 public key.
pub const X25519_PUBKEY_LEN: usize = 32;

/// Length of an ML-KEM-768 ciphertext (NIST FIPS 203, security level 3).
pub const MLKEM_CT_LEN: usize = 1088;

/// Length of an ML-KEM-768 encapsulation key (public).
pub const MLKEM_EK_LEN: usize = 1184;

/// Length of an ML-KEM-768 decapsulation key (private).
pub const MLKEM_DK_LEN: usize = 2400;

/// Length of an ML-KEM-768 shared secret (FIPS 203 fixes this at 32 bytes).
pub const MLKEM_SS_LEN: usize = 32;

/// Length of the X25519 shared secret.
pub const X25519_SS_LEN: usize = 32;

/// Length of the combined hybrid shared secret = X25519 || ML-KEM.
pub const HYBRID_SS_LEN: usize = X25519_SS_LEN + MLKEM_SS_LEN;

/// Length of the commitment to the ML-KEM ciphertext carried in the
/// Sphinx header (BLAKE3-256 digest).
pub const ALPHA_STAR_LEN: usize = 32;

/// HKDF salt used by all Gotham per-hop key derivations — domain separation.
const HKDF_SALT: &[u8] = b"gotham-hop-v1";

/// HKDF `info` strings for the four per-hop sub-keys.
const INFO_K_MAC: &[u8] = b"gotham:k_mac";
const INFO_K_HEADER: &[u8] = b"gotham:k_header";
const INFO_K_PAYLOAD: &[u8] = b"gotham:k_payload";
const INFO_K_BLIND: &[u8] = b"gotham:k_blind";

// ─── Types ──────────────────────────────────────────────────────────────────

type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;

/// Hybrid recipient public key (long-term identity of a relay).
#[derive(Clone)]
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes).
    pub x25519: [u8; X25519_PUBKEY_LEN],
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub mlkem: Box<[u8; MLKEM_EK_LEN]>,
}

/// Hybrid recipient secret key (long-term identity of a relay).
///
/// Zeroized on drop — never persisted to disk without further encryption.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub(crate) x25519: [u8; X25519_PUBKEY_LEN],
    pub(crate) mlkem: Box<[u8; MLKEM_DK_LEN]>,
}

/// Hybrid ciphertext: the `α` and `α'` components a sender produces.
#[derive(Clone)]
pub struct HybridCiphertext {
    /// X25519 ephemeral public key (carried in the Sphinx header `α`).
    pub alpha: [u8; X25519_PUBKEY_LEN],
    /// ML-KEM-768 ciphertext (carried at the prefix of the Sphinx payload).
    pub alpha_prime: Box<[u8; MLKEM_CT_LEN]>,
}

impl HybridCiphertext {
    /// BLAKE3 commitment to `α'` — carried in the Sphinx header.
    ///
    /// The recipient verifies this commitment after extracting `α'` from
    /// the payload prefix, preventing substitution attacks where a relay
    /// could swap in a different ciphertext to redirect key derivation.
    pub fn alpha_star(&self) -> [u8; ALPHA_STAR_LEN] {
        let mut h = Blake3Hasher::new();
        h.update(self.alpha_prime.as_slice());
        let mut out = [0u8; ALPHA_STAR_LEN];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

/// Combined hybrid shared secret = `ss_x || ss_pq` (64 bytes).
///
/// Zeroized on drop. Used as IKM for HKDF-SHA256 to derive per-hop
/// sub-keys via [`derive_subkeys`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridShared(pub(crate) [u8; HYBRID_SS_LEN]);

impl HybridShared {
    /// Constant-time equality test (used by tests and authenticated comparisons).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// Per-hop sub-keys derived from a `HybridShared` via HKDF-SHA256.
///
/// All four keys are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubKeys {
    /// Key for the Poly1305 MAC over the Sphinx header.
    pub k_mac: [u8; 32],
    /// Key for ChaCha20 stream encryption of the routing block `β`.
    pub k_header: [u8; 32],
    /// Key for the AEAD layer applied to the payload at this hop.
    pub k_payload: [u8; 32],
    /// Key for re-randomization of `(α, α*)` for the next hop.
    pub k_blind: [u8; 32],
}

// ─── Keypair generation ─────────────────────────────────────────────────────

/// Generate a fresh hybrid keypair from the supplied CSPRNG.
///
/// The X25519 and ML-KEM-768 keypairs are generated independently. The
/// caller MUST use a cryptographically secure RNG (e.g. `OsRng`) — passing
/// a deterministic stream RNG will compromise security.
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (HybridPublicKey, HybridSecretKey) {
    // X25519
    let x_sk = StaticSecret::random_from_rng(&mut *rng);
    let x_pk = X25519PublicKey::from(&x_sk);
    let x_sk_bytes = x_sk.to_bytes();
    let x_pk_bytes = x_pk.to_bytes();

    // ML-KEM-768
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

// ─── Encapsulate ────────────────────────────────────────────────────────────

/// Encapsulate to a recipient's hybrid public key.
///
/// Generates a fresh X25519 ephemeral keypair, performs DH with the
/// recipient, and runs ML-KEM-768 encapsulation. Returns the ciphertext
/// material `(α, α')` and the combined shared secret.
///
/// The X25519 ephemeral private key is dropped immediately after
/// computing the shared secret — forward secrecy is preserved.
///
/// **Security note:** the caller is responsible for ensuring `rng` is
/// cryptographically secure. Reuse of weak RNG state across calls is the
/// standard recipe for catastrophic key recovery.
pub fn encapsulate<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient: &HybridPublicKey,
) -> Result<(HybridCiphertext, HybridShared)> {
    // ── X25519 leg ────────────────────────────────────────────────────────
    let ephem_sk = EphemeralSecret::random_from_rng(&mut *rng);
    let alpha = X25519PublicKey::from(&ephem_sk).to_bytes();
    let recipient_x = X25519PublicKey::from(recipient.x25519);
    let ss_x = ephem_sk.diffie_hellman(&recipient_x);
    // ss_x consumed; ephem_sk dropped here

    // ── ML-KEM-768 leg ────────────────────────────────────────────────────
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

    // ── Combined shared secret ────────────────────────────────────────────
    let mut shared = [0u8; HYBRID_SS_LEN];
    shared[..X25519_SS_LEN].copy_from_slice(ss_x.as_bytes());
    shared[X25519_SS_LEN..].copy_from_slice(mlkem_ss.as_slice());

    Ok((
        HybridCiphertext { alpha, alpha_prime },
        HybridShared(shared),
    ))
}

// ─── Decapsulate ────────────────────────────────────────────────────────────

/// Decapsulate the hybrid ciphertext using the recipient's secret key.
///
/// Both legs (X25519 + ML-KEM-768) are executed in constant time per the
/// underlying primitives. ML-KEM's implicit-rejection design means
/// decapsulation never branches on validation failure (FIPS 203 §7.3) —
/// invalid ciphertexts produce a pseudo-random shared key indistinguishable
/// from a valid one to a timing observer.
///
/// The caller may optionally verify `α* = BLAKE3(α')` matches the
/// commitment carried in the Sphinx header (this is done by the header
/// processing pipeline, not here).
pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> Result<HybridShared> {
    // ── X25519 leg ────────────────────────────────────────────────────────
    let x_sk = StaticSecret::from(sk.x25519);
    let alpha_pk = X25519PublicKey::from(ct.alpha);
    let ss_x = x_sk.diffie_hellman(&alpha_pk);

    // ── ML-KEM-768 leg ────────────────────────────────────────────────────
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

    // ── Combined shared secret ────────────────────────────────────────────
    let mut shared = [0u8; HYBRID_SS_LEN];
    shared[..X25519_SS_LEN].copy_from_slice(ss_x.as_bytes());
    shared[X25519_SS_LEN..].copy_from_slice(mlkem_ss.as_slice());

    Ok(HybridShared(shared))
}

// ─── Sub-key derivation ─────────────────────────────────────────────────────

/// Derive the four per-hop sub-keys from a hybrid shared secret via
/// HKDF-SHA256.
///
/// `salt = b"gotham-hop-v1"` provides version domain-separation; the four
/// `info` strings provide purpose separation. HKDF guarantees that knowing
/// any sub-key gives no information about the others, even if the
/// adversary knows the salt and info strings.
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

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        // Deterministic seed — tests must be reproducible.
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
        // Same input → same output (BLAKE3 is deterministic)
        let commitment_2 = ct.alpha_star();
        assert_eq!(commitment_1, commitment_2);
    }

    #[test]
    fn alpha_star_changes_when_alpha_prime_changes() {
        let mut r = rng();
        let (pk, _sk) = generate_keypair(&mut r);
        let (ct1, _) = encapsulate(&mut r, &pk).unwrap();
        let (ct2, _) = encapsulate(&mut r, &pk).unwrap();
        // Two independent encapsulations → different α' → different commitments
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
        // Decapsulating with sk_b instead of sk_a: ML-KEM's implicit-
        // rejection produces a pseudo-random secret. Either decap fails
        // outright OR returns a secret that does not match the sender's.
        match decapsulate(&sk_b, &ct) {
            Err(_) => { /* acceptable */ }
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

    // Property tests — fuzz-light without proptest framework noise.
    // For full proptest coverage, see tests/property_hybrid.rs (TODO).
    #[test]
    fn many_round_trips_succeed() {
        let mut r = rng();
        let (pk, sk) = generate_keypair(&mut r);
        for _ in 0..256 {
            let (ct, ss_sender) = encapsulate(&mut r, &pk).unwrap();
            let ss_receiver = decapsulate(&sk, &ct).unwrap();
            assert!(ss_sender.ct_eq(&ss_receiver));
            let sub = derive_subkeys(&ss_receiver).unwrap();
            // sanity: keys are not all zeros
            assert!(sub.k_mac.iter().any(|&b| b != 0));
        }
    }
}
