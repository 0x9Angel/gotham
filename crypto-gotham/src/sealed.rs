// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Sealed-sender envelope (Signal-protocol style, simplified for v0.1).
//!
//! ## What it does
//!
//! Hides the *sender's identity* from the network. The mixnet (Gotham
//! relays) and any passive observer only see an opaque envelope; even
//! the exit relay that delivers locally cannot tell who sent the
//! message. The recipient — and only the recipient — can:
//!
//! 1. Decrypt the envelope using its long-term X25519 secret key.
//! 2. Read the sender's identity public key from inside.
//! 3. Hand the inner ciphertext to its existing X3DH + Double Ratchet
//!    session keyed on that sender.
//!
//! Real *cryptographic authentication* of the sender lives at the
//! Double-Ratchet layer (the inner ciphertext only decrypts with the
//! correct per-conversation ratchet state). The sender identity inside
//! the envelope is metadata: convenient for routing the inner ciphertext
//! to the right ratchet, but not the trust root.
//!
//! ## Wire format
//!
//! ```text
//! offset  size  field
//!     0    32   ephemeral X25519 public key (generated per-message)
//!    32    12   ChaCha20-Poly1305 nonce
//!    44    32   sender identity X25519 public key  ┐ AEAD-encrypted
//!    76     ?   inner body (e.g. Double-Ratchet CT) ┤  under k_seal
//!     ?    16   Poly1305 tag                        ┘
//! ```
//!
//! `k_seal = HKDF-SHA256(X25519(ephem_sk, recipient_pk), "gotham-sealed-v1")`.
//!
//! Total overhead: 32 + 12 + 16 = 60 bytes per envelope.
//!
//! ## Forward secrecy
//!
//! The ephemeral X25519 keypair is generated fresh per envelope and
//! dropped immediately after computing the shared secret. An attacker
//! who later compromises the sender's long-term keys cannot retroactively
//! decrypt past envelopes — they would need both the recipient's
//! long-term sk AND the per-envelope ephemeral sk (the latter never
//! existed in storage).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Length of the ephemeral X25519 pubkey at the head of the envelope.
pub const EPHEM_PK_LEN: usize = 32;

/// Length of the ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;

/// Length of the AEAD tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of the sender's identity X25519 public key inside the ciphertext.
pub const SENDER_PK_LEN: usize = 32;

/// Minimum size of a valid sealed envelope (empty body + headers + tag).
pub const MIN_ENVELOPE_LEN: usize = EPHEM_PK_LEN + NONCE_LEN + SENDER_PK_LEN + AEAD_TAG_LEN;

/// HKDF salt for envelope key derivation (version-locked).
const SEAL_KDF_SALT: &[u8] = b"gotham-sealed-v1";

/// Optional associated data prefix (binds the envelope to Gotham — an
/// envelope built for a different protocol won't accidentally decrypt).
const SEAL_AAD: &[u8] = b"gotham-sealed-envelope";

/// Seal `body` for `recipient_pk`, attesting `sender_pk` as the apparent
/// sender. Returns the on-wire envelope bytes.
///
/// `rng` MUST be cryptographically secure (`OsRng` in production).
pub fn seal<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient_pk: &[u8; 32],
    sender_pk: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>> {
    // 1. Fresh X25519 ephemeral; do the DH; drop the sk immediately.
    let ephem_sk = EphemeralSecret::random_from_rng(&mut *rng);
    let ephem_pk = X25519PublicKey::from(&ephem_sk).to_bytes();
    let recipient = X25519PublicKey::from(*recipient_pk);
    let shared = ephem_sk.diffie_hellman(&recipient);
    // ephem_sk now dropped; only the shared secret remains.

    // Reject a low-order recipient key: if the recipient's public key lies in
    // the small subgroup (order ≤ 8), the X25519 output is a fixed, publicly
    // known low-order point regardless of our ephemeral secret. Sealing to it
    // would produce an envelope any observer could re-derive the key for. A
    // well-formed directory/contact key never triggers this — it only fires on
    // a maliciously crafted recipient key. `was_contributory()` is the
    // constant-time subgroup check exposed by x25519-dalek.
    if !shared.was_contributory() {
        return Err(Error::Crypto(
            "recipient key is low-order (non-contributory DH)",
        ));
    }

    // 2. HKDF the shared into a 32-byte AEAD key.
    let hk = hkdf::Hkdf::<Sha256>::new(Some(SEAL_KDF_SALT), shared.as_bytes());
    let mut k_seal = [0u8; 32];
    hk.expand(b"k_seal", &mut k_seal)
        .map_err(|_| Error::Crypto("HKDF expand k_seal"))?;

    // 3. AEAD-encrypt `sender_pk || body` under k_seal with a random nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new((&k_seal).into());
    let mut plaintext = Vec::with_capacity(SENDER_PK_LEN + body.len());
    plaintext.extend_from_slice(sender_pk);
    plaintext.extend_from_slice(body);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: SEAL_AAD,
            },
        )
        .map_err(|_| Error::Crypto("AEAD seal encrypt"))?;
    plaintext.zeroize();
    k_seal.zeroize();

    // 4. Assemble envelope: ephem_pk || nonce || ciphertext (incl. tag).
    let mut out = Vec::with_capacity(EPHEM_PK_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&ephem_pk);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal an envelope intended for `recipient_sk`. Returns the
/// (apparent sender pubkey, inner body) pair on success.
///
/// Fails on any malformation, tampering, or wrong recipient.
pub fn unseal(recipient_sk: &[u8; 32], envelope: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(Error::Crypto("envelope too short"));
    }

    // 1. Parse fixed-size headers.
    let mut ephem_pk = [0u8; EPHEM_PK_LEN];
    ephem_pk.copy_from_slice(&envelope[..EPHEM_PK_LEN]);
    let nonce = &envelope[EPHEM_PK_LEN..EPHEM_PK_LEN + NONCE_LEN];
    let ciphertext = &envelope[EPHEM_PK_LEN + NONCE_LEN..];

    // 2. Re-derive the shared secret + AEAD key.
    let sk = StaticSecret::from(*recipient_sk);
    let ephem = X25519PublicKey::from(ephem_pk);
    let shared = sk.diffie_hellman(&ephem);

    // Reject a low-order ephemeral key. The ephemeral pubkey rides in the
    // (attacker-controllable) envelope header, so an attacker could set it to a
    // small-subgroup point to force an all-zero / predictable shared secret and
    // then forge an envelope whose AEAD key they know. `was_contributory()`
    // fails closed on exactly those points — cutting the small-subgroup /
    // invalid-curve forgery vector before the key is derived.
    if !shared.was_contributory() {
        return Err(Error::Crypto(
            "ephemeral key is low-order (non-contributory DH)",
        ));
    }

    let hk = hkdf::Hkdf::<Sha256>::new(Some(SEAL_KDF_SALT), shared.as_bytes());
    let mut k_seal = [0u8; 32];
    hk.expand(b"k_seal", &mut k_seal)
        .map_err(|_| Error::Crypto("HKDF expand k_seal"))?;

    // 3. AEAD-decrypt.
    let cipher = ChaCha20Poly1305::new((&k_seal).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: SEAL_AAD,
            },
        )
        .map_err(|_| Error::Crypto("AEAD seal decrypt"))?;
    k_seal.zeroize();

    if plaintext.len() < SENDER_PK_LEN {
        return Err(Error::Crypto("plaintext shorter than sender pk"));
    }
    let mut sender_pk = [0u8; SENDER_PK_LEN];
    sender_pk.copy_from_slice(&plaintext[..SENDER_PK_LEN]);
    let body = plaintext[SENDER_PK_LEN..].to_vec();
    Ok((sender_pk, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xDEAD_CAFE_5EAD_BEEF)
    }

    fn clamped_sk(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    #[test]
    fn round_trip_recovers_sender_and_body() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r); // sender pk is just metadata here

        let body = b"hello from sealed envelope";
        let env = seal(&mut r, &recipient_pk, &sender_pk, body).unwrap();
        let (sender_back, body_back) = unseal(&recipient_sk, &env).unwrap();
        assert_eq!(sender_back, sender_pk);
        assert_eq!(body_back, body);
    }

    #[test]
    fn envelope_overhead_matches_constants() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);
        let body = b"abc";
        let env = seal(&mut r, &recipient_pk, &sender_pk, body).unwrap();
        // Expected: ephem_pk (32) + nonce (12) + sender_pk (32) + body (3) + tag (16) = 95
        assert_eq!(
            env.len(),
            EPHEM_PK_LEN + NONCE_LEN + SENDER_PK_LEN + body.len() + AEAD_TAG_LEN
        );
    }

    #[test]
    fn empty_body_works() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);
        let env = seal(&mut r, &recipient_pk, &sender_pk, b"").unwrap();
        let (back_sender, back_body) = unseal(&recipient_sk, &env).unwrap();
        assert_eq!(back_sender, sender_pk);
        assert!(back_body.is_empty());
    }

    #[test]
    fn large_body_works() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);
        let body = vec![0xAA; 1600]; // ~ max for a Gotham payload
        let env = seal(&mut r, &recipient_pk, &sender_pk, &body).unwrap();
        let (back_sender, back_body) = unseal(&recipient_sk, &env).unwrap();
        assert_eq!(back_sender, sender_pk);
        assert_eq!(back_body, body);
    }

    #[test]
    fn two_seals_produce_distinct_envelopes() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);
        let body = b"identical body";
        let e1 = seal(&mut r, &recipient_pk, &sender_pk, body).unwrap();
        let e2 = seal(&mut r, &recipient_pk, &sender_pk, body).unwrap();
        assert_ne!(
            e1, e2,
            "envelope must differ across encryptions (ephem + nonce)"
        );
        // But both must decrypt to the same plaintext.
        assert_eq!(unseal(&recipient_sk, &e1).unwrap().1, body);
        assert_eq!(unseal(&recipient_sk, &e2).unwrap().1, body);
    }

    #[test]
    fn wrong_recipient_fails() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let wrong_sk = clamped_sk(&mut r);
        let sender_pk = clamped_sk(&mut r);
        let env = seal(&mut r, &recipient_pk, &sender_pk, b"secret").unwrap();
        assert!(unseal(&wrong_sk, &env).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);
        let mut env = seal(&mut r, &recipient_pk, &sender_pk, b"secret").unwrap();
        // Flip a bit in the ciphertext region.
        let last = env.len() - 5;
        env[last] ^= 0x01;
        assert!(unseal(&recipient_sk, &env).is_err());
    }

    #[test]
    fn tampered_ephem_pk_fails() {
        let mut r = rng();
        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut r);
        let mut env = seal(&mut r, &recipient_pk, &sender_pk, b"secret").unwrap();
        env[0] ^= 0x01; // change ephemeral pk → DH yields different secret
        assert!(unseal(&recipient_sk, &env).is_err());
    }

    #[test]
    fn too_short_envelope_fails() {
        let recipient_sk = clamped_sk(&mut rng());
        let env = vec![0u8; MIN_ENVELOPE_LEN - 1];
        assert!(unseal(&recipient_sk, &env).is_err());
    }

    #[test]
    fn low_order_ephemeral_is_rejected() {
        // u = 0 is a small-subgroup point: X25519 maps it to an all-zero
        // shared secret regardless of the recipient secret, so an attacker
        // who plants it in the envelope header knows the derived AEAD key.
        // `unseal` must fail closed BEFORE deriving the key.
        let recipient_sk = clamped_sk(&mut rng());
        // A well-formed-length envelope whose ephemeral pk (bytes 0..32) is the
        // low-order u = 0 point; the rest is irrelevant — we never reach AEAD.
        let env = vec![0u8; MIN_ENVELOPE_LEN + 4];
        let err = unseal(&recipient_sk, &env).unwrap_err();
        assert!(
            matches!(err, Error::Crypto(m) if m.contains("low-order")),
            "expected low-order rejection, got {err:?}"
        );
    }

    #[test]
    fn low_order_recipient_is_rejected() {
        // Sealing to a small-subgroup recipient key would yield an envelope
        // whose key any observer can re-derive — refuse it.
        let mut r = rng();
        let low_order = [0u8; 32]; // u = 0
        let sender_pk = clamped_sk(&mut r);
        let err = seal(&mut r, &low_order, &sender_pk, b"x").unwrap_err();
        assert!(
            matches!(err, Error::Crypto(m) if m.contains("low-order")),
            "expected low-order rejection, got {err:?}"
        );
    }
}
