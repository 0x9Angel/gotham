// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};

pub const EPHEM_PK_LEN: usize = 32;

pub const NONCE_LEN: usize = 12;

pub const AEAD_TAG_LEN: usize = 16;

pub const SENDER_PK_LEN: usize = 32;

pub const MIN_ENVELOPE_LEN: usize = EPHEM_PK_LEN + NONCE_LEN + SENDER_PK_LEN + AEAD_TAG_LEN;

const SEAL_KDF_SALT: &[u8] = b"gotham-sealed-v1";

const SEAL_AAD: &[u8] = b"gotham-sealed-envelope";

pub fn seal<R: CryptoRng + RngCore>(
    rng: &mut R,
    recipient_pk: &[u8; 32],
    sender_pk: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>> {
    let ephem_sk = EphemeralSecret::random_from_rng(&mut *rng);
    let ephem_pk = X25519PublicKey::from(&ephem_sk).to_bytes();
    let recipient = X25519PublicKey::from(*recipient_pk);
    let shared = ephem_sk.diffie_hellman(&recipient);

    if !shared.was_contributory() {
        return Err(Error::Crypto(
            "recipient key is low-order (non-contributory DH)",
        ));
    }

    let hk = hkdf::Hkdf::<Sha256>::new(Some(SEAL_KDF_SALT), shared.as_bytes());
    let mut k_seal = [0u8; 32];
    hk.expand(b"k_seal", &mut k_seal)
        .map_err(|_| Error::Crypto("HKDF expand k_seal"))?;

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

    let mut out = Vec::with_capacity(EPHEM_PK_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&ephem_pk);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn unseal(recipient_sk: &[u8; 32], envelope: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(Error::Crypto("envelope too short"));
    }

    let mut ephem_pk = [0u8; EPHEM_PK_LEN];
    ephem_pk.copy_from_slice(&envelope[..EPHEM_PK_LEN]);
    let nonce = &envelope[EPHEM_PK_LEN..EPHEM_PK_LEN + NONCE_LEN];
    let ciphertext = &envelope[EPHEM_PK_LEN + NONCE_LEN..];

    let sk = StaticSecret::from(*recipient_sk);
    let ephem = X25519PublicKey::from(ephem_pk);
    let shared = sk.diffie_hellman(&ephem);

    if !shared.was_contributory() {
        return Err(Error::Crypto(
            "ephemeral key is low-order (non-contributory DH)",
        ));
    }

    let hk = hkdf::Hkdf::<Sha256>::new(Some(SEAL_KDF_SALT), shared.as_bytes());
    let mut k_seal = [0u8; 32];
    hk.expand(b"k_seal", &mut k_seal)
        .map_err(|_| Error::Crypto("HKDF expand k_seal"))?;

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
        let sender_pk = clamped_sk(&mut r);

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
        let body = vec![0xAA; 1600];
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
        env[0] ^= 0x01;
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
        let recipient_sk = clamped_sk(&mut rng());
        let env = vec![0u8; MIN_ENVELOPE_LEN + 4];
        let err = unseal(&recipient_sk, &env).unwrap_err();
        assert!(
            matches!(err, Error::Crypto(m) if m.contains("low-order")),
            "expected low-order rejection, got {err:?}"
        );
    }

    #[test]
    fn low_order_recipient_is_rejected() {
        let mut r = rng();
        let low_order = [0u8; 32];
        let sender_pk = clamped_sk(&mut r);
        let err = seal(&mut r, &low_order, &sender_pk, b"x").unwrap_err();
        assert!(
            matches!(err, Error::Crypto(m) if m.contains("low-order")),
            "expected low-order rejection, got {err:?}"
        );
    }
}
