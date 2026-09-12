// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! LIONESS wide-block cipher (Anderson–Biham) over the Gotham payload region.
//!
//! ## Why
//!
//! The per-hop payload onion needs a transformation that is (a) length
//! preserving — the packet stays a fixed 2048 B at every hop — and (b)
//! **non-malleable**: flipping any bit anywhere must scramble the *whole* block,
//! so a relay cannot tag a packet (flip a known bit) and recognise it later.
//! A raw stream-cipher XOR gives (a) but not (b) — a flipped bit propagates
//! straight through. LIONESS is a provably-secure pseudo-random permutation
//! built from a stream cipher `S` and a keyed hash `H` in a 4-round unbalanced
//! Feistel, giving both.
//!
//! ## Construction
//!
//! The block is split `L ‖ R` with `|L| = 32` (the keyed-hash output length)
//! and `R` the remainder. With four round keys `k1..k4` derived from the layer
//! key:
//!
//! ```text
//! encrypt:                       decrypt (exact inverse, reversed order):
//!   R ^= S(L ^ k1)                 L ^= H(k4, R)
//!   L ^= H(k2, R)                  R ^= S(L ^ k3)
//!   R ^= S(L ^ k3)                 L ^= H(k2, R)
//!   L ^= H(k4, R)                  R ^= S(L ^ k1)
//! ```
//!
//! `S(seed)` is a ChaCha20 keystream keyed by `seed` (32 B, all-zero nonce),
//! XORed into `R`; `H(k, R)` is `blake3::keyed_hash(k, R)`, XORed into `L`.
//! Safe with a fixed nonce because each layer key is a per-packet ephemeral
//! (derived from a fresh X25519 exchange) and never reused.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

/// Length of the Feistel "left" half `L` (= blake3 keyed-hash output).
const L_LEN: usize = 32;

/// Minimum block length LIONESS can process (`|L| + 1`).
pub const MIN_BLOCK: usize = L_LEN + 1;

struct RoundKeys {
    k1: [u8; 32],
    k2: [u8; 32],
    k3: [u8; 32],
    k4: [u8; 32],
}

/// Derive the four round keys from a single 32-byte layer key. `blake3::derive_key`
/// is an infallible, domain-separated KDF (each context string yields an
/// independent key), so no fallible expansion or panic path is involved.
fn round_keys(key: &[u8; 32]) -> RoundKeys {
    RoundKeys {
        k1: blake3::derive_key("gotham-lioness-v1 round-key 1", key),
        k2: blake3::derive_key("gotham-lioness-v1 round-key 2", key),
        k3: blake3::derive_key("gotham-lioness-v1 round-key 3", key),
        k4: blake3::derive_key("gotham-lioness-v1 round-key 4", key),
    }
}

/// XOR a ChaCha20 keystream keyed by `seed` (all-zero nonce) into `dst`.
fn stream_xor(seed: &[u8; 32], dst: &mut [u8]) {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(seed.into(), (&nonce).into());
    cipher.apply_keystream(dst);
}

/// `L ^= blake3::keyed_hash(k, R)` over the first `L_LEN` bytes.
fn hash_into_l(k: &[u8; 32], r: &[u8], l: &mut [u8]) {
    let digest = blake3::keyed_hash(k, r);
    let d = digest.as_bytes();
    for i in 0..L_LEN {
        l[i] ^= d[i];
    }
}

/// 32-byte key = `L ^ k_round`.
fn seed_from(l: &[u8], k: &[u8; 32]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for i in 0..L_LEN {
        seed[i] = l[i] ^ k[i];
    }
    seed
}

/// Encrypt `block` in place with the LIONESS PRP under `key`.
///
/// F-69 — a block shorter than [`MIN_BLOCK`] is ZEROED, not left alone.
///
/// The old branch returned without touching it, under a comment calling that
/// "fail safe rather than panic". It is the opposite of safe: this function's
/// entire job is to make the payload unreadable, and returning early leaves
/// the caller holding PLAINTEXT that it believes is enciphered — and then
/// ships it. Failing open in a cipher is the one direction that must never be
/// chosen for convenience.
///
/// The branch is, today, unreachable: all eleven call sites pass either a
/// `packet[HEADER_LEN..]` slice of a buffer already length-checked against
/// `PACKET_SIZE`, or a freshly allocated region of exactly that size. So this
/// costs nothing and exists for the day one of those invariants is edited —
/// which is precisely when a silent no-op would be a plaintext leak nobody
/// looks for. Destroying the block instead makes that day an obvious decrypt
/// failure rather than a quiet disclosure.
pub fn encrypt(key: &[u8; 32], block: &mut [u8]) {
    if block.len() < MIN_BLOCK {
        // Zeroed, not asserted. A `debug_assert!` here would turn a broken
        // caller invariant into a panic — and with `panic = "abort"` that is a
        // crash, i.e. trading a confidentiality failure for an availability
        // one on a path that runs for every packet. Destroying the block makes
        // the failure loud where it matters (the decrypt fails) without giving
        // an attacker who can reach this branch a way to kill the process.
        block.fill(0);
        return;
    }
    let rk = round_keys(key);
    let (l, r) = block.split_at_mut(L_LEN);
    // R ^= S(L ^ k1)
    stream_xor(&seed_from(l, &rk.k1), r);
    // L ^= H(k2, R)
    hash_into_l(&rk.k2, r, l);
    // R ^= S(L ^ k3)
    stream_xor(&seed_from(l, &rk.k3), r);
    // L ^= H(k4, R)
    hash_into_l(&rk.k4, r, l);
}

/// Decrypt `block` in place — the exact inverse of [`encrypt`] under the same
/// `key`. Same length precondition, and the same F-69 treatment: a short block
/// is zeroed, so a broken caller invariant surfaces as a failed decrypt rather
/// than as ciphertext handed on as if it were plaintext.
pub fn decrypt(key: &[u8; 32], block: &mut [u8]) {
    if block.len() < MIN_BLOCK {
        // Zeroed, not asserted. A `debug_assert!` here would turn a broken
        // caller invariant into a panic — and with `panic = "abort"` that is a
        // crash, i.e. trading a confidentiality failure for an availability
        // one on a path that runs for every packet. Destroying the block makes
        // the failure loud where it matters (the decrypt fails) without giving
        // an attacker who can reach this branch a way to kill the process.
        block.fill(0);
        return;
    }
    let rk = round_keys(key);
    let (l, r) = block.split_at_mut(L_LEN);
    // L ^= H(k4, R)
    hash_into_l(&rk.k4, r, l);
    // R ^= S(L ^ k3)
    stream_xor(&seed_from(l, &rk.k3), r);
    // L ^= H(k2, R)
    hash_into_l(&rk.k2, r, l);
    // R ^= S(L ^ k1)
    stream_xor(&seed_from(l, &rk.k1), r);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x0110_5E55_1105)
    }

    // The Gotham payload region size (PACKET_SIZE - HEADER_LEN).
    const REGION: usize = 2048 - 384;

    #[test]
    fn encrypt_then_decrypt_is_identity() {
        let mut r = rng();
        let mut key = [0u8; 32];
        r.fill_bytes(&mut key);
        let mut block = vec![0u8; REGION];
        r.fill_bytes(&mut block);
        let original = block.clone();

        encrypt(&key, &mut block);
        assert_ne!(block, original, "ciphertext must differ from plaintext");
        decrypt(&key, &mut block);
        assert_eq!(block, original, "decrypt(encrypt(x)) must equal x");
    }

    #[test]
    fn wrong_key_does_not_recover() {
        let mut r = rng();
        let mut key = [0u8; 32];
        r.fill_bytes(&mut key);
        let mut wrong = key;
        wrong[0] ^= 0x01;
        let mut block = vec![7u8; REGION];
        let original = block.clone();
        encrypt(&key, &mut block);
        decrypt(&wrong, &mut block);
        assert_ne!(block, original, "wrong key must not recover the plaintext");
    }

    #[test]
    fn one_bit_ciphertext_change_avalanches_whole_block() {
        // Non-malleability: a single-bit flip anywhere in the ciphertext must
        // scramble a large fraction of the recovered plaintext — so a relay
        // can't tag-and-track a packet by flipping a known bit.
        let mut r = rng();
        let mut key = [0u8; 32];
        r.fill_bytes(&mut key);
        let mut block = vec![0u8; REGION];
        r.fill_bytes(&mut block);

        let mut ct = block.clone();
        encrypt(&key, &mut ct);

        // Flip one bit deep in R and one at the very end, decrypt both.
        for flip_at in [L_LEN + 500, REGION - 1] {
            let mut tampered = ct.clone();
            tampered[flip_at] ^= 0x01;
            decrypt(&key, &mut tampered);
            let differing = tampered
                .iter()
                .zip(block.iter())
                .filter(|(a, b)| a != b)
                .count();
            // Expect the change to spread across most of the block, not stay local.
            assert!(
                differing > REGION / 2,
                "avalanche too weak: only {differing}/{REGION} bytes changed"
            );
        }
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let mut r = rng();
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        r.fill_bytes(&mut k1);
        r.fill_bytes(&mut k2);
        let plain = vec![0xABu8; REGION];
        let mut c1 = plain.clone();
        let mut c2 = plain.clone();
        encrypt(&k1, &mut c1);
        encrypt(&k2, &mut c2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn layered_onion_round_trips_in_hop_order() {
        // Mirror the mixnet: sender encrypts inner→outer, each hop decrypts.
        let mut r = rng();
        let keys: Vec<[u8; 32]> = (0..3)
            .map(|_| {
                let mut k = [0u8; 32];
                r.fill_bytes(&mut k);
                k
            })
            .collect();
        let mut block = vec![0u8; REGION];
        r.fill_bytes(&mut block);
        let original = block.clone();

        // Sender: encrypt with the LAST hop's key first (innermost).
        for k in keys.iter().rev() {
            encrypt(k, &mut block);
        }
        // Hops peel in order 0,1,2.
        for k in keys.iter() {
            decrypt(k, &mut block);
        }
        assert_eq!(block, original);
    }

    #[test]
    fn a_short_block_is_destroyed_not_passed_through() {
        // F-69 — this test used to assert the opposite: that a short block was
        // "left untouched". Untouched means the caller ships PLAINTEXT it
        // believes is enciphered, which is the one failure direction a cipher
        // must never take for convenience. The branch is unreachable today;
        // the point is what happens the day a caller's length invariant is
        // edited, and then a silent no-op is a disclosure nobody looks for.
        let key = [9u8; 32];
        let mut block = vec![1u8; MIN_BLOCK - 1];
        encrypt(&key, &mut block);
        assert!(
            block.iter().all(|b| *b == 0),
            "a block too short to encipher must not survive as plaintext"
        );

        let mut block = vec![7u8; MIN_BLOCK - 1];
        decrypt(&key, &mut block);
        assert!(block.iter().all(|b| *b == 0));
    }
}
