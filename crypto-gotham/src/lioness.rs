// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

const L_LEN: usize = 32;

pub const MIN_BLOCK: usize = L_LEN + 1;

struct RoundKeys {
    k1: [u8; 32],
    k2: [u8; 32],
    k3: [u8; 32],
    k4: [u8; 32],
}

fn round_keys(key: &[u8; 32]) -> RoundKeys {
    RoundKeys {
        k1: blake3::derive_key("gotham-lioness-v1 round-key 1", key),
        k2: blake3::derive_key("gotham-lioness-v1 round-key 2", key),
        k3: blake3::derive_key("gotham-lioness-v1 round-key 3", key),
        k4: blake3::derive_key("gotham-lioness-v1 round-key 4", key),
    }
}

fn stream_xor(seed: &[u8; 32], dst: &mut [u8]) {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(seed.into(), (&nonce).into());
    cipher.apply_keystream(dst);
}

fn hash_into_l(k: &[u8; 32], r: &[u8], l: &mut [u8]) {
    let digest = blake3::keyed_hash(k, r);
    let d = digest.as_bytes();
    for i in 0..L_LEN {
        l[i] ^= d[i];
    }
}

fn seed_from(l: &[u8], k: &[u8; 32]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for i in 0..L_LEN {
        seed[i] = l[i] ^ k[i];
    }
    seed
}

pub fn encrypt(key: &[u8; 32], block: &mut [u8]) {
    if block.len() < MIN_BLOCK {
        block.fill(0);
        return;
    }
    let rk = round_keys(key);
    let (l, r) = block.split_at_mut(L_LEN);
    stream_xor(&seed_from(l, &rk.k1), r);
    hash_into_l(&rk.k2, r, l);
    stream_xor(&seed_from(l, &rk.k3), r);
    hash_into_l(&rk.k4, r, l);
}

pub fn decrypt(key: &[u8; 32], block: &mut [u8]) {
    if block.len() < MIN_BLOCK {
        block.fill(0);
        return;
    }
    let rk = round_keys(key);
    let (l, r) = block.split_at_mut(L_LEN);
    hash_into_l(&rk.k4, r, l);
    stream_xor(&seed_from(l, &rk.k3), r);
    hash_into_l(&rk.k2, r, l);
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
        let mut r = rng();
        let mut key = [0u8; 32];
        r.fill_bytes(&mut key);
        let mut block = vec![0u8; REGION];
        r.fill_bytes(&mut block);

        let mut ct = block.clone();
        encrypt(&key, &mut ct);

        for flip_at in [L_LEN + 500, REGION - 1] {
            let mut tampered = ct.clone();
            tampered[flip_at] ^= 0x01;
            decrypt(&key, &mut tampered);
            let differing = tampered
                .iter()
                .zip(block.iter())
                .filter(|(a, b)| a != b)
                .count();
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

        for k in keys.iter().rev() {
            encrypt(k, &mut block);
        }
        for k in keys.iter() {
            decrypt(k, &mut block);
        }
        assert_eq!(block, original);
    }

    #[test]
    fn a_short_block_is_destroyed_not_passed_through() {
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
