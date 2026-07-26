// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Sphinx-style header — v0.1 slot-based design.
//!
//! ## Design choices (v0.1)
//!
//! **X25519-only per-hop key agreement.** The ML-KEM-768 hybrid (see
//! [`crate::hybrid`]) is reserved for the application-layer end-to-end
//! session. Per-hop ML-KEM would exceed the 2048 B packet budget.
//!
//! **Slot-based routing block.** β is organised as [`MAX_HOPS`] fixed
//! 64-byte slots; each hop's record sits at offset `hop_index * 64`. We
//! ship a 1-byte `hop_index` field in the header — it leaks the hop's
//! position in the chain (bounded by `MAX_HOPS = 5`). v0.2 will replace
//! this with the classical Sphinx shift-and-pad construction once we have
//! battle-tested the simpler version.
//!
//! **Per-slot independent ChaCha20 streams.** Each slot is XOR'd with the
//! relevant hop's ChaCha20(k_header) keystream. Unlinkability of slots
//! across hops follows from the per-packet ephemeral k_header — a relay
//! at hop *i* cannot decrypt any slot other than its own because the
//! per-hop key derivation is gated by the X25519 + re-blinding chain.
//!
//! **MAC chain.** Each γ_i is `Poly1305(k_mac_i, meta || α_i || β || trailer)`.
//! Hop *i*'s routing record carries `next_gamma = γ_{i+1}`, so after
//! unwrap the relay knows the value to place in the next header's γ.
//!
//! ## Wire format (384 B)
//!
//! ```text
//! offset  size  field
//!     0     1  version (= 1)
//!     1     1  mode (0=low-lat, 1=balanced, 2=paranoid)
//!     2     1  hop_count (n; 1 ≤ n ≤ MAX_HOPS)
//!     3     1  hop_index (i; 0 ≤ i < hop_count) — increments per hop
//!     4    32  α — X25519 ephemeral public key for this hop
//!    36   320  β — 5 × 64 B encrypted routing slots
//!   356    16  γ — Poly1305 MAC over (meta || α || β || trailer)
//!   372    12  trailer — random padding (covered by γ)
//! ```

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

// ─── Constants ──────────────────────────────────────────────────────────────

/// Total header length on the wire.
pub const HEADER_LEN: usize = 384;

/// Length of α (X25519 ephemeral public key).
pub const ALPHA_LEN: usize = 32;

/// Length of β (routing block).
pub const BETA_LEN: usize = 320;

/// Length of γ (Poly1305 MAC).
pub const GAMMA_LEN: usize = 16;

/// Length of the trailing random padding (covered by γ).
pub const TRAILER_LEN: usize = HEADER_LEN - 4 - ALPHA_LEN - BETA_LEN - GAMMA_LEN;
const _: () = assert!(TRAILER_LEN == 12);

/// Length of a single routing record / slot.
pub const RECORD_LEN: usize = 64;

/// Maximum number of hops a packet may traverse.
pub const MAX_HOPS: usize = BETA_LEN / RECORD_LEN;
const _: () = assert!(MAX_HOPS == 5);

/// Header version byte.
pub const VERSION: u8 = 1;

/// Anonymity modes (numeric values stable across versions).
pub mod mode {
    /// 3-hop, ~50-100 ms added latency.
    pub const LOW_LATENCY: u8 = 0;
    /// 4-hop, ~150 ms added latency. Default.
    pub const BALANCED: u8 = 1;
    /// 5-hop, ~300 ms added latency.
    pub const PARANOID: u8 = 2;
}

const SUBKEY_SALT: &[u8] = b"gotham-hop-v1";
const SUBKEY_INFO: &[u8] = b"gotham:subkeys";

/// Flag bits in [`RoutingRecord::flag`].
pub mod flag {
    /// This hop is the packet's final destination — no further forwarding.
    pub const IS_LAST_HOP: u8 = 0b0000_0001;
    /// Hand the unwrapped payload to the local delivery handler.
    pub const DELIVER_LOCAL: u8 = 0b0000_0010;
    /// The next hop is reachable only via a rendezvous (RFC B3): this hop must
    /// deliver to the relay identified by `next_node_id` over its live
    /// rendezvous tunnel instead of dialing `next_ipv4:next_port` (which is a
    /// zero sentinel for such a record). See `docs/gotham/design/rfc-b3-*`.
    pub const VIA_RENDEZVOUS: u8 = 0b0000_0100;
}

// ─── Routing record ─────────────────────────────────────────────────────────

/// A single hop's routing instructions, 64 B encoded.
///
/// ```text
/// offset  size  field
///     0     4  next_ipv4
///     4     2  next_port  (big-endian)
///     6    32  next_node_id  (relay identity fingerprint)
///    38    16  next_gamma  (the γ the next hop's header will carry)
///    54     4  delay_micros  (big-endian)
///    58     1  flag
///    59     5  _padding (must be zero)
/// ```
#[derive(Clone, Copy, Debug, Zeroize)]
pub struct RoutingRecord {
    /// Next hop's IPv4 address octets.
    pub next_ipv4: [u8; 4],
    /// Next hop's UDP port.
    pub next_port: u16,
    /// Next hop's relay identity fingerprint (X25519 pubkey in v0.1).
    pub next_node_id: [u8; 32],
    /// γ to install in the next header (the next hop's MAC).
    pub next_gamma: [u8; GAMMA_LEN],
    /// Mix delay this hop should sleep before forwarding (microseconds).
    pub delay_micros: u32,
    /// Bitfield, see [`flag`].
    pub flag: u8,
    /// MUST be zero; reserved for future use.
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
    /// Pack to wire bytes (64 B).
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

    /// Parse wire bytes back to a record. Total-function; semantic
    /// validation (e.g. zero `_padding`) is the caller's responsibility.
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

    /// True iff this hop is the packet's final destination.
    #[must_use]
    pub fn is_last_hop(&self) -> bool {
        self.flag & flag::IS_LAST_HOP != 0
    }

    /// True iff the next hop must be reached over a rendezvous tunnel (RFC B3)
    /// keyed by [`RoutingRecord::next_node_id`] rather than by dialing
    /// `next_ipv4:next_port` (which is a zero sentinel for such a record).
    #[must_use]
    pub fn is_via_rendezvous(&self) -> bool {
        self.flag & flag::VIA_RENDEZVOUS != 0
    }
}

// ─── Header ─────────────────────────────────────────────────────────────────

/// v0.1 slot-based Sphinx header. See module docs for the wire layout.
#[derive(Clone, Debug)]
pub struct Header {
    /// Always equals [`VERSION`].
    pub version: u8,
    /// Anonymity mode (see [`mode`]).
    pub mode: u8,
    /// Total hop count `n` (`1 ≤ n ≤ MAX_HOPS`).
    pub hop_count: u8,
    /// Position of THIS hop in the chain (`0 ≤ hop_index < hop_count`).
    /// **v0.1 leaks this 1 B** — fixed by `header_v2`.
    pub hop_index: u8,
    /// α — X25519 ephemeral pubkey for this hop.
    pub alpha: [u8; ALPHA_LEN],
    /// β — encrypted routing slots, one per hop.
    pub beta: [u8; BETA_LEN],
    /// γ — Poly1305 MAC over (meta || α || β\[slot_i\] || trailer).
    pub gamma: [u8; GAMMA_LEN],
    /// Random padding covered by γ.
    pub trailer: [u8; TRAILER_LEN],
}

impl Header {
    /// Pack header to its on-wire 384-byte representation.
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

    /// Parse on-wire bytes into a `Header`. Rejects bad version /
    /// out-of-range hop counters.
    pub fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        let version = bytes[0];
        if version != VERSION {
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

    /// MAC input for hop `slot_idx`.
    ///
    /// Authenticates: `version || mode || hop_count || slot_idx || α || β[slot_idx] || trailer`.
    /// Only the relevant slot of β is included — this allows each γ_i to
    /// remain stable when other slots are subsequently updated by the
    /// sender's wrap loop. Cross-slot integrity is provided per-hop: a
    /// malicious upstream relay rewriting slot[j] (j > i) cannot forge
    /// γ_j, so the downstream hop drops the packet.
    fn mac_input_for_slot(&self, slot_idx: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + ALPHA_LEN + RECORD_LEN + TRAILER_LEN);
        v.push(self.version);
        v.push(self.mode);
        v.push(self.hop_count);
        v.push(slot_idx as u8);
        v.extend_from_slice(&self.alpha);
        let start = slot_idx * RECORD_LEN;
        v.extend_from_slice(&self.beta[start..start + RECORD_LEN]);
        v.extend_from_slice(&self.trailer);
        v
    }
}

// ─── Per-hop sub-keys (X25519-only) ────────────────────────────────────────

/// Per-hop derived secrets used by the Sphinx unwrap pipeline.
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct HopSubKeys {
    /// Poly1305 MAC key (γ verification).
    pub k_mac: [u8; 32],
    /// ChaCha20 key for the slot's encryption.
    pub k_header: [u8; 32],
    /// Key reserved for v0.2 per-hop payload AEAD.
    pub k_payload: [u8; 32],
    /// Scalar used to re-blind α to the next hop.
    pub k_blind: [u8; 32],
}

/// Derive per-hop sub-keys from a 32-byte X25519 shared secret via HKDF-SHA256.
pub fn derive_hop_subkeys(shared_x: &[u8; 32]) -> Result<HopSubKeys> {
    // M-1 (SECURITY-AUDIT): reject the all-zero X25519 shared secret, which is
    // produced exactly when the input point is low-order (RFC 7748 §6.1).
    // Without this, a malicious upstream relay could substitute α with a
    // small-order point so that every downstream hop derives the *same*
    // predictable shared secret — collapsing the mixnet's per-hop key
    // separation. The fold is constant-time (always scans all 32 bytes).
    if shared_x.iter().fold(0u8, |acc, &b| acc | b) == 0 {
        return Err(Error::Crypto(
            "low-order point: all-zero X25519 shared secret",
        ));
    }
    let hk = hkdf::Hkdf::<Sha256>::new(Some(SUBKEY_SALT), shared_x);
    let mut buf = [0u8; 32 * 4];
    hk.expand(SUBKEY_INFO, &mut buf)
        .map_err(|_| Error::Crypto("HKDF expand hop sub-keys"))?;
    let mut sub = HopSubKeys {
        k_mac: [0; 32],
        k_header: [0; 32],
        k_payload: [0; 32],
        k_blind: [0; 32],
    };
    sub.k_mac.copy_from_slice(&buf[0..32]);
    sub.k_header.copy_from_slice(&buf[32..64]);
    sub.k_payload.copy_from_slice(&buf[64..96]);
    sub.k_blind.copy_from_slice(&buf[96..128]);
    Ok(sub)
}

// ─── Crypto helpers ─────────────────────────────────────────────────────────

/// ChaCha20 keystream of `len` bytes using a fixed all-zero nonce.
/// Safe because each `k_header` is a per-packet ephemeral and never reused.
fn chacha20_stream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    let mut buf = vec![0u8; len];
    cipher.apply_keystream(&mut buf);
    buf
}

// The per-hop payload onion now uses the LIONESS wide-block PRP — see
// [`crate::lioness`]. The sender applies one LIONESS layer per hop
// (inner→outer), each relay peels exactly its own with `k_payload`, and after
// the last hop the original bytes remain. Unlike the earlier stream-cipher XOR,
// LIONESS is non-malleable: a relay flipping any bit scrambles the whole block,
// so it cannot tag-and-track a packet across two points of the path.

fn poly1305_tag(key: &[u8; 32], data: &[u8]) -> [u8; GAMMA_LEN] {
    let mac = Poly1305::new(key.into()).compute_unpadded(data);
    let mut out = [0u8; GAMMA_LEN];
    out.copy_from_slice(mac.as_slice());
    out
}

fn blind_alpha(alpha: &[u8; ALPHA_LEN], k_blind: &[u8; 32]) -> [u8; ALPHA_LEN] {
    x25519(*k_blind, *alpha)
}

// ─── Sender: derive_route_secrets ───────────────────────────────────────────

/// Derive the chain of per-hop (α, sub-keys) given recipient public keys.
///
/// Uses a single ephemeral X25519 scalar at the sender; for each hop, the
/// scalar is blinded by `k_blind_{i-1}` derived from the previous hop's
/// shared secret, producing the chain of α values.
///
/// The ephemeral master scalar is zeroized before return — forward secrecy
/// is preserved.
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
        // Reject low-order / small-subgroup relay keys BEFORE using them.
        // `pk_bytes` comes straight from a directory descriptor, so it is
        // attacker-supplied under threat models (2) a malicious relay and (3) a
        // malicious authority. `Mul<Scalar> for MontgomeryPoint` runs the ladder
        // over the scalar's canonical value WITHOUT clamping, so `s_curr` is not
        // forced to a multiple of 8: a low-order point would yield a shared
        // secret from a tiny set, making that hop's k_header / k_payload /
        // k_blind publicly computable — i.e. that layer of the onion is
        // readable by anyone, and the blinding chain is pinned. `sealed.rs`
        // already guards its DH this way (`was_contributory`); the Sphinx path
        // must not be weaker. The all-zero-secret check in `derive_hop_subkeys`
        // catches only the identity, not the rest of the small subgroup.
        //
        // `MontgomeryPoint` exposes no `is_small_order`, so clear the cofactor
        // by hand: [8]P is the identity exactly for the points of order
        // dividing 8, which is precisely the small subgroup. The identity in
        // Montgomery form encodes as all-zero.
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

// ─── Sender: wrap_header (slot-based) ───────────────────────────────────────

/// Sender-side header construction.
///
/// β layout: slot `i` (= bytes `i*64..(i+1)*64`) carries the encrypted
/// routing record for hop `i`. Unused slots (`i ≥ n`) are filled with
/// random bytes from the supplied RNG — indistinguishable from the
/// encrypted slots at the wire level.
///
/// Each hop's γ is computed inside-out so the predecessor's record can
/// carry it in its `next_gamma` field.
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

    // ── 1. Initialize β with random bytes for ALL slots ──────────────────
    //      (real records overwrite slots 0..n; slots n..MAX_HOPS stay random)
    let mut beta = [0u8; BETA_LEN];
    rng.fill_bytes(&mut beta);

    // ── 2. Encrypt slot[i] for each hop, computing γ chain inside-out ───
    //      (γ for the last hop first, then propagate into next_gamma fields)
    let mut next_gamma = [0u8; GAMMA_LEN];

    for i in (0..n).rev() {
        let mut record_i = records[i];
        // For the last hop, next_gamma is irrelevant (no next hop) but we
        // still set it to zero for determinism.
        record_i.next_gamma = next_gamma;

        let record_bytes = record_i.encode();
        let stream = chacha20_stream(&sub_keys[i].k_header, RECORD_LEN);
        let offset = i * RECORD_LEN;
        for j in 0..RECORD_LEN {
            beta[offset + j] = record_bytes[j] ^ stream[j];
        }

        // Compute γ_i over (meta || α_i || β[slot_i] || trailer).
        // β[slot_i] is the freshly-encrypted slot we just wrote. Subsequent
        // iterations modifying other slots will NOT invalidate this γ.
        let candidate = Header {
            version: VERSION,
            mode,
            hop_count: n as u8,
            hop_index: i as u8,
            alpha: alphas[i],
            beta,
            gamma: [0; GAMMA_LEN], // not part of MAC input
            trailer,
        };
        next_gamma = poly1305_tag(&sub_keys[i].k_mac, &candidate.mac_input_for_slot(i));
    }

    // After the loop, next_gamma holds γ_0 — the MAC for the first hop.
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

// ─── Hop: unwrap_header ─────────────────────────────────────────────────────

/// What a hop returns after [`unwrap_header`].
pub struct UnwrapOutcome {
    /// The routing record this hop just decrypted from its slot.
    pub record: RoutingRecord,
    /// The header to forward to the next hop (re-blinded α, advanced
    /// `hop_index`, γ taken from `record.next_gamma`).
    pub next_header: Header,
}

/// Per-hop unwrap:
/// 1. Verify γ.
/// 2. Decrypt slot[hop_index] to recover the routing record.
/// 3. Re-blind α for the next hop.
/// 4. Increment hop_index, plug `record.next_gamma` into the next header's γ.
pub fn unwrap_header(header: &Header, sub_keys: &HopSubKeys) -> Result<UnwrapOutcome> {
    let i = header.hop_index as usize;
    let n = header.hop_count as usize;
    if i >= n || n > MAX_HOPS {
        return Err(Error::Malformed("hop_index/hop_count out of range"));
    }

    // 1. Verify γ over (meta || α || β[slot_i] || trailer)
    let expected = poly1305_tag(&sub_keys.k_mac, &header.mac_input_for_slot(i));
    if !bool::from(expected.ct_eq(&header.gamma)) {
        return Err(Error::BadMac);
    }

    // 2. Decrypt this hop's slot
    let offset = i * RECORD_LEN;
    let stream = chacha20_stream(&sub_keys.k_header, RECORD_LEN);
    let mut record_bytes = [0u8; RECORD_LEN];
    for j in 0..RECORD_LEN {
        record_bytes[j] = header.beta[offset + j] ^ stream[j];
    }
    let record = RoutingRecord::decode(&record_bytes);

    // 3. Build next header
    let next_alpha = blind_alpha(&header.alpha, &sub_keys.k_blind);
    let next_header = Header {
        version: header.version,
        mode: header.mode,
        hop_count: header.hop_count,
        hop_index: header.hop_index.saturating_add(1),
        alpha: next_alpha,
        beta: header.beta, // β unchanged across hops in v0.1 slot-based design
        gamma: record.next_gamma,
        trailer: header.trailer,
    };

    Ok(UnwrapOutcome {
        record,
        next_header,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
        bytes[2] = 0; // hop_count = 0 illegal
        assert!(matches!(Header::decode(&bytes), Err(Error::Malformed(_))));
        bytes[2] = (MAX_HOPS + 1) as u8;
        assert!(matches!(Header::decode(&bytes), Err(Error::Malformed(_))));
    }

    #[test]
    fn derive_hop_subkeys_rejects_low_order_point() {
        // M-1: the all-zero shared secret (produced by a low-order input point)
        // must be rejected, so a substituted small-order α cannot force every
        // downstream hop onto the same predictable key.
        assert!(matches!(
            derive_hop_subkeys(&[0u8; 32]),
            Err(Error::Crypto(_))
        ));

        // A DH against the all-zero (low-order) Montgomery point yields the
        // all-zero secret — exactly the relay's `x25519(sk, header.alpha)` path.
        let shared = x25519([7u8; 32], [0u8; 32]);
        assert_eq!(shared, [0u8; 32], "sanity: low-order point ⇒ all-zero DH");
        assert!(matches!(derive_hop_subkeys(&shared), Err(Error::Crypto(_))));

        // A normal non-zero shared secret still derives fine.
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
        // Tampering with the slot the hop will read breaks that hop's γ.
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
        // Flip a bit in slot 0 (hop 0's slot).
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
    fn cross_slot_tamper_caught_downstream() {
        // Tampering with slot 2 doesn't break hop 0's MAC (by design — γ_i
        // covers only slot[i]), but DOES break hop 2's MAC.
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
        // Flip a bit in slot 2.
        header.beta[2 * RECORD_LEN + 5] ^= 0x40;

        // Hop 0 succeeds (its slot is slot 0, untampered).
        let (sk0, _) = &relays[0];
        let shared0 = sk0.diffie_hellman(&X25519PublicKey::from(header.alpha));
        let hop_sub0 = derive_hop_subkeys(shared0.as_bytes()).unwrap();
        let outcome0 = unwrap_header(&header, &hop_sub0).expect("hop 0 should succeed");
        // Forward to hop 1.
        let header1 = outcome0.next_header;
        // Hop 1 also succeeds (its slot is slot 1, untampered).
        let (sk1, _) = &relays[1];
        let shared1 = sk1.diffie_hellman(&X25519PublicKey::from(header1.alpha));
        let hop_sub1 = derive_hop_subkeys(shared1.as_bytes()).unwrap();
        let outcome1 = unwrap_header(&header1, &hop_sub1).expect("hop 1 should succeed");
        // Hop 2 fails (its slot 2 is tampered).
        let header2 = outcome1.next_header;
        let (sk2, _) = &relays[2];
        let shared2 = sk2.diffie_hellman(&X25519PublicKey::from(header2.alpha));
        let hop_sub2 = derive_hop_subkeys(shared2.as_bytes()).unwrap();
        assert!(matches!(
            unwrap_header(&header2, &hop_sub2),
            Err(Error::BadMac)
        ));
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
        header.hop_index = 1; // attacker tries to read a different slot
        let (sk, _) = &relays[0];
        let shared = sk.diffie_hellman(&X25519PublicKey::from(header.alpha));
        let hop_sub = derive_hop_subkeys(shared.as_bytes()).unwrap();
        // MAC includes hop_index, so this must fail.
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

    /// Relay KEM keys come from the signed directory, so they are
    /// attacker-supplied under a malicious relay (2) or a malicious authority
    /// (3). A small-subgroup point collapses that hop's shared secret to one of
    /// a handful of values, making its k_header / k_payload / k_blind publicly
    /// computable — that onion layer becomes readable and the blinding chain
    /// pinned. Every low-order encoding must be refused before use.
    #[test]
    fn a_low_order_relay_key_is_refused_not_silently_used() {
        // The complete set of curve25519 Montgomery encodings of order
        // dividing 8 (identity, order-2, order-4, order-8, and the two
        // non-canonical p / p+1 forms).
        const LOW_ORDER: [[u8; 32]; 7] = [
            // 0 — the identity (order 1 / 4 depending on convention)
            [0u8; 32],
            // 1 — order 4
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            // the two order-8 points
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
            // Put the hostile key in each hop position in turn — the check must
            // not be limited to the first (or last) hop.
            for pos in 0..3 {
                let mut pks: Vec<[u8; 32]> = honest.iter().map(|(_, pk)| *pk).collect();
                pks[pos] = *bad;
                assert!(
                    derive_route_secrets(&mut r, &pks).is_err(),
                    "low-order key #{i} at hop {pos} must be refused"
                );
            }
        }

        // Sanity: the guard is not rejecting honest keys.
        let pks: Vec<[u8; 32]> = honest.iter().map(|(_, pk)| *pk).collect();
        assert!(derive_route_secrets(&mut r, &pks).is_ok());
    }
}
