// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Relay self-enrollment + authority-side registry — the Level-1 automated
//! directory.
//!
//! In v0.1 the operator hand-built a signed directory. This module replaces
//! that with a self-forming roster:
//!
//! 1. A relay POSTs a [`RelayEnrollment`] (its X25519 routing/KEM key + the
//!    address it is reachable on + the tier it serves) to the directory
//!    authority, and re-POSTs it as a heartbeat every few minutes.
//! 2. The authority keeps live enrollments in a [`Registry`], drops any that
//!    stop heartbeating ([`Registry::prune_at`]), and on demand bakes the live
//!    set into an authority-signed [`SignedDirectory`]
//!    ([`Registry::build_signed_at`]) — exactly the artifact the app already
//!    verifies and consumes.
//!
//! ## Authentication (honest scope)
//!
//! This module enforces *shape* + *anti-replay* (monotonic `seq` per key).
//! It deliberately does NOT prove possession of the X25519 secret — that is
//! the caller's job:
//!
//! - **Closed test (today):** the HTTP authority gates `/enroll` behind an
//!   operator-issued bearer token + per-IP rate limit, so only trusted
//!   volunteers can enroll. A bogus entry that does not hold the secret simply
//!   cannot decrypt traffic routed to it (an availability nuisance, not an
//!   anonymity break).
//! - **Hardening (next):** a Noise-XK liveness probe from the authority to the
//!   advertised address proves both reachability *and* possession of the
//!   X25519 secret before the relay is listed.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::directory::{
    apply_diversity_caps, DirectoryDoc, RelayDescriptor, RelayTier, SignedDirectory,
};
use crate::error::{Error, Result};

/// Wire-format version for [`RelayEnrollment`]. Bump on any breaking change.
pub const ENROLL_VERSION: u8 = 1;

/// How long an enrollment stays live without a fresh heartbeat before the
/// authority evicts it (seconds). A relay re-announces well within this.
pub const ENROLL_STALE_AFTER_SECS: u64 = 1800; // 30 min

/// Bucket width (seconds) for the k-of-n admission **epoch** a relay proposes on
/// enrollment (1 day). Rationale: for several independent authorities to sign
/// the SAME `(identity, epoch, operator)` message — the only way their
/// attestations combine into one [`crypto_gotham_directory::AdmissionCert`] — the
/// relay must send an IDENTICAL epoch to each. Bucketing `now` to the day makes
/// that value stable across the relay's own ~60 s heartbeats (so the signed
/// message doesn't churn every beat) while still advancing daily, which bounds
/// admission-revocation latency (authorities revoke by declining to re-sign a
/// newer epoch). The relay picks ONE bucketed value and sends it verbatim to all
/// authorities; each authority only validates the value is recent (see the
/// authority binary) before signing it, so a day-boundary race is impossible —
/// the authorities sign the relay's number, they don't recompute it.
pub const ATTEST_EPOCH_BUCKET_SECS: u64 = 86_400;

/// The current admission epoch a relay should propose at `now`: `now` floored to
/// the [`ATTEST_EPOCH_BUCKET_SECS`] bucket. Stable within a day, monotonic across
/// days.
#[must_use]
pub fn current_attest_epoch(now: u64) -> u64 {
    (now / ATTEST_EPOCH_BUCKET_SECS) * ATTEST_EPOCH_BUCKET_SECS
}

/// Current Unix-seconds timestamp, or `0` if the clock is before the epoch.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A relay's self-submitted claim to the directory authority.
///
/// The same struct is used for the first enrollment and for every subsequent
/// heartbeat — only `seq` changes (it must strictly increase per key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayEnrollment {
    /// Must equal [`ENROLL_VERSION`].
    pub version: u8,
    /// X25519 public key, hex-encoded (64 chars / 32 bytes). This is both the
    /// relay's routing identity (`next_node_id`) and its Sphinx KEM key.
    pub kem_pubkey_hex: String,
    /// Reachable socket address, e.g. `"203.0.113.7:443"`.
    pub addr: String,
    /// Tier the operator is willing to serve.
    pub tier: RelayTier,
    /// Optional ISO 3166-1 alpha-2 country code (`"FR"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Optional free-form operator nickname (transparency only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Monotonic heartbeat counter — bumped on every re-announce.
    pub seq: u64,
    /// RFC B3: when set, this relay is behind CGNAT and reachable only via the
    /// rendezvous relay whose X25519 key (`kem_pubkey_hex`) is this hex string;
    /// `addr` is then empty and the authority proves liveness by ASKING R,
    /// not by dialing back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,
    /// RFC B3: this directly-reachable relay is willing to serve as a rendezvous
    /// point for CGNAT relays.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rendezvous_capable: bool,
    /// RFC B3 §4: hex DH-MAC **proof of possession** for a rendezvous-hosted
    /// (CGNAT) relay, which cannot be dialed back. It is
    /// [`pop_tag`](Self::pop_tag)`(DH(relay_sk, authority_pop_pk), kem, seq)` —
    /// only the holder of `relay_sk` can produce it, and it binds possession to
    /// this `kem_pubkey_hex` + `seq`, so the authority proves possession WITHOUT
    /// trusting the rendezvous relay. Required for rendezvous enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pop_proof: Option<String>,
    /// k-of-n decentralised admission (the multi-authority trust anchor): the
    /// epoch this relay proposes for its admission attestation, IDENTICAL across
    /// every authority it enrolls with (see [`current_attest_epoch`]). Each
    /// authority signs `(kem_pubkey_hex, attest_epoch, operator)` and serves the
    /// resulting attestation; a consuming app pins the authority set and admits
    /// the relay only once `k` distinct authorities have attested this exact
    /// tuple. `None` on legacy single-authority enrollments (no attestation is
    /// issued — the relay is then only admissible via the blanket-signed
    /// directory, the transition path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest_epoch: Option<u64>,
    /// Whether this relay hosts a store-and-forward mailbox (`--mailbox`). When
    /// true the authority advertises it as `mailbox` in the relay's directory
    /// descriptor so clients can pick it for offline/NAT'd delivery. Additive;
    /// absent (false) for relays that don't host one. Mirrors how
    /// `rendezvous_capable` is self-declared through enrollment.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mailbox: bool,
}

impl RelayEnrollment {
    /// Build a fresh enrollment at `seq` (caller starts at 1 and bumps).
    pub fn new(
        kem_pubkey_hex: String,
        addr: String,
        tier: RelayTier,
        country: Option<String>,
        operator: Option<String>,
        seq: u64,
    ) -> Self {
        Self {
            version: ENROLL_VERSION,
            kem_pubkey_hex,
            addr,
            tier,
            country,
            operator,
            seq,
            rendezvous: None,
            rendezvous_capable: false,
            pop_proof: None,
            attest_epoch: None,
            mailbox: false,
        }
    }

    /// Advertise that this relay hosts a store-and-forward mailbox (`--mailbox`),
    /// so the authority sets the `mailbox` flag on its directory descriptor.
    #[must_use]
    pub fn with_mailbox(mut self, yes: bool) -> Self {
        self.mailbox = yes;
        self
    }

    /// Propose an admission `epoch` for k-of-n decentralised attestation. The
    /// caller MUST use the SAME value (see [`current_attest_epoch`]) for every
    /// authority it enrolls with, so their attestations sign an identical
    /// message and combine into one quorum certificate.
    #[must_use]
    pub fn with_attest_epoch(mut self, epoch: u64) -> Self {
        self.attest_epoch = Some(epoch);
        self
    }

    /// RFC B3 §4 DH-MAC possession tag. `shared` is the X25519 secret
    /// `DH(relay_sk, authority_pop_pk)` (equivalently `DH(authority_pop_sk,
    /// relay_kem_pk)` on the authority side). The tag binds possession of the
    /// relay key to `kem_pubkey` + `seq`: only a holder of `relay_sk` can compute
    /// `shared`, and a captured tag cannot be replayed for a different key or a
    /// higher `seq`. Independent of any rendezvous relay.
    #[must_use]
    pub fn pop_tag(shared: &[u8; 32], kem_pubkey: &[u8; 32], seq: u64) -> [u8; 32] {
        let k = blake3::derive_key("gotham-rendezvous-pop-v1", shared);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(kem_pubkey);
        h.update(&seq.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Canonical hash of the WHOLE enrollment except `pop_proof` itself — the
    /// transcript the v2 possession proof commits to.
    ///
    /// Every field is length-prefixed and `Option`s carry an explicit
    /// present/absent tag, so no two distinct enrollments can produce the same
    /// digest by shifting bytes between adjacent fields.
    #[must_use]
    pub fn binding_hash(&self) -> [u8; 32] {
        fn put_str(h: &mut blake3::Hasher, s: &str) {
            h.update(&(s.len() as u32).to_le_bytes());
            h.update(s.as_bytes());
        }
        fn put_opt_str(h: &mut blake3::Hasher, s: Option<&String>) {
            match s {
                Some(v) => {
                    h.update(&[1u8]);
                    put_str(h, v);
                }
                None => {
                    h.update(&[0u8]);
                }
            }
        }
        let mut h = blake3::Hasher::new();
        h.update(b"gotham-enroll-binding-v1");
        h.update(&[self.version]);
        put_str(&mut h, &self.kem_pubkey_hex);
        put_str(&mut h, &self.addr);
        h.update(&[self.tier as u8]);
        put_opt_str(&mut h, self.country.as_ref());
        put_opt_str(&mut h, self.operator.as_ref());
        h.update(&self.seq.to_le_bytes());
        put_opt_str(&mut h, self.rendezvous.as_ref());
        h.update(&[u8::from(self.rendezvous_capable)]);
        match self.attest_epoch {
            Some(e) => {
                h.update(&[1u8]);
                h.update(&e.to_le_bytes());
            }
            None => {
                h.update(&[0u8]);
            }
        }
        h.update(&[u8::from(self.mailbox)]);
        *h.finalize().as_bytes()
    }

    /// v2 possession tag: binds `shared` to the ENTIRE enrollment transcript.
    ///
    /// [`pop_tag`](Self::pop_tag) covers only `(kem_pubkey, seq)`, which leaves
    /// `addr`, `tier`, `operator`, `country`, `mailbox` and
    /// `rendezvous_capable` unauthenticated. Enrollments are POSTed as JSON over
    /// plain HTTP (the shipped installers default to `http://<authority>:8443`),
    /// so an on-path attacker could rewrite those fields in flight, leave
    /// `kem_pubkey_hex` / `seq` / `pop_proof` intact, and have the authority
    /// accept and then Ed25519-SIGN the tampered descriptor — laundering the
    /// tampering into a document every client trusts. Repointing `addr` hands
    /// the attacker an on-path position at the entry tier; rewriting `operator`
    /// or `country` defeats the path-diversity guards; flipping `mailbox`
    /// silently blackholes offline delivery.
    ///
    /// The liveness dial-back does not close this: it only proves *something at
    /// `addr` speaks Noise-XK as this key*, which a plain UDP forwarder in front
    /// of the real relay satisfies, and it says nothing at all about the other
    /// fields.
    ///
    /// A distinct `derive_key` context from v1 means a captured v1 tag can never
    /// be replayed as a v2 tag.
    #[must_use]
    pub fn pop_tag_v2(shared: &[u8; 32], binding: &[u8; 32]) -> [u8; 32] {
        let k = blake3::derive_key("gotham-enroll-pop-v2", shared);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(binding);
        *h.finalize().as_bytes()
    }

    /// Verify a [`pop_tag_v2`](Self::pop_tag_v2) transcript-bound proof against
    /// the authority's side of the DH. Constant-time; `false` if the proof is
    /// absent, malformed, or does not match this exact enrollment.
    #[must_use]
    pub fn verify_pop_v2(&self, shared: &[u8; 32]) -> bool {
        let Some(hexstr) = &self.pop_proof else {
            return false;
        };
        let Some(provided) = hex::decode(hexstr)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        else {
            return false;
        };
        let expected = Self::pop_tag_v2(shared, &self.binding_hash());
        let diff = provided
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }

    /// Attach a hex-encoded [`pop_tag`](Self::pop_tag) possession proof.
    #[must_use]
    pub fn with_pop_proof(mut self, tag_hex: String) -> Self {
        self.pop_proof = Some(tag_hex);
        self
    }

    /// Verify an RFC B3 §4 possession proof: recompute the DH-MAC from `shared`
    /// (the authority's side `DH(authority_pop_sk, relay_kem_pk)`) and compare it
    /// to `self.pop_proof` in constant time. Returns `false` if the proof is
    /// absent, malformed, or does not match.
    #[must_use]
    pub fn verify_pop(&self, shared: &[u8; 32]) -> bool {
        let Some(hexstr) = &self.pop_proof else {
            return false;
        };
        let Some(kem) = hex::decode(&self.kem_pubkey_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        else {
            return false;
        };
        let Some(provided) = hex::decode(hexstr)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
        else {
            return false;
        };
        let expected = Self::pop_tag(shared, &kem, self.seq);
        // Constant-time compare.
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= provided[i] ^ expected[i];
        }
        diff == 0
    }

    /// Mark this enrollment as CGNAT-hosted via rendezvous relay `r_kem_hex`
    /// (RFC B3). The relay's `addr` should be empty.
    #[must_use]
    pub fn with_rendezvous(mut self, r_kem_hex: String) -> Self {
        self.rendezvous = Some(r_kem_hex);
        self
    }

    /// Mark this directly-reachable relay as willing to host CGNAT relays.
    #[must_use]
    pub fn with_rendezvous_capable(mut self, yes: bool) -> Self {
        self.rendezvous_capable = yes;
        self
    }

    /// Validate the shape: version, a 32-byte hex key, and (for a directly-
    /// reachable relay) a parseable, routable socket address. Does NOT prove key
    /// possession (see module docs). Returns the parsed `SocketAddr` for a
    /// direct relay, or `None` for an RFC B3 rendezvous-hosted relay (which has
    /// no dialable address — the authority proves it live by asking its
    /// rendezvous relay instead of dialing back).
    pub fn validate(&self) -> Result<Option<std::net::SocketAddr>> {
        if self.version != ENROLL_VERSION {
            return Err(Error::Directory("unsupported enrollment version"));
        }
        let key = hex::decode(&self.kem_pubkey_hex)
            .map_err(|_| Error::Directory("bad kem_pubkey hex"))?;
        if key.len() != 32 {
            return Err(Error::Directory("kem_pubkey wrong length"));
        }
        // RFC B3: a rendezvous-hosted relay carries a valid rendezvous key and no
        // dialable address. It cannot ALSO be rendezvous_capable (a hosted relay
        // cannot host). The addr field is ignored (should be empty).
        if let Some(r) = &self.rendezvous {
            if self.rendezvous_capable {
                return Err(Error::Directory(
                    "a rendezvous-hosted relay cannot also be rendezvous_capable",
                ));
            }
            let rb = hex::decode(r).map_err(|_| Error::Directory("bad rendezvous hex"))?;
            if rb.len() != 32 {
                return Err(Error::Directory("rendezvous key wrong length"));
            }
            return Ok(None);
        }
        let sa: std::net::SocketAddr = self
            .addr
            .parse()
            .map_err(|_| Error::Directory("addr is not a numeric socket address"))?;
        if sa.ip().is_unspecified() {
            return Err(Error::Directory("addr must not be the unspecified address"));
        }
        // Reject loopback: a loopback relay is unreachable by others AND defeats
        // the path selector's /16 diversity check (which relaxes for 127.0.0.0/8
        // so local tests can share a host). Rejecting it at ingest keeps that
        // relaxation from ever applying to a real signed directory, so one host
        // can't smuggle two loopback relays onto both ends of a flow.
        if sa.ip().is_loopback() {
            return Err(Error::Directory("addr must not be a loopback address"));
        }
        if sa.port() == 0 {
            return Err(Error::Directory("addr port must not be zero"));
        }
        Ok(Some(sa))
    }

    /// Project into a [`RelayDescriptor`]. The X25519 key fills both the
    /// identity and KEM slots (the relay has a single key), matching the
    /// `sign-directory` convention.
    fn to_descriptor(&self) -> RelayDescriptor {
        RelayDescriptor {
            id_pubkey_hex: self.kem_pubkey_hex.clone(),
            kem_pubkey_hex: self.kem_pubkey_hex.clone(),
            addr: self.addr.clone(),
            tier: self.tier,
            country: self.country.clone(),
            asn: None,
            operator: self.operator.clone(),
            uptime_pct: None,
            // Self-declared via enrollment (`--mailbox`), like rendezvous_capable,
            // so a mailbox host is discoverable in the auto-built directory.
            mailbox: self.mailbox,
            // RFC B3: carry the reverse-transport reachability through to the
            // routable descriptor so the path selector treats a CGNAT relay as
            // reachable-via-R (and inherits R's diversity position).
            rendezvous: self.rendezvous.clone(),
            rendezvous_capable: self.rendezvous_capable,
        }
    }
}

/// Derive the authority's stable X25519 PoP secret from its Ed25519 signing-key
/// seed (RFC B3 §4). Deterministic, so the PoP public key is fixed across
/// authority restarts and CGNAT relays can pin it as `--authority-pop-key`.
#[must_use]
pub fn derive_authority_pop_sk(ed25519_seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("gotham-authority-pop-x25519-v1", ed25519_seed)
}

/// One live relay as tracked by the authority.
#[derive(Debug, Clone)]
struct RegEntry {
    enrollment: RelayEnrollment,
    /// Unix-seconds of the most recent accepted heartbeat.
    last_seen: u64,
}

/// In-memory roster of live relays held by the directory authority.
///
/// Keyed by `kem_pubkey_hex`. Enforces monotonic `seq` per key (anti-replay)
/// and evicts entries that stop heartbeating.
#[derive(Debug, Default)]
pub struct Registry {
    entries: HashMap<String, RegEntry>,
}

impl Registry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll or heartbeat a relay against the wall clock.
    pub fn enroll(&mut self, e: RelayEnrollment) -> Result<()> {
        self.enroll_at(e, now_unix())
    }

    /// Enroll or heartbeat at an injected timestamp (deterministic tests).
    ///
    /// Validates the enrollment shape, rejects a `seq` that is not strictly
    /// greater than the one already on file for this key (replay / rollback),
    /// then records it with `last_seen = now`.
    pub fn enroll_at(&mut self, e: RelayEnrollment, now: u64) -> Result<()> {
        e.validate()?;
        if let Some(existing) = self.entries.get(&e.kem_pubkey_hex) {
            if e.seq <= existing.enrollment.seq {
                return Err(Error::Directory("enrollment seq not increasing (replay)"));
            }
        }
        self.entries.insert(
            e.kem_pubkey_hex.clone(),
            RegEntry {
                enrollment: e,
                last_seen: now,
            },
        );
        Ok(())
    }

    /// Evict every relay whose last heartbeat is older than
    /// [`ENROLL_STALE_AFTER_SECS`]. Returns the number evicted.
    pub fn prune_at(&mut self, now: u64) -> usize {
        let cutoff = now.saturating_sub(ENROLL_STALE_AFTER_SECS);
        let before = self.entries.len();
        self.entries.retain(|_, v| v.last_seen >= cutoff);
        before - self.entries.len()
    }

    /// Number of relays currently on file (call [`prune_at`](Self::prune_at)
    /// first for the live count).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no relays are enrolled.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// RFC B3: the `(addr, kem-pubkey)` of a directly-reachable, rendezvous-
    /// capable relay identified by its kem-hex — or `None` if it is unknown,
    /// itself rendezvous-hosted, or not willing to host. The authority uses this
    /// to verify a CGNAT relay's liveness via its rendezvous point instead of
    /// dialing the (unreachable) relay directly.
    pub fn rendezvous_point(&self, kem_hex: &str) -> Option<(std::net::SocketAddr, [u8; 32])> {
        let e = &self.entries.get(kem_hex)?.enrollment;
        if e.rendezvous.is_some() || !e.rendezvous_capable {
            return None;
        }
        let addr = e.addr.parse().ok()?;
        let pk: [u8; 32] = hex::decode(&e.kem_pubkey_hex).ok()?.try_into().ok()?;
        Some((addr, pk))
    }

    /// k-of-n decentralised admission: the `(identity_hex, epoch, operator)` of
    /// every LIVE relay that proposed an admission epoch AND survives the same
    /// diversity caps as the signed directory. The authority signs each tuple on
    /// demand to serve at `GET /admissions` — it stores no attestations, so the
    /// served set always tracks the live registry (a pruned relay disappears
    /// from admissions too). Call [`prune_at`](Self::prune_at) first.
    ///
    /// Bounding to the capped set matters two ways: (1) an attestation for a
    /// relay the directory won't list is useless to the app (it iterates the
    /// listed descriptors), and (2) it caps the per-request signing work to the
    /// SAME bounded set `/directory` already exposes — so `/admissions` can't be
    /// turned into an O(registry) Ed25519-signing CPU amplifier by inflating the
    /// registry past the caps.
    pub fn admission_inputs(&self) -> Vec<(String, u64, Option<String>)> {
        let mut descriptors: Vec<RelayDescriptor> = self
            .entries
            .values()
            .map(|v| v.enrollment.to_descriptor())
            .collect();
        descriptors.sort_by(|a, b| a.id_pubkey_hex.cmp(&b.id_pubkey_hex));
        apply_diversity_caps(descriptors)
            .into_iter()
            .filter_map(|d| {
                let e = &self.entries.get(&d.kem_pubkey_hex)?.enrollment;
                e.attest_epoch
                    .map(|ep| (e.kem_pubkey_hex.clone(), ep, e.operator.clone()))
            })
            .collect()
    }

    /// How many distinct tiers are currently represented. A working 3-hop
    /// mixnet needs entry + mix + exit, so the authority can warn when this
    /// is `< 3`.
    pub fn tier_coverage(&self) -> usize {
        let mut tiers = [false; 3];
        for v in self.entries.values() {
            match v.enrollment.tier {
                RelayTier::Entry => tiers[0] = true,
                RelayTier::Mix => tiers[1] = true,
                RelayTier::Exit => tiers[2] = true,
            }
        }
        tiers.iter().filter(|t| **t).count()
    }

    /// Bake the live roster into an authority-signed [`SignedDirectory`] valid
    /// for `valid_secs`. Descriptors are sorted by key for deterministic
    /// signing.
    pub fn build_signed(&self, authority: &SigningKey, valid_secs: u64) -> Result<SignedDirectory> {
        let mut descriptors: Vec<RelayDescriptor> = self
            .entries
            .values()
            .map(|v| v.enrollment.to_descriptor())
            .collect();
        descriptors.sort_by(|a, b| a.id_pubkey_hex.cmp(&b.id_pubkey_hex));
        // Bound how much of the directory any one subnet/operator can be, so an
        // open flood of relays can't buy a proportional share of path selection.
        let descriptors = apply_diversity_caps(descriptors);
        let doc = DirectoryDoc::new(descriptors, std::time::Duration::from_secs(valid_secs))?;
        SignedDirectory::sign(doc, authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keyhex(n: u8) -> String {
        hex::encode([n; 32])
    }

    fn enrollment(key: &str, addr: &str, tier: RelayTier, seq: u64) -> RelayEnrollment {
        RelayEnrollment::new(key.to_string(), addr.to_string(), tier, None, None, seq)
    }

    #[test]
    fn validate_accepts_well_formed() {
        let e = enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1);
        let sa = e
            .validate()
            .unwrap()
            .expect("direct relay returns Some(addr)");
        assert_eq!(sa.port(), 443);
    }

    #[test]
    fn validate_accepts_rendezvous_hosted_relay_without_addr() {
        // RFC B3: a CGNAT relay carries a rendezvous key and an empty addr, and
        // validates to `None` (no dialable socket).
        let e = enrollment(&keyhex(1), "", RelayTier::Mix, 1).with_rendezvous(keyhex(2));
        assert!(e.validate().unwrap().is_none());
        // A hosted relay that also claims to be a rendezvous point is rejected.
        let bad = enrollment(&keyhex(1), "", RelayTier::Mix, 1)
            .with_rendezvous(keyhex(2))
            .with_rendezvous_capable(true);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn pop_proof_roundtrips_and_binds_key_and_seq() {
        use x25519_dalek::{PublicKey, StaticSecret};
        // Authority PoP key (stable, derived) + a relay's X25519 key.
        let auth_sk = derive_authority_pop_sk(&[7u8; 32]);
        let auth_pk = PublicKey::from(&StaticSecret::from(auth_sk));
        let relay_sk = [9u8; 32];
        let relay_pk = PublicKey::from(&StaticSecret::from(relay_sk)).to_bytes();

        // N builds the proof from DH(relay_sk, auth_pk).
        let shared_n = StaticSecret::from(relay_sk).diffie_hellman(&auth_pk);
        let e = RelayEnrollment::new(
            hex::encode(relay_pk),
            String::new(),
            RelayTier::Mix,
            None,
            None,
            5,
        )
        .with_rendezvous(keyhex(3))
        .with_pop_proof(hex::encode(RelayEnrollment::pop_tag(
            shared_n.as_bytes(),
            &relay_pk,
            5,
        )));

        // The authority verifies from DH(auth_sk, relay_pk) — the same secret.
        let shared_a = StaticSecret::from(auth_sk).diffie_hellman(&PublicKey::from(relay_pk));
        assert!(
            e.verify_pop(shared_a.as_bytes()),
            "a valid proof must verify"
        );

        // Bound to seq: the same proof must not verify for a different seq (this
        // is what stops a captured proof from hijacking a key with a higher seq).
        let mut e_seq = e.clone();
        e_seq.seq = 6;
        assert!(
            !e_seq.verify_pop(shared_a.as_bytes()),
            "proof must be bound to seq"
        );

        // An attacker WITHOUT the authority's PoP secret cannot forge it.
        let wrong = StaticSecret::from([2u8; 32]).diffie_hellman(&PublicKey::from(relay_pk));
        assert!(
            !e.verify_pop(wrong.as_bytes()),
            "proof must not verify under a wrong secret"
        );

        // An enrollment with no proof at all is rejected.
        let none = RelayEnrollment::new(
            hex::encode(relay_pk),
            String::new(),
            RelayTier::Mix,
            None,
            None,
            5,
        );
        assert!(
            !none.verify_pop(shared_a.as_bytes()),
            "absent proof must not verify"
        );
    }

    #[test]
    fn attest_epoch_is_day_bucketed_and_stable_within_a_day() {
        let bucket = ATTEST_EPOCH_BUCKET_SECS;
        // Two instants in the SAME day bucket the same value — so a relay's
        // ~60 s heartbeats propose an identical epoch to every authority.
        let day_start = 1_700_000_000 / bucket * bucket;
        assert_eq!(current_attest_epoch(day_start), day_start);
        assert_eq!(current_attest_epoch(day_start + 59), day_start);
        assert_eq!(current_attest_epoch(day_start + bucket - 1), day_start);
        // The next day advances the bucket by exactly one width.
        assert_eq!(current_attest_epoch(day_start + bucket), day_start + bucket);
        // The builder threads it onto the enrollment.
        let e = enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1)
            .with_attest_epoch(day_start);
        assert_eq!(e.attest_epoch, Some(day_start));
        // It round-trips through the wire format additively (absent by default).
        let plain = enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1);
        assert_eq!(plain.attest_epoch, None);
        let json = serde_json::to_string(&plain).unwrap();
        assert!(
            !json.contains("attest_epoch"),
            "absent epoch is skipped on the wire"
        );
    }

    #[test]
    fn validate_rejects_bad_key_and_addr() {
        let mut e = enrollment("zz", "203.0.113.7:443", RelayTier::Entry, 1);
        assert!(e.validate().is_err());
        e = enrollment(&keyhex(1), "not-an-addr", RelayTier::Entry, 1);
        assert!(e.validate().is_err());
        e = enrollment(&keyhex(1), "0.0.0.0:443", RelayTier::Entry, 1);
        assert!(e.validate().is_err());
        e = enrollment(&keyhex(1), "203.0.113.7:0", RelayTier::Entry, 1);
        assert!(e.validate().is_err());
        // Loopback is rejected (defeats /16 path diversity + unreachable).
        e = enrollment(&keyhex(1), "127.0.0.1:443", RelayTier::Entry, 1);
        assert!(e.validate().is_err(), "loopback addr must be rejected");
        e = enrollment(&keyhex(1), "[::1]:443", RelayTier::Entry, 1);
        assert!(e.validate().is_err(), "ipv6 loopback addr must be rejected");
    }

    #[test]
    fn admission_inputs_filters_epoch_and_tracks_live_set() {
        let mut r = Registry::new();
        // Two relays propose an admission epoch, one does not (legacy).
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1).with_attest_epoch(1000),
            1000,
        )
        .unwrap();
        r.enroll_at(
            enrollment(&keyhex(2), "198.51.100.7:443", RelayTier::Mix, 1).with_attest_epoch(1000),
            1000,
        )
        .unwrap();
        r.enroll_at(
            enrollment(&keyhex(3), "192.0.2.7:443", RelayTier::Exit, 1),
            1000,
        )
        .unwrap();
        let inputs = r.admission_inputs();
        // Only the two epoch-proposing relays are attestable.
        assert_eq!(inputs.len(), 2);
        assert!(inputs.iter().all(|(_, ep, _)| *ep == 1000));
        assert!(inputs.iter().any(|(k, _, _)| *k == keyhex(1)));
        assert!(inputs.iter().any(|(k, _, _)| *k == keyhex(2)));
        assert!(
            !inputs.iter().any(|(k, _, _)| *k == keyhex(3)),
            "no-epoch relay excluded"
        );
        // Pruning the live set drops it from admissions too.
        r.prune_at(1000 + ENROLL_STALE_AFTER_SECS + 1);
        assert!(r.admission_inputs().is_empty());
    }

    #[test]
    fn enroll_then_heartbeat_bumps_seq() {
        let mut r = Registry::new();
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1),
            1000,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
        // Heartbeat with a higher seq is accepted and refreshes last_seen.
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 2),
            2000,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
    }

    /// The v1 possession proof covered only `(kem‖seq)`. Enrollments are POSTed
    /// as JSON over plain HTTP, so an on-path attacker could rewrite every other
    /// field in flight, leave `kem_pubkey_hex` / `seq` / `pop_proof` intact, and
    /// have the authority accept AND Ed25519-sign the tampered descriptor into
    /// the directory that every client trusts. The v2 proof must break on a
    /// change to ANY field.
    #[test]
    fn the_possession_proof_covers_every_enrollment_field() {
        let shared = [7u8; 32];
        let base = RelayEnrollment::new(
            keyhex(1),
            "203.0.113.7:443".into(),
            RelayTier::Entry,
            Some("FR".into()),
            Some("alice".into()),
            9,
        )
        .with_mailbox(true)
        .with_attest_epoch(86_400)
        .with_rendezvous_capable(true);
        let signed = base
            .clone()
            .with_pop_proof(hex::encode(RelayEnrollment::pop_tag_v2(
                &shared,
                &base.binding_hash(),
            )));
        assert!(
            signed.verify_pop_v2(&shared),
            "an untampered enrollment must verify"
        );

        // Every field an on-path attacker would want to rewrite.
        type Mutation = (&'static str, Box<dyn Fn(&mut RelayEnrollment)>);
        let mutations: Vec<Mutation> = vec![
            // repoint the relay at an attacker-controlled host
            (
                "addr",
                Box::new(|e: &mut RelayEnrollment| e.addr = "198.51.100.9:443".into()),
            ),
            // move it between tiers to steer path selection
            (
                "tier",
                Box::new(|e: &mut RelayEnrollment| e.tier = RelayTier::Exit),
            ),
            // collide or split operator labels to defeat diversity caps
            (
                "operator",
                Box::new(|e: &mut RelayEnrollment| e.operator = Some("mallory".into())),
            ),
            (
                "country",
                Box::new(|e: &mut RelayEnrollment| e.country = Some("US".into())),
            ),
            // flip the mailbox flag to blackhole offline delivery
            (
                "mailbox",
                Box::new(|e: &mut RelayEnrollment| e.mailbox = false),
            ),
            (
                "rendezvous_capable",
                Box::new(|e: &mut RelayEnrollment| e.rendezvous_capable = false),
            ),
            (
                "rendezvous",
                Box::new(|e: &mut RelayEnrollment| e.rendezvous = Some(keyhex(2))),
            ),
            // break k-of-n quorum assembly by desyncing the epoch per authority
            (
                "attest_epoch",
                Box::new(|e: &mut RelayEnrollment| e.attest_epoch = Some(172_800)),
            ),
            ("seq", Box::new(|e: &mut RelayEnrollment| e.seq = 10)),
            (
                "kem_pubkey_hex",
                Box::new(|e: &mut RelayEnrollment| e.kem_pubkey_hex = keyhex(2)),
            ),
            ("version", Box::new(|e: &mut RelayEnrollment| e.version = 2)),
        ];
        for (field, mutate) in mutations {
            let mut tampered = signed.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.verify_pop_v2(&shared),
                "rewriting `{field}` must invalidate the possession proof"
            );
        }

        // Domain separation: a captured v1 tag is never a valid v2 tag.
        let kem = <[u8; 32]>::try_from(hex::decode(keyhex(1)).unwrap()).unwrap();
        let legacy = base
            .clone()
            .with_pop_proof(hex::encode(RelayEnrollment::pop_tag(&shared, &kem, 9)));
        assert!(
            legacy.verify_pop(&shared),
            "the v1 tag still verifies as v1"
        );
        assert!(
            !legacy.verify_pop_v2(&shared),
            "a v1 tag must NOT be accepted as a v2 transcript-bound proof"
        );

        // …and a v2 tag is not accepted by the legacy verifier either.
        assert!(!signed.verify_pop(&shared));
    }

    /// Two different enrollments must never hash to the same binding — the
    /// length prefixes exist so bytes cannot be shifted between adjacent
    /// fields (e.g. operator "ab"+country "c" vs operator "a"+country "bc").
    #[test]
    fn the_binding_hash_is_unambiguous_across_adjacent_string_fields() {
        let mk = |country: Option<&str>, operator: Option<&str>| {
            RelayEnrollment::new(
                keyhex(1),
                "203.0.113.7:443".into(),
                RelayTier::Entry,
                country.map(str::to_string),
                operator.map(str::to_string),
                1,
            )
        };
        assert_ne!(
            mk(Some("ab"), Some("c")).binding_hash(),
            mk(Some("a"), Some("bc")).binding_hash()
        );
        // An absent field is distinguishable from an empty one.
        assert_ne!(
            mk(None, Some("x")).binding_hash(),
            mk(Some(""), Some("x")).binding_hash()
        );
    }

    #[test]
    fn enroll_rejects_replayed_seq() {
        let mut r = Registry::new();
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 5),
            1000,
        )
        .unwrap();
        let res = r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 5),
            1001,
        );
        assert!(res.is_err());
        let res = r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 3),
            1002,
        );
        assert!(res.is_err());
    }

    #[test]
    fn prune_drops_silent_relays() {
        let mut r = Registry::new();
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1),
            1000,
        )
        .unwrap();
        // Still fresh just under the window.
        assert_eq!(r.prune_at(1000 + ENROLL_STALE_AFTER_SECS), 0);
        assert_eq!(r.len(), 1);
        // One second past the window → evicted.
        assert_eq!(r.prune_at(1000 + ENROLL_STALE_AFTER_SECS + 1), 1);
        assert!(r.is_empty());
    }

    #[test]
    fn tier_coverage_counts_distinct_tiers() {
        let mut r = Registry::new();
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.1:443", RelayTier::Entry, 1),
            1,
        )
        .unwrap();
        r.enroll_at(
            enrollment(&keyhex(2), "203.0.113.2:443", RelayTier::Mix, 1),
            1,
        )
        .unwrap();
        assert_eq!(r.tier_coverage(), 2);
        r.enroll_at(
            enrollment(&keyhex(3), "203.0.113.3:443", RelayTier::Exit, 1),
            1,
        )
        .unwrap();
        assert_eq!(r.tier_coverage(), 3);
    }

    #[test]
    fn build_signed_is_verifiable_and_complete() {
        let mut r = Registry::new();
        for (i, tier) in [RelayTier::Entry, RelayTier::Mix, RelayTier::Exit]
            .iter()
            .enumerate()
        {
            r.enroll_at(
                enrollment(
                    &keyhex(i as u8 + 1),
                    &format!("203.0.113.{}:443", i + 1),
                    *tier,
                    1,
                ),
                1,
            )
            .unwrap();
        }
        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let signed = r.build_signed(&authority, 3600).unwrap();
        assert_eq!(signed.doc.relays.len(), 3);
        signed.verify(&authority.verifying_key()).unwrap();
    }
}
