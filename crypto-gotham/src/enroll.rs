// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::directory::{
    apply_diversity_caps, DirectoryDoc, RelayDescriptor, RelayTier, SignedDirectory,
};
use crate::error::{Error, Result};

pub const ENROLL_VERSION: u8 = 1;

pub const ENROLL_STALE_AFTER_SECS: u64 = 1800;

pub const ATTEST_EPOCH_BUCKET_SECS: u64 = 86_400;

#[must_use]
pub fn current_attest_epoch(now: u64) -> u64 {
    (now / ATTEST_EPOCH_BUCKET_SECS) * ATTEST_EPOCH_BUCKET_SECS
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayEnrollment {
    pub version: u8,
    pub kem_pubkey_hex: String,
    pub addr: String,
    pub tier: RelayTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rendezvous_capable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pop_proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mailbox: bool,
}

impl RelayEnrollment {
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

    #[must_use]
    pub fn with_mailbox(mut self, yes: bool) -> Self {
        self.mailbox = yes;
        self
    }

    #[must_use]
    pub fn with_attest_epoch(mut self, epoch: u64) -> Self {
        self.attest_epoch = Some(epoch);
        self
    }

    #[must_use]
    pub fn pop_tag(shared: &[u8; 32], kem_pubkey: &[u8; 32], seq: u64) -> [u8; 32] {
        let k = blake3::derive_key("gotham-rendezvous-pop-v1", shared);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(kem_pubkey);
        h.update(&seq.to_le_bytes());
        *h.finalize().as_bytes()
    }

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

    #[must_use]
    pub fn pop_tag_v2(shared: &[u8; 32], binding: &[u8; 32]) -> [u8; 32] {
        let k = blake3::derive_key("gotham-enroll-pop-v2", shared);
        let mut h = blake3::Hasher::new_keyed(&k);
        h.update(binding);
        *h.finalize().as_bytes()
    }

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

    #[must_use]
    pub fn with_pop_proof(mut self, tag_hex: String) -> Self {
        self.pop_proof = Some(tag_hex);
        self
    }

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
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= provided[i] ^ expected[i];
        }
        diff == 0
    }

    #[must_use]
    pub fn with_rendezvous(mut self, r_kem_hex: String) -> Self {
        self.rendezvous = Some(r_kem_hex);
        self
    }

    #[must_use]
    pub fn with_rendezvous_capable(mut self, yes: bool) -> Self {
        self.rendezvous_capable = yes;
        self
    }

    pub fn validate(&self) -> Result<Option<std::net::SocketAddr>> {
        if self.version != ENROLL_VERSION {
            return Err(Error::Directory("unsupported enrollment version"));
        }
        let key = hex::decode(&self.kem_pubkey_hex)
            .map_err(|_| Error::Directory("bad kem_pubkey hex"))?;
        if key.len() != 32 {
            return Err(Error::Directory("kem_pubkey wrong length"));
        }
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
        if sa.ip().is_loopback() {
            return Err(Error::Directory("addr must not be a loopback address"));
        }
        if sa.port() == 0 {
            return Err(Error::Directory("addr port must not be zero"));
        }
        Ok(Some(sa))
    }

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
            mailbox: self.mailbox,
            rendezvous: self.rendezvous.clone(),
            rendezvous_capable: self.rendezvous_capable,
        }
    }
}

#[must_use]
pub fn derive_authority_pop_sk(ed25519_seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("gotham-authority-pop-x25519-v1", ed25519_seed)
}

#[derive(Debug, Clone)]
struct RegEntry {
    enrollment: RelayEnrollment,
    last_seen: u64,
    first_seen: u64,
}

#[derive(Debug, Default)]
pub struct Registry {
    entries: HashMap<String, RegEntry>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(&mut self, e: RelayEnrollment) -> Result<()> {
        self.enroll_at(e, now_unix())
    }

    pub fn enroll_at(&mut self, e: RelayEnrollment, now: u64) -> Result<()> {
        e.validate()?;
        if let Some(existing) = self.entries.get(&e.kem_pubkey_hex) {
            if e.seq <= existing.enrollment.seq {
                return Err(Error::Directory("enrollment seq not increasing (replay)"));
            }
        }
        let first_seen = self
            .entries
            .get(&e.kem_pubkey_hex)
            .map(|existing| existing.first_seen)
            .unwrap_or(now);
        self.entries.insert(
            e.kem_pubkey_hex.clone(),
            RegEntry {
                enrollment: e,
                last_seen: now,
                first_seen,
            },
        );
        Ok(())
    }

    pub fn prune_at(&mut self, now: u64) -> usize {
        let cutoff = now.saturating_sub(ENROLL_STALE_AFTER_SECS);
        let before = self.entries.len();
        self.entries.retain(|_, v| v.last_seen >= cutoff);
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn rendezvous_point(&self, kem_hex: &str) -> Option<(std::net::SocketAddr, [u8; 32])> {
        let e = &self.entries.get(kem_hex)?.enrollment;
        if e.rendezvous.is_some() || !e.rendezvous_capable {
            return None;
        }
        let addr = e.addr.parse().ok()?;
        let pk: [u8; 32] = hex::decode(&e.kem_pubkey_hex).ok()?.try_into().ok()?;
        Some((addr, pk))
    }

    fn order_for_diversity_caps(
        entries: &std::collections::HashMap<String, RegEntry>,
        descriptors: &mut [RelayDescriptor],
    ) {
        descriptors.sort_by_cached_key(|d| {
            let first_seen = entries
                .get(&d.kem_pubkey_hex)
                .map(|e| e.first_seen)
                .unwrap_or(u64::MAX);
            (
                first_seen,
                *blake3::hash(d.id_pubkey_hex.as_bytes()).as_bytes(),
            )
        });
    }

    pub fn admission_inputs(&self) -> Vec<(String, u64, Option<String>)> {
        let mut descriptors: Vec<RelayDescriptor> = self
            .entries
            .values()
            .map(|v| v.enrollment.to_descriptor())
            .collect();
        Self::order_for_diversity_caps(&self.entries, &mut descriptors);
        apply_diversity_caps(descriptors)
            .into_iter()
            .filter_map(|d| {
                let e = &self.entries.get(&d.kem_pubkey_hex)?.enrollment;
                e.attest_epoch
                    .map(|ep| (e.kem_pubkey_hex.clone(), ep, e.operator.clone()))
            })
            .collect()
    }

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

    pub fn build_signed(&self, authority: &SigningKey, valid_secs: u64) -> Result<SignedDirectory> {
        let mut descriptors: Vec<RelayDescriptor> = self
            .entries
            .values()
            .map(|v| v.enrollment.to_descriptor())
            .collect();
        Self::order_for_diversity_caps(&self.entries, &mut descriptors);
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
        let e = enrollment(&keyhex(1), "", RelayTier::Mix, 1).with_rendezvous(keyhex(2));
        assert!(e.validate().unwrap().is_none());
        let bad = enrollment(&keyhex(1), "", RelayTier::Mix, 1)
            .with_rendezvous(keyhex(2))
            .with_rendezvous_capable(true);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn pop_proof_roundtrips_and_binds_key_and_seq() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let auth_sk = derive_authority_pop_sk(&[7u8; 32]);
        let auth_pk = PublicKey::from(&StaticSecret::from(auth_sk));
        let relay_sk = [9u8; 32];
        let relay_pk = PublicKey::from(&StaticSecret::from(relay_sk)).to_bytes();

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

        let shared_a = StaticSecret::from(auth_sk).diffie_hellman(&PublicKey::from(relay_pk));
        assert!(
            e.verify_pop(shared_a.as_bytes()),
            "a valid proof must verify"
        );

        let mut e_seq = e.clone();
        e_seq.seq = 6;
        assert!(
            !e_seq.verify_pop(shared_a.as_bytes()),
            "proof must be bound to seq"
        );

        let wrong = StaticSecret::from([2u8; 32]).diffie_hellman(&PublicKey::from(relay_pk));
        assert!(
            !e.verify_pop(wrong.as_bytes()),
            "proof must not verify under a wrong secret"
        );

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
        let day_start = 1_700_000_000 / bucket * bucket;
        assert_eq!(current_attest_epoch(day_start), day_start);
        assert_eq!(current_attest_epoch(day_start + 59), day_start);
        assert_eq!(current_attest_epoch(day_start + bucket - 1), day_start);
        assert_eq!(current_attest_epoch(day_start + bucket), day_start + bucket);
        let e = enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 1)
            .with_attest_epoch(day_start);
        assert_eq!(e.attest_epoch, Some(day_start));
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
        e = enrollment(&keyhex(1), "127.0.0.1:443", RelayTier::Entry, 1);
        assert!(e.validate().is_err(), "loopback addr must be rejected");
        e = enrollment(&keyhex(1), "[::1]:443", RelayTier::Entry, 1);
        assert!(e.validate().is_err(), "ipv6 loopback addr must be rejected");
    }

    #[test]
    fn admission_inputs_filters_epoch_and_tracks_live_set() {
        let mut r = Registry::new();
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
        assert_eq!(inputs.len(), 2);
        assert!(inputs.iter().all(|(_, ep, _)| *ep == 1000));
        assert!(inputs.iter().any(|(k, _, _)| *k == keyhex(1)));
        assert!(inputs.iter().any(|(k, _, _)| *k == keyhex(2)));
        assert!(
            !inputs.iter().any(|(k, _, _)| *k == keyhex(3)),
            "no-epoch relay excluded"
        );
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
        r.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Entry, 2),
            2000,
        )
        .unwrap();
        assert_eq!(r.len(), 1);
    }

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

        type Mutation = (&'static str, Box<dyn Fn(&mut RelayEnrollment)>);
        let mutations: Vec<Mutation> = vec![
            (
                "addr",
                Box::new(|e: &mut RelayEnrollment| e.addr = "198.51.100.9:443".into()),
            ),
            (
                "tier",
                Box::new(|e: &mut RelayEnrollment| e.tier = RelayTier::Exit),
            ),
            (
                "operator",
                Box::new(|e: &mut RelayEnrollment| e.operator = Some("mallory".into())),
            ),
            (
                "country",
                Box::new(|e: &mut RelayEnrollment| e.country = Some("US".into())),
            ),
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

        assert!(!signed.verify_pop(&shared));
    }

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
        assert_eq!(r.prune_at(1000 + ENROLL_STALE_AFTER_SECS), 0);
        assert_eq!(r.len(), 1);
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

    #[test]
    fn seniority_decides_a_full_bucket_not_a_low_identity_key() {
        let mut reg = Registry::default();

        for (i, key) in [0xF1u8, 0xF2, 0xF3].iter().enumerate() {
            reg.enroll_at(
                enrollment(
                    &keyhex(*key),
                    &format!("203.0.113.{}:443", 10 + i),
                    RelayTier::Mix,
                    1,
                ),
                1_000,
            )
            .unwrap();
        }

        for (i, key) in [0x00u8, 0x01, 0x02].iter().enumerate() {
            reg.enroll_at(
                enrollment(
                    &keyhex(*key),
                    &format!("203.0.113.{}:443", 20 + i),
                    RelayTier::Mix,
                    1,
                ),
                2_000,
            )
            .unwrap();
        }

        let mut descriptors: Vec<RelayDescriptor> = reg
            .entries
            .values()
            .map(|v| v.enrollment.to_descriptor())
            .collect();
        Registry::order_for_diversity_caps(&reg.entries, &mut descriptors);
        let kept = crate::directory::apply_diversity_caps(descriptors);

        assert_eq!(kept.len(), crate::directory::MAX_RELAYS_PER_24);
        for key in [0xF1u8, 0xF2, 0xF3] {
            assert!(
                kept.iter().any(|d| d.kem_pubkey_hex == keyhex(key)),
                "an established relay was evicted by a ground key"
            );
        }
        for key in [0x00u8, 0x01, 0x02] {
            assert!(
                !kept.iter().any(|d| d.kem_pubkey_hex == keyhex(key)),
                "a late ground key must not take a contested slot"
            );
        }
    }

    #[test]
    fn a_heartbeat_does_not_reset_seniority() {
        let mut reg = Registry::default();
        reg.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Mix, 1),
            1_000,
        )
        .unwrap();
        reg.enroll_at(
            enrollment(&keyhex(1), "203.0.113.7:443", RelayTier::Mix, 2),
            9_000,
        )
        .unwrap();
        let e = reg.entries.get(&keyhex(1)).unwrap();
        assert_eq!(e.first_seen, 1_000, "seniority must not reset");
        assert_eq!(e.last_seen, 9_000, "liveness must still advance");
    }
}
