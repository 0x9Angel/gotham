// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

pub const DIRECTORY_VERSION: u8 = 1;

pub const SIGNATURE_LEN: usize = 64;

pub const ED25519_PUBKEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayTier {
    Entry,
    Mix,
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayDescriptor {
    pub id_pubkey_hex: String,
    pub kem_pubkey_hex: String,
    pub addr: String,
    pub tier: RelayTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_pct: Option<f32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mailbox: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rendezvous_capable: bool,
}

impl RelayDescriptor {
    pub fn kem_pubkey_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.kem_pubkey_hex)
            .map_err(|_| Error::Directory("bad kem_pubkey hex"))?;
        if v.len() != 32 {
            return Err(Error::Directory("kem_pubkey wrong length"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }

    pub fn id_pubkey_bytes(&self) -> Result<[u8; 32]> {
        let v =
            hex::decode(&self.id_pubkey_hex).map_err(|_| Error::Directory("bad id_pubkey hex"))?;
        if v.len() != 32 {
            return Err(Error::Directory("id_pubkey wrong length"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }

    pub fn ipv4_octets(&self) -> Result<[u8; 4]> {
        let sa: std::net::SocketAddr = self
            .addr
            .parse()
            .map_err(|_| Error::Directory("bad addr"))?;
        match sa {
            std::net::SocketAddr::V4(v4) => Ok(v4.ip().octets()),
            std::net::SocketAddr::V6(_) => Err(Error::Directory("ipv6 addr not yet supported")),
        }
    }

    pub fn port(&self) -> Result<u16> {
        let sa: std::net::SocketAddr = self
            .addr
            .parse()
            .map_err(|_| Error::Directory("bad addr"))?;
        Ok(sa.port())
    }

    #[must_use]
    pub fn ip_addr(&self) -> Option<std::net::IpAddr> {
        self.addr
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|sa| sa.ip())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryDoc {
    pub version: u8,
    pub valid_after: u64,
    pub valid_until: u64,
    pub relays: Vec<RelayDescriptor>,
}

impl DirectoryDoc {
    pub fn new(relays: Vec<RelayDescriptor>, validity: std::time::Duration) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Directory("system clock before epoch"))?
            .as_secs();
        let mut relays = relays;
        relays.sort_by(|a, b| a.id_pubkey_hex.cmp(&b.id_pubkey_hex));
        let valid_until = now
            .checked_add(validity.as_secs())
            .ok_or(Error::Directory("validity window overflows u64"))?;
        Ok(Self {
            version: DIRECTORY_VERSION,
            valid_after: now,
            valid_until,
            relays,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::Directory("serialize directory doc"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedDirectory {
    pub doc: DirectoryDoc,
    pub authority_pubkey_hex: String,
    pub signature_hex: String,
}

impl SignedDirectory {
    pub fn sign(doc: DirectoryDoc, signing_key: &SigningKey) -> Result<Self> {
        let canonical = doc.canonical_bytes()?;
        let sig: Signature = signing_key.sign(&canonical);
        let authority_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let signature_hex = hex::encode(sig.to_bytes());
        Ok(Self {
            doc,
            authority_pubkey_hex,
            signature_hex,
        })
    }

    pub fn verify(&self, expected_authority: &VerifyingKey) -> Result<()> {
        let expected_bytes = expected_authority.to_bytes();
        let actual = hex::decode(&self.authority_pubkey_hex)
            .map_err(|_| Error::Directory("bad authority pubkey hex"))?;
        if actual != expected_bytes {
            return Err(Error::Directory("authority pubkey mismatch"));
        }

        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|_| Error::Directory("bad signature hex"))?;
        let sig_arr: [u8; SIGNATURE_LEN] = sig_bytes
            .try_into()
            .map_err(|_| Error::Directory("signature wrong length"))?;
        let sig = Signature::from_bytes(&sig_arr);
        let canonical = self.doc.canonical_bytes()?;
        expected_authority
            .verify(&canonical, &sig)
            .map_err(|_| Error::Directory("signature verify failed"))?;

        if self.doc.version != DIRECTORY_VERSION {
            return Err(Error::Directory("unsupported directory version"));
        }

        if self.doc.valid_after > self.doc.valid_until {
            return Err(Error::Directory("inverted validity window"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Directory("system clock before epoch"))?
            .as_secs();
        if now < self.doc.valid_after {
            return Err(Error::Directory("directory not yet valid"));
        }
        if now > self.doc.valid_until {
            return Err(Error::Directory("directory expired"));
        }

        Ok(())
    }

    pub fn verify_monotonic(
        &self,
        expected_authority: &VerifyingKey,
        seen_valid_after: u64,
    ) -> Result<u64> {
        self.verify(expected_authority)?;
        if self.doc.valid_after < seen_valid_after {
            return Err(Error::Directory(
                "directory is older than one already seen (rollback attempt)",
            ));
        }
        Ok(self.doc.valid_after)
    }

    pub fn verify_with_transitions(
        &self,
        pinned: &VerifyingKey,
        transitions: &[AuthorityKeyTransition],
    ) -> Result<()> {
        const MAX_TRANSITIONS: usize = 64;
        if transitions.len() > MAX_TRANSITIONS {
            return Err(Error::Directory("too many key transitions"));
        }
        let edges: Vec<([u8; 32], [u8; 32])> =
            transitions.iter().filter_map(|t| t.verify().ok()).collect();

        let actual = decode_pubkey32(&self.authority_pubkey_hex)?;

        let mut trusted: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        trusted.insert(pinned.to_bytes());
        loop {
            let mut grew = false;
            for (old_pub, new_pub) in &edges {
                if trusted.contains(old_pub) && trusted.insert(*new_pub) {
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        {
            let mut successor: std::collections::HashMap<[u8; 32], [u8; 32]> =
                std::collections::HashMap::new();
            for (old_pub, new_pub) in edges.iter().filter(|(o, _)| trusted.contains(o)) {
                if let Some(prev) = successor.insert(*old_pub, *new_pub) {
                    if prev != *new_pub {
                        return Err(Error::Directory(
                            "forked authority key transition: a trusted key certifies two successors",
                        ));
                    }
                }
            }
        }

        let superseded: std::collections::HashSet<[u8; 32]> =
            edges.iter().map(|(old_pub, _)| *old_pub).collect();

        if superseded.contains(&actual) {
            return Err(Error::Directory(
                "authority pubkey has been rotated away from: superseded key",
            ));
        }
        if !trusted.contains(&actual) {
            return Err(Error::Directory(
                "authority pubkey not trusted: no rotation chain from the pinned key",
            ));
        }
        let signer = VerifyingKey::from_bytes(&actual)
            .map_err(|_| Error::Directory("bad authority pubkey"))?;
        self.verify(&signer)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|_| Error::Directory("serialize signed doc"))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::Directory("parse signed doc"))
    }
}

#[derive(Debug, Clone)]
pub struct SelectedPath<'a> {
    pub hops: Vec<&'a RelayDescriptor>,
}

pub struct PathSelector<'a> {
    relays: &'a [RelayDescriptor],
    guards: &'a [String],
}

impl<'a> PathSelector<'a> {
    #[must_use]
    pub fn new(relays: &'a [RelayDescriptor]) -> Self {
        Self {
            relays,
            guards: &[],
        }
    }

    #[must_use]
    pub fn with_guards(mut self, guards: &'a [String]) -> Self {
        self.guards = guards;
        self
    }

    fn entry_pool<'p>(&self, entries: Vec<&'p RelayDescriptor>) -> Vec<&'p RelayDescriptor> {
        if self.guards.is_empty() {
            return entries;
        }
        let guarded: Vec<&RelayDescriptor> = entries
            .iter()
            .copied()
            .filter(|r| {
                self.guards
                    .iter()
                    .any(|g| g.eq_ignore_ascii_case(&r.id_pubkey_hex))
            })
            .collect();
        if guarded.is_empty() {
            entries
        } else {
            guarded
        }
    }

    pub fn pick<R: Rng>(&self, rng: &mut R, hop_count: usize) -> Result<SelectedPath<'a>> {
        if !(3..=5).contains(&hop_count) {
            return Err(Error::Directory("hop_count must be 3..=5"));
        }
        let mix_count = hop_count - 2;

        let by_id = index_by_id(self.relays);
        let entries: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Entry && r.rendezvous.is_none())
            .collect();
        let entries = self.entry_pool(entries);
        let mixes: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Mix)
            .collect();
        let exits: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Exit && r.rendezvous.is_none())
            .collect();

        if entries.is_empty() {
            return Err(Error::Directory("no entry relays available"));
        }
        if mixes.len() < mix_count {
            return Err(Error::Directory("not enough mix relays"));
        }
        if exits.is_empty() {
            return Err(Error::Directory("no exit relays available"));
        }

        const MAX_TRIES: usize = 32;
        for _ in 0..MAX_TRIES {
            let mut hops: Vec<&RelayDescriptor> = Vec::with_capacity(hop_count);
            let mut used_ids: HashSet<&str> = HashSet::new();

            let entry = entries
                .choose(rng)
                .ok_or(Error::Directory("entry pool empty"))?;
            hops.push(*entry);
            used_ids.insert(&entry.id_pubkey_hex);

            let mut chosen_mixes: Vec<&&RelayDescriptor> = mixes
                .iter()
                .filter(|m| !used_ids.contains(m.id_pubkey_hex.as_str()))
                .collect();
            chosen_mixes.shuffle(rng);
            let mut mixes_placed = 0usize;
            for m in chosen_mixes.iter() {
                if mixes_placed == mix_count {
                    break;
                }
                if let Some(r_hex) = m.rendezvous.as_deref() {
                    let Some(r) = by_id.get(r_hex).copied() else {
                        continue;
                    };
                    if r.rendezvous.is_some()
                        || !r.rendezvous_capable
                        || used_ids.contains(r.id_pubkey_hex.as_str())
                        || !path_diverse(&hops, r, &by_id)
                    {
                        continue;
                    }
                    hops.push(r);
                    used_ids.insert(&r.id_pubkey_hex);
                    hops.push(**m);
                    used_ids.insert(&m.id_pubkey_hex);
                    mixes_placed += 1;
                } else {
                    if !path_diverse(&hops, m, &by_id) {
                        continue;
                    }
                    hops.push(**m);
                    used_ids.insert(&m.id_pubkey_hex);
                    mixes_placed += 1;
                }
            }
            if mixes_placed != mix_count {
                continue;
            }

            let candidate_exits: Vec<&&RelayDescriptor> = exits
                .iter()
                .filter(|e| !used_ids.contains(e.id_pubkey_hex.as_str()))
                .filter(|e| path_diverse(&hops, e, &by_id))
                .collect();
            let Some(exit) = candidate_exits.choose(rng) else {
                continue;
            };
            hops.push(**exit);

            return Ok(SelectedPath { hops });
        }

        Err(Error::Directory(
            "no diverse path found after MAX_TRIES attempts",
        ))
    }

    pub fn pick_to_exit<R: Rng>(
        &self,
        rng: &mut R,
        hop_count: usize,
        exit: &'a RelayDescriptor,
    ) -> Result<SelectedPath<'a>> {
        if !(3..=5).contains(&hop_count) {
            return Err(Error::Directory("hop_count must be 3..=5"));
        }
        let mix_count = hop_count - 2;

        let by_id = index_by_id(self.relays);
        let entries: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Entry && r.rendezvous.is_none())
            .filter(|r| r.id_pubkey_hex != exit.id_pubkey_hex)
            .collect();
        let entries = self.entry_pool(entries);
        let mixes: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Mix && r.rendezvous.is_none())
            .filter(|r| r.id_pubkey_hex != exit.id_pubkey_hex)
            .collect();
        if entries.is_empty() {
            return Err(Error::Directory("no entry relays available"));
        }
        if mixes.len() < mix_count {
            return Err(Error::Directory("not enough mix relays"));
        }

        const MAX_TRIES: usize = 32;
        for _ in 0..MAX_TRIES {
            let mut hops: Vec<&RelayDescriptor> = Vec::with_capacity(hop_count);
            let mut used_ids: HashSet<&str> = HashSet::new();
            used_ids.insert(&exit.id_pubkey_hex);

            let entry = entries
                .choose(rng)
                .ok_or(Error::Directory("entry pool empty"))?;
            hops.push(*entry);
            used_ids.insert(&entry.id_pubkey_hex);

            let mut chosen_mixes: Vec<&&RelayDescriptor> = mixes
                .iter()
                .filter(|m| !used_ids.contains(m.id_pubkey_hex.as_str()))
                .collect();
            chosen_mixes.shuffle(rng);
            let mut ok = true;
            for m in chosen_mixes.iter().take(mix_count) {
                if !path_diverse(&hops, m, &by_id) {
                    ok = false;
                    break;
                }
                hops.push(**m);
                used_ids.insert(&m.id_pubkey_hex);
            }
            if !ok || hops.len() != 1 + mix_count {
                continue;
            }

            if !path_diverse(&hops, exit, &by_id) {
                continue;
            }
            hops.push(exit);
            return Ok(SelectedPath { hops });
        }

        Err(Error::Directory(
            "no diverse path to the chosen exit after MAX_TRIES attempts",
        ))
    }
}

type IdIndex<'a> = std::collections::HashMap<&'a str, &'a RelayDescriptor>;

fn index_by_id(relays: &[RelayDescriptor]) -> IdIndex<'_> {
    relays
        .iter()
        .map(|r| (r.id_pubkey_hex.as_str(), r))
        .collect()
}

fn eff_diversity_ip(d: &RelayDescriptor, by_id: &IdIndex) -> Option<std::net::IpAddr> {
    match &d.rendezvous {
        Some(rid) => by_id.get(rid.as_str()).and_then(|r| r.ip_addr()),
        None => d.ip_addr(),
    }
}

fn eff_operator<'a>(d: &'a RelayDescriptor, by_id: &IdIndex<'a>) -> Option<&'a str> {
    match &d.rendezvous {
        Some(rid) => by_id
            .get(rid.as_str())
            .copied()
            .and_then(|r| r.operator.as_deref()),
        None => d.operator.as_deref(),
    }
}

fn path_diverse(existing: &[&RelayDescriptor], cand: &RelayDescriptor, by_id: &IdIndex) -> bool {
    existing.iter().all(|h| pair_diverse(h, cand, by_id))
}

fn pair_diverse(a: &RelayDescriptor, b: &RelayDescriptor, by_id: &IdIndex) -> bool {
    match (eff_operator(a, by_id), eff_operator(b, by_id)) {
        (Some(op_a), Some(op_b)) if op_a == op_b => return false,
        (Some(_), Some(_)) => {}
        _ => return false,
    }
    let (ea, eb) = (eff_diversity_ip(a, by_id), eff_diversity_ip(b, by_id));
    if (a.rendezvous.is_some() && ea.is_none()) || (b.rendezvous.is_some() && eb.is_none()) {
        return false;
    }
    if let (Some(ip_a), Some(ip_b)) = (ea, eb) {
        if !network_diverse(ip_a, ip_b) {
            return false;
        }
    }
    true
}

fn network_diverse(a: std::net::IpAddr, b: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (oa, ob) = (a.octets(), b.octets());
            if a.is_loopback() && b.is_loopback() {
                return true;
            }
            oa[0] != ob[0] || oa[1] != ob[1]
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (oa, ob) = (a.octets(), b.octets());
            if a.is_loopback() && b.is_loopback() {
                return true;
            }
            oa[..6] != ob[..6]
        }
        _ => true,
    }
}

pub const MAX_RELAYS_PER_24: usize = 3;
pub const MAX_RELAYS_PER_16: usize = 8;
pub const MAX_RELAYS_PER_48: usize = 8;
pub const MAX_RELAYS_PER_OPERATOR: usize = 5;

pub fn apply_diversity_caps(descriptors: Vec<RelayDescriptor>) -> Vec<RelayDescriptor> {
    use std::collections::HashMap;
    use std::net::IpAddr;

    #[allow(clippy::type_complexity)]
    let (eff_ips, eff_ops): (Vec<Option<IpAddr>>, Vec<Option<String>>) = {
        let by_id = index_by_id(&descriptors);
        descriptors
            .iter()
            .map(|d| {
                (
                    eff_diversity_ip(d, &by_id),
                    eff_operator(d, &by_id).map(str::to_owned),
                )
            })
            .unzip()
    };

    let mut per24: HashMap<[u8; 3], usize> = HashMap::new();
    let mut per16: HashMap<[u8; 2], usize> = HashMap::new();
    let mut per48: HashMap<[u8; 6], usize> = HashMap::new();
    let mut per_op: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(descriptors.len());

    for (i, d) in descriptors.into_iter().enumerate() {
        let ip = eff_ips[i];

        if d.rendezvous.is_some() && ip.is_none() {
            continue;
        }

        let net_ok = match ip {
            Some(IpAddr::V4(v4)) => {
                let o = v4.octets();
                per24.get(&[o[0], o[1], o[2]]).copied().unwrap_or(0) < MAX_RELAYS_PER_24
                    && per16.get(&[o[0], o[1]]).copied().unwrap_or(0) < MAX_RELAYS_PER_16
            }
            Some(IpAddr::V6(v6)) => {
                let o = v6.octets();
                let mut k = [0u8; 6];
                k.copy_from_slice(&o[..6]);
                per48.get(&k).copied().unwrap_or(0) < MAX_RELAYS_PER_48
            }
            None => true,
        };

        let op_ok = match eff_ops[i].as_deref() {
            Some(op) => per_op.get(op).copied().unwrap_or(0) < MAX_RELAYS_PER_OPERATOR,
            None => true,
        };

        if !(net_ok && op_ok) {
            continue;
        }

        match ip {
            Some(IpAddr::V4(v4)) => {
                let o = v4.octets();
                *per24.entry([o[0], o[1], o[2]]).or_insert(0) += 1;
                *per16.entry([o[0], o[1]]).or_insert(0) += 1;
            }
            Some(IpAddr::V6(v6)) => {
                let o = v6.octets();
                let mut k = [0u8; 6];
                k.copy_from_slice(&o[..6]);
                *per48.entry(k).or_insert(0) += 1;
            }
            None => {}
        }
        if let Some(op) = eff_ops[i].as_deref() {
            *per_op.entry(op.to_string()).or_insert(0) += 1;
        }
        kept.push(d);
    }
    kept
}

fn decode_pubkey32(hex_str: &str) -> Result<[u8; 32]> {
    hex::decode(hex_str)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Directory("authority key not 32-byte hex"))
}

fn verify_detached(pub_bytes: &[u8; 32], msg: &[u8], sig_hex: &str) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pub_bytes)
        .map_err(|_| Error::Directory("bad authority pubkey"))?;
    let sig_arr: [u8; SIGNATURE_LEN] = hex::decode(sig_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Directory("bad transition signature hex"))?;
    vk.verify(msg, &Signature::from_bytes(&sig_arr))
        .map_err(|_| Error::Directory("transition signature verify failed"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityKeyTransition {
    pub old_pubkey_hex: String,
    pub new_pubkey_hex: String,
    pub sig_old_hex: String,
    pub sig_new_hex: String,
}

impl AuthorityKeyTransition {
    const DOMAIN: &'static [u8] = b"gotham-authority-transition-v1";

    fn signing_bytes(old_pub: &[u8; 32], new_pub: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::DOMAIN.len() + 64);
        b.extend_from_slice(Self::DOMAIN);
        b.extend_from_slice(old_pub);
        b.extend_from_slice(new_pub);
        b
    }

    pub fn build(old: &SigningKey, new: &SigningKey) -> Self {
        let old_pub = old.verifying_key().to_bytes();
        let new_pub = new.verifying_key().to_bytes();
        let msg = Self::signing_bytes(&old_pub, &new_pub);
        Self {
            old_pubkey_hex: hex::encode(old_pub),
            new_pubkey_hex: hex::encode(new_pub),
            sig_old_hex: hex::encode(old.sign(&msg).to_bytes()),
            sig_new_hex: hex::encode(new.sign(&msg).to_bytes()),
        }
    }

    pub fn verify(&self) -> Result<([u8; 32], [u8; 32])> {
        let old_pub = decode_pubkey32(&self.old_pubkey_hex)?;
        let new_pub = decode_pubkey32(&self.new_pubkey_hex)?;
        let msg = Self::signing_bytes(&old_pub, &new_pub);
        verify_detached(&old_pub, &msg, &self.sig_old_hex)?;
        verify_detached(&new_pub, &msg, &self.sig_new_hex)?;
        Ok((old_pub, new_pub))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xABAD_CAFE)
    }

    fn fake_relay(name: &str, tier: RelayTier, ipv4: [u8; 4], operator: &str) -> RelayDescriptor {
        RelayDescriptor {
            id_pubkey_hex: hex::encode([name.bytes().next().unwrap_or(0); 32]),
            kem_pubkey_hex: hex::encode([name.bytes().next().unwrap_or(0).wrapping_add(1); 32]),
            addr: format!("{}.{}.{}.{}:443", ipv4[0], ipv4[1], ipv4[2], ipv4[3]),
            tier,
            country: None,
            asn: None,
            operator: Some(operator.to_string()),
            uptime_pct: Some(99.5),
            mailbox: false,
            rendezvous: None,
            rendezvous_capable: false,
        }
    }

    #[test]
    fn an_unattested_operator_never_counts_as_a_different_one() {
        let unlabelled = |name: &str, ip: [u8; 4]| {
            let mut r = fake_relay(name, RelayTier::Mix, ip, "ignored");
            r.operator = None;
            r
        };
        let by_id: IdIndex = std::collections::HashMap::new();

        let a = unlabelled("a", [203, 0, 113, 1]);
        let b = unlabelled("b", [198, 51, 100, 1]);
        assert!(
            !pair_diverse(&a, &b, &by_id),
            "two unlabelled relays must NOT be treated as different operators"
        );

        let mut c = unlabelled("c", [192, 0, 2, 1]);
        c.operator = Some("acme".into());
        assert!(
            !pair_diverse(&a, &c, &by_id),
            "an unlabelled relay paired with a labelled one is still unproven"
        );

        let d = fake_relay("d", RelayTier::Mix, [203, 0, 113, 2], "acme");
        let e = fake_relay("e", RelayTier::Mix, [198, 51, 100, 2], "globex");
        assert!(
            pair_diverse(&d, &e, &by_id),
            "two attested, distinct operators on distinct networks must be allowed"
        );
    }

    #[test]
    fn diversity_caps_bound_subnet_and_operator() {
        let mk = |i: usize, ip: [u8; 4]| {
            fake_relay(&format!("r{i}"), RelayTier::Mix, ip, &format!("op{i}"))
        };

        let same24: Vec<_> = (1..=6).map(|i| mk(i, [203, 0, 113, i as u8])).collect();
        assert_eq!(apply_diversity_caps(same24).len(), MAX_RELAYS_PER_24);

        let same16: Vec<_> = (0..20).map(|i| mk(i, [198, 51, i as u8, 1])).collect();
        assert_eq!(apply_diversity_caps(same16).len(), MAX_RELAYS_PER_16);

        let same_op: Vec<_> = (0..20)
            .map(|i| {
                fake_relay(
                    &format!("s{i}"),
                    RelayTier::Mix,
                    [40 + i as u8, 50 + i as u8, 0, 1],
                    "evil",
                )
            })
            .collect();
        assert_eq!(apply_diversity_caps(same_op).len(), MAX_RELAYS_PER_OPERATOR);

        let diverse: Vec<_> = (0..10)
            .map(|i| mk(i, [70 + i as u8, 80 + i as u8, 0, 1]))
            .collect();
        assert_eq!(apply_diversity_caps(diverse).len(), 10);
    }

    #[test]
    fn doc_canonical_bytes_deterministic() {
        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let r2 = fake_relay("b", RelayTier::Mix, [5, 6, 7, 8], "op2");
        let doc = DirectoryDoc {
            version: DIRECTORY_VERSION,
            valid_after: 1_000_000,
            valid_until: 1_001_000,
            relays: vec![r1.clone(), r2.clone()],
        };
        let b1 = doc.canonical_bytes().unwrap();
        let b2 = doc.canonical_bytes().unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        use rand::RngCore;
        r.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key();

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &signing_key).unwrap();
        signed
            .verify(&pubkey)
            .expect("freshly signed doc must verify");
    }

    #[test]
    fn authority_transition_verifies_and_rotates_trust() {
        let old = SigningKey::from_bytes(&[1u8; 32]);
        let new = SigningKey::from_bytes(&[2u8; 32]);
        let t = AuthorityKeyTransition::build(&old, &new);
        let (o, n) = t.verify().expect("transition self-verifies");
        assert_eq!(o, old.verifying_key().to_bytes());
        assert_eq!(n, new.verifying_key().to_bytes());

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &new).unwrap();
        assert!(signed.verify(&old.verifying_key()).is_err());
        signed
            .verify_with_transitions(&old.verifying_key(), std::slice::from_ref(&t))
            .expect("rotated key trusted via transition");
    }

    #[test]
    fn a_superseded_authority_key_is_refused() {
        let old = SigningKey::from_bytes(&[1u8; 32]);
        let new = SigningKey::from_bytes(&[2u8; 32]);
        let t = AuthorityKeyTransition::build(&old, &new);

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();

        let by_old = SignedDirectory::sign(doc.clone(), &old).unwrap();
        assert!(
            by_old
                .verify_with_transitions(&old.verifying_key(), std::slice::from_ref(&t))
                .is_err(),
            "a key that has been rotated away from must not sign directories",
        );

        let by_new = SignedDirectory::sign(doc, &new).unwrap();
        by_new
            .verify_with_transitions(&old.verifying_key(), std::slice::from_ref(&t))
            .expect("the successor key is the live one");
    }

    #[test]
    fn a_mid_chain_authority_key_is_refused() {
        let a = SigningKey::from_bytes(&[1u8; 32]);
        let b = SigningKey::from_bytes(&[2u8; 32]);
        let c = SigningKey::from_bytes(&[3u8; 32]);
        let chain = vec![
            AuthorityKeyTransition::build(&a, &b),
            AuthorityKeyTransition::build(&b, &c),
        ];

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();

        for (key, name) in [(&a, "the original"), (&b, "the intermediate")] {
            let signed = SignedDirectory::sign(doc.clone(), key).unwrap();
            assert!(
                signed
                    .verify_with_transitions(&a.verifying_key(), &chain)
                    .is_err(),
                "{name} key was superseded and must be refused",
            );
        }

        let signed = SignedDirectory::sign(doc, &c).unwrap();
        signed
            .verify_with_transitions(&a.verifying_key(), &chain)
            .expect("only the end of the chain signs");
    }

    #[test]
    fn a_forked_transition_chain_is_refused_outright() {
        let a = SigningKey::from_bytes(&[1u8; 32]);
        let b = SigningKey::from_bytes(&[2u8; 32]);
        let evil = SigningKey::from_bytes(&[9u8; 32]);
        let chain = vec![
            AuthorityKeyTransition::build(&a, &b),
            AuthorityKeyTransition::build(&a, &evil),
        ];

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();

        for (key, who) in [
            (&evil, "the forged successor"),
            (&b, "the honest successor"),
        ] {
            let signed = SignedDirectory::sign(doc.clone(), key).unwrap();
            assert!(
                signed
                    .verify_with_transitions(&a.verifying_key(), &chain)
                    .is_err(),
                "a forked chain must be refused even for {who}: the fork itself is the evidence",
            );
        }
        let dup = vec![
            AuthorityKeyTransition::build(&a, &b),
            AuthorityKeyTransition::build(&a, &b),
        ];
        SignedDirectory::sign(doc, &b)
            .unwrap()
            .verify_with_transitions(&a.verifying_key(), &dup)
            .expect("a duplicated edge is redundant, not contradictory");
    }

    #[test]
    fn a_fork_among_untrusted_keys_is_noise_not_a_refusal() {
        let a = SigningKey::from_bytes(&[1u8; 32]);
        let b = SigningKey::from_bytes(&[2u8; 32]);
        let x = SigningKey::from_bytes(&[7u8; 32]);
        let y = SigningKey::from_bytes(&[8u8; 32]);
        let z = SigningKey::from_bytes(&[9u8; 32]);
        let chain = vec![
            AuthorityKeyTransition::build(&x, &y),
            AuthorityKeyTransition::build(&a, &b),
            AuthorityKeyTransition::build(&x, &z),
        ];

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        SignedDirectory::sign(doc, &b)
            .unwrap()
            .verify_with_transitions(&a.verifying_key(), &chain)
            .expect("junk edges from keys we never trusted must not deny service");
    }

    #[test]
    fn a_withheld_rotation_still_lets_a_leaked_key_mint_one_successor() {
        let a = SigningKey::from_bytes(&[1u8; 32]);
        let evil = SigningKey::from_bytes(&[9u8; 32]);
        let only_evil = vec![AuthorityKeyTransition::build(&a, &evil)];

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &evil).unwrap();
        assert!(
            signed
                .verify_with_transitions(&a.verifying_key(), &only_evil)
                .is_ok(),
            "KNOWN LIMIT — if this starts failing, the containment landed: update \
             directory.rs's F-26 comment and the register's F-26 residual",
        );
    }

    #[test]
    fn authority_transition_rejects_tamper_and_unchained_key() {
        let old = SigningKey::from_bytes(&[1u8; 32]);
        let new = SigningKey::from_bytes(&[2u8; 32]);

        let mut t = AuthorityKeyTransition::build(&old, &new);
        t.new_pubkey_hex = hex::encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(t.verify().is_err());

        let rogue = SigningKey::from_bytes(&[3u8; 32]);
        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &rogue).unwrap();
        assert!(signed
            .verify_with_transitions(&old.verifying_key(), &[])
            .is_err());
    }

    #[test]
    fn verify_rejects_wrong_authority() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        use rand::RngCore;
        r.fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        r.fill_bytes(&mut seed);
        let imposter_pub = SigningKey::from_bytes(&seed).verifying_key();

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &signer).unwrap();
        assert!(matches!(
            signed.verify(&imposter_pub),
            Err(Error::Directory(_))
        ));
    }

    #[test]
    fn verify_rejects_tampered_doc() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        use rand::RngCore;
        r.fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        let pubkey = signer.verifying_key();

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let mut signed = SignedDirectory::sign(doc, &signer).unwrap();
        signed.doc.relays[0].addr = "9.9.9.9:443".to_string();
        assert!(matches!(signed.verify(&pubkey), Err(Error::Directory(_))));
    }

    #[test]
    fn verify_rejects_expired() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        use rand::RngCore;
        r.fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        let pubkey = signer.verifying_key();

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let mut doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        doc.valid_after = 1_000_000;
        doc.valid_until = 1_001_000;
        let signed = SignedDirectory::sign(doc, &signer).unwrap();
        assert!(matches!(signed.verify(&pubkey), Err(Error::Directory(_))));
    }

    #[test]
    fn a_replayed_older_directory_is_rejected_even_though_it_verifies() {
        use rand::RngCore;
        let mut r = rng();
        let mut seed = [0u8; 32];
        r.fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        let pubkey = signer.verifying_key();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mk = |valid_after: u64, relays: Vec<RelayDescriptor>| {
            let mut doc =
                DirectoryDoc::new(relays, std::time::Duration::from_secs(86_400)).unwrap();
            doc.valid_after = valid_after;
            doc.valid_until = now + 86_400;
            SignedDirectory::sign(doc, &signer).unwrap()
        };
        let older = mk(
            now - 7200,
            vec![fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1")],
        );
        let newer = mk(
            now - 3600,
            vec![
                fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1"),
                fake_relay("b", RelayTier::Mix, [5, 6, 7, 8], "op2"),
            ],
        );

        assert!(older.verify(&pubkey).is_ok());
        assert!(newer.verify(&pubkey).is_ok());

        let high = newer.verify_monotonic(&pubkey, 0).expect("newer accepted");
        assert_eq!(high, now - 3600);

        assert!(
            older.verify_monotonic(&pubkey, high).is_err(),
            "an older-but-still-valid directory must be rejected as a rollback"
        );
        assert_eq!(
            newer.verify_monotonic(&pubkey, high).unwrap(),
            high,
            "the current document must remain acceptable"
        );
        let mut stale = DirectoryDoc::new(
            vec![fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1")],
            std::time::Duration::from_secs(86_400),
        )
        .unwrap();
        stale.valid_after = now - 172_800;
        stale.valid_until = now - 86_400;
        let stale = SignedDirectory::sign(stale, &signer).unwrap();
        assert!(
            stale.verify(&pubkey).is_err(),
            "an expired directory must fail plain verification"
        );
        assert!(
            stale.verify_monotonic(&pubkey, 0).is_err(),
            "an expired directory must be refused whatever the high-water mark"
        );
        assert!(
            stale.verify_monotonic(&pubkey, now - 172_800).is_err(),
            "the high-water path must not short-circuit the validity window"
        );
    }

    #[test]
    fn verify_rejects_not_yet_valid() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        use rand::RngCore;
        r.fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        let pubkey = signer.verifying_key();

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let mut doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86_400;
        doc.valid_after = future;
        doc.valid_until = future + 86_400;
        let signed = SignedDirectory::sign(doc, &signer).unwrap();
        assert!(matches!(signed.verify(&pubkey), Err(Error::Directory(_))));
    }

    #[test]
    fn json_roundtrip() {
        let mut r = rng();
        let mut seed = [0u8; 32];
        use rand::RngCore;
        r.fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        let pubkey = signer.verifying_key();

        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let r2 = fake_relay("b", RelayTier::Mix, [5, 6, 7, 8], "op2");
        let r3 = fake_relay("c", RelayTier::Exit, [9, 10, 11, 12], "op3");
        let doc =
            DirectoryDoc::new(vec![r1, r2, r3], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &signer).unwrap();
        let json = signed.to_json_pretty().unwrap();
        let parsed = SignedDirectory::from_json(json.as_bytes()).unwrap();
        assert_eq!(parsed, signed);
        parsed.verify(&pubkey).unwrap();
    }

    #[test]
    fn pick_to_exit_forces_the_chosen_last_hop_ignoring_its_tier() {
        let mut r = rng();
        let entry = fake_relay("e", RelayTier::Entry, [1, 0, 0, 1], "opE");
        let mix = fake_relay("m", RelayTier::Mix, [2, 0, 0, 1], "opM");
        let host = fake_relay("h", RelayTier::Mix, [3, 0, 0, 1], "opH");
        let relays = vec![entry, mix, host.clone()];
        let path = PathSelector::new(&relays)
            .pick_to_exit(&mut r, 3, &host)
            .expect("path to the chosen exit");
        assert_eq!(path.hops.len(), 3);
        assert_eq!(
            path.hops[2].id_pubkey_hex, host.id_pubkey_hex,
            "last hop must be the forced host"
        );
        assert_eq!(path.hops[0].tier, RelayTier::Entry);
        assert!(
            path.hops[..2]
                .iter()
                .all(|h| h.id_pubkey_hex != host.id_pubkey_hex),
            "the forced exit must not also appear earlier in the path"
        );
    }

    fn make_balanced_directory() -> Vec<RelayDescriptor> {
        vec![
            fake_relay("a", RelayTier::Entry, [10, 0, 0, 1], "alice"),
            fake_relay("b", RelayTier::Entry, [192, 168, 0, 1], "bob"),
            fake_relay("c", RelayTier::Mix, [172, 16, 0, 1], "charlie"),
            fake_relay("d", RelayTier::Mix, [203, 0, 113, 1], "david"),
            fake_relay("e", RelayTier::Mix, [198, 51, 100, 1], "eve"),
            fake_relay("f", RelayTier::Mix, [100, 64, 0, 1], "frank"),
            fake_relay("g", RelayTier::Exit, [1, 1, 1, 1], "grace"),
            fake_relay("h", RelayTier::Exit, [8, 8, 8, 1], "henry"),
        ]
    }

    #[test]
    fn rendezvous_hosted_relays_inherit_rendezvous_network_for_caps() {
        let r = fake_relay("R", RelayTier::Mix, [10, 0, 0, 1], "opR");
        let r_id = r.id_pubkey_hex.clone();
        let mut set = vec![r];
        for i in 0..12u8 {
            let mut n = fake_relay(&format!("N{i}"), RelayTier::Mix, [172, 16, 0, i + 1], "opN");
            n.addr = String::new();
            n.rendezvous = Some(r_id.clone());
            set.push(n);
        }
        assert_eq!(apply_diversity_caps(set).len(), MAX_RELAYS_PER_24);
    }

    #[test]
    fn path_selection_splices_rendezvous_relay_before_hosted_mix() {
        let mut r = rng();
        let mut relays = vec![
            fake_relay("a", RelayTier::Entry, [10, 0, 0, 1], "alice"),
            fake_relay("b", RelayTier::Entry, [192, 168, 0, 1], "bob"),
            fake_relay("g", RelayTier::Exit, [1, 1, 1, 1], "grace"),
            fake_relay("h", RelayTier::Exit, [8, 8, 8, 1], "henry"),
        ];
        let mut rr = fake_relay("R", RelayTier::Mix, [172, 16, 0, 1], "rr");
        rr.rendezvous_capable = true;
        let r_id = rr.id_pubkey_hex.clone();
        let mut n = fake_relay("N", RelayTier::Mix, [0, 0, 0, 0], "nn");
        n.addr = String::new();
        n.rendezvous = Some(r_id.clone());
        let n_id = n.id_pubkey_hex.clone();
        relays.push(rr);
        relays.push(n);
        let sel = PathSelector::new(&relays);

        let mut saw_hosted = false;
        for _ in 0..60 {
            let path = sel.pick(&mut r, 3).expect("pick");
            if let Some(pos) = path.hops.iter().position(|h| h.id_pubkey_hex == n_id) {
                saw_hosted = true;
                assert!(pos > 0, "a hosted relay can never be the entry");
                assert_eq!(
                    path.hops[pos - 1].id_pubkey_hex,
                    r_id,
                    "the rendezvous relay R must be spliced immediately before N"
                );
            }
        }
        assert!(
            saw_hosted,
            "the hosted mix should be selected + spliced at least once"
        );
    }

    #[test]
    fn hosted_relay_with_absent_rendezvous_is_dropped_from_caps() {
        let mut n = fake_relay("N", RelayTier::Mix, [0, 0, 0, 0], "nn");
        n.addr = String::new();
        n.rendezvous =
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into());
        let direct = fake_relay("d", RelayTier::Mix, [203, 0, 113, 1], "dd");
        let kept = apply_diversity_caps(vec![n, direct]);
        assert_eq!(kept.len(), 1, "only the directly-reachable relay survives");
        assert_eq!(
            kept[0].id_pubkey_hex,
            fake_relay("d", RelayTier::Mix, [203, 0, 113, 1], "dd").id_pubkey_hex
        );
    }

    #[test]
    fn pick_3_hop_path() {
        let mut r = rng();
        let relays = make_balanced_directory();
        let sel = PathSelector::new(&relays);
        let path = sel.pick(&mut r, 3).expect("3-hop pick");
        assert_eq!(path.hops.len(), 3);
        assert_eq!(path.hops[0].tier, RelayTier::Entry);
        assert_eq!(path.hops[1].tier, RelayTier::Mix);
        assert_eq!(path.hops[2].tier, RelayTier::Exit);
    }

    #[test]
    fn pick_5_hop_path() {
        let mut r = rng();
        let relays = make_balanced_directory();
        let sel = PathSelector::new(&relays);
        let path = sel.pick(&mut r, 5).expect("5-hop pick");
        assert_eq!(path.hops.len(), 5);
        assert_eq!(path.hops[0].tier, RelayTier::Entry);
        assert_eq!(path.hops[4].tier, RelayTier::Exit);
        for h in &path.hops[1..4] {
            assert_eq!(h.tier, RelayTier::Mix);
        }
    }

    #[test]
    fn pick_rejects_invalid_hop_count() {
        let mut r = rng();
        let relays = make_balanced_directory();
        let sel = PathSelector::new(&relays);
        assert!(sel.pick(&mut r, 2).is_err());
        assert!(sel.pick(&mut r, 6).is_err());
    }

    #[test]
    fn pick_no_consecutive_same_operator() {
        let mut r = rng();
        let relays = make_balanced_directory();
        let sel = PathSelector::new(&relays);
        for _ in 0..20 {
            let path = sel.pick(&mut r, 3).unwrap();
            for w in path.hops.windows(2) {
                let (a, b) = (w[0], w[1]);
                if let (Some(oa), Some(ob)) = (&a.operator, &b.operator) {
                    assert_ne!(oa, ob, "consecutive hops shared operator");
                }
            }
        }
    }

    #[test]
    fn network_diverse_covers_v4_16_and_v6_48() {
        use std::net::IpAddr;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(!network_diverse(p("203.0.113.1"), p("203.0.200.9")));
        assert!(network_diverse(p("203.0.113.1"), p("198.51.100.1")));
        assert!(!network_diverse(
            p("2001:db8:1::1"),
            p("2001:db8:1:ffff::9")
        ));
        assert!(network_diverse(p("2001:db8:1::1"), p("2001:db8:2::1")));
        assert!(network_diverse(p("203.0.113.1"), p("2001:db8:1::1")));
        assert!(network_diverse(p("127.0.0.1"), p("127.0.0.2")));
    }

    #[test]
    fn pick_refuses_one_operator_at_both_ends() {
        let mut r = rng();
        let relays = vec![
            fake_relay("a", RelayTier::Entry, [10, 0, 0, 1], "colluder"),
            fake_relay("c", RelayTier::Mix, [172, 16, 0, 1], "charlie"),
            fake_relay("g", RelayTier::Exit, [1, 1, 1, 1], "colluder"),
        ];
        let sel = PathSelector::new(&relays);
        assert!(
            sel.pick(&mut r, 3).is_err(),
            "must refuse a path whose entry and exit share an operator"
        );
    }

    #[test]
    fn pick_entry_and_exit_always_distinct_operators() {
        let mut r = rng();
        let mut relays = make_balanced_directory();
        relays.push(fake_relay("x", RelayTier::Entry, [5, 5, 0, 1], "colluder"));
        relays.push(fake_relay("y", RelayTier::Exit, [6, 6, 0, 1], "colluder"));
        let sel = PathSelector::new(&relays);
        for _ in 0..50 {
            let path = sel.pick(&mut r, 3).unwrap();
            for i in 0..path.hops.len() {
                for j in (i + 1)..path.hops.len() {
                    assert_ne!(
                        path.hops[i].operator, path.hops[j].operator,
                        "two hops on the same path shared an operator"
                    );
                }
            }
        }
    }

    #[test]
    fn pick_fails_when_pool_too_small() {
        let mut r = rng();
        let relays = vec![fake_relay("a", RelayTier::Entry, [10, 0, 0, 1], "alice")];
        let sel = PathSelector::new(&relays);
        assert!(sel.pick(&mut r, 3).is_err());
    }

    #[test]
    fn descriptor_kem_pubkey_extraction() {
        let r = fake_relay("z", RelayTier::Mix, [10, 0, 0, 1], "op");
        let bytes = r.kem_pubkey_bytes().expect("decode kem pk");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn descriptor_ipv4_port_extraction() {
        let r = fake_relay("y", RelayTier::Entry, [10, 20, 30, 40], "op");
        assert_eq!(r.ipv4_octets().unwrap(), [10, 20, 30, 40]);
        assert_eq!(r.port().unwrap(), 443);
    }

    #[test]
    fn doc_relays_sorted_by_id() {
        let r1 = fake_relay("z", RelayTier::Mix, [1, 2, 3, 4], "op1");
        let r2 = fake_relay("a", RelayTier::Mix, [5, 6, 7, 8], "op2");
        let r3 = fake_relay("m", RelayTier::Mix, [9, 10, 11, 12], "op3");
        let doc =
            DirectoryDoc::new(vec![r1, r2, r3], std::time::Duration::from_secs(86_400)).unwrap();
        let mut sorted = doc.relays.clone();
        sorted.sort_by(|a, b| a.id_pubkey_hex.cmp(&b.id_pubkey_hex));
        assert_eq!(
            doc.relays, sorted,
            "doc.relays must be sorted by id_pubkey_hex"
        );
    }

    #[test]
    fn entry_guards_pin_the_first_hop_and_degrade_gracefully() {
        let mut r = rng();
        let relays = vec![
            fake_relay("a", RelayTier::Entry, [1, 1, 1, 1], "op1"),
            fake_relay("b", RelayTier::Entry, [2, 2, 2, 2], "op2"),
            fake_relay("c", RelayTier::Entry, [3, 3, 3, 3], "op3"),
            fake_relay("m", RelayTier::Mix, [4, 4, 4, 4], "op4"),
            fake_relay("n", RelayTier::Mix, [5, 5, 5, 5], "op5"),
            fake_relay("x", RelayTier::Exit, [6, 6, 6, 6], "op6"),
        ];
        let guards = vec![relays[0].id_pubkey_hex.clone()];

        for _ in 0..64 {
            let path = PathSelector::new(&relays)
                .with_guards(&guards)
                .pick(&mut r, 3)
                .expect("a guarded path must still be selectable");
            assert_eq!(path.hops[0].id_pubkey_hex, relays[0].id_pubkey_hex);
        }
        let exit = relays[5].clone();
        for _ in 0..32 {
            let path = PathSelector::new(&relays)
                .with_guards(&guards)
                .pick_to_exit(&mut r, 3, &exit)
                .expect("a guarded path to a forced exit must be selectable");
            assert_eq!(path.hops[0].id_pubkey_hex, relays[0].id_pubkey_hex);
        }

        let seen: std::collections::HashSet<String> = (0..64)
            .filter_map(|_| PathSelector::new(&relays).pick(&mut r, 3).ok())
            .map(|p| p.hops[0].id_pubkey_hex.clone())
            .collect();
        assert!(seen.len() > 1, "the unguarded selector must not be sticky");

        let gone = vec!["deadbeef".to_string()];
        assert!(PathSelector::new(&relays)
            .with_guards(&gone)
            .pick(&mut r, 3)
            .is_ok());

        assert!(PathSelector::new(&relays)
            .with_guards(&[])
            .pick(&mut r, 3)
            .is_ok());
    }
}
