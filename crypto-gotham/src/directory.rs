// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Directory authority — signed JSON list of available relays.
//!
//! The directory is the bootstrap source-of-truth for the mixnet: it
//! enumerates which relays are live, in which tier (entry / mix / exit),
//! and their cryptographic identity material (Ed25519 fingerprint + the
//! X25519 KEM key Sphinx encapsulates to).
//!
//! ## Signature scheme
//!
//! `SignedDirectory = { doc, authority_pubkey, signature }` where
//! `signature = Ed25519_sign(authority_sk, canonical_json(doc))`.
//!
//! Canonical JSON here means `serde_json::to_vec(&doc)` — deterministic
//! field order (the `#[derive(Serialize)]` macro emits fields in source
//! order) and no whitespace. Pretty-printing is forbidden in the signing
//! path.
//!
//! ## v0.1 limitations (deferred to v0.2)
//!
//! - Single Ed25519 authority key (v0.2: N-of-M multi-sig)
//! - JSON wire format (v0.2 may switch to MessagePack for size + canonical)
//! - No revocation list (v0.2: signed revocation records)
//! - No "consensus protocol" — the authority is a single source of truth
//!
//! ## Path selection
//!
//! [`PathSelector::pick`] implements the v0.1 selection algorithm:
//! 1. Pick exactly one relay from the `Entry` tier
//! 2. Pick the appropriate number of `Mix` relays
//! 3. Pick exactly one relay from the `Exit` tier
//! 4. Apply diversity constraints (no two consecutive hops from same
//!    operator / same /16 IPv4 / same country when possible)

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Current directory document version. Bumped on any schema change.
pub const DIRECTORY_VERSION: u8 = 1;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Which tier of the 3-tier mesh a relay serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayTier {
    /// First hop — sees client IP.
    Entry,
    /// Middle hop — sees only other relays.
    Mix,
    /// Last hop — sees recipient IP.
    Exit,
}

/// One relay's published descriptor.
///
/// `id_pubkey_hex` is the long-term Ed25519 identity (used for signing
/// the relay's own attestations and for the routing record's
/// `next_node_id` field). `kem_pubkey_hex` is the X25519 key Sphinx
/// encapsulates against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayDescriptor {
    /// Ed25519 identity public key (hex-encoded 64 chars).
    pub id_pubkey_hex: String,
    /// X25519 KEM public key (hex-encoded 64 chars).
    pub kem_pubkey_hex: String,
    /// Socket address — `"1.2.3.4:443"` for IPv4 or `"[::1]:443"` for IPv6.
    pub addr: String,
    /// Tier this relay serves.
    pub tier: RelayTier,
    /// Optional ISO 3166-1 alpha-2 country code (`"FR"`, `"DE"`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Optional autonomous system number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// Optional operator name (free-form, for transparency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Optional rolling uptime percentage (0.0 – 100.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_pct: Option<f32>,
    /// Whether this relay hosts a store-and-forward [`mailbox`](crate::mailbox)
    /// for offline delivery. Advertised so clients can pick a mailbox host;
    /// defaults to `false` and is absent from older directories.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mailbox: bool,
    /// RFC B3 reverse transport. When set, this relay is behind CGNAT and is
    /// **not** directly dialable at `addr`; it is reachable only via the
    /// rendezvous relay whose Ed25519 identity is this hex string. A path
    /// selector must place that rendezvous relay immediately before this one,
    /// and this relay inherits the rendezvous relay's network position for
    /// diversity accounting. Absent (`None`) for ordinary directly-reachable
    /// relays and older directories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,
    /// RFC B3. Whether this (directly-reachable) relay is willing to serve as a
    /// rendezvous point for CGNAT relays. Defaults to `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rendezvous_capable: bool,
}

impl RelayDescriptor {
    /// Decode the hex-encoded X25519 KEM pubkey into raw bytes.
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

    /// Decode the hex-encoded Ed25519 identity pubkey into raw bytes.
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

    /// Extract the IPv4 octets from the descriptor's `addr` field.
    /// Returns `Err` if the address is IPv6 (v0.2 will switch to a typed
    /// `SocketAddr` field).
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

    /// Extract the port from `addr`.
    pub fn port(&self) -> Result<u16> {
        let sa: std::net::SocketAddr = self
            .addr
            .parse()
            .map_err(|_| Error::Directory("bad addr"))?;
        Ok(sa.port())
    }

    /// The relay's IP address (v4 or v6), or `None` if `addr` doesn't parse.
    /// Used by path selection for network-diversity checks that must work for
    /// BOTH address families (unlike [`ipv4_octets`](Self::ipv4_octets)).
    #[must_use]
    pub fn ip_addr(&self) -> Option<std::net::IpAddr> {
        self.addr
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|sa| sa.ip())
    }
}

/// The unsigned directory document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryDoc {
    /// Schema version (must be [`DIRECTORY_VERSION`]).
    pub version: u8,
    /// Unix-seconds timestamp at which this document becomes valid.
    pub valid_after: u64,
    /// Unix-seconds timestamp at which this document expires.
    pub valid_until: u64,
    /// All published relays, in canonical (descriptor.id_pubkey_hex)
    /// order for determinism. Callers SHOULD sort before signing.
    pub relays: Vec<RelayDescriptor>,
}

impl DirectoryDoc {
    /// Build a doc with `valid_after = now`, `valid_until = now + duration`.
    /// Sorts `relays` by `id_pubkey_hex` for deterministic signing.
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

    /// Canonical bytes for signing — `serde_json::to_vec` (compact, no
    /// whitespace, field order preserved by the serde derive).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::Directory("serialize directory doc"))
    }
}

/// A signed directory document ready to publish.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedDirectory {
    /// The unsigned document.
    pub doc: DirectoryDoc,
    /// Hex-encoded Ed25519 authority public key (so recipients can pin it).
    pub authority_pubkey_hex: String,
    /// Hex-encoded Ed25519 signature over [`DirectoryDoc::canonical_bytes`].
    pub signature_hex: String,
}

impl SignedDirectory {
    /// Sign `doc` with `signing_key`. The authority pubkey is included
    /// alongside so consumers can verify it matches the one they pinned.
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

    /// Verify the signature against an authority public key pinned by
    /// the caller, AND check the document's validity window.
    ///
    /// Returns `Ok(())` if everything checks out. Caller MUST refuse to
    /// use the directory on any error.
    pub fn verify(&self, expected_authority: &VerifyingKey) -> Result<()> {
        // 1. Authority pubkey check.
        let expected_bytes = expected_authority.to_bytes();
        let actual = hex::decode(&self.authority_pubkey_hex)
            .map_err(|_| Error::Directory("bad authority pubkey hex"))?;
        if actual != expected_bytes {
            return Err(Error::Directory("authority pubkey mismatch"));
        }

        // 2. Signature check.
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

        // 3. Schema version.
        if self.doc.version != DIRECTORY_VERSION {
            return Err(Error::Directory("unsupported directory version"));
        }

        // 4. Validity window. Reject a degenerate/inverted window outright so
        //    a malformed (but correctly signed) doc can't pass the two-sided
        //    check inconsistently.
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

    /// Verify, then reject anything older than the newest document already seen.
    ///
    /// [`verify`](Self::verify) proves authenticity but says nothing about
    /// FRESHNESS beyond the validity window: within that window every signed
    /// document the authority ever published is equally acceptable. A malicious
    /// host, CDN or on-path attacker can therefore serve an OLD but still-valid
    /// directory — one published before a misbehaving relay was removed, or with
    /// a smaller relay set that narrows path selection toward relays the
    /// attacker controls — and the client accepts it with no way to tell.
    ///
    /// `seen_valid_after` is the largest `valid_after` this client has accepted
    /// so far (0 on first run). Because `valid_after` is inside the signed
    /// canonical bytes, it cannot be advanced by the attacker, which makes it a
    /// usable monotonic counter without a wire-format change.
    ///
    /// Returns the new high-water mark on success, for the caller to persist.
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

    /// Verify like [`Self::verify`], but accept a signing authority key that is
    /// either `pinned` OR transitively certified from `pinned` by a verified
    /// chain of [`AuthorityKeyTransition`]s. This lets a rotated authority key
    /// be trusted by clients that only pin the OLD key — closing the "authority
    /// key = update-only single point of failure" gap: publish the transition
    /// alongside the directory and existing installs adopt the new key without
    /// an app update. Trust only ever flows old → new.
    pub fn verify_with_transitions(
        &self,
        pinned: &VerifyingKey,
        transitions: &[AuthorityKeyTransition],
    ) -> Result<()> {
        // Bound attacker-supplied work: `transitions` is published alongside the
        // directory, so a hostile server could pad it. A real rotation history is
        // tiny, and the fixpoint below must not re-run Ed25519 verification once
        // per pass (that would be O(N²) signature checks on a crafted chain).
        const MAX_TRANSITIONS: usize = 64;
        if transitions.len() > MAX_TRANSITIONS {
            return Err(Error::Directory("too many key transitions"));
        }
        // Verify each transition's two signatures exactly ONCE, up front, into a
        // cheap in-memory edge list (invalid edges are dropped here).
        let edges: Vec<([u8; 32], [u8; 32])> =
            transitions.iter().filter_map(|t| t.verify().ok()).collect();

        let actual = decode_pubkey32(&self.authority_pubkey_hex)?;

        // Transitively expand the trust set over the verified edge list (HashSet
        // lookups only, no crypto): start at the pinned key and follow each
        // old→new edge until the set stops growing or the actual signer becomes
        // trusted (early exit — no need to expand further once it is reachable).
        let mut trusted: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        trusted.insert(pinned.to_bytes());
        while !trusted.contains(&actual) {
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

        if !trusted.contains(&actual) {
            return Err(Error::Directory(
                "authority pubkey not trusted: no rotation chain from the pinned key",
            ));
        }
        let signer = VerifyingKey::from_bytes(&actual)
            .map_err(|_| Error::Directory("bad authority pubkey"))?;
        // Reuse the full check (pubkey match, signature, schema, validity window).
        self.verify(&signer)
    }

    /// Serialize to a pretty-printed JSON string for publication.
    /// (Signing uses canonical compact JSON internally — pretty output
    /// is purely for human inspection; consumers always re-canonicalize.)
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|_| Error::Directory("serialize signed doc"))
    }

    /// Parse from a JSON byte slice. Does NOT verify the signature —
    /// always call [`Self::verify`] after parsing.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::Directory("parse signed doc"))
    }
}

// ─── Path selection ─────────────────────────────────────────────────────────

/// A selected path through the mesh: ordered list of relay descriptors.
#[derive(Debug, Clone)]
pub struct SelectedPath<'a> {
    /// Hops in order from entry to exit.
    pub hops: Vec<&'a RelayDescriptor>,
}

/// Pick a path through the mesh subject to v0.1 diversity rules.
pub struct PathSelector<'a> {
    relays: &'a [RelayDescriptor],
}

impl<'a> PathSelector<'a> {
    /// Wrap a slice of descriptors for path selection.
    #[must_use]
    pub fn new(relays: &'a [RelayDescriptor]) -> Self {
        Self { relays }
    }

    /// Pick one path with `hop_count` total hops (`3 ≤ hop_count ≤ 5`).
    ///
    /// Constraints applied (in order):
    /// 1. First hop must be from `Entry` tier
    /// 2. Last hop must be from `Exit` tier
    /// 3. Intermediate hops from `Mix` tier
    /// 4. No relay appears twice
    /// 5. No two hops **anywhere on the path** share an operator (if
    ///    `operator` present) — in particular entry ≠ exit operator, which
    ///    defeats single-operator sender↔recipient correlation
    /// 6. No two hops **anywhere on the path** share a /16 IPv4 prefix
    /// 7. Best-effort country diversity (warn but don't fail)
    ///
    /// Returns `Err` if not enough relays exist to satisfy constraints.
    pub fn pick<R: Rng>(&self, rng: &mut R, hop_count: usize) -> Result<SelectedPath<'a>> {
        if !(3..=5).contains(&hop_count) {
            return Err(Error::Directory("hop_count must be 3..=5"));
        }
        let mix_count = hop_count - 2;

        // RFC B3: a rendezvous-hosted (CGNAT) relay is usable only as a MIDDLE
        // hop, and only spliced immediately AFTER its rendezvous relay R (see the
        // mix loop). It is never an entry or exit (those see the client /
        // recipient IP and a CGNAT relay has none). Entry/exit pools therefore
        // exclude hosted relays; the mix pool includes them.
        let by_id = index_by_id(self.relays);
        let entries: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Entry && r.rendezvous.is_none())
            .collect();
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

        // Try up to N times to find a path satisfying the diversity constraints.
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
            // Place `mix_count` middle hops. A rendezvous-hosted mix N is spliced
            // as its rendezvous relay R followed by N (R is a transparent extra
            // hop that does not count toward mix_count); the R→N adjacency is
            // exempt from the /16 rule (they share a network by construction),
            // and N inherits R's position so it is already diverse against the
            // prefix.
            let mut mixes_placed = 0usize;
            for m in chosen_mixes.iter() {
                if mixes_placed == mix_count {
                    break;
                }
                if let Some(r_hex) = m.rendezvous.as_deref() {
                    // Hosted mix: resolve + splice R.
                    let Some(r) = by_id.get(r_hex).copied() else {
                        continue; // R absent from the directory → not routable
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
                    // Direct mix: diverse against the ENTIRE prefix.
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
                // Exit must be diverse from EVERY prior hop — crucially the
                // entry — so no single operator sits on both ends of the flow.
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

    /// Like [`pick`](Self::pick), but the LAST hop is forced to `exit` (a
    /// specific relay) instead of a random Exit-tier node. Used to route a
    /// message to a chosen relay — e.g. a store-and-forward mailbox host — so a
    /// deposit can ride the mixnet (hiding the depositor's IP) instead of a
    /// direct connection. Entry + mixes are still diversity-selected and never
    /// reuse `exit`. `exit`'s advertised tier is ignored (the caller chose it on
    /// purpose); only the /16 + operator adjacency rule to the last mix applies.
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

        // RFC B3: rendezvous-hosted relays are not routable until Phase 2 — see
        // `pick`. (`exit` is caller-forced; the caller owns its routability.)
        let by_id = index_by_id(self.relays);
        let entries: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.tier == RelayTier::Entry && r.rendezvous.is_none())
            .filter(|r| r.id_pubkey_hex != exit.id_pubkey_hex)
            .collect();
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

            // Force the chosen exit — but it must still be diverse from every
            // prior hop (entry included), so the forced exit can never collude
            // with the entry operator to correlate sender↔recipient.
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

/// True if `cand` is diverse (operator + /16) against **every** relay already
/// in `existing` — not just the last one. This is what closes the
/// single-operator end-to-end correlation attack: if diversity were only
/// checked between consecutive hops, one operator could run both the entry and
/// the exit of the same flow (adjacent to neither of its own nodes) and observe
/// the sender IP at the entry and the recipient IP at the exit simultaneously.
/// Enforcing diversity against the whole prefix guarantees no operator (and no
/// /16) appears twice anywhere on the path, so entry and exit are always
/// distinct operators / networks.
/// Index identity-hex → descriptor, for RFC B3 rendezvous resolution.
type IdIndex<'a> = std::collections::HashMap<&'a str, &'a RelayDescriptor>;

fn index_by_id(relays: &[RelayDescriptor]) -> IdIndex<'_> {
    relays
        .iter()
        .map(|r| (r.id_pubkey_hex.as_str(), r))
        .collect()
}

/// The IP address a descriptor occupies for DIVERSITY purposes. RFC B3: a
/// rendezvous-hosted relay (`rendezvous` set) has no address of its own — it
/// sits behind its rendezvous relay R and therefore INHERITS R's network
/// position. Without this, an adversary could multiply its subnet/operator share
/// by hiding many relays behind one R and defeat the network-diversity guarantee.
/// Returns `None` when the relay is rendezvous-hosted but R is absent from the
/// set (it is then unroutable and never selected).
fn eff_diversity_ip(d: &RelayDescriptor, by_id: &IdIndex) -> Option<std::net::IpAddr> {
    match &d.rendezvous {
        Some(rid) => by_id.get(rid.as_str()).and_then(|r| r.ip_addr()),
        None => d.ip_addr(),
    }
}

/// The operator label a descriptor occupies for diversity. RFC B3: a rendezvous-
/// hosted relay inherits its rendezvous relay R's operator, so an operator cannot
/// dodge the per-operator cap by hiding relays behind its own rendezvous point.
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

/// True if `a` and `b` may share a path (operator + /16 diversity). RFC B3
/// rendezvous-hosted relays are compared on their rendezvous relay's network
/// position (see [`eff_diversity_ip`]).
fn pair_diverse(a: &RelayDescriptor, b: &RelayDescriptor, by_id: &IdIndex) -> bool {
    // Operator diversity (only enforced if BOTH have an operator set).
    //
    // RESIDUAL LIMITATION: gossip-admitted relays carry `operator: None` (the
    // self-signed advertisement has no operator field), so on the self-forming
    // network this check is inert and network diversity (/16, /48 below) is the
    // real guarantee. Defeating a Sybil operator who runs relays across several
    // subnets requires *operator attestation* (labels bound by the authority
    // set), which is future work — see docs/gotham/README.md.
    if let (Some(op_a), Some(op_b)) = (eff_operator(a, by_id), eff_operator(b, by_id)) {
        if op_a == op_b {
            return false;
        }
    }
    let (ea, eb) = (eff_diversity_ip(a, by_id), eff_diversity_ip(b, by_id));
    // Fail CLOSED: a rendezvous-hosted relay whose R is absent has no resolvable
    // network position — treat it as NON-diverse, never silently diverse (which
    // the `if let (Some, Some)` below would otherwise do).
    if (a.rendezvous.is_some() && ea.is_none()) || (b.rendezvous.is_some() && eb.is_none()) {
        return false;
    }
    // Network diversity: reject same /16 (IPv4) or same /48 (IPv6). Enforced
    // whenever both effective addresses parse; non-routable addresses never reach
    // a signed production directory (rejected at enrollment/ingest), so the
    // loopback relaxation below only ever fires for local integration tests.
    if let (Some(ip_a), Some(ip_b)) = (ea, eb) {
        if !network_diverse(ip_a, ip_b) {
            return false;
        }
    }
    true
}

/// True if `a` and `b` sit in different network blocks: different /16 for IPv4
/// (different /48 for IPv6), i.e. they may share a path. Two loopback addresses
/// are treated as diverse ONLY so local integration tests can stand up several
/// relays on 127.0.0.0/8; production directories never carry loopback (ingest
/// rejects it — see [`crate::enroll::RelayEnrollment::validate`]).
fn network_diverse(a: std::net::IpAddr, b: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let (oa, ob) = (a.octets(), b.octets());
            if a.is_loopback() && b.is_loopback() {
                return true; // test-only relaxation
            }
            oa[0] != ob[0] || oa[1] != ob[1]
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let (oa, ob) = (a.octets(), b.octets());
            if a.is_loopback() && b.is_loopback() {
                return true; // test-only relaxation
            }
            // /48 = first 6 bytes.
            oa[..6] != ob[..6]
        }
        // Mixed families can't collide on a subnet.
        _ => true,
    }
}

/// Directory-wide anti-Sybil concentration caps.
///
/// `pair_diverse`/`path_diverse` bound diversity along a SINGLE selected path;
/// they do not bound how much of the WHOLE directory one actor controls. These
/// caps do: at directory-build time we keep at most this many relays per IPv4
/// /24 and /16 (per IPv6 /48), and per operator label — so an adversary who
/// floods relays from one subnet or operator cannot buy a proportional share of
/// path selection. Mixnet compromise scales ~ (adversary fraction)^2 at the
/// first+last hop, so bounding population share is the load-bearing control on
/// an open network.
pub const MAX_RELAYS_PER_24: usize = 3;
/// Max relays kept per IPv4 /16. See [`MAX_RELAYS_PER_24`].
pub const MAX_RELAYS_PER_16: usize = 8;
/// Max relays kept per IPv6 /48. See [`MAX_RELAYS_PER_24`].
pub const MAX_RELAYS_PER_48: usize = 8;
/// Max relays kept per operator label (only enforced when the label is set).
pub const MAX_RELAYS_PER_OPERATOR: usize = 5;

/// Enforce the directory-wide concentration caps above, returning the retained
/// descriptors. The input SHOULD already be in a deterministic order (the
/// authority sorts by identity key first) so the retained set is reproducible
/// and the signature stable; within each over-subscribed bucket the earliest
/// entries in that order are kept.
pub fn apply_diversity_caps(descriptors: Vec<RelayDescriptor>) -> Vec<RelayDescriptor> {
    use std::collections::HashMap;
    use std::net::IpAddr;

    // RFC B3: resolve each relay's EFFECTIVE diversity IP before consuming the
    // vec — a rendezvous-hosted relay inherits its rendezvous R's network
    // position, so it counts against R's /24 //16 //48 budget. Without this an
    // adversary would hide many relays behind one R and buy extra subnet share.
    // Positional (index-aligned with `descriptors`), NOT keyed by identity, so
    // it is robust to duplicate identity keys.
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

        // RFC B3: a rendezvous-hosted relay whose R is absent has no network
        // position — it is unroutable AND (with ip == None) would escape the
        // caps entirely. Drop it rather than keep it uncapped.
        if d.rendezvous.is_some() && ip.is_none() {
            continue;
        }

        // Network concentration.
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
            // Unparseable addresses are rejected at enrollment; don't cap-drop.
            None => true,
        };

        // Operator concentration (effective label — a hosted relay inherits R's).
        let op_ok = match eff_ops[i].as_deref() {
            Some(op) => per_op.get(op).copied().unwrap_or(0) < MAX_RELAYS_PER_OPERATOR,
            None => true,
        };

        if !(net_ok && op_ok) {
            continue;
        }

        // Commit the counts for the retained relay.
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

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Decode a hex string into a 32-byte Ed25519 public key.
fn decode_pubkey32(hex_str: &str) -> Result<[u8; 32]> {
    hex::decode(hex_str)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Directory("authority key not 32-byte hex"))
}

/// Verify a detached hex signature over `msg` under the given pubkey bytes.
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

/// A signed directory-authority key transition (rotation) certificate.
///
/// The OLD authority key certifies its successor and the NEW key proves
/// possession — both sign the same domain-separated statement. Published
/// alongside the directory so clients that only pin the OLD key can adopt the
/// rotated key without an app update (see
/// [`SignedDirectory::verify_with_transitions`]). Trust flows old → new only,
/// so a compromised NEW key can never certify itself back onto an old anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityKeyTransition {
    /// Hex-encoded Ed25519 pubkey of the outgoing (certifying) authority key.
    pub old_pubkey_hex: String,
    /// Hex-encoded Ed25519 pubkey of the incoming (successor) authority key.
    pub new_pubkey_hex: String,
    /// `old` key's signature over [`Self::signing_bytes`].
    pub sig_old_hex: String,
    /// `new` key's signature over [`Self::signing_bytes`] (proof of possession).
    pub sig_new_hex: String,
}

impl AuthorityKeyTransition {
    const DOMAIN: &'static [u8] = b"gotham-authority-transition-v1";

    /// Canonical bytes both keys sign: `DOMAIN || old_pub(32) || new_pub(32)`.
    fn signing_bytes(old_pub: &[u8; 32], new_pub: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::DOMAIN.len() + 64);
        b.extend_from_slice(Self::DOMAIN);
        b.extend_from_slice(old_pub);
        b.extend_from_slice(new_pub);
        b
    }

    /// Build a transition certifying `new` as the successor of `old`. Sign this
    /// with the OFFLINE/HSM-held old key, then rotate the online signer to `new`.
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

    /// Verify BOTH signatures over the canonical statement. Returns
    /// `(old_pubkey, new_pubkey)` on success.
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
    fn diversity_caps_bound_subnet_and_operator() {
        // Distinct operators so the operator cap never masks the network caps.
        let mk = |i: usize, ip: [u8; 4]| {
            fake_relay(&format!("r{i}"), RelayTier::Mix, ip, &format!("op{i}"))
        };

        // 6 relays in 203.0.113.0/24 → capped to the /24 limit.
        let same24: Vec<_> = (1..=6).map(|i| mk(i, [203, 0, 113, i as u8])).collect();
        assert_eq!(apply_diversity_caps(same24).len(), MAX_RELAYS_PER_24);

        // 20 relays across distinct /24s of one /16 → capped to the /16 limit.
        let same16: Vec<_> = (0..20).map(|i| mk(i, [198, 51, i as u8, 1])).collect();
        assert_eq!(apply_diversity_caps(same16).len(), MAX_RELAYS_PER_16);

        // 20 relays, one operator, all distinct /16s → capped to the operator limit.
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

        // Fully diverse relays (distinct /16 + operator) are all kept.
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

        // A directory signed by the NEW key is rejected by the OLD pin alone…
        let r1 = fake_relay("a", RelayTier::Entry, [1, 2, 3, 4], "op1");
        let doc = DirectoryDoc::new(vec![r1], std::time::Duration::from_secs(86_400)).unwrap();
        let signed = SignedDirectory::sign(doc, &new).unwrap();
        assert!(signed.verify(&old.verifying_key()).is_err());
        // …but accepted once the transition chain from the pinned old key is given.
        signed
            .verify_with_transitions(&old.verifying_key(), std::slice::from_ref(&t))
            .expect("rotated key trusted via transition");
    }

    #[test]
    fn authority_transition_rejects_tamper_and_unchained_key() {
        let old = SigningKey::from_bytes(&[1u8; 32]);
        let new = SigningKey::from_bytes(&[2u8; 32]);

        // A transition tampered after signing (new_pub swapped) fails to verify.
        let mut t = AuthorityKeyTransition::build(&old, &new);
        t.new_pubkey_hex = hex::encode(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(t.verify().is_err());

        // A directory signed by an unrelated key with no transition is rejected.
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
        // Mutate the doc — should now fail verification.
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
        // Force expiration into the past.
        doc.valid_after = 1_000_000;
        doc.valid_until = 1_001_000;
        let signed = SignedDirectory::sign(doc, &signer).unwrap();
        assert!(matches!(signed.verify(&pubkey), Err(Error::Directory(_))));
    }

    /// Authenticity is not freshness. Inside the validity window EVERY document
    /// the authority ever signed verifies equally, so a malicious host or
    /// on-path attacker can replay an OLD one — e.g. from before a misbehaving
    /// relay was removed, or with a smaller relay set that narrows path
    /// selection toward relays they run. `valid_after` is inside the signed
    /// bytes, so it cannot be forged forward and serves as a monotonic counter.
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

        // Two genuine documents, both currently valid; `newer` was published an
        // hour after `older`. `older` names FEWER relays — the attacker's goal.
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

        // Both are authentic — plain `verify` cannot tell them apart.
        assert!(older.verify(&pubkey).is_ok());
        assert!(newer.verify(&pubkey).is_ok());

        // Accept the newer one, recording its high-water mark…
        let high = newer.verify_monotonic(&pubkey, 0).expect("newer accepted");
        assert_eq!(high, now - 3600);

        // …after which replaying the older one is refused.
        assert!(
            older.verify_monotonic(&pubkey, high).is_err(),
            "an older-but-still-valid directory must be rejected as a rollback"
        );
        // Re-serving the SAME document is fine (not a rollback) — clients
        // refetch on a timer and must not lock themselves out.
        assert_eq!(
            newer.verify_monotonic(&pubkey, high).unwrap(),
            high,
            "the current document must remain acceptable"
        );
        // An expired document is still rejected on its own terms.
        assert!(older.verify_monotonic(&pubkey, 0).is_ok());
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
        // Future validity window.
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
        // The forced exit is tagged MIX (e.g. a mailbox host that isn't an Exit)
        // — pick_to_exit must still place it last, with its tier ignored.
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

    // ─── RFC B3 rendezvous transport ───────────────────────────────────────

    #[test]
    fn rendezvous_hosted_relays_inherit_rendezvous_network_for_caps() {
        // One rendezvous relay R and many CGNAT relays hosted behind it. Each
        // hosted relay has no address of its own; RFC B3 makes it inherit R's
        // network position, so they all compete for R's /24 budget instead of
        // escaping the caps (which they would if their `None` address counted as
        // "no network"). Without inheritance all 13 would be kept.
        let r = fake_relay("R", RelayTier::Mix, [10, 0, 0, 1], "opR");
        let r_id = r.id_pubkey_hex.clone();
        let mut set = vec![r];
        for i in 0..12u8 {
            let mut n = fake_relay(&format!("N{i}"), RelayTier::Mix, [172, 16, 0, i + 1], "opN");
            n.addr = String::new(); // CGNAT: not directly dialable
            n.rendezvous = Some(r_id.clone());
            set.push(n);
        }
        // All 13 resolve to R's 10.0.0.1 → same /24 → bounded by the /24 cap.
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
        // A rendezvous-capable direct mix R and a CGNAT mix N hosted by it.
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

        // Over many picks, N is sometimes the chosen middle hop; whenever it is,
        // its rendezvous relay R must sit immediately before it (never as entry).
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
        // RFC B3 fail-closed: a CGNAT relay whose R is not in the set has no
        // network position and must NOT be kept (it would otherwise escape the
        // concentration caps entirely).
        let mut n = fake_relay("N", RelayTier::Mix, [0, 0, 0, 0], "nn");
        n.addr = String::new();
        n.rendezvous = Some(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(), // absent R
        );
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
        // Build a directory where it's impossible to pick a path without
        // sharing operators only if we have enough variety.
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
        // IPv4 /16.
        assert!(!network_diverse(p("203.0.113.1"), p("203.0.200.9")));
        assert!(network_diverse(p("203.0.113.1"), p("198.51.100.1")));
        // IPv6 /48 (first 6 bytes).
        assert!(!network_diverse(
            p("2001:db8:1::1"),
            p("2001:db8:1:ffff::9")
        ));
        assert!(network_diverse(p("2001:db8:1::1"), p("2001:db8:2::1")));
        // Mixed families never collide.
        assert!(network_diverse(p("203.0.113.1"), p("2001:db8:1::1")));
        // Loopback relaxation is test-only (both must be loopback).
        assert!(network_diverse(p("127.0.0.1"), p("127.0.0.2")));
    }

    #[test]
    fn pick_refuses_one_operator_at_both_ends() {
        // A colluding operator runs BOTH an entry and an exit node (distinct
        // keys, distinct /16 — so ONLY the operator rule can catch it). With no
        // other exit available, a diverse path is impossible, and `pick` must
        // FAIL rather than hand the same operator both the sender IP (entry) and
        // the recipient IP (exit) — the single-operator correlation attack.
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
        // With honest alternatives present, picks succeed, but the entry and
        // exit operators must never coincide even though they are non-adjacent
        // hops — and no operator may appear twice anywhere on the path.
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
        // Only entries, no exits / mixes.
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
}
