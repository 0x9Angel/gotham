// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! k-of-n authority attestation — the Sybil-resistance trust anchor for the
//! decentralised gossip directory.
//!
//! A self-signed [`Advertisement`](crate::Advertisement) proves a relay
//! controls its key, but not that it is a *legitimate* relay: anyone can mint a
//! key and advertise. The v0.1 static directory papered over this with a single
//! authority signing the whole roster — one key whose compromise forges the
//! entire network (k = 1, n = 1). The decentralised directory replaces that
//! single point of trust with a **quorum**: a relay is admissible only if at
//! least `k` of `n` pinned directory authorities have signed an
//! [`AdmissionCert`] for its identity key.
//!
//! Consumers pin the [`AuthoritySet`] out of band (bootstrap seeds) and reject
//! any relay lacking a valid quorum, so forging a relay now costs `k`
//! independent authority compromises instead of one. The authorities never
//! need to be online together or agree on a global snapshot — each signs a
//! relay's `(identity, epoch)` independently, and the `k` signatures travel
//! with that relay through the gossip layer.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::error::{DirectoryError, Result};

/// Domain-separation tag for the bytes an authority signs. Versioned so a
/// future admission-message change can't be confused with this one.
const ADMISSION_DOMAIN: &[u8] = b"gotham-admission-v1|";

/// Maximum age of an admission certificate a consumer will accept, in seconds
/// (30 days). This is the **revocation latency**: authorities revoke a relay by
/// declining to re-sign a newer epoch, and consumers stop admitting it once the
/// last cert ages past this window. A captured old cert therefore cannot admit
/// a relay indefinitely.
pub const MAX_ADMISSION_AGE_SECS: u64 = 30 * 24 * 3600;

/// Clock-skew tolerance for an admission's epoch being slightly in the future.
pub const ADMISSION_CLOCK_SKEW_SECS: u64 = 3600;

/// The pinned set of directory authorities and the admission threshold `k`.
///
/// Pinned by every consumer as the bootstrap trust anchor. `threshold` is the
/// minimum number of DISTINCT authority signatures a relay must collect to be
/// admitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthoritySet {
    /// Authority Ed25519 verifying keys, hex-encoded (64 chars each).
    pub authorities_hex: Vec<String>,
    /// Minimum number of distinct valid authority signatures to admit a relay.
    /// Invariant: `1..=authorities_hex.len()`.
    pub threshold: usize,
}

impl AuthoritySet {
    /// Build a set from authority verifying keys + a threshold. Rejects an
    /// empty list, an out-of-range threshold, or duplicate keys (a duplicate
    /// would let one authority count more than once toward `k`).
    pub fn new(authorities: &[VerifyingKey], threshold: usize) -> Result<Self> {
        if authorities.is_empty() {
            return Err(DirectoryError::Other("authority set is empty".into()));
        }
        if threshold == 0 || threshold > authorities.len() {
            return Err(DirectoryError::Other(format!(
                "threshold {threshold} out of range 1..={}",
                authorities.len()
            )));
        }
        let authorities_hex: Vec<String> = authorities
            .iter()
            .map(|k| hex::encode(k.to_bytes()))
            .collect();
        let unique: BTreeSet<&String> = authorities_hex.iter().collect();
        if unique.len() != authorities_hex.len() {
            return Err(DirectoryError::Other("duplicate authority key".into()));
        }
        Ok(Self {
            authorities_hex,
            threshold,
        })
    }

    /// Number of authorities (`n`).
    pub fn n(&self) -> usize {
        self.authorities_hex.len()
    }

    /// Is `pk_hex` one of the pinned authorities? (case-insensitive)
    fn contains(&self, pk_hex: &str) -> bool {
        self.authorities_hex
            .iter()
            .any(|a| a.eq_ignore_ascii_case(pk_hex))
    }
}

/// One authority's signature over an admission message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attestation {
    /// The signing authority's Ed25519 verifying key, hex-encoded.
    pub authority_pk_hex: String,
    /// Ed25519 signature over the admission's canonical bytes, hex-encoded.
    pub signature_hex: String,
}

/// A relay's k-of-n admission certificate: proof that a quorum of pinned
/// authorities vouched for its identity key at a given epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdmissionCert {
    /// The admitted relay's Ed25519 identity key, hex-encoded (must match the
    /// advertisement's `identity_pk_hex`).
    pub identity_pk_hex: String,
    /// Admission epoch (unix seconds). Lets consumers require re-attestation
    /// and lets authorities revoke by simply not re-signing a newer epoch.
    pub epoch: u64,
    /// Authority-attested **operator label**, bound into the signed bytes. When
    /// present it is projected onto [`RelayDescriptor::operator`], making the
    /// path selector's operator-diversity check effective on gossip-admitted
    /// relays (whose self-signed advertisement carries no operator field).
    ///
    /// SECURITY NOTE: this is a *mechanism*. It only yields Sybil resistance if
    /// the authorities REFUSE to attest dishonest/duplicate labels — a
    /// deployment policy the authority set must enforce; the code merely carries
    /// and binds the label. `None` ⇒ no operator diversity for this relay (falls
    /// back to /16 // /48 network diversity).
    #[serde(default)]
    pub operator: Option<String>,
    /// The collected authority signatures.
    pub attestations: Vec<Attestation>,
}

impl AdmissionCert {
    /// Canonical bytes an authority signs: domain tag + identity + epoch +
    /// operator label, with an unambiguous `|` separator (`|` never appears in
    /// hex or a decimal number, and the operator segment is last).
    pub fn admission_bytes(identity_pk_hex: &str, epoch: u64, operator: Option<&str>) -> Vec<u8> {
        let op = operator.unwrap_or("");
        let mut v =
            Vec::with_capacity(ADMISSION_DOMAIN.len() + identity_pk_hex.len() + 24 + op.len());
        v.extend_from_slice(ADMISSION_DOMAIN);
        v.extend_from_slice(identity_pk_hex.as_bytes());
        v.push(b'|');
        v.extend_from_slice(epoch.to_string().as_bytes());
        v.push(b'|');
        v.extend_from_slice(op.as_bytes());
        v
    }

    /// Produce one authority's attestation for `(identity_pk_hex, epoch,
    /// operator)`. Each authority calls this independently; the relay collects
    /// `k` of them.
    pub fn attest(
        authority: &SigningKey,
        identity_pk_hex: &str,
        epoch: u64,
        operator: Option<&str>,
    ) -> Attestation {
        let msg = Self::admission_bytes(identity_pk_hex, epoch, operator);
        let sig: Signature = authority.sign(&msg);
        Attestation {
            authority_pk_hex: hex::encode(authority.verifying_key().to_bytes()),
            signature_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// Assemble a certificate from collected attestations.
    pub fn assemble(
        identity_pk_hex: String,
        epoch: u64,
        operator: Option<String>,
        attestations: Vec<Attestation>,
    ) -> Self {
        Self {
            identity_pk_hex,
            epoch,
            operator,
            attestations,
        }
    }

    /// Is this cert's epoch fresh at `now` — within [`MAX_ADMISSION_AGE_SECS`]
    /// in the past and no more than [`ADMISSION_CLOCK_SKEW_SECS`] in the
    /// future? A stale cert must be rejected so revocation-by-non-renewal has
    /// teeth; a far-future epoch (which would stay "fresh" forever) is refused.
    pub fn is_fresh(&self, now: u64) -> bool {
        self.epoch <= now.saturating_add(ADMISSION_CLOCK_SKEW_SECS)
            && now.saturating_sub(self.epoch) <= MAX_ADMISSION_AGE_SECS
    }

    /// Verify against a pinned [`AuthoritySet`]. Every *counted* attestation
    /// must (a) come from a distinct pinned authority and (b) carry a valid
    /// signature over `(identity_pk_hex, epoch)`. Unknown-authority, duplicate,
    /// and bad-signature attestations are ignored rather than fatal — so a cert
    /// padded with junk still verifies iff a genuine quorum is present, and an
    /// attacker cannot invalidate a good cert by appending garbage.
    ///
    /// Returns the number of valid distinct signatures on success, or
    /// [`DirectoryError::InsufficientQuorum`] if it falls short of `k`.
    pub fn verify(&self, set: &AuthoritySet) -> Result<usize> {
        let msg =
            Self::admission_bytes(&self.identity_pk_hex, self.epoch, self.operator.as_deref());
        let mut counted: BTreeSet<String> = BTreeSet::new();
        // Each pinned authority is verified AT MOST ONCE (tracked in
        // `attempted`, whether or not the signature checks out). This bounds the
        // signature checks to `n` regardless of how many junk attestations a
        // cert carries — otherwise a cert padded with thousands of
        // pinned-authority-named-but-invalid attestations would force a full
        // ed25519 verify each (an attestation-flooding CPU-DoS amplifier over
        // gossip). A legitimately-issued cert has one attestation per authority,
        // so this never rejects an honest cert.
        let mut attempted: BTreeSet<String> = BTreeSet::new();
        for att in &self.attestations {
            let pk_hex = att.authority_pk_hex.to_lowercase();
            if !set.contains(&pk_hex) || attempted.contains(&pk_hex) {
                continue;
            }
            attempted.insert(pk_hex.clone());
            if verify_att(&pk_hex, &att.signature_hex, &msg).is_ok() {
                counted.insert(pk_hex);
            }
        }
        if counted.len() >= set.threshold {
            Ok(counted.len())
        } else {
            Err(DirectoryError::InsufficientQuorum {
                got: counted.len(),
                need: set.threshold,
            })
        }
    }
}

/// Verify one authority signature over `msg`.
fn verify_att(pk_hex: &str, sig_hex: &str, msg: &[u8]) -> Result<()> {
    let pk_bytes: [u8; 32] = hex::decode(pk_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| DirectoryError::Other("authority pk wrong length".into()))?;
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| DirectoryError::BadSignature)?;
    let sig_bytes: [u8; SIGNATURE_LENGTH] = hex::decode(sig_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| DirectoryError::Other("signature wrong length".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    pk.verify(msg, &sig)
        .map_err(|_| DirectoryError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn authorities(n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
    }

    fn verifying(keys: &[SigningKey]) -> Vec<VerifyingKey> {
        keys.iter().map(|k| k.verifying_key()).collect()
    }

    #[test]
    fn quorum_of_k_of_n_admits() {
        let auth = authorities(5);
        let set = AuthoritySet::new(&verifying(&auth), 3).unwrap();
        let id = "bb".repeat(32);
        // 3 of 5 authorities attest → meets threshold.
        let atts: Vec<Attestation> = auth[..3]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, 1000, None))
            .collect();
        let cert = AdmissionCert::assemble(id, 1000, None, atts);
        assert_eq!(cert.verify(&set).unwrap(), 3);
    }

    #[test]
    fn below_threshold_is_rejected() {
        let auth = authorities(5);
        let set = AuthoritySet::new(&verifying(&auth), 3).unwrap();
        let id = "cc".repeat(32);
        let atts: Vec<Attestation> = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, 1, None))
            .collect();
        let cert = AdmissionCert::assemble(id, 1, None, atts);
        assert!(matches!(
            cert.verify(&set),
            Err(DirectoryError::InsufficientQuorum { got: 2, need: 3 })
        ));
    }

    #[test]
    fn unknown_authority_does_not_count() {
        let auth = authorities(3);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        let id = "dd".repeat(32);
        // Two attestations: one real authority, one outsider. Only 1 counts.
        let outsider = SigningKey::generate(&mut OsRng);
        let atts = vec![
            AdmissionCert::attest(&auth[0], &id, 7, None),
            AdmissionCert::attest(&outsider, &id, 7, None),
        ];
        let cert = AdmissionCert::assemble(id, 7, None, atts);
        assert!(matches!(
            cert.verify(&set),
            Err(DirectoryError::InsufficientQuorum { got: 1, need: 2 })
        ));
    }

    #[test]
    fn duplicate_authority_counts_once() {
        let auth = authorities(3);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        let id = "ee".repeat(32);
        // Same authority attesting twice must not satisfy a 2-of-3 quorum.
        let att = AdmissionCert::attest(&auth[0], &id, 42, None);
        let cert = AdmissionCert::assemble(id, 42, None, vec![att.clone(), att]);
        assert!(matches!(
            cert.verify(&set),
            Err(DirectoryError::InsufficientQuorum { got: 1, need: 2 })
        ));
    }

    #[test]
    fn tampered_epoch_breaks_signatures() {
        let auth = authorities(3);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        let id = "ff".repeat(32);
        let atts: Vec<Attestation> = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, 100, None))
            .collect();
        // Forge a later epoch without re-signing — signatures no longer match.
        let mut cert = AdmissionCert::assemble(id, 100, None, atts);
        cert.epoch = 200;
        assert!(matches!(
            cert.verify(&set),
            Err(DirectoryError::InsufficientQuorum { got: 0, need: 2 })
        ));
    }

    #[test]
    fn wrong_identity_in_signature_is_rejected() {
        let auth = authorities(2);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        // Authorities signed for a DIFFERENT identity; presenting the cert under
        // another identity must fail (the signed message no longer matches).
        let signed_id = "11".repeat(32);
        let atts: Vec<Attestation> = auth
            .iter()
            .map(|a| AdmissionCert::attest(a, &signed_id, 5, None))
            .collect();
        let cert = AdmissionCert::assemble("22".repeat(32), 5, None, atts);
        assert!(cert.verify(&set).is_err());
    }

    #[test]
    fn junk_padding_cannot_break_a_real_quorum() {
        let auth = authorities(3);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        let id = "33".repeat(32);
        let mut atts: Vec<Attestation> = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, 9, None))
            .collect();
        // Append a malformed attestation — must be ignored, quorum still holds.
        atts.push(Attestation {
            authority_pk_hex: "not-hex".into(),
            signature_hex: "garbage".into(),
        });
        let cert = AdmissionCert::assemble(id, 9, None, atts);
        assert_eq!(cert.verify(&set).unwrap(), 2);
    }

    #[test]
    fn is_fresh_bounds_epoch_window() {
        let cert = AdmissionCert::assemble("aa".repeat(32), 1_000_000, None, Vec::new());
        assert!(cert.is_fresh(1_000_000)); // exactly now
        assert!(cert.is_fresh(1_000_000 + MAX_ADMISSION_AGE_SECS)); // edge of window
        assert!(!cert.is_fresh(1_000_000 + MAX_ADMISSION_AGE_SECS + 1)); // too old
        assert!(cert.is_fresh(1_000_000 - ADMISSION_CLOCK_SKEW_SECS)); // slight future ok
        assert!(!cert.is_fresh(1_000_000 - ADMISSION_CLOCK_SKEW_SECS - 1)); // too far future
    }

    #[test]
    fn junk_attestations_for_a_pinned_authority_do_not_inflate_quorum() {
        // Attestation-flooding DoS vector: pad a cert with many attestations
        // naming a genuine pinned authority but with garbage signatures. They
        // must not count toward quorum, and (via attempted-dedup) cost at most
        // one verify per authority — not one per junk attestation.
        let auth = authorities(3);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        let id = "77".repeat(32);
        let a0_hex = hex::encode(auth[0].verifying_key().to_bytes());
        // One real attestation (auth[0]) followed by 500 junk ones naming auth[0].
        let mut atts = vec![AdmissionCert::attest(&auth[0], &id, 3, None)];
        for _ in 0..500 {
            atts.push(Attestation {
                authority_pk_hex: a0_hex.clone(),
                signature_hex: "00".repeat(64),
            });
        }
        let cert = AdmissionCert::assemble(id, 3, None, atts);
        // Only the single distinct authority counts → below the 2-of-3 quorum.
        assert!(matches!(
            cert.verify(&set),
            Err(DirectoryError::InsufficientQuorum { got: 1, need: 2 })
        ));
    }

    #[test]
    fn authority_set_rejects_bad_threshold_and_dupes() {
        let auth = authorities(3);
        let vks = verifying(&auth);
        assert!(AuthoritySet::new(&vks, 0).is_err());
        assert!(AuthoritySet::new(&vks, 4).is_err());
        assert!(AuthoritySet::new(&[], 1).is_err());
        // Duplicate key.
        let dupe = vec![vks[0], vks[0], vks[1]];
        assert!(AuthoritySet::new(&dupe, 2).is_err());
    }
}
