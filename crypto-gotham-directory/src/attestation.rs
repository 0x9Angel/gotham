// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::error::{DirectoryError, Result};

const ADMISSION_DOMAIN: &[u8] = b"gotham-admission-v1|";

pub const MAX_ADMISSION_AGE_SECS: u64 = 30 * 24 * 3600;

pub const ADMISSION_CLOCK_SKEW_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthoritySet {
    pub authorities_hex: Vec<String>,
    pub threshold: usize,
}

impl AuthoritySet {
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

    pub fn n(&self) -> usize {
        self.authorities_hex.len()
    }

    fn contains(&self, pk_hex: &str) -> bool {
        self.authorities_hex
            .iter()
            .any(|a| a.eq_ignore_ascii_case(pk_hex))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attestation {
    pub authority_pk_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdmissionCert {
    pub identity_pk_hex: String,
    pub epoch: u64,
    #[serde(default)]
    pub operator: Option<String>,
    pub attestations: Vec<Attestation>,
}

impl AdmissionCert {
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

    pub fn is_fresh(&self, now: u64) -> bool {
        self.epoch <= now.saturating_add(ADMISSION_CLOCK_SKEW_SECS)
            && now.saturating_sub(self.epoch) <= MAX_ADMISSION_AGE_SECS
    }

    pub fn verify(&self, set: &AuthoritySet) -> Result<usize> {
        let msg =
            Self::admission_bytes(&self.identity_pk_hex, self.epoch, self.operator.as_deref());
        let mut counted: BTreeSet<String> = BTreeSet::new();
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
        assert!(cert.is_fresh(1_000_000));
        assert!(cert.is_fresh(1_000_000 + MAX_ADMISSION_AGE_SECS));
        assert!(!cert.is_fresh(1_000_000 + MAX_ADMISSION_AGE_SECS + 1));
        assert!(cert.is_fresh(1_000_000 - ADMISSION_CLOCK_SKEW_SECS));
        assert!(!cert.is_fresh(1_000_000 - ADMISSION_CLOCK_SKEW_SECS - 1));
    }

    #[test]
    fn junk_attestations_for_a_pinned_authority_do_not_inflate_quorum() {
        let auth = authorities(3);
        let set = AuthoritySet::new(&verifying(&auth), 2).unwrap();
        let id = "77".repeat(32);
        let a0_hex = hex::encode(auth[0].verifying_key().to_bytes());
        let mut atts = vec![AdmissionCert::attest(&auth[0], &id, 3, None)];
        for _ in 0..500 {
            atts.push(Attestation {
                authority_pk_hex: a0_hex.clone(),
                signature_hex: "00".repeat(64),
            });
        }
        let cert = AdmissionCert::assemble(id, 3, None, atts);
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
        let dupe = vec![vks[0], vks[0], vks[1]];
        assert!(AuthoritySet::new(&dupe, 2).is_err());
    }
}
