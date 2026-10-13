use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crypto_gotham::directory::RelayDescriptor;

use crate::advertisement::Advertisement;
use crate::attestation::{AdmissionCert, AuthoritySet};
use crate::error::{DirectoryError, Result};

pub const STALE_AFTER_SECS: u64 = 3600;

pub const MAX_GOSSIP_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Roster {
    pub entries: HashMap<String, Advertisement>,
    #[serde(default)]
    pub admissions: HashMap<String, AdmissionCert>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, ad: Advertisement) -> Result<()> {
        ad.verify()?;
        let key = ad.identity_pk_hex.to_lowercase();
        if let Some(existing) = self.entries.get(&key) {
            if ad.seq <= existing.seq {
                return Err(DirectoryError::StaleSeq {
                    got: ad.seq,
                    have: existing.seq,
                });
            }
        }
        self.entries.insert(key, ad);
        Ok(())
    }

    pub fn insert_admitted(
        &mut self,
        ad: Advertisement,
        cert: AdmissionCert,
        set: &AuthoritySet,
        now: u64,
    ) -> Result<()> {
        ad.verify()?;
        if !cert
            .identity_pk_hex
            .eq_ignore_ascii_case(&ad.identity_pk_hex)
        {
            return Err(DirectoryError::IdentityMismatch);
        }
        cert.verify(set)?;
        if !cert.is_fresh(now) {
            return Err(DirectoryError::AdmissionExpired);
        }
        let key = ad.identity_pk_hex.to_lowercase();
        if let Some(existing) = self.entries.get(&key) {
            if ad.seq <= existing.seq {
                return Err(DirectoryError::StaleSeq {
                    got: ad.seq,
                    have: existing.seq,
                });
            }
        }
        if let Some(prev) = self.admissions.get(&key) {
            if cert.epoch < prev.epoch {
                return Err(DirectoryError::AdmissionExpired);
            }
        }
        self.admissions.insert(key.clone(), cert);
        self.entries.insert(key, ad);
        Ok(())
    }

    pub fn merge_admitted(&mut self, other: &Roster, now_unix: u64, set: &AuthoritySet) -> usize {
        let mut delta = 0usize;
        for (peer_key, ad) in &other.entries {
            if now_unix.saturating_sub(ad.signed_at) > STALE_AFTER_SECS {
                continue;
            }
            if ad.verify().is_err() {
                continue;
            }
            let key = ad.identity_pk_hex.to_lowercase();
            let Some(cert) = other
                .admissions
                .get(peer_key)
                .or_else(|| other.admissions.get(&key))
            else {
                continue;
            };
            if !cert.identity_pk_hex.eq_ignore_ascii_case(&key)
                || cert.verify(set).is_err()
                || !cert.is_fresh(now_unix)
            {
                continue;
            }
            match self.entries.get(&key) {
                Some(existing) if existing.seq >= ad.seq => {}
                _ => {
                    if let Some(prev) = self.admissions.get(&key) {
                        if cert.epoch < prev.epoch {
                            continue;
                        }
                    }
                    self.admissions.insert(key.clone(), cert.clone());
                    self.entries.insert(key, ad.clone());
                    delta += 1;
                }
            }
        }
        delta
    }

    pub fn merge(&mut self, other: &Roster, now_unix: u64) -> usize {
        let mut delta = 0usize;
        for ad in other.entries.values() {
            if now_unix.saturating_sub(ad.signed_at) > STALE_AFTER_SECS {
                continue;
            }
            if ad.verify().is_err() {
                tracing::warn!("merge: dropping ad with bad signature");
                continue;
            }
            let key = ad.identity_pk_hex.to_lowercase();
            match self.entries.get(&key) {
                Some(existing) if existing.seq >= ad.seq => {}
                _ => {
                    self.entries.insert(key, ad.clone());
                    delta += 1;
                }
            }
        }
        delta
    }

    pub fn prune_stale(&mut self, now_unix: u64) -> usize {
        let cutoff = now_unix.saturating_sub(STALE_AFTER_SECS);
        let before = self.entries.len();
        self.entries.retain(|_, ad| ad.signed_at >= cutoff);
        let live: std::collections::HashSet<String> = self.entries.keys().cloned().collect();
        self.admissions.retain(|id, _| live.contains(id));
        before - self.entries.len()
    }

    pub fn verify_incoming(other: &Roster, set: &AuthoritySet, now: u64) -> Roster {
        let mut out = Roster::new();
        for (peer_key, ad) in other.entries.iter().take(MAX_GOSSIP_ENTRIES) {
            if now.saturating_sub(ad.signed_at) > STALE_AFTER_SECS || ad.verify().is_err() {
                continue;
            }
            let key = ad.identity_pk_hex.to_lowercase();
            let Some(cert) = other
                .admissions
                .get(peer_key)
                .or_else(|| other.admissions.get(&key))
            else {
                continue;
            };
            if !cert.identity_pk_hex.eq_ignore_ascii_case(&key)
                || cert.verify(set).is_err()
                || !cert.is_fresh(now)
            {
                continue;
            }
            out.entries.insert(key.clone(), ad.clone());
            out.admissions.insert(key, cert.clone());
        }
        out
    }

    pub fn splice_verified(&mut self, verified: &Roster) -> usize {
        let mut delta = 0usize;
        for (key, ad) in &verified.entries {
            let Some(cert) = verified.admissions.get(key) else {
                continue;
            };
            match self.entries.get(key) {
                Some(existing) if existing.seq >= ad.seq => {}
                _ => {
                    if let Some(prev) = self.admissions.get(key) {
                        if cert.epoch < prev.epoch {
                            continue;
                        }
                    }
                    self.admissions.insert(key.clone(), cert.clone());
                    self.entries.insert(key.clone(), ad.clone());
                    delta += 1;
                }
            }
        }
        delta
    }

    pub fn to_relay_descriptors(&self, set: &AuthoritySet, now: u64) -> Vec<RelayDescriptor> {
        let mut out = Vec::new();
        for (key, ad) in &self.entries {
            if now.saturating_sub(ad.signed_at) > STALE_AFTER_SECS || ad.verify().is_err() {
                continue;
            }
            let Some(cert) = self.admissions.get(key) else {
                continue;
            };
            if !cert.identity_pk_hex.eq_ignore_ascii_case(key)
                || cert.verify(set).is_err()
                || !cert.is_fresh(now)
            {
                continue;
            }
            if let Some(mut rd) = ad.to_relay_descriptor(now) {
                if cert.operator.is_some() {
                    rd.operator = cert.operator.clone();
                }
                out.push(rd);
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Capabilities;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn fresh_ad(seq: u64) -> (Advertisement, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            seq,
        )
        .unwrap();
        (ad, key)
    }

    #[test]
    fn insert_then_lookup() {
        let mut r = Roster::new();
        let (ad, _) = fresh_ad(1);
        let id = ad.identity_pk_hex.clone();
        r.insert(ad).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.entries.contains_key(&id));
    }

    #[test]
    fn insert_rejects_stale_seq() {
        let mut r = Roster::new();
        let key = SigningKey::generate(&mut OsRng);
        let ad1 = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            5,
        )
        .unwrap();
        let ad2 = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            3,
        )
        .unwrap();
        r.insert(ad1).unwrap();
        let res = r.insert(ad2);
        assert!(matches!(res, Err(DirectoryError::StaleSeq { .. })));
    }

    #[test]
    fn merge_picks_higher_seq() {
        let key = SigningKey::generate(&mut OsRng);
        let ad_old = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            1,
        )
        .unwrap();
        let ad_new = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "9.9.9.9:443".into(),
            Capabilities::Exit,
            2,
        )
        .unwrap();
        let mut a = Roster::new();
        a.insert(ad_old).unwrap();
        let mut b = Roster::new();
        b.insert(ad_new).unwrap();
        let delta = a.merge(&b, ad_new_signed_at(&b));
        assert_eq!(delta, 1);
        let merged = a.entries.values().next().unwrap();
        assert_eq!(merged.seq, 2);
        assert_eq!(merged.address, "9.9.9.9:443");
    }

    fn ad_new_signed_at(r: &Roster) -> u64 {
        r.entries
            .values()
            .map(|a| a.signed_at)
            .max()
            .unwrap_or_default()
    }

    #[test]
    fn merge_drops_stale_entries() {
        let key = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            1,
        )
        .unwrap();
        let stale_now = ad.signed_at + STALE_AFTER_SECS + 1;
        let mut a = Roster::new();
        let mut b = Roster::new();
        b.insert(ad).unwrap();
        let delta = a.merge(&b, stale_now);
        assert_eq!(delta, 0);
        assert!(a.is_empty());
    }

    #[test]
    fn prune_stale_removes_old() {
        let mut r = Roster::new();
        let (ad, _) = fresh_ad(1);
        let signed_at = ad.signed_at;
        r.insert(ad).unwrap();
        let pruned = r.prune_stale(signed_at + STALE_AFTER_SECS + 1);
        assert_eq!(pruned, 1);
        assert!(r.is_empty());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("roster.json");
        let mut a = Roster::new();
        let (ad, _) = fresh_ad(1);
        let id = ad.identity_pk_hex.clone();
        a.insert(ad).unwrap();
        a.save_to(&path).unwrap();
        let b = Roster::load_from(&path).unwrap();
        assert_eq!(b.len(), 1);
        assert!(b.entries.contains_key(&id));
    }

    #[test]
    fn load_from_missing_file_returns_empty() {
        let r = Roster::load_from(Path::new("/tmp/does-not-exist-asdf-1234.json")).unwrap();
        assert!(r.is_empty());
    }

    use crate::attestation::{AdmissionCert, AuthoritySet};
    use ed25519_dalek::VerifyingKey;

    fn authority_set(n: usize, k: usize) -> (Vec<SigningKey>, AuthoritySet) {
        let auth: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let vks: Vec<VerifyingKey> = auth.iter().map(|a| a.verifying_key()).collect();
        (auth, AuthoritySet::new(&vks, k).unwrap())
    }

    fn admitted(auth: &[SigningKey], k: usize) -> (Advertisement, AdmissionCert, u64) {
        let relay = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign(
            &relay,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            1,
        )
        .unwrap();
        let id = ad.identity_pk_hex.clone();
        let epoch = ad.signed_at;
        let atts = auth[..k]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, epoch, None))
            .collect();
        (ad, AdmissionCert::assemble(id, epoch, None, atts), epoch)
    }

    #[test]
    fn insert_admitted_accepts_quorum_and_stores_cert() {
        let (auth, set) = authority_set(5, 3);
        let (ad, cert, now) = admitted(&auth, 3);
        let id = ad.identity_pk_hex.clone();
        let mut r = Roster::new();
        r.insert_admitted(ad, cert, &set, now).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.admissions.contains_key(&id), "admission persisted");
    }

    #[test]
    fn insert_admitted_rejects_sub_quorum() {
        let (auth, set) = authority_set(5, 3);
        let (ad, cert, now) = admitted(&auth, 2);
        let mut r = Roster::new();
        assert!(matches!(
            r.insert_admitted(ad, cert, &set, now),
            Err(DirectoryError::InsufficientQuorum { got: 2, need: 3 })
        ));
        assert!(r.is_empty());
    }

    #[test]
    fn insert_admitted_rejects_identity_mismatch() {
        let (auth, set) = authority_set(3, 2);
        let (ad, _, now) = admitted(&auth, 2);
        let other = SigningKey::generate(&mut OsRng);
        let other_id = hex::encode(other.verifying_key().to_bytes());
        let atts = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &other_id, now, None))
            .collect();
        let mismatched = AdmissionCert::assemble(other_id, now, None, atts);
        let mut r = Roster::new();
        assert!(matches!(
            r.insert_admitted(ad, mismatched, &set, now),
            Err(DirectoryError::IdentityMismatch)
        ));
    }

    #[test]
    fn merge_admitted_only_pulls_quorum_backed_entries() {
        let (auth, set) = authority_set(4, 3);

        let mut peer = Roster::new();
        let (ad_ok, cert_ok, now) = admitted(&auth, 3);
        peer.insert_admitted(ad_ok, cert_ok, &set, now).unwrap();
        let sybil = SigningKey::generate(&mut OsRng);
        let ad_sybil = Advertisement::sign(
            &sybil,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "9.9.9.9:443".into(),
            Capabilities::All,
            1,
        )
        .unwrap();
        peer.insert(ad_sybil).unwrap();

        let mut mine = Roster::new();
        let delta = mine.merge_admitted(&peer, now, &set);
        assert_eq!(delta, 1, "only the quorum-backed relay is admitted");
        assert_eq!(mine.len(), 1);
    }

    #[test]
    fn prune_stale_drops_orphaned_admissions() {
        let (auth, set) = authority_set(3, 2);
        let (ad, cert, now) = admitted(&auth, 2);
        let signed_at = ad.signed_at;
        let mut r = Roster::new();
        r.insert_admitted(ad, cert, &set, now).unwrap();
        let pruned = r.prune_stale(signed_at + STALE_AFTER_SECS + 1);
        assert_eq!(pruned, 1);
        assert!(r.is_empty());
        assert!(r.admissions.is_empty(), "orphaned admission dropped");
    }

    #[test]
    fn case_variant_identity_cannot_bypass_seq_antireplay() {
        let (auth, set) = authority_set(3, 2);
        let relay = SigningKey::generate(&mut OsRng);
        let id_lc = hex::encode(relay.verifying_key().to_bytes());
        let id_uc = id_lc.to_uppercase();

        let ad10 = Advertisement::sign(
            &relay,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "10.0.0.1:443".into(),
            Capabilities::All,
            10,
        )
        .unwrap();
        let ad1 = Advertisement::sign(
            &relay,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "6.6.6.6:443".into(),
            Capabilities::Exit,
            1,
        )
        .unwrap();
        let now = ad10.signed_at.max(ad1.signed_at);
        let cert = |epoch: u64| {
            let atts = auth[..2]
                .iter()
                .map(|a| AdmissionCert::attest(a, &id_lc, epoch, None))
                .collect();
            AdmissionCert::assemble(id_lc.clone(), epoch, None, atts)
        };

        let mut mine = Roster::new();
        mine.insert_admitted(ad10, cert(now), &set, now).unwrap();

        let mut attacker = Roster::new();
        attacker.entries.insert(id_uc.clone(), ad1);
        attacker.admissions.insert(id_uc, cert(now));

        let delta = mine.merge_admitted(&attacker, now, &set);
        assert_eq!(delta, 0, "case-variant key must not bypass seq anti-replay");
        assert_eq!(mine.len(), 1);
        let kept = mine.entries.values().next().unwrap();
        assert_eq!(kept.seq, 10, "the honest seq=10 ad must survive");
        assert_eq!(kept.address, "10.0.0.1:443");
    }

    #[test]
    fn stale_admission_is_rejected() {
        use crate::attestation::MAX_ADMISSION_AGE_SECS;
        let (auth, set) = authority_set(3, 2);
        let relay = SigningKey::generate(&mut OsRng);
        let id = hex::encode(relay.verifying_key().to_bytes());
        let ad = Advertisement::sign(
            &relay,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".into(),
            Capabilities::All,
            1,
        )
        .unwrap();
        let old_epoch = 1_000u64;
        let atts = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, old_epoch, None))
            .collect();
        let cert = AdmissionCert::assemble(id, old_epoch, None, atts);
        let now = old_epoch + MAX_ADMISSION_AGE_SECS + 1;
        let mut r = Roster::new();
        assert!(matches!(
            r.insert_admitted(ad, cert, &set, now),
            Err(DirectoryError::AdmissionExpired)
        ));
    }

    #[test]
    fn bridge_emits_only_fresh_admitted_routable_descriptors() {
        use crypto_gotham::directory::RelayTier;
        let (auth, set) = authority_set(3, 2);
        let kem = "22".repeat(32);
        let mk = |cap: Capabilities, addr: &str| {
            let relay = SigningKey::generate(&mut OsRng);
            let ad = Advertisement::sign(&relay, kem.clone(), addr.into(), cap, 1).unwrap();
            let id = ad.identity_pk_hex.clone();
            let epoch = ad.signed_at;
            let atts = auth[..2]
                .iter()
                .map(|a| AdmissionCert::attest(a, &id, epoch, None))
                .collect();
            (ad, AdmissionCert::assemble(id, epoch, None, atts))
        };
        let (ad_e, cert_e) = mk(Capabilities::Entry, "1.1.1.1:443");
        let (ad_x, cert_x) = mk(Capabilities::Exit, "2.2.2.2:443");
        let now = ad_e.signed_at.max(ad_x.signed_at);
        let mut r = Roster::new();
        r.insert_admitted(ad_e, cert_e, &set, now).unwrap();
        r.insert_admitted(ad_x, cert_x, &set, now).unwrap();
        let sybil = SigningKey::generate(&mut OsRng);
        r.insert(
            Advertisement::sign(
                &sybil,
                kem.clone(),
                "9.9.9.9:443".into(),
                Capabilities::All,
                1,
            )
            .unwrap(),
        )
        .unwrap();

        let descs = r.to_relay_descriptors(&set, now);
        assert_eq!(descs.len(), 2, "only the two admitted relays are routable");
        let tiers: std::collections::HashSet<_> = descs.iter().map(|d| d.tier).collect();
        assert!(tiers.contains(&RelayTier::Entry) && tiers.contains(&RelayTier::Exit));
        assert!(descs.iter().all(|d| d.kem_pubkey_hex == kem));
        assert!(descs.iter().all(|d| d.id_pubkey_hex != d.kem_pubkey_hex));
    }

    #[test]
    fn attested_operator_label_projects_onto_descriptor() {
        let (auth, set) = authority_set(3, 2);
        let kem = "33".repeat(32);
        let relay = SigningKey::generate(&mut OsRng);
        let ad =
            Advertisement::sign(&relay, kem, "1.1.1.1:443".into(), Capabilities::All, 1).unwrap();
        let id = ad.identity_pk_hex.clone();
        let epoch = ad.signed_at;
        let op = Some("acme-relays".to_string());
        let atts = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, epoch, op.as_deref()))
            .collect();
        let cert = AdmissionCert::assemble(id, epoch, op.clone(), atts);
        let now = ad.signed_at;
        let mut r = Roster::new();
        r.insert_admitted(ad, cert, &set, now).unwrap();
        let descs = r.to_relay_descriptors(&set, now);
        assert_eq!(descs.len(), 1);
        assert_eq!(
            descs[0].operator, op,
            "authority-attested operator must project onto the descriptor"
        );
    }

    #[test]
    fn tampered_operator_label_breaks_quorum() {
        let (auth, set) = authority_set(3, 2);
        let kem = "44".repeat(32);
        let relay = SigningKey::generate(&mut OsRng);
        let ad =
            Advertisement::sign(&relay, kem, "1.1.1.1:443".into(), Capabilities::All, 1).unwrap();
        let id = ad.identity_pk_hex.clone();
        let epoch = ad.signed_at;
        let atts = auth[..2]
            .iter()
            .map(|a| AdmissionCert::attest(a, &id, epoch, Some("honest-op")))
            .collect();
        let mut cert = AdmissionCert::assemble(id, epoch, Some("honest-op".into()), atts);
        cert.operator = Some("attacker-op".into());
        assert!(
            cert.verify(&set).is_err(),
            "swapping the signed operator label must break the quorum"
        );
    }
}
