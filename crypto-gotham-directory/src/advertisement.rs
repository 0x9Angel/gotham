use crypto_gotham::directory::{RelayDescriptor, RelayTier};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::error::{DirectoryError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capabilities {
    All,
    Entry,
    Mix,
    Exit,
    None,
}

impl Capabilities {
    pub fn can_entry(&self) -> bool {
        matches!(self, Capabilities::All | Capabilities::Entry)
    }
    pub fn can_mix(&self) -> bool {
        matches!(self, Capabilities::All | Capabilities::Mix)
    }
    pub fn can_exit(&self) -> bool {
        matches!(self, Capabilities::All | Capabilities::Exit)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advertisement {
    pub wire_version: u8,

    pub identity_pk_hex: String,

    pub kem_pubkey_hex: String,

    pub address: String,

    pub capabilities: Capabilities,

    pub seq: u64,

    pub signed_at: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rendezvous_capable: bool,

    pub signature_hex: String,
}

impl Advertisement {
    pub fn sign(
        signing_key: &SigningKey,
        kem_pubkey_hex: String,
        address: String,
        capabilities: Capabilities,
        seq: u64,
    ) -> Result<Self> {
        Self::sign_full(
            signing_key,
            kem_pubkey_hex,
            address,
            capabilities,
            seq,
            None,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_full(
        signing_key: &SigningKey,
        kem_pubkey_hex: String,
        address: String,
        capabilities: Capabilities,
        seq: u64,
        rendezvous: Option<String>,
        rendezvous_capable: bool,
    ) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| DirectoryError::Other("system clock before epoch".into()))?
            .as_secs();

        let identity_pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let mut ad = Self {
            wire_version: crate::WIRE_VERSION,
            identity_pk_hex,
            kem_pubkey_hex,
            address,
            capabilities,
            seq,
            signed_at: now,
            rendezvous,
            rendezvous_capable,
            signature_hex: String::new(),
        };
        let canonical = ad.canonical_bytes()?;
        let sig: Signature = signing_key.sign(&canonical);
        ad.signature_hex = hex::encode(sig.to_bytes());
        Ok(ad)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_version: u8,
            identity_pk_hex: &'a str,
            kem_pubkey_hex: &'a str,
            address: &'a str,
            capabilities: Capabilities,
            seq: u64,
            signed_at: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            rendezvous: Option<&'a str>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            rendezvous_capable: bool,
        }
        let c = Canonical {
            wire_version: self.wire_version,
            identity_pk_hex: &self.identity_pk_hex,
            kem_pubkey_hex: &self.kem_pubkey_hex,
            address: &self.address,
            capabilities: self.capabilities,
            seq: self.seq,
            signed_at: self.signed_at,
            rendezvous: self.rendezvous.as_deref(),
            rendezvous_capable: self.rendezvous_capable,
        };
        Ok(serde_json::to_vec(&c)?)
    }

    pub fn kem_pubkey_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.kem_pubkey_hex)?;
        v.as_slice()
            .try_into()
            .map_err(|_| DirectoryError::Other("kem_pubkey_hex wrong length".into()))
    }

    pub fn to_relay_descriptor(&self, now: u64) -> Option<RelayDescriptor> {
        let id = hex::decode(&self.identity_pk_hex).ok()?;
        if id.is_empty() {
            return None;
        }
        self.kem_pubkey_bytes().ok()?;
        let tier = match self.capabilities {
            Capabilities::Entry => RelayTier::Entry,
            Capabilities::Mix => RelayTier::Mix,
            Capabilities::Exit => RelayTier::Exit,
            Capabilities::All => match self.beacon_tier_byte(&id, now) % 3 {
                0 => RelayTier::Entry,
                1 => RelayTier::Mix,
                _ => RelayTier::Exit,
            },
            Capabilities::None => return None,
        };
        Some(RelayDescriptor {
            id_pubkey_hex: self.identity_pk_hex.clone(),
            kem_pubkey_hex: self.kem_pubkey_hex.clone(),
            addr: self.address.clone(),
            tier,
            country: None,
            asn: None,
            operator: None,
            uptime_pct: None,
            mailbox: false,
            rendezvous: self.rendezvous.clone(),
            rendezvous_capable: self.rendezvous_capable,
        })
    }

    fn beacon_tier_byte(&self, id: &[u8], now: u64) -> u8 {
        let day = now / 86_400;
        let mut h = blake3::Hasher::new();
        h.update(b"gotham-gossip-tier-v1");
        h.update(id);
        h.update(&day.to_le_bytes());
        h.finalize().as_bytes()[0]
    }

    pub fn verify(&self) -> Result<()> {
        if self.wire_version != crate::WIRE_VERSION {
            return Err(DirectoryError::WireVersionMismatch(self.wire_version));
        }
        let pk_bytes_vec = hex::decode(&self.identity_pk_hex)?;
        let pk_bytes: [u8; 32] = pk_bytes_vec
            .as_slice()
            .try_into()
            .map_err(|_| DirectoryError::Other("identity_pk_hex wrong length".into()))?;
        let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| DirectoryError::BadSignature)?;
        let sig_bytes_vec = hex::decode(&self.signature_hex)?;
        let sig_bytes: [u8; SIGNATURE_LENGTH] = sig_bytes_vec
            .as_slice()
            .try_into()
            .map_err(|_| DirectoryError::Other("signature_hex wrong length".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let canonical = self.canonical_bytes()?;
        pk.verify(&canonical, &sig)
            .map_err(|_| DirectoryError::BadSignature)?;
        match &self.rendezvous {
            Some(r) => {
                if self.rendezvous_capable {
                    return Err(DirectoryError::Other(
                        "a rendezvous-hosted relay cannot also be rendezvous_capable".into(),
                    ));
                }
                let rb = hex::decode(r)
                    .map_err(|_| DirectoryError::Other("rendezvous id not hex".into()))?;
                if rb.len() != 32 {
                    return Err(DirectoryError::Other("rendezvous id wrong length".into()));
                }
            }
            None => {
                let sa: std::net::SocketAddr = self.address.parse().map_err(|_| {
                    DirectoryError::Other("advertisement addr not a socket address".into())
                })?;
                if sa.ip().is_unspecified() || sa.port() == 0 {
                    return Err(DirectoryError::Other(
                        "advertisement addr must not be unspecified / port 0".into(),
                    ));
                }
            }
        }
        self.kem_pubkey_bytes().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".to_string(),
            Capabilities::All,
            1,
        )
        .unwrap();
        ad.verify().unwrap();
    }

    #[test]
    fn tampered_address_fails_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let mut ad = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".to_string(),
            Capabilities::All,
            1,
        )
        .unwrap();
        ad.address = "5.6.7.8:443".to_string();
        assert!(matches!(ad.verify(), Err(DirectoryError::BadSignature)));
    }

    #[test]
    fn tampered_seq_fails_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let mut ad = Advertisement::sign(
            &key,
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
            "1.2.3.4:443".to_string(),
            Capabilities::All,
            1,
        )
        .unwrap();
        ad.seq = 99;
        assert!(matches!(ad.verify(), Err(DirectoryError::BadSignature)));
    }

    const KEM_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const R_ID_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn rendezvous_ad_signs_and_verifies_with_empty_address() {
        let key = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign_full(
            &key,
            KEM_HEX.into(),
            String::new(),
            Capabilities::Mix,
            1,
            Some(R_ID_HEX.into()),
            false,
        )
        .unwrap();
        ad.verify()
            .expect("rendezvous-hosted ad with empty addr must verify");
        assert_eq!(ad.rendezvous.as_deref(), Some(R_ID_HEX));
    }

    #[test]
    fn rendezvous_and_capable_are_mutually_exclusive() {
        let key = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign_full(
            &key,
            KEM_HEX.into(),
            String::new(),
            Capabilities::Mix,
            1,
            Some(R_ID_HEX.into()),
            true,
        )
        .unwrap();
        assert!(ad.verify().is_err());
    }

    #[test]
    fn tampered_rendezvous_binding_fails_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let mut ad = Advertisement::sign_full(
            &key,
            KEM_HEX.into(),
            String::new(),
            Capabilities::Mix,
            1,
            Some(R_ID_HEX.into()),
            false,
        )
        .unwrap();
        ad.rendezvous =
            Some("3333333333333333333333333333333333333333333333333333333333333333".into());
        assert!(matches!(ad.verify(), Err(DirectoryError::BadSignature)));
    }

    #[test]
    fn rendezvous_capable_direct_ad_roundtrips() {
        let key = SigningKey::generate(&mut OsRng);
        let ad = Advertisement::sign_full(
            &key,
            KEM_HEX.into(),
            "1.2.3.4:443".into(),
            Capabilities::Mix,
            1,
            None,
            true,
        )
        .unwrap();
        ad.verify().unwrap();
        assert!(ad.rendezvous_capable);
    }

    #[test]
    fn capability_predicates() {
        assert!(Capabilities::All.can_entry());
        assert!(Capabilities::All.can_mix());
        assert!(Capabilities::All.can_exit());
        assert!(Capabilities::Entry.can_entry());
        assert!(!Capabilities::Entry.can_exit());
        assert!(!Capabilities::None.can_entry());
        assert!(!Capabilities::None.can_mix());
        assert!(!Capabilities::None.can_exit());
    }
}
