//! Wire format for a single relay's self-advertisement.

use crypto_gotham::directory::{RelayDescriptor, RelayTier};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::error::{DirectoryError, Result};

/// What this relay claims it can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capabilities {
    /// Relay can serve any position in a 3-hop path.
    All,
    /// Relay is willing to be the entry hop (sees client IP).
    Entry,
    /// Relay is willing to be a middle hop (sees only other relays).
    Mix,
    /// Relay is willing to be the exit hop (sees recipient).
    Exit,
    /// Consumer-only — does NOT forward for others (mobile clients).
    /// Does not advertise via this struct; this variant is included
    /// for completeness so a single enum can represent every node
    /// kind without falling back to `Option<Capabilities>`.
    None,
}

impl Capabilities {
    /// `true` if a path-selection routine should consider this relay
    /// for an entry-tier slot.
    pub fn can_entry(&self) -> bool {
        matches!(self, Capabilities::All | Capabilities::Entry)
    }
    /// `true` for middle-tier eligibility.
    pub fn can_mix(&self) -> bool {
        matches!(self, Capabilities::All | Capabilities::Mix)
    }
    /// `true` for exit-tier eligibility.
    pub fn can_exit(&self) -> bool {
        matches!(self, Capabilities::All | Capabilities::Exit)
    }
}

/// One relay's signed claim of existence.
///
/// Lives on disk inside the [`Roster`](crate::Roster) JSON, and
/// (in Phase 1) flows over the gossip wire.
///
/// Anti-replay: the `seq` field MUST be monotonically increasing per
/// `identity_pk_hex`. Receivers reject any advertisement whose `seq`
/// is ≤ the value they already have for the same identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advertisement {
    /// Wire format version. Must equal [`crate::WIRE_VERSION`].
    pub wire_version: u8,

    /// Ed25519 identity public key, hex-encoded (64 chars / 32 bytes).
    /// This is the unique key for roster lookup and the identity a k-of-n
    /// [`AdmissionCert`](crate::AdmissionCert) vouches for.
    pub identity_pk_hex: String,

    /// X25519 KEM public key, hex-encoded (64 chars / 32 bytes) — the key
    /// Sphinx/Noise encapsulate against for routing. Distinct from the Ed25519
    /// signing identity above (Tor-style split): the signature proves control
    /// of the identity, this key carries traffic. Bound into the signature so a
    /// peer cannot swap in its own routing key for someone else's identity.
    pub kem_pubkey_hex: String,

    /// Reachability address. Phase 0: `"1.2.3.4:443"`. Phase 1 (Chantier
    /// 2 = Arti): `"<56-char-onion>.onion:443"`.
    pub address: String,

    /// What this relay can do.
    pub capabilities: Capabilities,

    /// Monotonic sequence counter. Bumped each time the relay re-signs
    /// its advertisement (e.g. heartbeat every 5 min, or whenever a
    /// field changes).
    pub seq: u64,

    /// Unix-seconds timestamp of when this advertisement was signed.
    /// Used for staleness eviction (drop if `now - signed_at > 1h`).
    pub signed_at: u64,

    /// RFC B3. When set, this relay is behind CGNAT and reachable ONLY via the
    /// rendezvous relay whose Ed25519 identity is this hex string; `address` is
    /// then an empty sentinel. Signed (in [`canonical_bytes`](Self::canonical_bytes))
    /// so a gossip peer can neither forge nor strip it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<String>,

    /// RFC B3. Whether this directly-reachable relay will serve as a rendezvous
    /// point for CGNAT relays. Signed. Defaults to `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rendezvous_capable: bool,

    /// Hex-encoded Ed25519 signature over the canonical bytes of the
    /// struct (every field above this one, JSON-serialised in field
    /// order).
    pub signature_hex: String,
}

impl Advertisement {
    /// Build + sign a fresh advertisement binding the Ed25519 signing identity
    /// to its X25519 routing key (`kem_pubkey_hex`), address, and capabilities.
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

    /// Build + sign an advertisement including the RFC B3 rendezvous fields.
    /// `rendezvous = Some(R_identity_hex)` marks this relay CGNAT-only (reachable
    /// via R; `address` should be empty). `rendezvous_capable = true` marks a
    /// directly-reachable relay willing to host CGNAT relays. The two are
    /// mutually exclusive (a hosted relay cannot itself host).
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

    /// Bytes to be signed / verified. Excludes the `signature_hex`
    /// field itself.
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
            // RFC B3 fields are signed. Skipped when absent/false so a plain
            // direct relay's canonical bytes stay minimal (and identical for
            // every non-rendezvous relay at this wire version).
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

    /// Decode the hex-encoded X25519 KEM pubkey into raw bytes (32).
    pub fn kem_pubkey_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.kem_pubkey_hex)?;
        v.as_slice()
            .try_into()
            .map_err(|_| DirectoryError::Other("kem_pubkey_hex wrong length".into()))
    }

    /// Project this advertisement into a routable
    /// [`RelayDescriptor`](crypto_gotham::directory::RelayDescriptor) for the
    /// path selector, at wall-clock `now` (unix seconds). Returns `None` for a
    /// consumer-only relay ([`Capabilities::None`]) or a malformed routing key.
    ///
    /// A [`Capabilities::All`] relay is assigned ONE tier so it always occupies
    /// exactly one routing slot — never entry AND exit for the same path, which
    /// would deanonymise. The assignment is an **un-grindable daily beacon**
    /// (`blake3(identity ‖ day)`), NOT a fixed function of the identity: an
    /// operator cannot grind its Ed25519 key to a permanent tier and flood it
    /// (e.g. concentrate in the exit tier that sees recipients). Each day the
    /// whole admitted set spreads ~uniformly across tiers, and grinding a key to
    /// a chosen tier for many days ahead is infeasible (3⁻ⁿ).
    pub fn to_relay_descriptor(&self, now: u64) -> Option<RelayDescriptor> {
        let id = hex::decode(&self.identity_pk_hex).ok()?;
        if id.is_empty() {
            return None;
        }
        self.kem_pubkey_bytes().ok()?; // routing key must be well-formed
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

    /// First byte of the daily tier beacon `blake3(domain ‖ identity ‖ day)`,
    /// where `day = now / 86400`. Rotating the beacon daily makes the tier an
    /// operator cannot pin by grinding its key.
    fn beacon_tier_byte(&self, id: &[u8], now: u64) -> u8 {
        let day = now / 86_400;
        let mut h = blake3::Hasher::new();
        h.update(b"gotham-gossip-tier-v1");
        h.update(id);
        h.update(&day.to_le_bytes());
        h.finalize().as_bytes()[0]
    }

    /// Verify the signature against the claimed identity. Returns
    /// `Ok(())` on success. Also checks the KEM key is well-formed (32 bytes),
    /// since a malformed routing key would make the entry un-routable.
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
        // Address gate. RFC B3: a rendezvous-hosted relay (`rendezvous` set) is
        // NOT directly dialable — its `address` is an empty sentinel and its
        // reachability is the rendezvous binding, so we validate THAT instead of
        // a socket address. A direct relay must still have a usable one.
        match &self.rendezvous {
            Some(r) => {
                // A hosted relay cannot itself be a rendezvous point.
                if self.rendezvous_capable {
                    return Err(DirectoryError::Other(
                        "a rendezvous-hosted relay cannot also be rendezvous_capable".into(),
                    ));
                }
                // The binding must be a well-formed 32-byte Ed25519 identity.
                let rb = hex::decode(r)
                    .map_err(|_| DirectoryError::Other("rendezvous id not hex".into()))?;
                if rb.len() != 32 {
                    return Err(DirectoryError::Other("rendezvous id wrong length".into()));
                }
            }
            None => {
                // Reject a plainly-unusable reachability address (unspecified /
                // port 0). NOTE: loopback is intentionally NOT rejected here —
                // local gossip integration tests advertise and DIAL 127.0.0.1
                // bound addresses. In production, loopback must be kept out of
                // the roster at the authority ADMISSION gate (it signs the
                // AdmissionCert), not at self-verify; the enrollment path already
                // rejects loopback (see
                // `crypto_gotham::enroll::RelayEnrollment::validate`). Path
                // selection additionally treats two loopback hops as non-diverse
                // only in tests.
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
        // Reject a well-signed ad whose routing key is malformed — it verifies
        // authorship but could never carry traffic.
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
            String::new(), // CGNAT: no dialable address
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
            true, // a hosted relay cannot also be a rendezvous point
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
        // Swap in a different rendezvous relay — the signature must catch it.
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
