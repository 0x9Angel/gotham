// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Relay-side auto-enrollment client.
//!
//! When `--authority-url` is set, the relay POSTs a [`RelayEnrollment`] to the
//! directory authority on startup and re-POSTs it as a heartbeat on an
//! interval. This is what makes the network self-forming: the operator no
//! longer hand-edits a directory — the relay announces itself.
//!
//! Failures are never fatal: the relay keeps forwarding packets regardless of
//! whether the authority is reachable, and simply retries on the next tick.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypto_gotham::directory::RelayTier;
use crypto_gotham::enroll::RelayEnrollment;
use tracing::{info, warn};

/// Everything the enrollment loop needs.
#[derive(Debug, Clone)]
pub struct EnrollConfig {
    /// Base URL of the PRIMARY directory authority, e.g. `https://dir.example.org`.
    /// This one may carry a pinned PoP key (`authority_pop_pk`) and drives the
    /// advertise-address resolution in the relay binary.
    pub authority_url: String,
    /// k-of-n decentralised admission: ADDITIONAL directory authorities to also
    /// enroll with each tick (empty in the single-authority default). The relay
    /// sends every authority the SAME enrollment (same `seq`, same proposed
    /// admission epoch) so their independent attestations combine into one quorum
    /// certificate on the app side. Each authority's PoP key is auto-fetched from
    /// its own `/pop` (a public key — a MITM can only self-DoS this relay's proof,
    /// never forge it).
    pub extra_authority_urls: Vec<String>,
    /// The publicly reachable address peers should use, e.g. `203.0.113.7:443`.
    /// May differ from the bind interface (NAT / port-forward).
    pub advertise_addr: String,
    /// This relay's X25519 public key (hex) — its routing + KEM identity.
    pub kem_pubkey_hex: String,
    /// Tier the operator is willing to serve.
    pub tier: RelayTier,
    /// Optional bearer token issued by the operator for the closed test.
    pub token: Option<String>,
    /// Optional ISO country code.
    pub country: Option<String>,
    /// Optional operator nickname.
    pub operator: Option<String>,
    /// Interval between heartbeats.
    pub heartbeat: Duration,
    /// RFC B3: if set, this relay is CGNAT and reachable only via the rendezvous
    /// relay whose X25519 key (hex) is this string. The enrollment then carries
    /// NO dialable address and the authority proves liveness by asking R.
    pub rendezvous: Option<String>,
    /// RFC B3: this directly-reachable relay is willing to host CGNAT relays.
    pub rendezvous_capable: bool,
    /// Whether this relay hosts a store-and-forward mailbox (`--mailbox`) — the
    /// enrollment advertises it so clients discover it in the directory.
    pub mailbox: bool,
    /// RFC B3 §4: this relay's X25519 SECRET key — used to compute the DH-MAC
    /// possession proof when enrolling as a CGNAT (rendezvous) relay.
    pub relay_sk: [u8; 32],
    /// RFC B3 §4: the authority's X25519 PoP public key (from
    /// `--authority-pop-key`) the possession-proof DH is computed against.
    /// Required for a rendezvous enrollment.
    pub authority_pop_pk: Option<[u8; 32]>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

/// Fetch the authority's PoP PUBLIC key (32-byte X25519, hex) from
/// `GET <authority_url>/pop`. Returns `None` on any error so the caller retries.
///
/// The key is public — it is only an input to the possession-proof DH, never a
/// secret — so an unauthenticated fetch is safe: the worst a MITM can do by
/// serving a wrong key is make this relay's own proof fail to verify (it can't
/// forge a proof for a key it doesn't hold). Operators who want to rule out even
/// that self-inflicted enroll failure can pin the key with `--authority-pop-key`.
async fn fetch_authority_pop_pk(client: &reqwest::Client, authority_url: &str) -> Option<[u8; 32]> {
    let url = format!("{}/pop", authority_url.trim_end_matches('/'));
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    let bytes = hex::decode(body.trim()).ok()?;
    let key = <[u8; 32]>::try_from(bytes).ok()?;
    info!("enroll: auto-provisioned authority PoP key from /pop");
    Some(key)
}

/// One directory authority the relay enrolls with, plus the mutable PoP-key
/// state the possession proof against it needs.
struct AuthorityTarget {
    /// `<base>` — used for the `/pop` fetch and in logs.
    base_url: String,
    /// `<base>/enroll`.
    enroll_url: String,
    /// This authority's PoP PUBLIC key (each authority derives its own from its
    /// signing identity, so this is per-target). Pinned or auto-fetched.
    pop_pk: Option<[u8; 32]>,
    /// `true` if `pop_pk` was pinned (`--authority-pop-key`). A pinned key is
    /// trusted and never dropped on a rejection (re-fetching could only
    /// downgrade it); an auto-fetched one is dropped + re-fetched to self-heal a
    /// transient MITM. Only the primary authority can be pinned today.
    pinned: bool,
}

/// Build the enrollment fields shared across every authority this tick: the same
/// `seq`, the same proposed admission `epoch`, tier, operator, rendezvous. The
/// per-authority possession proof is attached separately (it depends on each
/// authority's PoP key), so this carries none.
fn base_enrollment(cfg: &EnrollConfig, seq: u64, epoch: u64) -> RelayEnrollment {
    // RFC B3: a rendezvous-hosted relay advertises no dialable address.
    let advertise = if cfg.rendezvous.is_some() {
        String::new()
    } else {
        cfg.advertise_addr.clone()
    };
    let mut e = RelayEnrollment::new(
        cfg.kem_pubkey_hex.clone(),
        advertise,
        cfg.tier,
        cfg.country.clone(),
        cfg.operator.clone(),
        seq,
    )
    // k-of-n admission: the SAME epoch goes to every authority so their
    // attestations sign an identical message and combine into one certificate.
    .with_attest_epoch(epoch);
    if let Some(r) = &cfg.rendezvous {
        e = e.with_rendezvous(r.clone());
    }
    if cfg.rendezvous_capable {
        e = e.with_rendezvous_capable(true);
    }
    if cfg.mailbox {
        e = e.with_mailbox(true);
    }
    e
}

/// Attach the DH-MAC possession proof for ONE authority (bound to its `pop_pk`),
/// provable only by the holder of `relay_sk`. Required by the authority for
/// EVERY enrollment.
///
/// The proof covers the ENTIRE enrollment transcript
/// ([`RelayEnrollment::binding_hash`]), not just `(kem‖seq)`. Enrollments are
/// POSTed as JSON over plain HTTP by the shipped installers, so an on-path
/// attacker can rewrite the body in flight; a proof over `(kem‖seq)` alone
/// survives that rewrite and the authority would then sign the tampered
/// descriptor into the directory every client trusts.
///
/// MUST be called LAST, after every other field is set — the tag commits to
/// them. `base_enrollment` above already sets attest_epoch / rendezvous /
/// rendezvous_capable / mailbox before this runs; any new field must be added
/// there, not after.
fn attach_pop_proof(
    e: RelayEnrollment,
    cfg: &EnrollConfig,
    pop_pk: [u8; 32],
    _seq: u64,
) -> RelayEnrollment {
    if hex::decode(&cfg.kem_pubkey_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .is_none()
    {
        warn!("enroll: own kem_pubkey_hex malformed; cannot build PoP proof");
        return e;
    }
    let shared = x25519_dalek::StaticSecret::from(cfg.relay_sk)
        .diffie_hellman(&x25519_dalek::PublicKey::from(pop_pk));
    let tag = RelayEnrollment::pop_tag_v2(shared.as_bytes(), &e.binding_hash());
    e.with_pop_proof(hex::encode(tag))
}

/// Run the enrollment loop forever: enroll now with EVERY configured authority
/// (primary + extras for k-of-n admission), then heartbeat every `cfg.heartbeat`,
/// bumping `seq` each round.
///
/// `seq` is seeded from the wall clock so that a relay which restarts always
/// presents a higher `seq` than its previous (not-yet-pruned) entry — the
/// authority rejects non-increasing `seq` as replay. The same `seq` is sent to
/// every authority (each tracks it independently per key), so they stay in step.
pub async fn run_enrollment_loop(cfg: EnrollConfig) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "enroll: cannot build HTTP client; auto-enroll disabled");
            return;
        }
    };

    // Primary authority (may carry a pinned PoP key) + any extras (auto-fetch).
    let mut targets: Vec<AuthorityTarget> = Vec::with_capacity(1 + cfg.extra_authority_urls.len());
    let primary = cfg.authority_url.trim_end_matches('/').to_string();
    targets.push(AuthorityTarget {
        enroll_url: format!("{primary}/enroll"),
        base_url: primary,
        pop_pk: cfg.authority_pop_pk,
        pinned: cfg.authority_pop_pk.is_some(),
    });
    for url in &cfg.extra_authority_urls {
        let base = url.trim_end_matches('/').to_string();
        targets.push(AuthorityTarget {
            enroll_url: format!("{base}/enroll"),
            base_url: base,
            pop_pk: None,
            pinned: false,
        });
    }
    if targets.len() > 1 {
        info!(
            authorities = targets.len(),
            "k-of-n enrollment: announcing to multiple directory authorities so a quorum can admit this relay"
        );
    }

    let mut seq: u64 = now_unix();

    // RFC B3: a rendezvous-hosted relay is proven live by the authority ASKING
    // its rendezvous host R, not by dialing us back. That query only succeeds
    // once our reverse tunnel is registered at R — and the tunnel is established
    // by a task started in parallel with this loop. Enrolling immediately
    // therefore loses a race we can simply not enter: the authority answers
    // "rendezvous relay does not host this relay" and, before this grace period
    // existed, we then waited a FULL heartbeat (up to 5 min for a volunteer)
    // before retrying — so a correctly-configured relay looked broken for
    // minutes on first start. Give the tunnel a moment first.
    if cfg.rendezvous.is_some() {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // Backoff for the FIRST successful enrollment. Until a relay is listed it
    // contributes nothing, so retry far faster than the steady-state heartbeat;
    // once listed, settle into `cfg.heartbeat`.
    let mut settled = false;
    const FIRST_ENROLL_RETRY: Duration = Duration::from_secs(5);
    const FIRST_ENROLL_RETRY_MAX: Duration = Duration::from_secs(60);
    let mut retry = FIRST_ENROLL_RETRY;

    loop {
        let mut any_ok = false;
        // One proposed admission epoch for ALL authorities this tick.
        let epoch = crypto_gotham::enroll::current_attest_epoch(now_unix());
        let base = base_enrollment(&cfg, seq, epoch);

        for t in &mut targets {
            // Auto-provision this authority's PoP key if not pinned/known. It is
            // PUBLIC, so a MITM serving a wrong key only makes OUR OWN proof fail
            // (self-inflicted enroll failure), never a hijack.
            if t.pop_pk.is_none() {
                t.pop_pk = fetch_authority_pop_pk(&client, &t.base_url).await;
            }

            let enrollment = match t.pop_pk {
                Some(pk) => attach_pop_proof(base.clone(), &cfg, pk, seq),
                None => {
                    warn!(
                        authority = %t.base_url,
                        "enroll: no authority PoP key yet (pin --authority-pop-key or wait for /pop) — the authority requires a possession proof and will reject until then"
                    );
                    base.clone()
                }
            };

            let mut req = client.post(&t.enroll_url).json(&enrollment);
            if let Some(tok) = &cfg.token {
                req = req.bearer_auth(tok);
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(seq, authority = %t.base_url, "enrolled with directory authority");
                    any_ok = true;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    // Self-heal a poisoned auto-fetched PoP key (never a pinned one).
                    if !t.pinned && body.contains("possession proof") {
                        warn!(authority = %t.base_url, "enroll: possession proof rejected; will re-fetch the auto-provisioned PoP key next tick");
                        t.pop_pk = None;
                    }
                    warn!(%status, authority = %t.base_url, body = %body, "enroll rejected by authority (will retry)");
                }
                Err(e) => {
                    warn!(error = %e, authority = %t.base_url, "enroll request failed (will retry)");
                }
            }
        }

        seq = seq.saturating_add(1);
        if any_ok {
            settled = true;
        }
        if settled {
            tokio::time::sleep(cfg.heartbeat).await;
        } else {
            // Not listed yet — retry quickly, backing off so a persistently
            // misconfigured relay does not hammer the authority.
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(FIRST_ENROLL_RETRY_MAX);
        }
    }
}

/// Parse a `--tier` string into a [`RelayTier`]. A single relay serves one
/// tier; `mix` (middle hop, sees neither client nor recipient) is the
/// privacy-safest default for volunteers.
pub fn parse_tier(s: &str) -> Result<RelayTier, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "entry" => Ok(RelayTier::Entry),
        "mix" | "" => Ok(RelayTier::Mix),
        "exit" => Ok(RelayTier::Exit),
        other => Err(format!("unknown tier `{other}` — use entry|mix|exit")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tier_maps_known_values() {
        assert_eq!(parse_tier("entry").unwrap(), RelayTier::Entry);
        assert_eq!(parse_tier("MIX").unwrap(), RelayTier::Mix);
        assert_eq!(parse_tier("").unwrap(), RelayTier::Mix);
        assert_eq!(parse_tier(" exit ").unwrap(), RelayTier::Exit);
        assert!(parse_tier("all").is_err());
    }

    fn cfg_for(kem_hex: String, extra: Vec<String>) -> EnrollConfig {
        EnrollConfig {
            authority_url: "http://a1:8443".into(),
            extra_authority_urls: extra,
            advertise_addr: "203.0.113.7:443".into(),
            kem_pubkey_hex: kem_hex,
            tier: RelayTier::Mix,
            token: None,
            country: None,
            operator: Some("op".into()),
            heartbeat: Duration::from_secs(60),
            rendezvous: None,
            rendezvous_capable: false,
            mailbox: false,
            relay_sk: [9u8; 32],
            authority_pop_pk: None,
        }
    }

    #[test]
    fn base_enrollment_carries_the_shared_admission_epoch() {
        let kem = hex::encode([3u8; 32]);
        let cfg = cfg_for(
            kem.clone(),
            vec!["http://a2:8443".into(), "http://a3:8443".into()],
        );
        let e = base_enrollment(&cfg, 42, 1_700_000_000);
        assert_eq!(
            e.attest_epoch,
            Some(1_700_000_000),
            "epoch is threaded onto the enrollment"
        );
        assert_eq!(e.seq, 42);
        assert_eq!(e.operator.as_deref(), Some("op"));
        // The shared base carries no possession proof — that's per-authority.
        assert!(e.pop_proof.is_none());
    }

    #[test]
    fn pop_proof_is_authority_specific_but_epoch_is_shared() {
        // Two authorities with DIFFERENT PoP keys → two different proofs over the
        // SAME (kem, seq), while the admission epoch stays identical (so the
        // attestations combine). Proves the split base/proof design.
        use x25519_dalek::{PublicKey, StaticSecret};
        let kem = hex::encode(PublicKey::from(&StaticSecret::from([9u8; 32])).to_bytes());
        let cfg = cfg_for(kem, vec![]);
        let base = base_enrollment(&cfg, 7, 1_700_000_000);
        let pk_a = PublicKey::from(&StaticSecret::from([1u8; 32])).to_bytes();
        let pk_b = PublicKey::from(&StaticSecret::from([2u8; 32])).to_bytes();
        let ea = attach_pop_proof(base.clone(), &cfg, pk_a, 7);
        let eb = attach_pop_proof(base.clone(), &cfg, pk_b, 7);
        assert!(ea.pop_proof.is_some() && eb.pop_proof.is_some());
        assert_ne!(
            ea.pop_proof, eb.pop_proof,
            "different authorities → different proofs"
        );
        assert_eq!(
            ea.attest_epoch, eb.attest_epoch,
            "same admission epoch to both"
        );
    }
}
