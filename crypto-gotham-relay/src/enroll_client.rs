// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypto_gotham::directory::RelayTier;
use crypto_gotham::enroll::RelayEnrollment;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct EnrollConfig {
    pub authority_url: String,
    pub extra_authority_urls: Vec<String>,
    pub advertise_addr: String,
    pub kem_pubkey_hex: String,
    pub tier: RelayTier,
    pub token: Option<String>,
    pub country: Option<String>,
    pub operator: Option<String>,
    pub heartbeat: Duration,
    pub rendezvous: Option<String>,
    pub rendezvous_capable: bool,
    pub mailbox: bool,
    pub relay_sk: [u8; 32],
    pub authority_pop_pk: Option<[u8; 32]>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1)
}

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

struct AuthorityTarget {
    base_url: String,
    enroll_url: String,
    pop_pk: Option<[u8; 32]>,
    pinned: bool,
}

fn base_enrollment(cfg: &EnrollConfig, seq: u64, epoch: u64) -> RelayEnrollment {
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

    if cfg.rendezvous.is_some() {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let mut settled = false;
    const FIRST_ENROLL_RETRY: Duration = Duration::from_secs(5);
    const FIRST_ENROLL_RETRY_MAX: Duration = Duration::from_secs(60);
    let mut retry = FIRST_ENROLL_RETRY;

    loop {
        let mut any_ok = false;
        let epoch = crypto_gotham::enroll::current_attest_epoch(now_unix());
        let base = base_enrollment(&cfg, seq, epoch);

        for t in &mut targets {
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
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(FIRST_ENROLL_RETRY_MAX);
        }
    }
}

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
        assert!(e.pop_proof.is_none());
    }

    #[test]
    fn pop_proof_is_authority_specific_but_epoch_is_shared() {
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
