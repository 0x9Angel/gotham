// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Peer-to-peer directory **gossip** — the transport that removes the single
//! directory authority as a runtime bottleneck.
//!
//! Each relay keeps a [`Roster`] (its view of the network) and periodically
//! runs **push-pull anti-entropy** with a few random peers over QUIC + Noise XK
//! (ALPN `gotham-dir/1`): it pushes its roster, the peer merges it, the peer
//! replies with its roster, and the initiator merges that. Both sides converge,
//! so the union of everyone's knowledge propagates hop by hop — no relay has to
//! reach one central server, and a seized server can't stop discovery.
//!
//! Trust is anchored by the k-of-n admission layer, not the transport: every
//! merged entry is re-verified against the pinned
//! [`AuthoritySet`](crypto_gotham_directory::AuthoritySet)
//! ([`Roster::merge_admitted`]), so a peer can only relay entries a quorum of
//! authorities already vouched for — it cannot inject relays. The serving half
//! lives in [`crate::transport::serve_gossip_connection`]; this module is the
//! outbound half: the node loop and the client round.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crypto_gotham::directory::RelayDescriptor;
use crypto_gotham_directory::{
    AdmissionCert, Advertisement, AuthoritySet, Capabilities, Roster, STALE_AFTER_SECS,
};
use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use rand::seq::SliceRandom;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::transport::{
    build_gossip_client_endpoint, noise_initiator_handshake, read_noise_blob_capped,
    write_noise_blob, GossipService, TransportError, MAX_GOSSIP_FRAME,
};

/// How many random peers a node gossips with per round.
const GOSSIP_FANOUT: usize = 3;

/// Current unix time in seconds (the roster freshness clock).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Errors from an outbound gossip round.
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    /// Underlying QUIC + Noise transport failure.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// Roster (de)serialisation failure.
    #[error("roster codec: {0}")]
    Codec(String),
}

/// Everything a relay needs to advertise + admit itself into the gossip mesh.
pub struct GossipConfig {
    /// Ed25519 advertisement signing key (the relay's gossip identity).
    pub identity: SigningKey,
    /// The relay's X25519 routing (KEM) public key, hex-encoded.
    pub kem_pubkey_hex: String,
    /// The reachable `ip:port` peers use to connect to this relay.
    pub advertise_addr: String,
    /// What this relay is willing to serve.
    pub capabilities: Capabilities,
    /// The relay's k-of-n admission certificate (authority-issued out of band).
    pub admission: AdmissionCert,
    /// The relay's X25519 secret, used as the Noise XK initiator static key.
    pub noise_sk: [u8; 32],
    /// Bootstrap peers as `(addr, kem_pubkey)` — tried every round in addition
    /// to roster peers, so a fresh node with an empty roster can still join.
    /// Redundant (but harmless) once the roster has converged.
    pub bootstrap: Vec<(SocketAddr, [u8; 32])>,
}

/// A running gossip node: owns the shared roster + authority set (also served
/// inbound via [`GossipService`]) and drives the outbound anti-entropy loop.
pub struct GossipNode {
    cfg: GossipConfig,
    authority_set: Arc<AuthoritySet>,
    roster: Arc<Mutex<Roster>>,
    endpoint: Endpoint,
    seq: AtomicU64,
}

impl GossipNode {
    /// Build a node over a shared roster + pinned authority set. Seeds the
    /// advertisement sequence counter from the clock so a restart is never
    /// rejected as an anti-replay of the previous run's advertisements.
    pub fn new(
        cfg: GossipConfig,
        roster: Arc<Mutex<Roster>>,
        authority_set: Arc<AuthoritySet>,
    ) -> Result<Self, GossipError> {
        Ok(Self {
            cfg,
            authority_set,
            roster,
            endpoint: build_gossip_client_endpoint()?,
            seq: AtomicU64::new(now_unix()),
        })
    }

    /// The [`GossipService`] to hand the inbound listener so it serves this
    /// node's roster (shares the same `Arc`s — inbound merges and outbound
    /// rounds see one roster).
    pub fn service(&self) -> GossipService {
        GossipService {
            roster: Arc::clone(&self.roster),
            authority_set: Arc::clone(&self.authority_set),
        }
    }

    /// Our own lowercase identity hex (roster key).
    fn identity_hex(&self) -> String {
        hex::encode(self.cfg.identity.verifying_key().to_bytes())
    }

    /// Re-sign our own advertisement with a fresh `seq`/timestamp and (re)admit
    /// it into the roster, so peers keep seeing us as live. If our own
    /// admission has aged out, we drop from our roster — correct
    /// revocation-by-non-renewal — and log it.
    async fn refresh_self(&self, now: u64) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let ad = match Advertisement::sign(
            &self.cfg.identity,
            self.cfg.kem_pubkey_hex.clone(),
            self.cfg.advertise_addr.clone(),
            self.cfg.capabilities,
            seq,
        ) {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "gossip: could not sign self advertisement");
                return;
            }
        };
        let mut r = self.roster.lock().await;
        if let Err(e) = r.insert_admitted(ad, self.cfg.admission.clone(), &self.authority_set, now)
        {
            debug!(error = %e, "gossip: self re-admission refused (stale admission?)");
        }
    }

    /// Pick up to `GOSSIP_FANOUT` random fresh, admitted peers (excluding self)
    /// that carry a routable address + KEM key.
    fn pick_peers(&self, roster: &Roster, now: u64) -> Vec<(SocketAddr, [u8; 32])> {
        let me = self.identity_hex().to_lowercase();
        let mut cands: Vec<(SocketAddr, [u8; 32])> = roster
            .entries
            .iter()
            .filter(|(key, ad)| {
                key.as_str() != me
                    && now.saturating_sub(ad.signed_at) <= STALE_AFTER_SECS
                    && roster.admissions.contains_key(*key)
            })
            .filter_map(|(_, ad)| {
                let addr = ad.address.parse::<SocketAddr>().ok()?;
                let kem = ad.kem_pubkey_bytes().ok()?;
                Some((addr, kem))
            })
            .collect();
        let mut rng = rand::thread_rng();
        cands.shuffle(&mut rng);
        cands.truncate(GOSSIP_FANOUT);
        cands
    }

    /// Run one gossip cycle: refresh self, prune stale, then push-pull with a
    /// few random peers. Returns the number of new/updated entries learned.
    pub async fn gossip_once(&self) -> usize {
        let now = now_unix();
        self.refresh_self(now).await;
        let mut peers = {
            let mut r = self.roster.lock().await;
            r.prune_stale(now);
            self.pick_peers(&r, now)
        };
        // Always also try the configured bootstrap seeds (dedup by address) so a
        // still-empty roster can converge from cold.
        for bp in &self.cfg.bootstrap {
            if !peers.iter().any(|(a, _)| a == &bp.0) {
                peers.push(*bp);
            }
        }
        let mut merged = 0usize;
        for (addr, kem) in peers {
            match gossip_round_client(
                &self.endpoint,
                addr,
                &kem,
                &self.cfg.noise_sk,
                &self.roster,
                &self.authority_set,
            )
            .await
            {
                Ok(d) => merged += d,
                // Never log the peer address (routing metadata).
                Err(e) => debug!(error = %e, "gossip: round with a peer failed"),
            }
        }
        merged
    }

    /// Snapshot the roster as routable descriptors for the path selector.
    pub async fn routable_descriptors(&self) -> Vec<RelayDescriptor> {
        let now = now_unix();
        self.roster
            .lock()
            .await
            .to_relay_descriptors(&self.authority_set, now)
    }

    /// Seed the roster with a peer we already trust the admission of (e.g. from
    /// a shipped bootstrap file). Best-effort: an entry that fails verification
    /// is dropped.
    pub async fn seed(&self, ad: Advertisement, cert: AdmissionCert) {
        let now = now_unix();
        let mut r = self.roster.lock().await;
        if let Err(e) = r.insert_admitted(ad, cert, &self.authority_set, now) {
            debug!(error = %e, "gossip: bootstrap seed rejected");
        }
    }
}

/// Spawn the periodic outbound gossip loop.
pub fn spawn_gossip_loop(node: Arc<GossipNode>, interval: Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            let merged = node.gossip_once().await;
            if merged > 0 {
                info!(merged, "gossip: converged new roster entries");
            }
        }
    });
}

/// One outbound push-pull round: push our roster to `peer_addr` (Noise-pinning
/// the peer's `peer_kem_pk`), read the peer's roster, and merge it under our
/// pinned authority set. Returns the number of entries the merge pulled in.
async fn gossip_round_client(
    endpoint: &Endpoint,
    peer_addr: SocketAddr,
    peer_kem_pk: &[u8; 32],
    my_sk: &[u8; 32],
    roster: &Arc<Mutex<Roster>>,
    set: &AuthoritySet,
) -> Result<usize, GossipError> {
    let conn = endpoint
        .connect(peer_addr, "gotham-relay.local")
        .map_err(TransportError::Connect)?
        .await
        .map_err(TransportError::Connection)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(TransportError::Connection)?;
    let mut noise = noise_initiator_handshake(my_sk, peer_kem_pk, &mut send, &mut recv).await?;

    // Push our roster.
    let ours = { roster.lock().await.clone() };
    let bytes = rmp_serde::to_vec_named(&ours).map_err(|e| GossipError::Codec(e.to_string()))?;
    write_noise_blob(&mut noise, &mut send, &bytes).await?;

    // Pull the peer's roster (tight gossip frame cap), verify OFF the lock, then
    // splice the verified result under a short-held lock.
    let blob = read_noise_blob_capped(&mut noise, &mut recv, MAX_GOSSIP_FRAME).await?;
    let peer: Roster =
        rmp_serde::from_slice(&blob).map_err(|e| GossipError::Codec(e.to_string()))?;
    let now = now_unix();
    let verified = Roster::verify_incoming(&peer, set, now);
    let delta = {
        let mut r = roster.lock().await;
        r.splice_verified(&verified)
    };

    send.finish().ok();
    conn.close(0u32.into(), b"done");
    Ok(delta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham_directory::Attestation;
    use ed25519_dalek::SigningKey as EdKey;
    use ed25519_dalek::VerifyingKey;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::process::Relay;
    use crate::transport::{build_server_endpoint, serve_endpoint_with_services};

    fn clamped_sk() -> [u8; 32] {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    fn authorities(n: usize, k: usize) -> (Vec<EdKey>, Arc<AuthoritySet>) {
        let auth: Vec<EdKey> = (0..n).map(|_| EdKey::generate(&mut OsRng)).collect();
        let vks: Vec<VerifyingKey> = auth.iter().map(|a| a.verifying_key()).collect();
        (auth, Arc::new(AuthoritySet::new(&vks, k).unwrap()))
    }

    fn admit(auth: &[EdKey], k: usize, id: &str, epoch: u64) -> AdmissionCert {
        let atts: Vec<Attestation> = auth[..k]
            .iter()
            .map(|a| AdmissionCert::attest(a, id, epoch, None))
            .collect();
        AdmissionCert::assemble(id.to_string(), epoch, None, atts)
    }

    /// Spawn a full relay node (mixnet + gossip) on 127.0.0.1:0, publish its own
    /// advertisement, and return its handle.
    async fn spawn_node(
        auth: &[EdKey],
        k: usize,
        set: &Arc<AuthoritySet>,
        caps: Capabilities,
    ) -> Arc<GossipNode> {
        crate::init_crypto();
        let kem_sk = clamped_sk();
        let kem_hex = hex::encode(PublicKey::from(&StaticSecret::from(kem_sk)).to_bytes());
        let ed = EdKey::generate(&mut OsRng);
        let id = hex::encode(ed.verifying_key().to_bytes());
        let cert = admit(auth, k, &id, now_unix());

        let endpoint = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let cfg = GossipConfig {
            identity: ed,
            kem_pubkey_hex: kem_hex,
            advertise_addr: addr.to_string(),
            capabilities: caps,
            admission: cert,
            noise_sk: kem_sk,
            bootstrap: Vec::new(),
        };
        let roster = Arc::new(Mutex::new(Roster::new()));
        let node = Arc::new(GossipNode::new(cfg, roster, Arc::clone(set)).unwrap());

        let relay = Relay::new(kem_sk, 1024, Duration::from_secs(60), 0);
        let svc = node.service();
        tokio::spawn(async move {
            let _ =
                serve_endpoint_with_services(endpoint, kem_sk, relay, None, None, Some(svc), None)
                    .await;
        });
        node.refresh_self(now_unix()).await; // publish self before returning
        node
    }

    async fn self_ad(node: &GossipNode) -> (Advertisement, AdmissionCert) {
        let r = node.roster.lock().await;
        (
            r.entries.values().next().unwrap().clone(),
            r.admissions.values().next().unwrap().clone(),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_nodes_converge_and_produce_routable_descriptors() {
        let (auth, set) = authorities(3, 2);

        // Three admitted nodes, distinct capabilities → a full entry/mix/exit
        // set after the bridge.
        let a = spawn_node(&auth, 2, &set, Capabilities::Entry).await;
        let b = spawn_node(&auth, 2, &set, Capabilities::Mix).await;
        let c = spawn_node(&auth, 2, &set, Capabilities::Exit).await;

        // Bootstrap a connected topology: A↔B know each other, C knows A.
        let (a_ad, a_cert) = self_ad(&a).await;
        let (b_ad, b_cert) = self_ad(&b).await;
        a.seed(b_ad, b_cert).await;
        b.seed(a_ad.clone(), a_cert.clone()).await;
        c.seed(a_ad, a_cert).await;

        // Anti-entropy propagates knowledge transitively across rounds.
        for _ in 0..6 {
            a.gossip_once().await;
            b.gossip_once().await;
            c.gossip_once().await;
        }

        for node in [&a, &b, &c] {
            let n = node.roster.lock().await.len();
            assert!(n >= 3, "expected convergence to >=3 entries, got {n}");
        }
        // A can now build a routable 3-tier directory purely from gossip.
        let descs = a.routable_descriptors().await;
        assert_eq!(descs.len(), 3);
        let tiers: std::collections::HashSet<_> = descs.iter().map(|d| d.tier).collect();
        assert_eq!(
            tiers.len(),
            3,
            "entry/mix/exit all present after convergence"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gossip_drops_entries_admitted_by_a_different_authority_set() {
        // A pins authority set S1; a hostile peer pins S2 and pushes an entry
        // admitted only under S2. A must not adopt it.
        let (auth1, set1) = authorities(3, 2);
        let (auth2, set2) = authorities(3, 2);

        let a = spawn_node(&auth1, 2, &set1, Capabilities::Entry).await;
        // Hostile node admitted under S2 only.
        let evil = spawn_node(&auth2, 2, &set2, Capabilities::Exit).await;

        let (evil_ad, evil_cert) = self_ad(&evil).await;
        // Even if A is pointed at evil, evil's ad carries an S2 admission A can't verify.
        a.seed(evil_ad, evil_cert).await; // seed uses A's set1 → rejected
        let (a_ad, a_cert) = self_ad(&a).await;
        evil.seed(a_ad, a_cert).await;

        for _ in 0..4 {
            a.gossip_once().await;
            evil.gossip_once().await;
        }
        // A's roster holds only itself; the S2-admitted relay was never adopted.
        let ids: Vec<String> = a.roster.lock().await.entries.keys().cloned().collect();
        assert_eq!(
            ids.len(),
            1,
            "A must reject an entry not admitted under its pinned set"
        );
        assert_eq!(ids[0], a.identity_hex().to_lowercase());
    }
}
