// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! RFC B3 reverse / rendezvous transport.
//!
//! A CGNAT relay **N** (no inbound reachability — mobile, Freebox with broken
//! UPnP, double-NAT) keeps a persistent **outbound** QUIC + Noise-IK tunnel to a
//! public **rendezvous relay R**. R registers the tunnel keyed by N's
//! *authenticated* identity and PUSHES mixnet packets down it; N reads them and
//! processes them exactly like any inbound packet. This gives N inbound
//! reachability with no port-forward, UPnP, or dialable address.
//!
//! Direction of trust: the tunnel uses **Noise IK**, so the initiator (N)
//! authenticates ITS static key to R — R binds the tunnel to N's proven
//! identity, and the handshake doubles as N's proof-of-possession (see the
//! authority/enroll path). The mixnet's own links use XK (responder-only auth);
//! this is the one place the initiator must be authenticated.
//!
//! Honest limitation: R sees the *timing and volume* of N's inbound traffic
//! (never its content — Sphinx). N should hold several rendezvous points and run
//! cover traffic; anonymity for a rendezvous-hosted relay is weaker than for a
//! directly-reachable one. See `docs/gotham/design/rfc-b3-*` §7.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::Connection;
use snow::TransportState;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::transport::{
    build_rendezvous_client_endpoint, noise_ik_initiator_handshake, noise_ik_responder_handshake,
    read_noise_frame, write_noise_frame, TransportError,
};

/// One live rendezvous tunnel held by R for a hosted relay N. R pushes packets
/// to N by writing Noise frames on `send` under `noise` (the R→N direction).
pub struct RendezvousTunnel {
    /// N's authenticated identity (its X25519 static pubkey == its `next_node_id`).
    pub peer_pk: [u8; 32],
    /// The source IP N dialed in from. Used to bound how many tunnels a single
    /// address may hold, so one host can't squat the whole table.
    src_ip: std::net::IpAddr,
    /// Kept so the tunnel (and its send stream) stays open for the table's life.
    _conn: Connection,
    send: Mutex<quinn::SendStream>,
    noise: Mutex<TransportState>,
}

impl RendezvousTunnel {
    /// Push one mixnet packet (must be `PACKET_SIZE`) down the tunnel to N.
    pub async fn push(&self, packet: &[u8]) -> Result<(), TransportError> {
        let mut send = self.send.lock().await;
        let mut noise = self.noise.lock().await;
        write_noise_frame(&mut noise, &mut send, packet).await
    }
}

/// Max concurrent hosted tunnels. Bounds memory against an attacker opening many
/// Noise-IK tunnels with throwaway identities (each valid but disposable). A real
/// rendezvous serves far fewer — its diversity budget already caps how many
/// hosted relays are even usable in the directory.
pub const MAX_TUNNELS: usize = 512;

/// Max tunnels a single source IP may hold. Bounds table-squatting: filling the
/// table now costs MAX_TUNNELS / MAX_TUNNELS_PER_IP distinct source addresses,
/// not just that many throwaway identities from one host. Refreshing an
/// already-hosted identity is exempt (it supersedes, not grows).
const MAX_TUNNELS_PER_IP: usize = 8;

/// Admission decision for a rendezvous tunnel. A NEW identity must fit under
/// BOTH the global cap and the per-source-IP cap; a refresh (identity already
/// hosted) always supersedes. Pure so it can be unit-tested without a live QUIC
/// connection.
fn may_admit(total: usize, same_ip: usize, is_refresh: bool) -> bool {
    is_refresh || (total < MAX_TUNNELS && same_ip < MAX_TUNNELS_PER_IP)
}

/// R-side table of live rendezvous tunnels, keyed by hosted-relay identity
/// (`next_node_id`). Cheap to clone (an `Arc`). A relay always has one; it stays
/// empty unless the relay is serving as a rendezvous point.
#[derive(Clone, Default)]
pub struct RendezvousTable {
    inner: Arc<Mutex<HashMap<[u8; 32], Arc<RendezvousTunnel>>>>,
}

impl RendezvousTable {
    /// A fresh, empty rendezvous table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tunnel. Returns `false` (rejecting it) if the table is at
    /// [`MAX_TUNNELS`] and this is a NEW identity — an attacker cannot exhaust
    /// memory with disposable-identity tunnels. Refreshing an already-hosted
    /// identity always succeeds (supersedes the stale tunnel).
    async fn register(&self, tunnel: Arc<RendezvousTunnel>) -> bool {
        let mut m = self.inner.lock().await;
        let is_refresh = m.contains_key(&tunnel.peer_pk);
        let same_ip = m.values().filter(|t| t.src_ip == tunnel.src_ip).count();
        if !may_admit(m.len(), same_ip, is_refresh) {
            return false;
        }
        m.insert(tunnel.peer_pk, tunnel);
        true
    }

    /// Deregister a tunnel — but ONLY if the entry currently in the table is
    /// still `tunnel` itself.
    ///
    /// `register` deliberately lets a refresh supersede an existing entry for
    /// the same identity, so two `serve_rendezvous_connection` tasks for one
    /// peer can be alive at once (a NAT rebind, a 4G↔Wi-Fi switch, or an
    /// attacker who can drop the old connection). An unconditional remove keyed
    /// only on `peer_pk` then let the OLD task's teardown delete the NEW live
    /// tunnel, permanently blackholing that CGNAT relay: the table says it is
    /// not hosted, while its client sees a healthy connection and never
    /// reconnects (`rendezvous_session` only redials on a read error).
    ///
    /// Identity-compare by pointer: each task holds the `Arc` it registered.
    async fn remove_if_current(&self, tunnel: &Arc<RendezvousTunnel>) {
        let mut m = self.inner.lock().await;
        if let Some(cur) = m.get(&tunnel.peer_pk) {
            if !Arc::ptr_eq(cur, tunnel) {
                return; // a newer tunnel superseded us — leave it alone
            }
        }
        m.remove(&tunnel.peer_pk);
    }

    /// The live tunnel for a hosted relay identity, if one is registered here.
    pub async fn get(&self, peer_pk: &[u8; 32]) -> Option<Arc<RendezvousTunnel>> {
        self.inner.lock().await.get(peer_pk).cloned()
    }

    /// Push a packet to hosted relay N. `Ok(false)` if N has no live tunnel here
    /// (the caller then drops the packet — we never dial a CGNAT relay).
    pub async fn push(&self, peer_pk: &[u8; 32], packet: &[u8]) -> Result<bool, TransportError> {
        let Some(tunnel) = self.get(peer_pk).await else {
            return Ok(false);
        };
        tunnel.push(packet).await?;
        Ok(true)
    }

    /// Number of live tunnels currently hosted (metrics / tests).
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True if no tunnels are hosted.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// Serve one inbound rendezvous connection (ALPN `gotham-rdv/1`), **R side**.
///
/// Runs the Noise-IK responder handshake (learning + authenticating N's
/// identity), registers the tunnel, then holds it open until the connection
/// drops — at which point it deregisters. R only ever WRITES to N (pushes); N
/// never sends mixnet frames back up this tunnel (its onward forwarding uses its
/// own outbound), so there is no inbound reader here.
pub async fn serve_rendezvous_connection(
    conn: Connection,
    static_sk: [u8; 32],
    table: RendezvousTable,
) -> Result<(), TransportError> {
    let src_ip = conn.remote_address().ip();
    let (mut send, mut recv) = conn.accept_bi().await?;
    let (noise, peer_pk) = noise_ik_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    info!(
        peer = %hex::encode(peer_pk),
        "rendezvous tunnel established — now hosting a CGNAT relay"
    );

    let tunnel = Arc::new(RendezvousTunnel {
        peer_pk,
        src_ip,
        _conn: conn.clone(),
        send: Mutex::new(send),
        noise: Mutex::new(noise),
    });
    if !table.register(Arc::clone(&tunnel)).await {
        warn!(peer = %hex::encode(peer_pk), "rendezvous table full — rejecting tunnel");
        conn.close(1u32.into(), b"rendezvous full");
        return Ok(());
    }

    // Block until the tunnel drops (QUIC keep-alive from N holds it open). We do
    // not expect inbound frames; a close means N is gone. `recv` is kept in scope
    // so the bi-stream is not half-closed early.
    let reason = conn.closed().await;
    let _ = &recv;
    debug!(peer = %hex::encode(peer_pk), ?reason, "rendezvous tunnel closed");
    table.remove_if_current(&tunnel).await;
    Ok(())
}

/// N-side: maintain a persistent rendezvous tunnel OUT to R, reconnecting on
/// failure, forwarding every packet R pushes down it into `inbound_tx`. Runs
/// until `inbound_tx` is closed. The caller drains `inbound_tx` and feeds each
/// packet to its `Relay::process` + onward forwarding (see Phase 2 wiring).
pub async fn run_rendezvous_client(
    r_addr: SocketAddr,
    r_pk: [u8; 32],
    my_sk: [u8; 32],
    inbound_tx: mpsc::Sender<Vec<u8>>,
) {
    const RETRY: Duration = Duration::from_secs(3);
    loop {
        if inbound_tx.is_closed() {
            return;
        }
        match rendezvous_session(r_addr, &r_pk, &my_sk, &inbound_tx).await {
            Ok(()) => debug!(r = %r_addr, "rendezvous session ended; reconnecting"),
            Err(e) => warn!(error = ?e, r = %r_addr, "rendezvous session failed; retrying"),
        }
        if inbound_tx.is_closed() {
            return;
        }
        tokio::time::sleep(RETRY).await;
    }
}

/// One rendezvous session: connect, IK-handshake, then read pushed packets until
/// the tunnel drops or the consumer goes away.
async fn rendezvous_session(
    r_addr: SocketAddr,
    r_pk: &[u8; 32],
    my_sk: &[u8; 32],
    inbound_tx: &mpsc::Sender<Vec<u8>>,
) -> Result<(), TransportError> {
    let endpoint = build_rendezvous_client_endpoint()?;
    let conn = endpoint.connect(r_addr, "gotham-relay.local")?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut noise = noise_ik_initiator_handshake(my_sk, r_pk, &mut send, &mut recv).await?;
    info!(r = %r_addr, "rendezvous tunnel up — inbound now arrives via R");

    // Every frame R pushes is a mixnet packet destined for us. `send` is kept in
    // scope so the stream stays open (we never write after the handshake).
    let _keep_send = send;
    loop {
        let packet = read_noise_frame(&mut noise, &mut recv).await?;
        // Bounded channel: a full queue BLOCKS here, which stops reading the QUIC
        // stream and lets quinn flow-control push back on R — bounded, back-
        // pressured delivery instead of an unbounded memory backlog. Errors only
        // when the consumer is gone.
        if inbound_tx.send(packet).await.is_err() {
            return Ok(()); // consumer gone
        }
    }
}

/// Bounded depth of a CGNAT relay's rendezvous-inbound queue. Past this, QUIC
/// flow control back-pressures the rendezvous relay R rather than the CGNAT
/// relay buffering without limit.
pub const RENDEZVOUS_INBOUND_QUEUE: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::build_server_endpoint;
    use crypto_gotham::PACKET_SIZE;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        (sk, pk)
    }

    #[test]
    fn may_admit_bounds_global_and_per_ip() {
        assert!(super::may_admit(0, 0, false), "empty table admits");
        assert!(super::may_admit(10, 3, false), "under both caps admits");
        // Global cap.
        assert!(
            !super::may_admit(MAX_TUNNELS, 0, false),
            "global-full rejects new"
        );
        assert!(
            super::may_admit(MAX_TUNNELS, 0, true),
            "refresh exempt from global cap"
        );
        // Per-source-IP cap — one host can't squat the table.
        assert!(
            !super::may_admit(10, MAX_TUNNELS_PER_IP, false),
            "per-IP-full rejects a new identity from that IP"
        );
        assert!(
            super::may_admit(10, MAX_TUNNELS_PER_IP - 1, false),
            "under the per-IP cap still admits"
        );
        assert!(
            super::may_admit(10, MAX_TUNNELS_PER_IP, true),
            "refresh exempt from per-IP cap"
        );
    }

    #[tokio::test]
    async fn rendezvous_tunnel_delivers_pushed_packet_to_cgnat_relay() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (r_sk, r_pk) = keypair(0x11); // rendezvous relay R
        let (n_sk, n_pk) = keypair(0x22); // CGNAT relay N

        // R: bind + accept ONE rendezvous connection into a shared table.
        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let r_addr = server.local_addr().unwrap();
        let table = RendezvousTable::new();
        {
            let table = table.clone();
            tokio::spawn(async move {
                if let Some(inc) = server.accept().await {
                    if let Ok(conn) = inc.await {
                        let _ = serve_rendezvous_connection(conn, r_sk, table).await;
                    }
                }
            });
        }

        // N: dial R and keep the tunnel up, surfacing pushes on `rx`.
        let (tx, mut rx) = mpsc::channel(64);
        tokio::spawn(run_rendezvous_client(r_addr, r_pk, n_sk, tx));

        // Wait for N's tunnel to register at R.
        let mut tries = 0;
        while table.get(&n_pk).await.is_none() {
            tries += 1;
            assert!(tries < 100, "tunnel never registered");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // R pushes a packet addressed to N by identity; N must receive it verbatim.
        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0] = 0xAB;
        packet[PACKET_SIZE - 1] = 0xCD;
        assert!(
            table.push(&n_pk, &packet).await.unwrap(),
            "N should be hosted"
        );

        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("push should arrive")
            .expect("channel open");
        assert_eq!(got, packet, "N must receive the exact packet R pushed");

        // Pushing to an unknown identity is a no-op (never dialed).
        let (_, stranger_pk) = keypair(0x99);
        assert!(!table.push(&stranger_pk, &packet).await.unwrap());
    }

    /// End-to-end (RFC B3 Phases 1+2+3 data path): a rendezvous relay R peels a
    /// `VIA_RENDEZVOUS` layer, pushes the inner packet down N's tunnel, and N —
    /// the CGNAT relay, reachable by no one directly — receives it and delivers
    /// it locally. Proves inbound reachability with zero inbound connectivity.
    #[tokio::test]
    async fn end_to_end_packet_reaches_cgnat_relay_via_rendezvous() {
        use crate::process::{ProcessOutcome, Relay};
        use crypto_gotham::header::{
            derive_route_secrets, flag, mode, wrap_header, RoutingRecord, HEADER_LEN, TRAILER_LEN,
        };
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let r_sk = [0x31u8; 32];
        let n_sk = [0x32u8; 32];
        let r_pk = PublicKey::from(&StaticSecret::from(r_sk)).to_bytes();
        let n_pk = PublicKey::from(&StaticSecret::from(n_sk)).to_bytes();

        // Build a 2-hop onion for [R, N]: R's record is VIA_RENDEZVOUS → N (by
        // identity, sentinel address); N is the last hop (deliver-local).
        let mut rng = ChaCha20Rng::seed_from_u64(0xB3B3_B3B3);
        let (alphas, sub_keys) = derive_route_secrets(&mut rng, &[r_pk, n_pk]).unwrap();
        let records = vec![
            RoutingRecord {
                next_ipv4: [0, 0, 0, 0],
                next_port: 0,
                next_node_id: n_pk,
                next_gamma: [0; 16],
                delay_micros: 0,
                flag: flag::VIA_RENDEZVOUS,
                _padding: [0; 5],
            },
            RoutingRecord {
                next_ipv4: [0, 0, 0, 0],
                next_port: 0,
                next_node_id: [0xEE; 32],
                next_gamma: [0; 16],
                delay_micros: 0,
                flag: flag::IS_LAST_HOP,
                _padding: [0; 5],
            },
        ];
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);
        let header = wrap_header(
            &mut rng,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        let mut packet = vec![0u8; PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        for (i, b) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let expected: Vec<u8> = (0..PACKET_SIZE - HEADER_LEN)
            .map(|i| (i % 256) as u8)
            .collect();
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }

        // Stand up R's rendezvous accept + N's tunnel (as in the tunnel test).
        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let r_addr = server.local_addr().unwrap();
        let table = RendezvousTable::new();
        {
            let table = table.clone();
            tokio::spawn(async move {
                if let Some(inc) = server.accept().await {
                    if let Ok(conn) = inc.await {
                        let _ = serve_rendezvous_connection(conn, r_sk, table).await;
                    }
                }
            });
        }
        let (tx, mut rx) = mpsc::channel(64);
        tokio::spawn(run_rendezvous_client(r_addr, r_pk, n_sk, tx));
        let mut tries = 0;
        while table.get(&n_pk).await.is_none() {
            tries += 1;
            assert!(tries < 100, "tunnel never registered");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // R peels its layer → must want to forward to N via rendezvous.
        let mut r_relay = Relay::new(r_sk, 100_000, Duration::from_secs(60), 0);
        let inner = match r_relay.process(&mut rng, &packet) {
            ProcessOutcome::Forward {
                via_rendezvous,
                next_node_id,
                packet,
                ..
            } => {
                assert!(via_rendezvous, "R must forward via rendezvous");
                assert_eq!(next_node_id, n_pk);
                packet
            }
            _ => panic!("R should Forward"),
        };

        // R pushes the peeled packet down N's tunnel (what serve_connection does).
        assert!(table.push(&n_pk, &inner).await.unwrap(), "N must be hosted");

        // N receives it over the tunnel and, being the last hop, delivers locally.
        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("N should receive the pushed packet")
            .expect("channel open");
        let mut n_relay = Relay::new(n_sk, 100_000, Duration::from_secs(60), 0);
        match n_relay.process(&mut rng, &received) {
            ProcessOutcome::DeliverLocal { payload, .. } => {
                assert_eq!(
                    payload.into_vec(),
                    expected,
                    "N must recover the original payload"
                );
            }
            _ => panic!("N (last hop) should DeliverLocal"),
        }
    }
}
