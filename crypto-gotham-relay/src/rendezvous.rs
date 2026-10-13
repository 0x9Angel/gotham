// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

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

pub struct RendezvousTunnel {
    pub peer_pk: [u8; 32],
    src_ip: std::net::IpAddr,
    _conn: Connection,
    send: Mutex<quinn::SendStream>,
    noise: Mutex<TransportState>,
}

impl RendezvousTunnel {
    pub async fn push(&self, packet: &[u8]) -> Result<(), TransportError> {
        let mut send = self.send.lock().await;
        let mut noise = self.noise.lock().await;
        write_noise_frame(&mut noise, &mut send, packet).await
    }
}

pub const MAX_TUNNELS: usize = 512;

const MAX_TUNNELS_PER_IP: usize = 8;

fn may_admit(total: usize, same_ip: usize, is_refresh: bool) -> bool {
    is_refresh || (total < MAX_TUNNELS && same_ip < MAX_TUNNELS_PER_IP)
}

#[derive(Clone, Default)]
pub struct RendezvousTable {
    inner: Arc<Mutex<HashMap<[u8; 32], Arc<RendezvousTunnel>>>>,
}

impl RendezvousTable {
    pub fn new() -> Self {
        Self::default()
    }

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

    async fn remove_if_current(&self, tunnel: &Arc<RendezvousTunnel>) {
        let mut m = self.inner.lock().await;
        if let Some(cur) = m.get(&tunnel.peer_pk) {
            if !Arc::ptr_eq(cur, tunnel) {
                return;
            }
        }
        m.remove(&tunnel.peer_pk);
    }

    pub async fn get(&self, peer_pk: &[u8; 32]) -> Option<Arc<RendezvousTunnel>> {
        self.inner.lock().await.get(peer_pk).cloned()
    }

    pub async fn push(&self, peer_pk: &[u8; 32], packet: &[u8]) -> Result<bool, TransportError> {
        let Some(tunnel) = self.get(peer_pk).await else {
            return Ok(false);
        };
        tunnel.push(packet).await?;
        Ok(true)
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

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

    let reason = conn.closed().await;
    let _ = &recv;
    debug!(peer = %hex::encode(peer_pk), ?reason, "rendezvous tunnel closed");
    table.remove_if_current(&tunnel).await;
    Ok(())
}

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

    let _keep_send = send;
    loop {
        let packet = read_noise_frame(&mut noise, &mut recv).await?;
        if inbound_tx.send(packet).await.is_err() {
            return Ok(());
        }
    }
}

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
        assert!(
            !super::may_admit(MAX_TUNNELS, 0, false),
            "global-full rejects new"
        );
        assert!(
            super::may_admit(MAX_TUNNELS, 0, true),
            "refresh exempt from global cap"
        );
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
        let (r_sk, r_pk) = keypair(0x11);
        let (n_sk, n_pk) = keypair(0x22);

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

        let (_, stranger_pk) = keypair(0x99);
        assert!(!table.push(&stranger_pk, &packet).await.unwrap());
    }

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

        assert!(table.push(&n_pk, &inner).await.unwrap(), "N must be hosted");

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
