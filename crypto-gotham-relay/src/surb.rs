// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::net::{Ipv4Addr, SocketAddrV4};

use crypto_gotham::directory::SelectedPath;
use crypto_gotham::header::{
    derive_route_secrets, flag, mode, wrap_header, RoutingRecord, HEADER_LEN, MAX_HOPS, TRAILER_LEN,
};
use crypto_gotham::{lioness, PACKET_SIZE};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::client::MAX_PAYLOAD_SIZE;
use crate::transport::{forward_packet, TransportError};

#[derive(Debug, thiserror::Error)]
pub enum SurbError {
    #[error("surb hop_count must be in 2..={MAX_HOPS}")]
    BadHopCount,
    #[error("surb directory field malformed")]
    BadDirectory,
    #[error("surb header build failed")]
    Header,
    #[error("surb reply exceeds one packet")]
    ReplyTooLarge,
    #[error("surb reply framing invalid")]
    BadReply,
    #[error("surb transport: {0}")]
    Transport(#[from] TransportError),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Surb {
    header: Vec<u8>,
    first_hop_ipv4: [u8; 4],
    first_hop_port: u16,
    first_hop_node_id: [u8; 32],
    reply_key: [u8; 32],
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SurbKeys {
    payload_keys: Vec<[u8; 32]>,
    reply_key: [u8; 32],
}

fn reply_hop_delay_micros<R: RngCore + ?Sized>(
    mode: crypto_gotham::cover::CoverMode,
    rng: &mut R,
) -> u32 {
    let sched = crate::delay::PoissonScheduler::new(mode.mean_hop_delay_micros());
    let micros = sched.next_delay(rng).as_micros().min(u32::MAX as u128) as u32;
    micros.max(1)
}

pub fn build_surb<R: CryptoRng + RngCore>(
    rng: &mut R,
    path: &SelectedPath<'_>,
) -> Result<(Surb, SurbKeys), SurbError> {
    build_surb_with_delay(rng, path, crypto_gotham::cover::CoverMode::Balanced)
}

pub fn build_surb_with_delay<R: CryptoRng + RngCore>(
    rng: &mut R,
    path: &SelectedPath<'_>,
    mode: crypto_gotham::cover::CoverMode,
) -> Result<(Surb, SurbKeys), SurbError> {
    let n = path.hops.len();
    if !(2..=MAX_HOPS).contains(&n) {
        return Err(SurbError::BadHopCount);
    }

    let recipient_pks: Vec<[u8; 32]> = path
        .hops
        .iter()
        .map(|r| r.kem_pubkey_bytes())
        .collect::<crypto_gotham::Result<Vec<_>>>()
        .map_err(|_| SurbError::BadDirectory)?;
    let (alphas, sub_keys) =
        derive_route_secrets(rng, &recipient_pks).map_err(|_| SurbError::Header)?;

    let mut records: Vec<RoutingRecord> = Vec::with_capacity(n);
    for i in 0..n {
        let mut rec = RoutingRecord::default();
        if i + 1 < n {
            let next = path.hops[i + 1];
            rec.next_ipv4 = next.ipv4_octets().map_err(|_| SurbError::BadDirectory)?;
            rec.next_port = next.port().map_err(|_| SurbError::BadDirectory)?;
            rec.next_node_id = next
                .kem_pubkey_bytes()
                .map_err(|_| SurbError::BadDirectory)?;
        } else {
            rec.flag = flag::IS_LAST_HOP;
        }
        rec.delay_micros = reply_hop_delay_micros(mode, rng);
        records.push(rec);
    }

    let mut trailer = [0u8; TRAILER_LEN];
    rng.fill_bytes(&mut trailer);
    let header = wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer)
        .map_err(|_| SurbError::Header)?;

    let mut reply_key = [0u8; 32];
    rng.fill_bytes(&mut reply_key);

    let first = path.hops[0];
    let surb = Surb {
        header: header.encode().to_vec(),
        first_hop_ipv4: first.ipv4_octets().map_err(|_| SurbError::BadDirectory)?,
        first_hop_port: first.port().map_err(|_| SurbError::BadDirectory)?,
        first_hop_node_id: first
            .kem_pubkey_bytes()
            .map_err(|_| SurbError::BadDirectory)?,
        reply_key,
    };
    let keys = SurbKeys {
        payload_keys: sub_keys.iter().map(|s| s.k_payload).collect(),
        reply_key,
    };
    Ok((surb, keys))
}

impl Surb {
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        rmp_serde::to_vec_named(self).ok()
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        rmp_serde::from_slice(b).ok()
    }

    pub fn first_hop(&self) -> (SocketAddrV4, [u8; 32]) {
        (
            SocketAddrV4::new(Ipv4Addr::from(self.first_hop_ipv4), self.first_hop_port),
            self.first_hop_node_id,
        )
    }

    pub fn seal_reply(&self, reply: &[u8]) -> Result<Vec<u8>, SurbError> {
        if self.header.len() != HEADER_LEN {
            return Err(SurbError::Header);
        }
        if reply.len() + 4 > MAX_PAYLOAD_SIZE {
            return Err(SurbError::ReplyTooLarge);
        }
        let mut region = vec![0u8; PACKET_SIZE - HEADER_LEN];
        region[0..4].copy_from_slice(&(reply.len() as u32).to_be_bytes());
        region[4..4 + reply.len()].copy_from_slice(reply);
        lioness::encrypt(&self.reply_key, &mut region);

        let mut packet = vec![0u8; PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&self.header);
        packet[HEADER_LEN..].copy_from_slice(&region);
        Ok(packet)
    }
}

impl SurbKeys {
    pub fn open(&self, delivered_region: &[u8]) -> Option<Vec<u8>> {
        if delivered_region.len() < PACKET_SIZE - HEADER_LEN {
            return None;
        }
        let mut buf = delivered_region.to_vec();
        for k in self.payload_keys.iter().rev() {
            lioness::encrypt(k, &mut buf);
        }
        lioness::decrypt(&self.reply_key, &mut buf);

        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if 4 + len > buf.len() {
            return None;
        }
        Some(buf[4..4 + len].to_vec())
    }
}

pub async fn ship_surb_reply(
    endpoint: &quinn::Endpoint,
    my_sk: &[u8; 32],
    surb: &Surb,
    reply: &[u8],
) -> Result<(), SurbError> {
    let packet = surb.seal_reply(reply)?;
    let (addr, first_node) = surb.first_hop();
    forward_packet(
        endpoint,
        std::net::SocketAddr::V4(addr),
        &first_node,
        my_sk,
        &packet,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_gotham::directory::{RelayDescriptor, RelayTier};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::net::{SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Once};
    use std::time::Duration;
    use tokio::sync::{mpsc, Mutex};
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::pool::ConnectionPool;
    use crate::process::Relay;
    use crate::transport::{
        build_client_endpoint, build_server_endpoint, serve_connection, DeliveryHandler,
    };

    static CRYPTO: Once = Once::new();
    fn init() {
        CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn clamped_sk(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    fn descriptor_from(sk: [u8; 32], addr: SocketAddrV4, tier: RelayTier) -> RelayDescriptor {
        let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        RelayDescriptor {
            id_pubkey_hex: hex::encode(pk),
            kem_pubkey_hex: hex::encode(pk),
            addr: addr.to_string(),
            tier,
            country: Some("FR".into()),
            asn: None,
            operator: Some(hex::encode(&pk[..4])),
            uptime_pct: Some(99.9),
            mailbox: false,
            rendezvous: None,
            rendezvous_capable: false,
        }
    }

    async fn spawn_relay(sk: [u8; 32], delivery: Option<DeliveryHandler>) -> SocketAddrV4 {
        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Arc::new(Mutex::new(Relay::new(sk, 4096, Duration::from_secs(60), 0)));
        let pool = Arc::new(ConnectionPool::new(client, sk));
        tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let relay = Arc::clone(&relay);
                let pool = Arc::clone(&pool);
                let delivery = delivery.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, delivery).await;
                    }
                });
            }
        });
        match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("v4 expected"),
        }
    }

    #[test]
    fn a_reply_hop_delay_is_drawn_from_the_same_law_as_a_forward_one() {
        use crypto_gotham::cover::CoverMode;
        let mut r = ChaCha20Rng::seed_from_u64(0xDE1A_1234);

        for mode in [
            CoverMode::LowLatency,
            CoverMode::Balanced,
            CoverMode::Paranoid,
        ] {
            let n = 4000;
            let samples: Vec<u32> = (0..n)
                .map(|_| reply_hop_delay_micros(mode, &mut r))
                .collect();

            assert!(
                samples.iter().all(|d| *d != 0),
                "{mode:?}: a reply carried the reserved 0, which is a free \
                 forward/reply distinguisher",
            );

            let mean = samples.iter().map(|d| *d as f64).sum::<f64>() / n as f64;
            let expected = mode.mean_hop_delay_micros() as f64;
            assert!(
                (mean - expected).abs() < expected * 0.15,
                "{mode:?}: mean {mean:.0} µs is not the forward law's {expected:.0} µs",
            );

            let distinct = samples
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len();
            assert!(distinct > n / 2, "{mode:?}: delays are not actually random");
        }
    }

    #[test]
    fn a_built_surb_carries_no_sentinel_delay() {
        use crypto_gotham::cover::CoverMode;
        let mut r = ChaCha20Rng::seed_from_u64(0x50FA_50FA);
        for mode in [CoverMode::LowLatency, CoverMode::Paranoid] {
            for _ in 0..64 {
                assert!(reply_hop_delay_micros(mode, &mut r) >= 1);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn surb_reply_reaches_creator_through_mixnet() {
        init();
        let mut r = ChaCha20Rng::seed_from_u64(0x050D_B0DB_0DB0);

        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_self = clamped_sk(&mut r);

        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let capture: DeliveryHandler = Arc::new(move |payload: Vec<u8>| {
            let _ = tx.send(payload);
        });

        let addr_entry = spawn_relay(sk_entry, None).await;
        let addr_mix = spawn_relay(sk_mix, None).await;
        let addr_self = spawn_relay(sk_self, Some(capture)).await;

        let hops = [
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix),
            descriptor_from(sk_self, addr_self, RelayTier::Exit),
        ];
        let path = crypto_gotham::directory::SelectedPath {
            hops: hops.iter().collect(),
        };

        let (surb, keys) = build_surb(&mut r, &path).expect("build surb");

        let reply = b"MailboxResponse::Delivery { sealed envelopes... }".to_vec();
        let host_ep = build_client_endpoint().unwrap();
        let host_sk = clamped_sk(&mut r);
        ship_surb_reply(&host_ep, &host_sk, &surb, &reply)
            .await
            .expect("ship reply");

        let delivered = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("reply did not arrive")
            .expect("channel closed");

        let recovered = keys.open(&delivered).expect("surb open");
        assert_eq!(
            recovered, reply,
            "recovered reply must equal what the host sent"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn anonymous_mailbox_fetch_via_surb_end_to_end() {
        use crypto_gotham::mailbox::{mailbox_id_for, Mailbox, MailboxRequest, MailboxResponse};

        init();
        let mut r = ChaCha20Rng::seed_from_u64(0x0F17_C450_DB00);

        let sk_entry = clamped_sk(&mut r);
        let sk_mix = clamped_sk(&mut r);
        let sk_self = clamped_sk(&mut r);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let capture: DeliveryHandler = Arc::new(move |p: Vec<u8>| {
            let _ = tx.send(p);
        });
        let addr_entry = spawn_relay(sk_entry, None).await;
        let addr_mix = spawn_relay(sk_mix, None).await;
        let addr_self = spawn_relay(sk_self, Some(capture)).await;
        let hops = [
            descriptor_from(sk_entry, addr_entry, RelayTier::Entry),
            descriptor_from(sk_mix, addr_mix, RelayTier::Mix),
            descriptor_from(sk_self, addr_self, RelayTier::Exit),
        ];
        let path = crypto_gotham::directory::SelectedPath {
            hops: hops.iter().collect(),
        };
        let (surb, keys) = build_surb(&mut r, &path).expect("build surb");

        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let id = mailbox_id_for(&recipient_pk);
        let stored = b"a sealed envelope for the recipient".to_vec();
        let mut mailbox = Mailbox::with_defaults();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        mailbox
            .deposit(id, stored.clone(), now, 0)
            .expect("deposit");
        let mailbox = Arc::new(Mutex::new(mailbox));

        let host_sk = clamped_sk(&mut r);
        let host_pk = PublicKey::from(&StaticSecret::from(host_sk)).to_bytes();
        let handler = crate::transport::make_mailbox_service_handler(host_sk, mailbox)
            .expect("service handler");

        let surb_bytes = surb.to_bytes().unwrap();
        let auth = crate::mailbox_client::fetch_auth_for(
            &recipient_sk,
            &host_pk,
            &crypto_gotham::mailbox::surb_fetch_binding(&surb_bytes),
            &id,
        );
        let req = MailboxRequest::FetchWithSurb {
            id,
            surb: surb_bytes,
            auth: Some(auth),
        };
        let apparent_sender = clamped_sk(&mut r);
        let framed_req = crate::client::GothamClient::seal_and_frame(
            &mut r,
            &host_pk,
            &apparent_sender,
            &req.to_bytes().unwrap(),
        )
        .unwrap();
        handler(framed_req);

        let delivered = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("surb reply did not arrive")
            .expect("channel closed");
        let reply = keys.open(&delivered).expect("open surb reply");
        let resp = MailboxResponse::from_bytes(&reply).expect("parse response");
        match resp {
            MailboxResponse::Delivery { sealed, more } => {
                assert_eq!(sealed, vec![stored], "wrong envelopes recovered");
                assert!(!more);
            }
            other => panic!("expected Delivery, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn surb_fetch_redeposits_a_message_too_large_for_one_packet() {
        use crypto_gotham::mailbox::{mailbox_id_for, Mailbox, MailboxRequest};

        init();
        let mut r = ChaCha20Rng::seed_from_u64(0x00BA_D515_E000);

        let sk_a = clamped_sk(&mut r);
        let sk_self = clamped_sk(&mut r);
        let hops = [
            descriptor_from(sk_a, "1.2.3.4:443".parse().unwrap(), RelayTier::Entry),
            descriptor_from(sk_self, "5.6.7.8:443".parse().unwrap(), RelayTier::Exit),
        ];
        let path = crypto_gotham::directory::SelectedPath {
            hops: hops.iter().collect(),
        };
        let (surb, _keys) = build_surb(&mut r, &path).expect("build surb");

        let recipient_sk = clamped_sk(&mut r);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let id = mailbox_id_for(&recipient_pk);
        let big = vec![0xABu8; crate::client::MAX_PAYLOAD_SIZE - 8];
        let mut mailbox = Mailbox::with_defaults();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        mailbox.deposit(id, big.clone(), now, 0).expect("deposit");
        let mailbox = Arc::new(Mutex::new(mailbox));

        let host_sk = clamped_sk(&mut r);
        let host_pk = PublicKey::from(&StaticSecret::from(host_sk)).to_bytes();
        let handler =
            crate::transport::make_mailbox_service_handler(host_sk, Arc::clone(&mailbox)).unwrap();

        let surb_bytes = surb.to_bytes().unwrap();
        let auth = crate::mailbox_client::fetch_auth_for(
            &recipient_sk,
            &host_pk,
            &crypto_gotham::mailbox::surb_fetch_binding(&surb_bytes),
            &id,
        );
        let req = MailboxRequest::FetchWithSurb {
            id,
            surb: surb_bytes,
            auth: Some(auth),
        };
        let apparent_sender = clamped_sk(&mut r);
        let framed = crate::client::GothamClient::seal_and_frame(
            &mut r,
            &host_pk,
            &apparent_sender,
            &req.to_bytes().unwrap(),
        )
        .unwrap();
        handler(framed);

        let mut recovered = false;
        for _ in 0..40 {
            {
                let mut mb = mailbox.lock().await;
                let (batch, _more) = mb.fetch_batch(&id, now, 8 * 1024 * 1024);
                if batch == vec![big.clone()] {
                    recovered = true;
                    break;
                }
                for env in batch {
                    let _ = mb.deposit(id, env, now, 0);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            recovered,
            "oversized message was lost — must be re-deposited, not dropped"
        );
    }

    #[test]
    fn surb_serialization_round_trips() {
        let mut r = ChaCha20Rng::seed_from_u64(1);
        let sk_a = clamped_sk(&mut r);
        let sk_self = clamped_sk(&mut r);
        let hops = [
            descriptor_from(sk_a, "1.2.3.4:443".parse().unwrap(), RelayTier::Entry),
            descriptor_from(sk_self, "5.6.7.8:443".parse().unwrap(), RelayTier::Exit),
        ];
        let path = crypto_gotham::directory::SelectedPath {
            hops: hops.iter().collect(),
        };
        let (surb, _keys) = build_surb(&mut r, &path).unwrap();
        let bytes = surb.to_bytes().unwrap();
        let back = Surb::from_bytes(&bytes).unwrap();
        assert_eq!(surb, back);
    }
}
