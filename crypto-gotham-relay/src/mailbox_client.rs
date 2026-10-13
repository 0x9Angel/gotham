// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::net::SocketAddr;

use crypto_gotham::mailbox::{
    fetch_auth_tag, FetchAuth, MailboxId, MailboxRequest, MailboxResponse, MailboxWireError,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rand::{CryptoRng, RngCore};
use snow::TransportState;
use zeroize::ZeroizeOnDrop;

use crate::transport::{
    build_mailbox_client_endpoint, noise_initiator_handshake_bound, read_noise_blob,
    write_noise_blob, TransportError,
};

#[derive(ZeroizeOnDrop)]
pub struct MailboxClient {
    #[zeroize(skip)]
    endpoint: Endpoint,
    client_sk: [u8; 32],
}

impl MailboxClient {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, TransportError> {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        Ok(Self {
            endpoint: build_mailbox_client_endpoint()?,
            client_sk: sk,
        })
    }

    async fn open(
        &self,
        relay_addr: SocketAddr,
        relay_pk: &[u8; 32],
    ) -> Result<(Connection, SendStream, RecvStream, TransportState, Vec<u8>), MailboxClientError>
    {
        let conn = self
            .endpoint
            .connect(relay_addr, "gotham-relay.local")
            .map_err(TransportError::Connect)?
            .await
            .map_err(TransportError::Connection)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(TransportError::Connection)?;
        let (noise, binding) =
            noise_initiator_handshake_bound(&self.client_sk, relay_pk, &mut send, &mut recv)
                .await?;
        Ok((conn, send, recv, noise, binding))
    }

    pub async fn deposit(
        &self,
        relay_addr: SocketAddr,
        relay_pk: &[u8; 32],
        mailbox_id: MailboxId,
        sealed: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<(), MailboxClientError> {
        let (conn, mut send, mut recv, mut noise, _binding) =
            self.open(relay_addr, relay_pk).await?;
        let req = MailboxRequest::Deposit {
            id: mailbox_id,
            sealed,
            ttl_secs,
        };
        write_noise_blob(&mut noise, &mut send, &req.to_bytes()?).await?;
        let resp = MailboxResponse::from_bytes(&read_noise_blob(&mut noise, &mut recv).await?)?;
        send.finish().ok();
        conn.close(0u32.into(), b"done");
        match resp {
            MailboxResponse::Ack => Ok(()),
            MailboxResponse::Error(e) => Err(MailboxClientError::Wire(e)),
            MailboxResponse::Delivery { .. } => Err(MailboxClientError::Unexpected),
        }
    }

    pub async fn fetch_all(
        &self,
        relay_addr: SocketAddr,
        relay_pk: &[u8; 32],
        mailbox_id: MailboxId,
        identity_sk: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, MailboxClientError> {
        let (conn, mut send, mut recv, mut noise, binding) =
            self.open(relay_addr, relay_pk).await?;
        let auth = fetch_auth_for(identity_sk, relay_pk, &binding, &mailbox_id);
        let mut all: Vec<Vec<u8>> = Vec::new();
        let mut rounds = 0usize;
        let mut total_bytes = 0usize;
        let result = loop {
            rounds += 1;
            if rounds > MAX_FETCH_ROUNDS {
                tracing::warn!(
                    rounds,
                    "mailbox host never signalled completion — aborting fetch"
                );
                break Err(MailboxClientError::Unexpected);
            }

            let req = MailboxRequest::Fetch {
                id: mailbox_id,
                auth: Some(auth),
            };
            if let Err(e) = write_noise_blob(&mut noise, &mut send, &req.to_bytes()?).await {
                break Err(e.into());
            }
            let resp = match read_noise_blob(&mut noise, &mut recv).await {
                Ok(bytes) => MailboxResponse::from_bytes(&bytes)?,
                Err(e) => break Err(e.into()),
            };
            match resp {
                MailboxResponse::Delivery { sealed, more } => {
                    if more && sealed.is_empty() {
                        tracing::warn!("mailbox host claimed more messages but sent none");
                        break Err(MailboxClientError::Unexpected);
                    }
                    total_bytes =
                        total_bytes.saturating_add(sealed.iter().map(|s| s.len()).sum::<usize>());
                    if total_bytes > MAX_FETCH_TOTAL_BYTES {
                        tracing::warn!(total_bytes, "mailbox fetch exceeded its byte budget");
                        break Err(MailboxClientError::Unexpected);
                    }
                    all.extend(sealed);
                    if !more {
                        break Ok(all);
                    }
                }
                MailboxResponse::Error(e) => break Err(MailboxClientError::Wire(e)),
                MailboxResponse::Ack => break Err(MailboxClientError::Unexpected),
            }
        };
        send.finish().ok();
        conn.close(0u32.into(), b"done");
        result
    }
}

#[must_use]
pub fn fetch_auth_for(
    identity_sk: &[u8; 32],
    relay_pk: &[u8; 32],
    binding: &[u8],
    mailbox_id: &MailboxId,
) -> FetchAuth {
    let shared = x25519_dalek::x25519(*identity_sk, *relay_pk);
    FetchAuth {
        pk: x25519_dalek::x25519(*identity_sk, x25519_dalek::X25519_BASEPOINT_BYTES),
        tag: fetch_auth_tag(&shared, binding, mailbox_id),
    }
}

const MAX_FETCH_ROUNDS: usize = 64;
const MAX_FETCH_TOTAL_BYTES: usize = 96 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum MailboxClientError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("mailbox refused: {0:?}")]
    Wire(MailboxWireError),
    #[error("unexpected mailbox response")]
    Unexpected,
}

impl From<MailboxWireError> for MailboxClientError {
    fn from(e: MailboxWireError) -> Self {
        MailboxClientError::Wire(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crypto_gotham::mailbox::{mailbox_id_for, Mailbox, MailboxPolicy};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tokio::sync::Mutex;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::process::Relay;
    use crate::transport::{build_server_endpoint, serve_endpoint_with_mailbox};

    fn clamped_sk(rng: &mut ChaCha20Rng) -> [u8; 32] {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;
        sk
    }

    async fn spawn_mailbox_relay(
        sk: [u8; 32],
        policy: MailboxPolicy,
    ) -> (SocketAddr, [u8; 32], Arc<Mutex<Mailbox>>) {
        crate::init_crypto();
        let endpoint = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        let store = Arc::new(Mutex::new(Mailbox::new(policy)));
        let relay = Relay::new(sk, 1024, Duration::from_secs(60), 0);
        let store_for_task = Arc::clone(&store);
        tokio::spawn(async move {
            let _ =
                serve_endpoint_with_mailbox(endpoint, sk, relay, None, Some(store_for_task)).await;
        });
        (addr, pk, store)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deposit_then_fetch_round_trips_over_quic() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0A11_B0B0);
        let relay_sk = clamped_sk(&mut rng);
        let (addr, relay_pk, _store) =
            spawn_mailbox_relay(relay_sk, MailboxPolicy::default()).await;

        let recipient_pk = clamped_sk(&mut rng);
        let recipient_pub = PublicKey::from(&StaticSecret::from(recipient_pk)).to_bytes();
        let mbid = mailbox_id_for(&recipient_pub);

        let client = MailboxClient::new(&mut rng).unwrap();

        client
            .deposit(addr, &relay_pk, mbid, b"sealed-one".to_vec(), 3600)
            .await
            .expect("deposit 1");
        client
            .deposit(addr, &relay_pk, mbid, b"sealed-two".to_vec(), 3600)
            .await
            .expect("deposit 2");

        let got = client
            .fetch_all(addr, &relay_pk, mbid, &recipient_pk)
            .await
            .expect("fetch");
        assert_eq!(got, vec![b"sealed-one".to_vec(), b"sealed-two".to_vec()]);
        let again = client
            .fetch_all(addr, &relay_pk, mbid, &recipient_pk)
            .await
            .expect("fetch 2");
        assert!(again.is_empty(), "fetch drains the mailbox");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fetch_all_loops_over_batches() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xB00C);
        let relay_sk = clamped_sk(&mut rng);
        let (addr, relay_pk, _store) =
            spawn_mailbox_relay(relay_sk, MailboxPolicy::default()).await;
        let owner_sk = clamped_sk(&mut rng);
        let owner_pk = PublicKey::from(&StaticSecret::from(owner_sk)).to_bytes();
        let mbid = mailbox_id_for(&owner_pk);
        let client = MailboxClient::new(&mut rng).unwrap();
        for i in 0..40u8 {
            client
                .deposit(addr, &relay_pk, mbid, vec![i; 100], 3600)
                .await
                .expect("deposit");
        }
        let got = client
            .fetch_all(addr, &relay_pk, mbid, &owner_sk)
            .await
            .expect("fetch");
        assert_eq!(got.len(), 40);
        assert_eq!(got[0], vec![0u8; 100]);
        assert_eq!(got[39], vec![39u8; 100]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sealed_envelope_survives_deposit_and_fetch_for_offline_peer() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x005E_A1ED);
        let relay_sk = clamped_sk(&mut rng);
        let (addr, relay_pk, _s) = spawn_mailbox_relay(relay_sk, MailboxPolicy::default()).await;

        let recipient_sk = clamped_sk(&mut rng);
        let recipient_pk = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut rng);

        let body = b"offline message body (a ratchet ciphertext in production)";
        let sealed =
            crypto_gotham::sealed::seal(&mut rng, &recipient_pk, &sender_pk, body).unwrap();
        let mbid = mailbox_id_for(&recipient_pk);

        let client = MailboxClient::new(&mut rng).unwrap();
        client
            .deposit(addr, &relay_pk, mbid, sealed, 0)
            .await
            .expect("deposit while recipient offline");

        let got = client
            .fetch_all(addr, &relay_pk, mbid, &recipient_sk)
            .await
            .expect("fetch");
        assert_eq!(got.len(), 1);
        let (unsealed_sender, unsealed_body) =
            crypto_gotham::sealed::unseal(&recipient_sk, &got[0]).expect("unseal");
        assert_eq!(unsealed_sender, sender_pk, "sender identity recovered");
        assert_eq!(unsealed_body, body, "body recovered intact");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mixnet_deposit_lands_in_mailbox_then_fetches_back() {
        use crate::process::Relay;
        use crate::transport::{make_mailbox_deposit_handler, serve_endpoint};
        use crate::GothamClient;
        use crypto_gotham::directory::{RelayDescriptor, RelayTier};
        use crypto_gotham::mailbox::MailboxRequest;
        use std::net::SocketAddr;

        crate::init_crypto();
        let mut rng = ChaCha20Rng::seed_from_u64(0x0DE9_051D);

        let descriptor = |sk: [u8; 32], addr: SocketAddr, tier, op: &str, mailbox| {
            let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
            RelayDescriptor {
                id_pubkey_hex: hex::encode(pk),
                kem_pubkey_hex: hex::encode(pk),
                addr: addr.to_string(),
                tier,
                country: Some("FR".into()),
                asn: None,
                operator: Some(op.into()),
                uptime_pct: Some(100.0),
                mailbox,
                rendezvous: None,
                rendezvous_capable: false,
            }
        };

        let sk_entry = clamped_sk(&mut rng);
        let sk_mix = clamped_sk(&mut rng);
        let entry_ep = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let entry_addr = entry_ep.local_addr().unwrap();
        let mix_ep = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let mix_addr = mix_ep.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_endpoint(
                entry_ep,
                sk_entry,
                Relay::new(sk_entry, 1024, Duration::from_secs(60), 0),
                None,
            )
            .await;
        });
        tokio::spawn(async move {
            let _ = serve_endpoint(
                mix_ep,
                sk_mix,
                Relay::new(sk_mix, 1024, Duration::from_secs(60), 0),
                None,
            )
            .await;
        });

        let sk_host = clamped_sk(&mut rng);
        let host_pk = PublicKey::from(&StaticSecret::from(sk_host)).to_bytes();
        let host_ep = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let host_addr = host_ep.local_addr().unwrap();
        let store = Arc::new(Mutex::new(Mailbox::with_defaults()));
        let delivery = make_mailbox_deposit_handler(sk_host, Arc::clone(&store));
        let store_for_serve = Arc::clone(&store);
        tokio::spawn(async move {
            let _ = crate::transport::serve_endpoint_with_services(
                host_ep,
                sk_host,
                Relay::new(sk_host, 1024, Duration::from_secs(60), 0),
                Some(delivery),
                Some(store_for_serve),
                None,
                None,
            )
            .await;
        });

        let recipient_sk = clamped_sk(&mut rng);
        let recipient_pub = PublicKey::from(&StaticSecret::from(recipient_sk)).to_bytes();
        let sender_pk = clamped_sk(&mut rng);

        let relays = vec![
            descriptor(sk_entry, entry_addr, RelayTier::Entry, "op-A", false),
            descriptor(sk_mix, mix_addr, RelayTier::Mix, "op-B", false),
            descriptor(sk_host, host_addr, RelayTier::Exit, "op-C", true),
        ];
        let host_desc = relays[2].clone();

        let inner =
            crypto_gotham::sealed::seal(&mut rng, &recipient_pub, &sender_pk, b"offline hi")
                .unwrap();
        let mbid = mailbox_id_for(&recipient_pub);
        let req = MailboxRequest::Deposit {
            id: mbid,
            sealed: inner,
            ttl_secs: 0,
        }
        .to_bytes()
        .unwrap();

        let gclient = GothamClient::new(&mut rng).unwrap();
        gclient
            .send_sealed_to_exit(&mut rng, &relays, 3, &host_desc, &sender_pk, &req)
            .await
            .expect("mixnet deposit send");

        let fetcher = MailboxClient::new(&mut rng).unwrap();
        let mut got = Vec::new();
        for _ in 0..30 {
            got = fetcher
                .fetch_all(host_addr, &host_pk, mbid, &recipient_sk)
                .await
                .unwrap();
            if !got.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            got.len(),
            1,
            "the mixnet-deposited message must be in the mailbox"
        );
        let (unsealed_sender, body) =
            crypto_gotham::sealed::unseal(&recipient_sk, &got[0]).unwrap();
        assert_eq!(unsealed_sender, sender_pk);
        assert_eq!(body, b"offline hi");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn oversize_deposit_is_refused_with_wire_error() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x0F5E);
        let relay_sk = clamped_sk(&mut rng);
        let policy = MailboxPolicy {
            max_msg_bytes: 16,
            ..MailboxPolicy::default()
        };
        let (addr, relay_pk, _store) = spawn_mailbox_relay(relay_sk, policy).await;
        let client = MailboxClient::new(&mut rng).unwrap();
        let err = client
            .deposit(
                addr,
                &relay_pk,
                mailbox_id_for(&[1u8; 32]),
                vec![0u8; 17],
                60,
            )
            .await
            .expect_err("oversize must be refused");
        assert!(matches!(
            err,
            MailboxClientError::Wire(MailboxWireError::TooLarge)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_public_key_alone_cannot_drain_someone_elses_mailbox() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
        let relay_sk = clamped_sk(&mut rng);
        let (addr, relay_pk, _store) =
            spawn_mailbox_relay(relay_sk, MailboxPolicy::default()).await;

        let victim_sk = clamped_sk(&mut rng);
        let victim_pk = PublicKey::from(&StaticSecret::from(victim_sk)).to_bytes();
        let mbid = mailbox_id_for(&victim_pk);

        let client = MailboxClient::new(&mut rng).unwrap();
        client
            .deposit(addr, &relay_pk, mbid, b"do-not-lose-me".to_vec(), 3600)
            .await
            .expect("deposit");

        let attacker_sk = clamped_sk(&mut rng);
        assert_eq!(
            mailbox_id_for(&victim_pk),
            mbid,
            "the attacker really can address the victim's mailbox"
        );
        let err = client
            .fetch_all(addr, &relay_pk, mbid, &attacker_sk)
            .await
            .expect_err("a fetch without the recipient's secret must be refused");
        assert!(
            matches!(
                err,
                MailboxClientError::Wire(MailboxWireError::Unauthorized)
            ),
            "expected Unauthorized, got {err:?}"
        );

        let got = client
            .fetch_all(addr, &relay_pk, mbid, &victim_sk)
            .await
            .expect("the rightful owner still fetches");
        assert_eq!(
            got,
            vec![b"do-not-lose-me".to_vec()],
            "the refused fetch must not have consumed anything"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_captured_proof_cannot_be_replayed_on_another_connection() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5EA1_5EA1);
        let relay_sk = clamped_sk(&mut rng);
        let (addr, relay_pk, store) = spawn_mailbox_relay(relay_sk, MailboxPolicy::default()).await;

        let victim_sk = clamped_sk(&mut rng);
        let victim_pk = PublicKey::from(&StaticSecret::from(victim_sk)).to_bytes();
        let mbid = mailbox_id_for(&victim_pk);

        let client = MailboxClient::new(&mut rng).unwrap();
        client
            .deposit(addr, &relay_pk, mbid, b"still-here".to_vec(), 3600)
            .await
            .expect("deposit");

        let stale = fetch_auth_for(&victim_sk, &relay_pk, b"some other session", &mbid);
        let (conn, mut send, mut recv, mut noise, _binding) =
            client.open(addr, &relay_pk).await.expect("open");
        let req = MailboxRequest::Fetch {
            id: mbid,
            auth: Some(stale),
        };
        write_noise_blob(&mut noise, &mut send, &req.to_bytes().unwrap())
            .await
            .unwrap();
        let resp =
            MailboxResponse::from_bytes(&read_noise_blob(&mut noise, &mut recv).await.unwrap())
                .unwrap();
        conn.close(0u32.into(), b"done");
        assert_eq!(
            resp,
            MailboxResponse::Error(MailboxWireError::Unauthorized),
            "a proof bound to another session must not be accepted"
        );
        assert_eq!(
            store.lock().await.total(),
            1,
            "the replayed fetch must not have drained anything"
        );
    }
}
