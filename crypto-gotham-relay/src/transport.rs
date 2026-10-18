// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::net::SocketAddr;
use std::sync::Arc;

use crypto_gotham::mailbox::{
    Mailbox, MailboxRequest, MailboxResponse, MailboxWireError, MAX_MAILBOX_FRAME,
};
use crypto_gotham::PACKET_SIZE;
use crypto_gotham_directory::{AuthoritySet, Roster};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use snow::TransportState;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::pool::ConnectionPool;
use crate::process::{ProcessOutcome, Relay};

pub type DeliveryHandler = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

pub fn make_unsealing_delivery_handler<F>(recipient_sk: [u8; 32], inner: F) -> DeliveryHandler
where
    F: Fn([u8; 32], Vec<u8>) + Send + Sync + 'static,
{
    Arc::new(move |payload: Vec<u8>| {
        if payload.len() < 4 {
            debug!("framed payload shorter than length prefix");
            return;
        }
        let len_bytes: [u8; 4] = match payload[..4].try_into() {
            Ok(arr) => arr,
            Err(_) => return,
        };
        let env_len = u32::from_be_bytes(len_bytes) as usize;
        if 4 + env_len > payload.len() {
            debug!("framed envelope length exceeds payload region");
            return;
        }
        let envelope = &payload[4..4 + env_len];

        match crypto_gotham::sealed::unseal(&recipient_sk, envelope) {
            Ok((sender_pk, body)) => inner(sender_pk, body),
            Err(_) => {
                debug!("sealed-sender unseal failed — dropping");
            }
        }
    })
}

pub fn make_mailbox_deposit_handler(
    host_sk: [u8; 32],
    mailbox: Arc<Mutex<Mailbox>>,
) -> DeliveryHandler {
    make_unsealing_delivery_handler(host_sk, move |_sender_pk, body| {
        if let Ok(MailboxRequest::Deposit {
            id,
            sealed,
            ttl_secs,
        }) = MailboxRequest::from_bytes(&body)
        {
            let mailbox = Arc::clone(&mailbox);
            tokio::spawn(async move {
                let now = now_unix();
                if let Err(e) = mailbox.lock().await.deposit(id, sealed, now, ttl_secs) {
                    debug!(?e, "mixnet mailbox deposit refused");
                }
            });
        }
    })
}

pub fn make_mailbox_service_handler(
    host_sk: [u8; 32],
    mailbox: Arc<Mutex<Mailbox>>,
) -> Result<DeliveryHandler, TransportError> {
    let reply_endpoint = build_client_endpoint()?;
    Ok(make_unsealing_delivery_handler(
        host_sk,
        move |_sender_pk, body| match MailboxRequest::from_bytes(&body) {
            Ok(MailboxRequest::Deposit {
                id,
                sealed,
                ttl_secs,
            }) => {
                let mailbox = Arc::clone(&mailbox);
                tokio::spawn(async move {
                    let now = now_unix();
                    if let Err(e) = mailbox.lock().await.deposit(id, sealed, now, ttl_secs) {
                        debug!(?e, "mixnet mailbox deposit refused");
                    }
                });
            }
            Ok(MailboxRequest::FetchWithSurb {
                id,
                surb: surb_bytes,
                auth,
            }) => {
                let Some(auth) = auth else {
                    debug!("mixnet mailbox fetch: missing possession proof — refused");
                    return;
                };
                let shared = x25519_dalek::x25519(host_sk, auth.pk);
                let binding = crypto_gotham::mailbox::surb_fetch_binding(&surb_bytes);
                if !auth.verify(&shared, &binding, &id) {
                    debug!("mixnet mailbox fetch: bad possession proof — refused");
                    return;
                }
                let Some(surb) = crate::surb::Surb::from_bytes(&surb_bytes) else {
                    debug!("mixnet mailbox fetch: malformed surb");
                    return;
                };
                let mailbox = Arc::clone(&mailbox);
                let endpoint = reply_endpoint.clone();
                tokio::spawn(async move {
                    let now = now_unix();
                    let (sealed, more) = {
                        let mut mb = mailbox.lock().await;
                        mb.fetch_batch(&id, now, SURB_FETCH_BUDGET)
                    };
                    if sealed.is_empty() {
                        return;
                    }
                    let resp = MailboxResponse::Delivery {
                        sealed: sealed.clone(),
                        more,
                    };
                    let ship = match resp.to_bytes() {
                        Ok(bytes) => {
                            crate::surb::ship_surb_reply(&endpoint, &host_sk, &surb, &bytes).await
                        }
                        Err(_) => Err(crate::surb::SurbError::ReplyTooLarge),
                    };
                    if let Err(e) = ship {
                        debug!(?e, "surb reply failed; re-depositing drained batch");
                        let mut mb = mailbox.lock().await;
                        for env in sealed {
                            let _ = mb.deposit(id, env, now, 0);
                        }
                    }
                });
            }
            _ => {}
        },
    ))
}

const NOISE_PARAMS: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";
const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const NOISE_TAG_LEN: usize = 16;

pub const MIXNET_ALPN: &[u8] = b"gotham/1";
pub const MAILBOX_ALPN: &[u8] = b"gotham-mbx/1";

pub const GOSSIP_ALPN: &[u8] = b"gotham-dir/1";

pub const RENDEZVOUS_ALPN: &[u8] = b"gotham-rdv/1";

pub const RENDEZVOUS_QUERY_ALPN: &[u8] = b"gotham-rdvq/1";

pub const MAX_GOSSIP_FRAME: usize = 4 * 1024 * 1024;

const NOISE_CHUNK: usize = 32 * 1024;

pub const FRAME_LEN: usize = PACKET_SIZE + NOISE_TAG_LEN;

const MAX_HANDSHAKE_MSG: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("quic connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("quic connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("quic write: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("quic read: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("malformed handshake message")]
    BadHandshake,
    #[error(
        "no response within {0:?} — nothing is reachable at that address. \
         Check that the UDP port is open in your provider's firewall \
         (cloud security list / security group), not only on the host itself."
    )]
    Unreachable(std::time::Duration),
}

pub fn make_self_signed_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec!["gotham-relay.local".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    Ok((cert_der, key_der))
}

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub fn build_server_endpoint(addr: SocketAddr) -> Result<Endpoint, TransportError> {
    let (cert, key) = make_self_signed_cert()?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![
        MIXNET_ALPN.to_vec(),
        MAILBOX_ALPN.to_vec(),
        GOSSIP_ALPN.to_vec(),
        RENDEZVOUS_ALPN.to_vec(),
        RENDEZVOUS_QUERY_ALPN.to_vec(),
    ];
    let quic_server_config =
        QuicServerConfig::try_from(server_crypto).map_err(|_| TransportError::BadHandshake)?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

fn build_client_endpoint_alpn(alpn: &[u8]) -> Result<Endpoint, TransportError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![alpn.to_vec()];
    let quic_client_config =
        QuicClientConfig::try_from(client_crypto).map_err(|_| TransportError::BadHandshake)?;
    let client_config = ClientConfig::new(Arc::new(quic_client_config));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().map_err(|_| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "bad client bind addr",
        ))
    })?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

pub fn build_client_endpoint() -> Result<Endpoint, TransportError> {
    build_client_endpoint_alpn(MIXNET_ALPN)
}

pub fn build_mailbox_client_endpoint() -> Result<Endpoint, TransportError> {
    build_client_endpoint_alpn(MAILBOX_ALPN)
}

pub fn build_gossip_client_endpoint() -> Result<Endpoint, TransportError> {
    build_client_endpoint_alpn(GOSSIP_ALPN)
}

pub fn build_rendezvous_client_endpoint() -> Result<Endpoint, TransportError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![RENDEZVOUS_ALPN.to_vec()];
    let quic_client_config =
        QuicClientConfig::try_from(client_crypto).map_err(|_| TransportError::BadHandshake)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .map_err(|_| TransportError::BadHandshake)?,
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().map_err(|_| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "bad client bind addr",
        ))
    })?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn write_handshake_msg(send: &mut SendStream, msg: &[u8]) -> Result<(), TransportError> {
    if msg.len() > MAX_HANDSHAKE_MSG {
        return Err(TransportError::BadHandshake);
    }
    let len = msg.len() as u16;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(msg).await?;
    Ok(())
}

const HANDSHAKE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn read_handshake_msg(
    recv: &mut RecvStream,
    buf: &mut [u8; MAX_HANDSHAKE_MSG],
) -> Result<usize, TransportError> {
    let mut len_bytes = [0u8; 2];
    tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, recv.read_exact(&mut len_bytes))
        .await
        .map_err(|_| TransportError::BadHandshake)??;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len > MAX_HANDSHAKE_MSG {
        return Err(TransportError::BadHandshake);
    }
    tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, recv.read_exact(&mut buf[..len]))
        .await
        .map_err(|_| TransportError::BadHandshake)??;
    Ok(len)
}

pub async fn noise_responder_handshake(
    static_sk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<TransportState, TransportError> {
    Ok(noise_responder_handshake_bound(static_sk, send, recv)
        .await?
        .0)
}

pub async fn noise_responder_handshake_bound(
    static_sk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<(TransportState, Vec<u8>), TransportError> {
    let params = NOISE_PARAMS.parse()?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(static_sk)
        .build_responder()?;

    let mut rx = [0u8; MAX_HANDSHAKE_MSG];
    let mut tx = [0u8; MAX_HANDSHAKE_MSG];
    let mut scratch = [0u8; MAX_HANDSHAKE_MSG];

    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let binding = hs.get_handshake_hash().to_vec();
    let transport = hs.into_transport_mode()?;
    Ok((transport, binding))
}

pub async fn noise_initiator_handshake(
    initiator_sk: &[u8; 32],
    server_static_pk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<TransportState, TransportError> {
    Ok(
        noise_initiator_handshake_bound(initiator_sk, server_static_pk, send, recv)
            .await?
            .0,
    )
}

pub async fn noise_initiator_handshake_bound(
    initiator_sk: &[u8; 32],
    server_static_pk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<(TransportState, Vec<u8>), TransportError> {
    let params = NOISE_PARAMS.parse()?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(initiator_sk)
        .remote_public_key(server_static_pk)
        .build_initiator()?;

    let mut tx = [0u8; MAX_HANDSHAKE_MSG];
    let mut rx = [0u8; MAX_HANDSHAKE_MSG];
    let mut scratch = [0u8; MAX_HANDSHAKE_MSG];

    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let binding = hs.get_handshake_hash().to_vec();
    let transport = hs.into_transport_mode()?;
    Ok((transport, binding))
}

pub async fn noise_ik_responder_handshake(
    static_sk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<(TransportState, [u8; 32]), TransportError> {
    let params = NOISE_IK_PARAMS.parse()?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(static_sk)
        .build_responder()?;

    let mut rx = [0u8; MAX_HANDSHAKE_MSG];
    let mut tx = [0u8; MAX_HANDSHAKE_MSG];
    let mut scratch = [0u8; MAX_HANDSHAKE_MSG];

    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;
    let remote = hs.get_remote_static().ok_or(TransportError::BadHandshake)?;
    if remote.len() != 32 {
        return Err(TransportError::BadHandshake);
    }
    let mut remote_pk = [0u8; 32];
    remote_pk.copy_from_slice(remote);

    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let transport = hs.into_transport_mode()?;
    Ok((transport, remote_pk))
}

pub async fn noise_ik_initiator_handshake(
    initiator_sk: &[u8; 32],
    responder_static_pk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<TransportState, TransportError> {
    let params = NOISE_IK_PARAMS.parse()?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(initiator_sk)
        .remote_public_key(responder_static_pk)
        .build_initiator()?;

    let mut tx = [0u8; MAX_HANDSHAKE_MSG];
    let mut rx = [0u8; MAX_HANDSHAKE_MSG];
    let mut scratch = [0u8; MAX_HANDSHAKE_MSG];

    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let transport = hs.into_transport_mode()?;
    Ok(transport)
}

pub type QuerierKeys = Arc<std::sync::RwLock<Vec<[u8; 32]>>>;

pub const MAX_QUERIER_KEYS: usize = 16;

pub fn querier_keys(pinned: Option<[u8; 32]>) -> QuerierKeys {
    Arc::new(std::sync::RwLock::new(pinned.into_iter().collect()))
}

pub fn add_querier_key(keys: &QuerierKeys, pk: [u8; 32]) {
    let mut held = match keys.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if held.contains(&pk) {
        return;
    }
    if held.len() >= MAX_QUERIER_KEYS {
        held.remove(0);
    }
    held.push(pk);
}

fn querier_known(keys: &QuerierKeys, pk: &[u8; 32]) -> bool {
    match keys.read() {
        Ok(g) => g.contains(pk),
        Err(poisoned) => poisoned.into_inner().contains(pk),
    }
}

pub async fn serve_rendezvous_query(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    queriers: Option<QuerierKeys>,
    table: crate::rendezvous::RendezvousTable,
) -> Result<(), TransportError> {
    let Some(queriers) = queriers else {
        return Err(TransportError::BadHandshake);
    };
    let (mut send, mut recv) = conn.accept_bi().await?;
    let (mut noise, querier_pk) =
        noise_ik_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    if !querier_known(&queriers, &querier_pk) {
        return Err(TransportError::BadHandshake);
    }
    let mut buf = Vec::new();
    let n = read_one_noise_msg(&mut noise, &mut recv, &mut buf).await?;
    if n != 32 {
        return Err(TransportError::BadHandshake);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&buf[..32]);
    let hosted = table.get(&pk).await.is_some();
    write_one_noise_msg(&mut noise, &mut send, &[u8::from(hosted)]).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

pub async fn probe_rendezvous_hosting(
    r_addr: SocketAddr,
    r_pk: &[u8; 32],
    authority_pop_sk: &[u8; 32],
    n_pk: &[u8; 32],
    timeout: std::time::Duration,
) -> Result<bool, TransportError> {
    let fut = async {
        let endpoint = build_client_endpoint_alpn(RENDEZVOUS_QUERY_ALPN)?;
        let conn = endpoint.connect(r_addr, "gotham-relay.local")?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut noise =
            noise_ik_initiator_handshake(authority_pop_sk, r_pk, &mut send, &mut recv).await?;
        write_one_noise_msg(&mut noise, &mut send, n_pk).await?;
        let mut buf = Vec::new();
        let n = read_one_noise_msg(&mut noise, &mut recv, &mut buf).await?;
        conn.close(0u32.into(), b"query done");
        endpoint.wait_idle().await;
        Ok::<bool, TransportError>(n >= 1 && buf.first() == Some(&1u8))
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(TransportError::Unreachable(timeout)),
    }
}

pub async fn probe_relay_liveness(
    addr: SocketAddr,
    expected_pk: &[u8; 32],
    initiator_sk: &[u8; 32],
    timeout: std::time::Duration,
) -> Result<(), TransportError> {
    let fut = async {
        let endpoint = build_client_endpoint()?;
        let conn = endpoint.connect(addr, "gotham-relay.local")?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let _ = noise_initiator_handshake(initiator_sk, expected_pk, &mut send, &mut recv).await?;
        conn.close(0u32.into(), b"probe ok");
        endpoint.wait_idle().await;
        Ok::<(), TransportError>(())
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(TransportError::Unreachable(timeout)),
    }
}

pub async fn write_noise_frame(
    transport: &mut TransportState,
    send: &mut SendStream,
    packet: &[u8],
) -> Result<(), TransportError> {
    if packet.len() != PACKET_SIZE {
        return Err(TransportError::BadHandshake);
    }
    let mut frame = vec![0u8; FRAME_LEN];
    let n = transport.write_message(packet, &mut frame)?;
    debug_assert_eq!(n, FRAME_LEN);
    send.write_all(&frame).await?;
    Ok(())
}

pub async fn read_noise_frame(
    transport: &mut TransportState,
    recv: &mut RecvStream,
) -> Result<Vec<u8>, TransportError> {
    let mut frame = vec![0u8; FRAME_LEN];
    recv.read_exact(&mut frame).await?;
    let mut packet = vec![0u8; PACKET_SIZE];
    let n = transport.read_message(&frame, &mut packet)?;
    debug_assert_eq!(n, PACKET_SIZE);
    Ok(packet)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn write_one_noise_msg(
    transport: &mut TransportState,
    send: &mut SendStream,
    msg: &[u8],
) -> Result<(), TransportError> {
    let mut buf = vec![0u8; msg.len() + NOISE_TAG_LEN];
    let n = transport.write_message(msg, &mut buf)?;
    let len = u16::try_from(n).map_err(|_| TransportError::BadHandshake)?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&buf[..n]).await?;
    Ok(())
}

async fn read_one_noise_msg(
    transport: &mut TransportState,
    recv: &mut RecvStream,
    out: &mut Vec<u8>,
) -> Result<usize, TransportError> {
    let mut len_bytes = [0u8; 2];
    recv.read_exact(&mut len_bytes).await?;
    let clen = u16::from_be_bytes(len_bytes) as usize;
    if !((NOISE_TAG_LEN + 1)..=NOISE_CHUNK + NOISE_TAG_LEN).contains(&clen) {
        return Err(TransportError::BadHandshake);
    }
    let mut cbuf = vec![0u8; clen];
    recv.read_exact(&mut cbuf).await?;
    let start = out.len();
    out.resize(start + clen, 0);
    let n = transport.read_message(&cbuf, &mut out[start..])?;
    out.truncate(start + n);
    Ok(n)
}

pub async fn write_noise_blob(
    transport: &mut TransportState,
    send: &mut SendStream,
    blob: &[u8],
) -> Result<(), TransportError> {
    if blob.len() > MAX_MAILBOX_FRAME {
        return Err(TransportError::BadHandshake);
    }
    let header = (blob.len() as u32).to_be_bytes();
    write_one_noise_msg(transport, send, &header).await?;
    for chunk in blob.chunks(NOISE_CHUNK) {
        write_one_noise_msg(transport, send, chunk).await?;
    }
    Ok(())
}

pub async fn read_noise_blob(
    transport: &mut TransportState,
    recv: &mut RecvStream,
) -> Result<Vec<u8>, TransportError> {
    read_noise_blob_capped(transport, recv, MAX_MAILBOX_FRAME).await
}

pub async fn read_noise_blob_capped(
    transport: &mut TransportState,
    recv: &mut RecvStream,
    max_frame: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut header = Vec::with_capacity(4);
    read_one_noise_msg(transport, recv, &mut header).await?;
    if header.len() != 4 {
        return Err(TransportError::BadHandshake);
    }
    let total = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if total > max_frame {
        return Err(TransportError::BadHandshake);
    }
    let mut out = Vec::with_capacity(total.min(1 << 20));
    while out.len() < total {
        let before = out.len();
        read_one_noise_msg(transport, recv, &mut out).await?;
        if out.len() <= before || out.len() > total {
            return Err(TransportError::BadHandshake);
        }
    }
    Ok(out)
}

const MAILBOX_FETCH_BUDGET: usize = 1024 * 1024;

const SURB_FETCH_BUDGET: usize = crate::client::MAX_PAYLOAD_SIZE - 256;

const MAX_MAILBOX_REQUESTS_PER_CONN: usize = 512;

static ALLOW_UNAUTH_MAILBOX_FETCH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_allow_unauthenticated_mailbox_fetch(yes: bool) {
    ALLOW_UNAUTH_MAILBOX_FETCH.store(yes, std::sync::atomic::Ordering::Relaxed);
}

#[must_use]
pub fn allow_unauthenticated_mailbox_fetch() -> bool {
    ALLOW_UNAUTH_MAILBOX_FETCH.load(std::sync::atomic::Ordering::Relaxed)
}

pub async fn serve_mailbox_connection(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    mailbox: Arc<Mutex<Mailbox>>,
    allow_unauthenticated_fetch: bool,
) -> Result<(), TransportError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let (mut noise, binding) =
        noise_responder_handshake_bound(&static_sk, &mut send, &mut recv).await?;
    debug!("noise handshake completed for mailbox conn");

    let mut served = 0usize;
    loop {
        let blob = match read_noise_blob(&mut noise, &mut recv).await {
            Ok(b) => b,
            Err(TransportError::Read(_)) | Err(TransportError::Io(_)) => break,
            Err(e) => return Err(e),
        };
        served += 1;
        if served > MAX_MAILBOX_REQUESTS_PER_CONN {
            debug!(
                served,
                "mailbox connection exceeded its request budget — closing"
            );
            let bytes = MailboxResponse::Error(MailboxWireError::RateLimited)
                .to_bytes()
                .map_err(|_| TransportError::BadHandshake)?;
            write_noise_blob(&mut noise, &mut send, &bytes).await.ok();
            break;
        }
        let resp = match MailboxRequest::from_bytes(&blob) {
            Ok(MailboxRequest::Deposit {
                id,
                sealed,
                ttl_secs,
            }) => {
                let now = now_unix();
                let mut mb = mailbox.lock().await;
                match mb.deposit(id, sealed, now, ttl_secs) {
                    Ok(()) => MailboxResponse::Ack,
                    Err(e) => MailboxResponse::Error(e.into()),
                }
            }
            Ok(MailboxRequest::Fetch { id, auth }) => match auth {
                Some(a) if a.verify(&x25519_dalek::x25519(static_sk, a.pk), &binding, &id) => {
                    let now = now_unix();
                    let mut mb = mailbox.lock().await;
                    let (sealed, more) = mb.fetch_batch(&id, now, MAILBOX_FETCH_BUDGET);
                    MailboxResponse::Delivery { sealed, more }
                }
                Some(_) => {
                    debug!("mailbox fetch: bad possession proof — refused");
                    MailboxResponse::Error(MailboxWireError::Unauthorized)
                }
                None if allow_unauthenticated_fetch => {
                    tracing::warn!(
                        "mailbox fetch served WITHOUT a possession proof — \
                             this relay allows remote message deletion by anyone \
                             holding a recipient's public key. Drop \
                             --allow-unauthenticated-mailbox-fetch once clients have updated."
                    );
                    let now = now_unix();
                    let mut mb = mailbox.lock().await;
                    let (sealed, more) = mb.fetch_batch(&id, now, MAILBOX_FETCH_BUDGET);
                    MailboxResponse::Delivery { sealed, more }
                }
                None => {
                    debug!("mailbox fetch: no possession proof — refused");
                    MailboxResponse::Error(MailboxWireError::Unauthorized)
                }
            },
            Ok(MailboxRequest::FetchWithSurb { .. }) => {
                MailboxResponse::Error(MailboxWireError::Malformed)
            }
            Err(_) => MailboxResponse::Error(MailboxWireError::Malformed),
        };
        let bytes = resp.to_bytes().map_err(|_| TransportError::BadHandshake)?;
        write_noise_blob(&mut noise, &mut send, &bytes).await?;
    }
    Ok(())
}

pub async fn serve_gossip_connection(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    roster: Arc<Mutex<Roster>>,
    set: Arc<AuthoritySet>,
) -> Result<(), TransportError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut noise = noise_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    debug!("noise handshake completed for gossip conn");

    loop {
        let blob = match read_noise_blob_capped(&mut noise, &mut recv, MAX_GOSSIP_FRAME).await {
            Ok(b) => b,
            Err(TransportError::Read(_)) | Err(TransportError::Io(_)) => break,
            Err(e) => return Err(e),
        };
        if let Ok(peer) = rmp_serde::from_slice::<Roster>(&blob) {
            let now = now_unix();
            let verified = Roster::verify_incoming(&peer, &set, now);
            let delta = {
                let mut r = roster.lock().await;
                r.splice_verified(&verified)
            };
            if delta > 0 {
                debug!(delta, "gossip: merged peer roster");
            }
        }
        let ours = { roster.lock().await.clone() };
        let bytes = rmp_serde::to_vec_named(&ours).map_err(|_| TransportError::BadHandshake)?;
        write_noise_blob(&mut noise, &mut send, &bytes).await?;
    }
    Ok(())
}

fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let data = conn.handshake_data()?;
    let hd = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    hd.protocol
}

static PER_SOURCE_LIMITER: std::sync::OnceLock<Mutex<crate::rate_limit::PerSourceLimiter>> =
    std::sync::OnceLock::new();

const PER_SOURCE_MAX_PPS: f64 = 200.0;
const PER_SOURCE_MAX_TRACKED: usize = 4096;

fn per_source_limiter() -> &'static Mutex<crate::rate_limit::PerSourceLimiter> {
    PER_SOURCE_LIMITER.get_or_init(|| {
        Mutex::new(crate::rate_limit::PerSourceLimiter::new(
            PER_SOURCE_MAX_PPS,
            0,
            PER_SOURCE_MAX_TRACKED,
        ))
    })
}

pub async fn serve_connection(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    relay: Arc<Mutex<Relay>>,
    pool: Arc<ConnectionPool>,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let src_ip = conn.remote_address().ip();
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut noise = noise_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    debug!("noise handshake completed for inbound conn");

    loop {
        let packet = match read_noise_frame(&mut noise, &mut recv).await {
            Ok(p) => p,
            Err(TransportError::Read(_)) | Err(TransportError::Io(_)) => break,
            Err(e) => return Err(e),
        };

        if !per_source_limiter()
            .lock()
            .await
            .check(src_ip, packet.len())
            .is_allowed()
        {
            debug!(%src_ip, "dropped: per-source rate limited");
            continue;
        }

        let outcome = {
            let mut r = relay.lock().await;
            let mut rng = rand::thread_rng();
            r.process(&mut rng, &packet)
        };

        match outcome {
            ProcessOutcome::Drop(reason) => {
                debug!(?reason, "dropped");
            }
            ProcessOutcome::DeliverLocal { delay, payload } => {
                let delivery = delivery.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    debug!(payload_len = payload.len(), "delivered locally");
                    if let Some(handler) = &delivery {
                        handler(payload.into_vec());
                    }
                });
            }
            ProcessOutcome::Forward {
                next_addr,
                next_node_id,
                delay,
                via_rendezvous,
                packet,
            } => {
                debug!("forward outcome");
                let pool = Arc::clone(&pool);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if via_rendezvous {
                        match pool.rendezvous().push(&next_node_id, &packet).await {
                            Ok(true) => debug!("forward via rendezvous ok"),
                            Ok(false) => debug!("rendezvous forward dropped: no live tunnel"),
                            Err(e) => warn!(error = ?e, "rendezvous push failed"),
                        }
                    } else {
                        match pool
                            .send(std::net::SocketAddr::V4(next_addr), next_node_id, &packet)
                            .await
                        {
                            Ok(()) => debug!("forward via pool ok"),
                            Err(e) => warn!(error = ?e, "forward via pool failed"),
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

pub async fn forward_packet(
    endpoint: &Endpoint,
    addr: SocketAddr,
    peer_pk: &[u8; 32],
    my_sk: &[u8; 32],
    packet: &[u8],
) -> Result<(), TransportError> {
    let conn = endpoint
        .connect(addr, "gotham-relay.local")
        .map_err(TransportError::Connect)?
        .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut noise = noise_initiator_handshake(my_sk, peer_pk, &mut send, &mut recv).await?;
    write_noise_frame(&mut noise, &mut send, packet).await?;
    send.finish().ok();
    let _ = send.stopped().await;
    Ok(())
}

fn spawn_replay_persistence(relay: Arc<Mutex<Relay>>) {
    const INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::spawn(async move {
        if !relay.lock().await.persists_replay() {
            return;
        }
        let mut ticker = tokio::time::interval(INTERVAL);
        loop {
            ticker.tick().await;
            let Some((buf, path)) = relay.lock().await.encode_replay() else {
                return;
            };
            let written = tokio::task::spawn_blocking(move || {
                crate::replay::persist::write_encoded(&buf, &path)
            })
            .await;
            match written {
                Ok(Ok(n)) => debug!(entries = n, "replay cache persisted"),
                Ok(Err(e)) => warn!(error = %e, "could not persist the replay cache"),
                Err(e) => warn!(error = %e, "replay persistence task panicked"),
            }
        }
    });
}

pub async fn run_rendezvous_relay(
    r_addr: SocketAddr,
    r_pk: [u8; 32],
    my_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    run_rendezvous_relay_shared(r_addr, r_pk, my_sk, Arc::new(Mutex::new(relay)), delivery).await
}

pub async fn run_rendezvous_relay_shared(
    r_addr: SocketAddr,
    r_pk: [u8; 32],
    my_sk: [u8; 32],
    relay: Arc<Mutex<Relay>>,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = build_client_endpoint()?;
    let pool = Arc::new(ConnectionPool::new(client, my_sk));
    spawn_replay_persistence(Arc::clone(&relay));
    let (tx, rx) = tokio::sync::mpsc::channel(crate::rendezvous::RENDEZVOUS_INBOUND_QUEUE);
    info!(r = %r_addr, "starting as a CGNAT (rendezvous-hosted) relay — inbound via R only");
    tokio::spawn(crate::rendezvous::run_rendezvous_client(
        r_addr, r_pk, my_sk, tx,
    ));
    run_rendezvous_inbound(rx, relay, pool, delivery).await;
    Ok(())
}

pub async fn run_rendezvous_inbound(
    mut inbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    relay: Arc<Mutex<Relay>>,
    pool: Arc<ConnectionPool>,
    delivery: Option<DeliveryHandler>,
) {
    while let Some(packet) = inbound_rx.recv().await {
        let outcome = {
            let mut r = relay.lock().await;
            let mut rng = rand::thread_rng();
            r.process(&mut rng, &packet)
        };
        match outcome {
            ProcessOutcome::Drop(reason) => debug!(?reason, "rendezvous-inbound dropped"),
            ProcessOutcome::DeliverLocal { delay, payload } => {
                let delivery = delivery.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if let Some(handler) = &delivery {
                        handler(payload.into_vec());
                    }
                });
            }
            ProcessOutcome::Forward {
                next_addr,
                next_node_id,
                delay,
                via_rendezvous,
                packet,
            } => {
                let pool = Arc::clone(&pool);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if via_rendezvous {
                        let _ = pool.rendezvous().push(&next_node_id, &packet).await;
                    } else {
                        let _ = pool
                            .send(std::net::SocketAddr::V4(next_addr), next_node_id, &packet)
                            .await;
                    }
                });
            }
        }
    }
}

pub async fn run_relay_listener(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    run_relay_listener_with_mailbox(listen_addr, static_sk, relay, delivery, None).await
}

pub async fn run_relay_listener_with_mailbox(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
) -> Result<(), TransportError> {
    run_relay_listener_with_services(listen_addr, static_sk, relay, delivery, mailbox, None, None)
        .await
}

pub async fn run_relay_listener_with_services(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
    gossip: Option<GossipService>,
    rendezvous_queriers: Option<QuerierKeys>,
) -> Result<(), TransportError> {
    run_relay_listener_with_services_shared(
        listen_addr,
        static_sk,
        Arc::new(Mutex::new(relay)),
        delivery,
        mailbox,
        gossip,
        rendezvous_queriers,
    )
    .await
}

pub async fn run_relay_listener_with_services_shared(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Arc<Mutex<Relay>>,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
    gossip: Option<GossipService>,
    rendezvous_queriers: Option<QuerierKeys>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server = build_server_endpoint(listen_addr)?;
    serve_endpoint_with_services_shared(
        server,
        static_sk,
        relay,
        delivery,
        mailbox,
        gossip,
        rendezvous_queriers,
    )
    .await
}

pub async fn serve_endpoint(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    serve_endpoint_with_services(endpoint, static_sk, relay, delivery, None, None, None).await
}

pub async fn serve_endpoint_with_mailbox(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
) -> Result<(), TransportError> {
    serve_endpoint_with_services(endpoint, static_sk, relay, delivery, mailbox, None, None).await
}

#[derive(Clone)]
pub struct GossipService {
    pub roster: Arc<Mutex<Roster>>,
    pub authority_set: Arc<AuthoritySet>,
}

pub async fn serve_endpoint_with_services(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
    gossip: Option<GossipService>,
    rendezvous_queriers: Option<QuerierKeys>,
) -> Result<(), TransportError> {
    serve_endpoint_with_services_shared(
        endpoint,
        static_sk,
        Arc::new(Mutex::new(relay)),
        delivery,
        mailbox,
        gossip,
        rendezvous_queriers,
    )
    .await
}

pub async fn serve_endpoint_with_services_shared(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Arc<Mutex<Relay>>,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
    gossip: Option<GossipService>,
    rendezvous_queriers: Option<QuerierKeys>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = build_client_endpoint()?;
    spawn_replay_persistence(Arc::clone(&relay));
    let pool = Arc::new(ConnectionPool::new(client, static_sk));
    let bound = endpoint.local_addr().ok();
    info!(
        ?bound,
        mailbox = mailbox.is_some(),
        gossip = gossip.is_some(),
        "gotham-relay QUIC listener accepting (pooled forwards)"
    );

    const MAX_INFLIGHT_CONNS: usize = 1024;
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_CONNS));

    while let Some(connecting) = endpoint.accept().await {
        let permit = match Arc::clone(&conn_limit).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!("connection limit reached; shedding new inbound connection");
                drop(connecting);
                continue;
            }
        };
        let relay = Arc::clone(&relay);
        let pool = Arc::clone(&pool);
        let sk = static_sk;
        let delivery = delivery.clone();
        let mailbox = mailbox.clone();
        let gossip = gossip.clone();
        let rendezvous_queriers = rendezvous_queriers.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match connecting.await {
                Ok(conn) => {
                    let alpn = negotiated_alpn(&conn);
                    match alpn.as_deref() {
                        Some(a) if a == MAILBOX_ALPN => match mailbox {
                            Some(mb) => {
                                if let Err(e) = serve_mailbox_connection(
                                    conn,
                                    sk,
                                    mb,
                                    allow_unauthenticated_mailbox_fetch(),
                                )
                                .await
                                {
                                    debug!(error = ?e, "mailbox connection ended");
                                }
                            }
                            None => conn.close(1u32.into(), b"no mailbox here"),
                        },
                        Some(a) if a == GOSSIP_ALPN => match gossip {
                            Some(g) => {
                                if let Err(e) =
                                    serve_gossip_connection(conn, sk, g.roster, g.authority_set)
                                        .await
                                {
                                    debug!(error = ?e, "gossip connection ended");
                                }
                            }
                            None => conn.close(1u32.into(), b"no gossip here"),
                        },
                        Some(a) if a == RENDEZVOUS_ALPN => {
                            if let Err(e) = crate::rendezvous::serve_rendezvous_connection(
                                conn,
                                sk,
                                pool.rendezvous().clone(),
                            )
                            .await
                            {
                                debug!(error = ?e, "rendezvous connection ended");
                            }
                        }
                        Some(a) if a == RENDEZVOUS_QUERY_ALPN => {
                            if let Err(e) = serve_rendezvous_query(
                                conn,
                                sk,
                                rendezvous_queriers,
                                pool.rendezvous().clone(),
                            )
                            .await
                            {
                                debug!(error = ?e, "rendezvous query ended");
                            }
                        }
                        _ => {
                            if let Err(e) = serve_connection(conn, sk, relay, pool, delivery).await
                            {
                                debug!(error = ?e, "connection ended");
                            }
                        }
                    }
                }
                Err(e) => debug!(error = ?e, "incoming connection failed"),
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn an_unreachable_relay_says_so_instead_of_blaming_the_handshake() {
        let addr: std::net::SocketAddr = "192.0.2.1:9102".parse().unwrap();
        let err = super::probe_relay_liveness(
            addr,
            &[0u8; 32],
            &[1u8; 32],
            std::time::Duration::from_millis(300),
        )
        .await
        .expect_err("a black-holed address cannot be probed");

        assert!(
            matches!(err, super::TransportError::Unreachable(_)),
            "expected Unreachable, got {err:?}",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("firewall"),
            "must point at the firewall: {msg}"
        );
        assert!(
            !msg.contains("handshake"),
            "must not send the operator hunting for a protocol bug: {msg}",
        );
    }

    use super::*;
    use crypto_gotham::header::{
        derive_route_secrets, flag, mode, wrap_header, RoutingRecord, HEADER_LEN, TRAILER_LEN,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::net::SocketAddrV4;
    use std::sync::Once;
    use x25519_dalek::{PublicKey, StaticSecret};

    static CRYPTO_PROVIDER: Once = Once::new();
    fn init_crypto_provider() {
        CRYPTO_PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xBADC0FFEE)
    }

    fn build_2hop_packet(
        rng: &mut ChaCha20Rng,
        relay1_sk: [u8; 32],
        relay2_sk: [u8; 32],
        relay2_addr: SocketAddrV4,
    ) -> Vec<u8> {
        let pks = [
            PublicKey::from(&StaticSecret::from(relay1_sk)).to_bytes(),
            PublicKey::from(&StaticSecret::from(relay2_sk)).to_bytes(),
        ];
        let (alphas, sub_keys) = derive_route_secrets(rng, &pks).unwrap();

        let records = vec![
            RoutingRecord {
                next_ipv4: relay2_addr.ip().octets(),
                next_port: relay2_addr.port(),
                next_node_id: pks[1],
                delay_micros: 0,
                ..RoutingRecord::default()
            },
            RoutingRecord {
                flag: flag::IS_LAST_HOP,
                ..RoutingRecord::default()
            },
        ];
        let mut trailer = [0u8; TRAILER_LEN];
        rng.fill_bytes(&mut trailer);

        let header =
            wrap_header(rng, mode::BALANCED, &alphas, &sub_keys, &records, trailer).unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        for (i, b) in packet[HEADER_LEN..].iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }
        packet
    }

    async fn spawn_relay(sk: [u8; 32]) -> (SocketAddrV4, tokio::task::JoinHandle<()>) {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Relay::new(sk, 1000, std::time::Duration::from_secs(60), 0);
        let relay = Arc::new(Mutex::new(relay));

        let pool_for_handle = Arc::new(ConnectionPool::new(client, sk));
        let handle = tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let relay = Arc::clone(&relay);
                let pool = Arc::clone(&pool_for_handle);
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, None).await;
                    }
                });
            }
        });

        let v4 = match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("expected v4"),
        };
        (v4, handle)
    }

    #[tokio::test]
    async fn probe_verifies_liveness_and_possession() {
        use x25519_dalek::{PublicKey, StaticSecret};
        let sk = [11u8; 32];
        let (addr, _h) = spawn_relay(sk).await;
        let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        let initiator = [22u8; 32];

        probe_relay_liveness(
            SocketAddr::V4(addr),
            &pk,
            &initiator,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("probe should succeed against a live relay that holds the key");

        let wrong = [0xAAu8; 32];
        let res = probe_relay_liveness(
            SocketAddr::V4(addr),
            &wrong,
            &initiator,
            std::time::Duration::from_secs(3),
        )
        .await;
        assert!(
            res.is_err(),
            "probe must fail when the responder does not hold the claimed key"
        );
    }

    #[tokio::test]
    async fn probe_fails_for_unreachable_address() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let res = probe_relay_liveness(
            dead,
            &[7u8; 32],
            &[22u8; 32],
            std::time::Duration::from_secs(2),
        )
        .await;
        assert!(res.is_err(), "probe must fail when nothing is reachable");
    }

    #[tokio::test]
    async fn rdvq_presence_query_requires_authority_auth() {
        init_crypto_provider();
        let mut r = rng();

        let mut r_sk = [0u8; 32];
        r.fill_bytes(&mut r_sk);
        let r_pk = PublicKey::from(&StaticSecret::from(r_sk)).to_bytes();
        let mut auth_sk = [0u8; 32];
        r.fill_bytes(&mut auth_sk);
        let auth_pk = PublicKey::from(&StaticSecret::from(auth_sk)).to_bytes();
        let mut imp_sk = [0u8; 32];
        r.fill_bytes(&mut imp_sk);
        let mut n_pk = [0u8; 32];
        r.fill_bytes(&mut n_pk);

        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = server.local_addr().unwrap();
        let serve_table = crate::rendezvous::RendezvousTable::new();
        let handle = tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let table = serve_table.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_rendezvous_query(
                            conn,
                            r_sk,
                            Some(querier_keys(Some(auth_pk))),
                            table,
                        )
                        .await;
                    }
                });
            }
        });

        let hosted = probe_rendezvous_hosting(
            bound,
            &r_pk,
            &auth_sk,
            &n_pk,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("authority query should complete");
        assert!(!hosted, "empty table ⇒ relay not hosted");

        let as_impostor = probe_rendezvous_hosting(
            bound,
            &r_pk,
            &imp_sk,
            &n_pk,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            as_impostor.is_err(),
            "a non-authority querier must be rejected"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn every_authority_the_rendezvous_point_knows_gets_an_answer() {
        init_crypto_provider();
        let mut r = rng();
        let mut key = || {
            let mut sk = [0u8; 32];
            r.fill_bytes(&mut sk);
            (sk, PublicKey::from(&StaticSecret::from(sk)).to_bytes())
        };
        let (r_sk, r_pk) = key();
        let (a1_sk, a1_pk) = key();
        let (a2_sk, a2_pk) = key();
        let (a3_sk, a3_pk) = key();
        let (imp_sk, _) = key();
        let (_, n_pk) = key();

        let queriers = querier_keys(Some(a1_pk));
        add_querier_key(&queriers, a2_pk);

        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = server.local_addr().unwrap();
        let serve_table = crate::rendezvous::RendezvousTable::new();
        let served = queriers.clone();
        let handle = tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let table = serve_table.clone();
                let keys = served.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_rendezvous_query(conn, r_sk, Some(keys), table).await;
                    }
                });
            }
        });

        let ask = |sk: [u8; 32]| async move {
            probe_rendezvous_hosting(bound, &r_pk, &sk, &n_pk, std::time::Duration::from_secs(5))
                .await
        };
        assert!(
            ask(a1_sk).await.is_ok(),
            "the first authority must get an answer"
        );
        assert!(
            ask(a2_sk).await.is_ok(),
            "the second authority must get an answer"
        );
        assert!(
            ask(imp_sk).await.is_err(),
            "an unknown querier must be refused"
        );
        assert!(
            ask(a3_sk).await.is_err(),
            "a third authority is refused until its key is learned"
        );
        add_querier_key(&queriers, a3_pk);
        assert!(
            ask(a3_sk).await.is_ok(),
            "a key learned later is accepted without a restart"
        );

        handle.abort();
    }

    #[test]
    fn querier_keys_are_deduplicated_and_bounded() {
        let keys = querier_keys(None);
        add_querier_key(&keys, [1u8; 32]);
        add_querier_key(&keys, [1u8; 32]);
        assert_eq!(keys.read().unwrap().len(), 1);
        for i in 0..(MAX_QUERIER_KEYS as u8 + 4) {
            add_querier_key(&keys, [i.wrapping_add(2); 32]);
        }
        let held = keys.read().unwrap();
        assert_eq!(held.len(), MAX_QUERIER_KEYS);
        assert!(
            !held.contains(&[1u8; 32]),
            "the oldest key goes first once the bound is reached"
        );
    }

    async fn spawn_relay_with_delivery(
        sk: [u8; 32],
    ) -> (SocketAddrV4, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let handler: DeliveryHandler = Arc::new(move |payload: Vec<u8>| {
            let _ = tx.send(payload);
        });
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Relay::new(sk, 1000, std::time::Duration::from_secs(60), 0);
        let relay = Arc::new(Mutex::new(relay));
        let pool = Arc::new(ConnectionPool::new(client, sk));
        tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let relay = Arc::clone(&relay);
                let pool = Arc::clone(&pool);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_connection(conn, sk, relay, pool, Some(handler)).await;
                    }
                });
            }
        });
        let v4 = match bound {
            SocketAddr::V4(v) => v,
            _ => panic!("expected v4"),
        };
        (v4, rx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deliver_local_hook_fires_at_last_hop() {
        init_crypto_provider();
        let mut r = rng();
        let mut sk = [0u8; 32];
        r.fill_bytes(&mut sk);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;

        let (addr, mut rx) = spawn_relay_with_delivery(sk).await;

        let pks = [PublicKey::from(&StaticSecret::from(sk)).to_bytes()];
        let (alphas, sub_keys) = derive_route_secrets(&mut r, &pks).unwrap();
        let records = vec![RoutingRecord {
            flag: flag::IS_LAST_HOP,
            ..RoutingRecord::default()
        }];
        let mut trailer = [0u8; TRAILER_LEN];
        r.fill_bytes(&mut trailer);
        let header = wrap_header(
            &mut r,
            mode::BALANCED,
            &alphas,
            &sub_keys,
            &records,
            trailer,
        )
        .unwrap();
        let mut packet = vec![0u8; crypto_gotham::PACKET_SIZE];
        packet[..HEADER_LEN].copy_from_slice(&header.encode());
        let marker = b"deliver-this-please";
        packet[HEADER_LEN..HEADER_LEN + marker.len()].copy_from_slice(marker);
        crypto_gotham::lioness::encrypt(&sub_keys[0].k_payload, &mut packet[HEADER_LEN..]);

        let client_ep = build_client_endpoint().unwrap();
        let conn = client_ep
            .connect(SocketAddr::V4(addr), "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut client_sk = [0u8; 32];
        r.fill_bytes(&mut client_sk);
        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;
        let server_pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
        let mut noise = noise_initiator_handshake(&client_sk, &server_pk, &mut send, &mut recv)
            .await
            .unwrap();
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();
        send.finish().ok();

        let payload = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .expect("delivery handler timed out")
            .expect("channel closed");
        assert_eq!(payload.len(), crypto_gotham::PACKET_SIZE - HEADER_LEN);
        assert_eq!(&payload[..marker.len()], marker);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn end_to_end_2hop_forward() {
        init_crypto_provider();
        let mut r = rng();

        let mut sk1 = [0u8; 32];
        let mut sk2 = [0u8; 32];
        r.fill_bytes(&mut sk1);
        r.fill_bytes(&mut sk2);
        for sk in [&mut sk1, &mut sk2] {
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
        }

        let (addr2, _h2) = spawn_relay(sk2).await;
        let (addr1, _h1) = spawn_relay(sk1).await;

        let packet = build_2hop_packet(&mut r, sk1, sk2, addr2);

        let client = build_client_endpoint().unwrap();
        let conn = client
            .connect(SocketAddr::V4(addr1), "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let mut client_sk = [0u8; 32];
        r.fill_bytes(&mut client_sk);
        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;
        let server_pk = PublicKey::from(&StaticSecret::from(sk1)).to_bytes();

        let mut noise = noise_initiator_handshake(&client_sk, &server_pk, &mut send, &mut recv)
            .await
            .unwrap();
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();
        send.finish().ok();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn noise_handshake_roundtrip() {
        init_crypto_provider();
        let mut r = rng();
        let mut server_sk = [0u8; 32];
        r.fill_bytes(&mut server_sk);
        server_sk[0] &= 248;
        server_sk[31] &= 127;
        server_sk[31] |= 64;

        let server_pk = PublicKey::from(&StaticSecret::from(server_sk)).to_bytes();

        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            if let Some(connecting) = server.accept().await {
                let conn = connecting.await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let mut noise = noise_responder_handshake(&server_sk, &mut send, &mut recv)
                    .await
                    .unwrap();
                let packet = read_noise_frame(&mut noise, &mut recv).await.unwrap();
                write_noise_frame(&mut noise, &mut send, &packet)
                    .await
                    .unwrap();
                let _ = conn.closed().await;
            }
        });

        let client = build_client_endpoint().unwrap();
        let conn = client
            .connect(bound, "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        let mut client_sk = [0u8; 32];
        r.fill_bytes(&mut client_sk);
        client_sk[0] &= 248;
        client_sk[31] &= 127;
        client_sk[31] |= 64;

        let mut noise = noise_initiator_handshake(&client_sk, &server_pk, &mut send, &mut recv)
            .await
            .unwrap();

        let mut packet = vec![0u8; PACKET_SIZE];
        for (i, b) in packet.iter_mut().enumerate() {
            *b = ((i * 31) % 256) as u8;
        }
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();

        let echoed = read_noise_frame(&mut noise, &mut recv).await.unwrap();
        assert_eq!(echoed, packet);

        drop(send);
        drop(recv);
        drop(conn);
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
    }
}
