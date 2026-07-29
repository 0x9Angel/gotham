// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! QUIC transport with per-link Noise XK encryption.
//!
//! ## Stack
//!
//! ```text
//!   Gotham packet (2048 B fixed)
//!     │
//!     ▼
//!   Noise XK (snow) — per-link symmetric ChaCha20-Poly1305
//!     │  + 16 B AEAD tag  →  2064 B on the wire
//!     ▼
//!   QUIC bi-stream over TLS 1.3 (rustls)
//!     │  TLS cert is self-signed; Noise XK provides the real authentication
//!     │  so we use a custom rustls verifier that accepts any cert.
//!     ▼
//!   UDP (default port 443)
//! ```
//!
//! ## Why two crypto layers?
//!
//! - **QUIC + TLS 1.3** gives us reliable streams, 0-RTT resumption,
//!   modern congestion control, NAT traversal, and packets that look
//!   identical to vanilla HTTPS on the wire (DPI-resistance for free).
//! - **Noise XK on top** pins the relay's long-term X25519 identity (the
//!   same key advertised in the directory) and prevents TLS-cert-MITM
//!   attacks. The client is anonymous to the relay (XK pattern: client
//!   not authenticated at the Noise layer; identity proven at the
//!   Gotham-packet layer instead).
//!
//! ## v0.1 status
//!
//! - One inbound bi-stream per connection (multiplexing left to v0.2)
//! - One outbound connection per forwarded packet (pooling left to v0.2)
//! - Cert verification skipped on client side (Noise XK provides auth)
//! - Fixed packet size 2048 + 16 B tag = 2064 B per Noise frame
//!
//! Mutable relay state is shared between connection-handler tasks via an
//! `Arc<Mutex<Relay>>`. Mutex contention is fine for the v0.1 single-relay
//! workload; v0.2 can shard the replay cache + scheduler if needed.

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

/// Callback invoked on `ProcessOutcome::DeliverLocal` — i.e. when a
/// Gotham packet reaches its final destination at this relay.
///
/// The handler receives the raw payload bytes (everything after the
/// 384 B header). For payloads wrapped in a sealed-sender envelope,
/// use [`make_unsealing_delivery_handler`] to compose with an
/// `unseal` step that yields `(sender_pk, body)`.
///
/// Implementations must be cheap to clone (the wrapped `Arc` makes
/// this O(1)) and safe to call from any tokio worker.
pub type DeliveryHandler = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Build a [`DeliveryHandler`] that automatically unseals incoming
/// payloads before dispatching them. The wrapped `inner` callback
/// receives `(sender_pk, body)` for valid envelopes; envelopes that
/// fail to unseal (wrong recipient, tampered, malformed) are dropped
/// silently — the relay never logs the failure with packet content.
///
/// **Wire format**: expects `GothamClient::send_sealed` framing — a
/// 4 B big-endian length prefix followed by the variable-length sealed
/// envelope, then zero-padding up to the 1664 B Gotham payload region.
pub fn make_unsealing_delivery_handler<F>(recipient_sk: [u8; 32], inner: F) -> DeliveryHandler
where
    F: Fn([u8; 32], Vec<u8>) + Send + Sync + 'static,
{
    Arc::new(move |payload: Vec<u8>| {
        // 1. Parse 4 B length prefix.
        if payload.len() < 4 {
            debug!("framed payload shorter than length prefix");
            return;
        }
        // The slice is exactly 4 B (we just checked `payload.len() >= 4`),
        // so `try_into` cannot fail here — but we avoid `.expect()` to
        // honour the crate-wide `deny(clippy::expect_used)` and to keep
        // the type-system honesty even when the policy lint is lifted.
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

        // 2. Unseal (also validates the AEAD tag).
        match crypto_gotham::sealed::unseal(&recipient_sk, envelope) {
            Ok((sender_pk, body)) => inner(sender_pk, body),
            Err(_) => {
                debug!("sealed-sender unseal failed — dropping");
            }
        }
    })
}

/// Build a [`DeliveryHandler`] for a mailbox host that accepts deposits over
/// the **mixnet** — so the depositor's IP is hidden, unlike the direct
/// [`serve_mailbox_connection`] control path (which the host sees the client IP
/// on). The mixnet payload is a sealed-sender envelope (sealed for the host)
/// wrapping a [`MailboxRequest::Deposit`]; the host unseals it and stores the
/// inner, still-sealed-for-recipient bytes. Only `Deposit` is honored — a fetch
/// needs a reply the one-way mixnet cannot provide.
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
            // The delivery handler is sync but the mailbox is a tokio mutex, so
            // apply the deposit on a spawned task. Fire-and-forget: a deposit
            // needs no reply, and the handler runs on a tokio worker so a
            // runtime is always present here.
            tokio::spawn(async move {
                let now = now_unix();
                if let Err(e) = mailbox.lock().await.deposit(id, sealed, now, ttl_secs) {
                    debug!(?e, "mixnet mailbox deposit refused");
                }
            });
        }
    })
}

/// Build a [`DeliveryHandler`] for a mailbox host that serves BOTH mixnet
/// deposits (IP-hidden, like [`make_mailbox_deposit_handler`]) AND **anonymous
/// SURB fetches** ([`MailboxRequest::FetchWithSurb`]). On a SURB fetch it drains
/// the mailbox and ships the batch back **through the mixnet** using the
/// enclosed single-use reply block, so it never learns the fetcher's IP or the
/// `IP ↔ mailbox_id` link — the one metadata leak a direct fetch could not
/// close. Owns a private client endpoint (mixnet ALPN) for injecting replies.
///
/// A `FetchWithSurb` MUST carry a [`FetchAuth`] possession proof (SEC-MBX-01):
/// a fetch is destructive, so without it any holder of the recipient's *public*
/// key could silently delete their offline messages and have the reply shipped
/// to an attacker-chosen path. The proof is bound to the reply block itself
/// ([`crypto_gotham::mailbox::surb_fetch_binding`]), so it cannot be lifted
/// onto a different SURB.
///
/// Residual limitations (documented, not yet closed):
/// - **Replay**: a SURB carries a fixed Sphinx header, so single-use rests on
///   the first return hop's γ-keyed replay cache (TTL-bounded). After the TTL a
///   replayed reply re-delivers the same already-consumed batch, which the
///   recipient's Double Ratchet drops. Mint a fresh SURB per fetch.
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
                // Possession proof FIRST: a fetch drains the mailbox, so an
                // unproven request is a remote message-deletion primitive. The
                // binding is derived from the reply block, so a captured tag
                // cannot be replayed onto a SURB pointing somewhere else.
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
                    // A SURB reply must fit ONE mixnet packet, so drain only up
                    // to a one-packet byte budget (not the 16 MiB direct-fetch
                    // budget). `more` tells the client to fetch again.
                    let (sealed, more) = {
                        let mut mb = mailbox.lock().await;
                        mb.fetch_batch(&id, now, SURB_FETCH_BUDGET)
                    };
                    // Nothing to send? Skip — a reply carrying an empty batch
                    // would still leak that *someone* polled this mailbox.
                    if sealed.is_empty() {
                        return;
                    }
                    let resp = MailboxResponse::Delivery {
                        sealed: sealed.clone(),
                        more,
                    };
                    // If the batch can't be serialized or shipped in one packet
                    // (e.g. a single stored message bigger than a packet, which
                    // `fetch_batch` returns alone by its forward-progress rule),
                    // RE-DEPOSIT it so the drain is not a silent data loss.
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
                            // ttl_secs=0 → policy default; best-effort.
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
/// Noise pattern for the RFC B3 rendezvous tunnel. IK (not XK) so the INITIATOR
/// (the CGNAT relay N) authenticates ITS static key to the responder R — R must
/// bind the tunnel to N's proven identity, and the handshake doubles as N's
/// proof-of-possession. XK only authenticates the responder.
const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const NOISE_TAG_LEN: usize = 16;

/// ALPN for the mixnet packet-forwarding protocol (fixed 2064 B Noise frames).
pub const MIXNET_ALPN: &[u8] = b"gotham/1";
/// ALPN for the store-and-forward mailbox control protocol (variable-length,
/// chunked Noise frames — see [`serve_mailbox_connection`]). Selected at the
/// QUIC handshake so a single relay endpoint serves both protocols without
/// disturbing the mixnet framing.
pub const MAILBOX_ALPN: &[u8] = b"gotham-mbx/1";

/// ALPN for the peer-to-peer directory **gossip** protocol (push-pull roster
/// anti-entropy — see [`serve_gossip_connection`]). Same endpoint, selected at
/// the QUIC handshake.
pub const GOSSIP_ALPN: &[u8] = b"gotham-dir/1";

/// ALPN for the RFC B3 reverse/rendezvous tunnel: a CGNAT relay N keeps a
/// persistent connection OUT to a rendezvous relay R on this ALPN, and R pushes
/// mixnet packets back down it. Authenticated with Noise IK (the initiator N's
/// static key is authenticated, unlike the mixnet's XK). See `rendezvous.rs`.
pub const RENDEZVOUS_ALPN: &[u8] = b"gotham-rdv/1";

/// ALPN for the RFC B3 rendezvous-hosting QUERY: the directory authority asks a
/// rendezvous relay R "do you currently host a live tunnel for relay N?" to
/// prove a CGNAT relay's liveness without dialing it. Noise-XK (R authenticated).
pub const RENDEZVOUS_QUERY_ALPN: &[u8] = b"gotham-rdvq/1";

/// Frame ceiling for a gossip roster blob (4 MiB) — far tighter than the
/// mailbox's 16 MiB, sized to [`crypto_gotham_directory::MAX_GOSSIP_ENTRIES`] ×
/// a per-entry budget. Bounds the roster (and thus the signature-verification
/// work) a peer can push in one round.
pub const MAX_GOSSIP_FRAME: usize = 4 * 1024 * 1024;

/// Plaintext bytes per Noise transport message when streaming a variable-length
/// mailbox blob. snow caps a single message at 65535 B (incl. the 16 B tag);
/// we stay well under that.
const NOISE_CHUNK: usize = 32 * 1024;

/// Wire size of one Noise-encapsulated Gotham packet.
pub const FRAME_LEN: usize = PACKET_SIZE + NOISE_TAG_LEN;

/// Max size of a Noise handshake message we'll accept.
const MAX_HANDSHAKE_MSG: usize = 1024;

/// Errors that can arise in the transport layer. We collapse the various
/// quinn/snow/rustls errors into a single category because production
/// callers never need to distinguish them — they either succeed or drop
/// the connection.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Underlying I/O failure (socket bind, read, write).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// QUIC connection-establishment failure.
    #[error("quic connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// QUIC connection-level error (peer reset, idle timeout, etc.).
    #[error("quic connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// QUIC stream write error.
    #[error("quic write: {0}")]
    Write(#[from] quinn::WriteError),
    /// QUIC stream read error (EOF before required byte count).
    #[error("quic read: {0}")]
    Read(#[from] quinn::ReadExactError),
    /// rustls TLS error.
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    /// Self-signed cert generation failure (rcgen).
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// Noise XK handshake / transport-state error.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    /// Caller-supplied data violated a Gotham protocol invariant
    /// (over-length handshake msg, bad packet size, …).
    #[error("malformed handshake message")]
    BadHandshake,
    /// Nothing answered within the time budget.
    ///
    /// Separate from [`BadHandshake`] on purpose. Both liveness probes used to
    /// report a timeout as a malformed handshake, which sends an operator
    /// hunting for a protocol bug when the cause is almost always a closed UDP
    /// port — a cloud security list, or a host firewall. That message cost an
    /// afternoon once; on a network run by volunteers it costs people's
    /// willingness to run a relay at all.
    #[error(
        "no response within {0:?} — nothing is reachable at that address. \
         Check that the UDP port is open in your provider's firewall \
         (cloud security list / security group), not only on the host itself."
    )]
    Unreachable(std::time::Duration),
}

// ─── Self-signed TLS cert (Noise XK provides real auth) ─────────────────────

/// Generate a fresh self-signed certificate for the QUIC TLS layer.
///
/// The Subject Alternative Name is irrelevant — the client-side verifier
/// (see [`SkipServerVerification`]) accepts any cert. Real peer
/// authentication happens at the Noise XK layer where the static
/// X25519 key is pinned against the directory entry.
pub fn make_self_signed_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec!["gotham-relay.local".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    Ok((cert_der, key_der))
}

// ─── Client-side: skip cert verification ────────────────────────────────────

/// A `rustls::ServerCertVerifier` that accepts any certificate.
///
/// **This is intentional.** The Gotham model relies on Noise XK at the
/// next layer for peer authentication; TLS at the QUIC level only
/// provides transport encryption + DPI resistance. Skipping verification
/// here removes the requirement for a PKI hierarchy among relays.
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

// ─── QUIC endpoint construction ─────────────────────────────────────────────

/// Build a QUIC server endpoint bound to `addr` with a self-signed cert.
pub fn build_server_endpoint(addr: SocketAddr) -> Result<Endpoint, TransportError> {
    let (cert, key) = make_self_signed_cert()?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    // Offer all protocols; the negotiated ALPN tells the accept loop which
    // handler to dispatch (mixnet forwarding / mailbox control / directory
    // gossip). A mixnet-only client that offers just `gotham/1` still
    // negotiates cleanly.
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

/// Build a QUIC client endpoint offering a single `alpn`. Uses 0.0.0.0:0
/// (ephemeral source port). Cert verification is skipped — Noise XK does the
/// auth.
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

/// Build a mixnet client endpoint (ALPN `gotham/1`).
pub fn build_client_endpoint() -> Result<Endpoint, TransportError> {
    build_client_endpoint_alpn(MIXNET_ALPN)
}

/// Build a mailbox-control client endpoint (ALPN `gotham-mbx/1`). Used by
/// [`MailboxClient`] to deposit/fetch against a mailbox-hosting relay.
pub fn build_mailbox_client_endpoint() -> Result<Endpoint, TransportError> {
    build_client_endpoint_alpn(MAILBOX_ALPN)
}

/// Build a directory-gossip client endpoint (ALPN `gotham-dir/1`). Used by the
/// gossip node to run push-pull roster anti-entropy with a peer relay.
pub fn build_gossip_client_endpoint() -> Result<Endpoint, TransportError> {
    build_client_endpoint_alpn(GOSSIP_ALPN)
}

/// Build a client endpoint for the RFC B3 rendezvous tunnel (ALPN
/// `gotham-rdv/1`), with QUIC keep-alive so the long-lived outbound tunnel from
/// a CGNAT relay is not reaped by the idle timeout.
pub fn build_rendezvous_client_endpoint() -> Result<Endpoint, TransportError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![RENDEZVOUS_ALPN.to_vec()];
    let quic_client_config =
        QuicClientConfig::try_from(client_crypto).map_err(|_| TransportError::BadHandshake)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
    // Keep the tunnel warm: PING well under the idle timeout so a silent tunnel
    // (no mixnet traffic for a while) is not reaped.
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

// ─── Length-prefixed handshake I/O ──────────────────────────────────────────

async fn write_handshake_msg(send: &mut SendStream, msg: &[u8]) -> Result<(), TransportError> {
    if msg.len() > MAX_HANDSHAKE_MSG {
        return Err(TransportError::BadHandshake);
    }
    let len = msg.len() as u16;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(msg).await?;
    Ok(())
}

/// Max wait for any single handshake read. A live peer sends each handshake
/// message immediately; a slowloris that opens a stream and then stalls (sends
/// nothing, or the length prefix but not the body) would otherwise park the
/// responder task on `read_exact` forever, pinning task + buffer memory. Every
/// responder handshake reads through this fn, so the bound is universal.
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

// ─── Noise XK handshake (responder = server, initiator = client) ────────────

/// Run the responder side of a Noise XK handshake over the supplied
/// stream pair, using `static_sk` as the responder's static private key.
///
/// On success, returns the symmetric transport state used for subsequent
/// frame encryption/decryption.
pub async fn noise_responder_handshake(
    static_sk: &[u8; 32],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<TransportState, TransportError> {
    Ok(noise_responder_handshake_bound(static_sk, send, recv)
        .await?
        .0)
}

/// Like [`noise_responder_handshake`], but also returns the Noise **handshake
/// hash** — a value unique to this connection and identical on both sides.
///
/// Used as a channel binding: an application-layer authenticator computed over
/// it cannot be lifted from one connection onto another. `snow` exposes the
/// hash only on `HandshakeState`, so it must be captured here, before the
/// state is consumed into transport mode.
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

    // XK pattern: <- e, es | -> e, ee | <- s, se
    // (Responder reads first message, writes second, reads third.)

    // 1. Read client's first message
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    // 2. Write our response
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    // 3. Read client's static-key message
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let binding = hs.get_handshake_hash().to_vec();
    let transport = hs.into_transport_mode()?;
    Ok((transport, binding))
}

/// Run the initiator side of a Noise XK handshake. `server_static_pk` is
/// the responder's pinned public key (obtained from the directory).
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

/// Like [`noise_initiator_handshake`], but also returns the Noise handshake
/// hash for use as a channel binding. See
/// [`noise_responder_handshake_bound`].
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

    // 1. Send first XK message
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    // 2. Read server response
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    // 3. Send static-key message
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let binding = hs.get_handshake_hash().to_vec();
    let transport = hs.into_transport_mode()?;
    Ok((transport, binding))
}

/// Responder side of a Noise **IK** handshake (RFC B3 rendezvous, R side). Uses
/// `static_sk` as R's static key: reads msg1 (which carries the initiator's
/// static), writes msg2. Returns the transport state AND the initiator's
/// authenticated static public key (N's identity) — the tunnel is bound to it,
/// and this is N's proof-of-possession.
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

    // IK pattern: -> e, es, s, ss | <- e, ee, se
    // 1. Read the initiator's first message (carries + authenticates its static).
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;
    let remote = hs.get_remote_static().ok_or(TransportError::BadHandshake)?;
    if remote.len() != 32 {
        return Err(TransportError::BadHandshake);
    }
    let mut remote_pk = [0u8; 32];
    remote_pk.copy_from_slice(remote);

    // 2. Write our response.
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;

    let transport = hs.into_transport_mode()?;
    Ok((transport, remote_pk))
}

/// Initiator side of a Noise **IK** handshake (RFC B3 rendezvous, N side).
/// `initiator_sk` is N's static key (authenticated to R); `responder_static_pk`
/// is R's pinned static key from the directory.
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

    // 1. -> e, es, s, ss
    let n = hs.write_message(&[], &mut tx)?;
    write_handshake_msg(send, &tx[..n]).await?;
    // 2. <- e, ee, se
    let n = read_handshake_msg(recv, &mut rx).await?;
    hs.read_message(&rx[..n], &mut scratch)?;

    let transport = hs.into_transport_mode()?;
    Ok(transport)
}

/// Serve one rendezvous-hosting QUERY (ALPN `gotham-rdvq/1`), **R side**. The
/// querier authenticates with **Noise-IK**, presenting its static key; R accepts
/// the query ONLY if that key equals the pinned authority PoP key
/// (`authority_pop_pk`). This closes the former unauthenticated presence oracle:
/// without the pin match — or if this relay has no pinned authority key at all —
/// R answers nothing (fail-closed), so an arbitrary party can no longer probe
/// which CGNAT relays are currently live. After auth, the authority sends a
/// 32-byte relay identity and R replies one byte: `1` if it currently holds a
/// live tunnel for that identity, `0` otherwise. R can only answer `1` for a
/// relay that actually completed a Noise-IK tunnel to it, so it cannot vouch for
/// a relay it does not genuinely host.
pub async fn serve_rendezvous_query(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    authority_pop_pk: Option<[u8; 32]>,
    table: crate::rendezvous::RendezvousTable,
) -> Result<(), TransportError> {
    // Fail-closed: no pinned authority ⇒ we never answer a presence query.
    let Some(expected) = authority_pop_pk else {
        return Err(TransportError::BadHandshake);
    };
    let (mut send, mut recv) = conn.accept_bi().await?;
    // IK responder: learn + authenticate the querier's static key.
    let (mut noise, querier_pk) =
        noise_ik_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    // Only the authority (holder of the PoP secret) may query. Both keys are
    // public, so a plain compare leaks nothing exploitable — reaching here
    // already required completing IK as *some* key.
    if querier_pk != expected {
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

/// Authority side: ask rendezvous relay R (pinned by `r_pk`) whether it hosts a
/// live tunnel for relay `n_pk`. Proves the CGNAT relay N is live + reachable via
/// R without dialing N. The authority authenticates to R with **Noise-IK** using
/// its stable PoP secret (`authority_pop_sk`), whose public half every relay
/// pins via `--authority-pop-key`; this is what lets R reject queries from anyone
/// but the authority. Bounded by `timeout`.
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
        // Nothing came back at all. Reporting that as a handshake failure names
        // the symptom this code saw, not the cause the operator has to fix.
        Err(_) => Err(TransportError::Unreachable(timeout)),
    }
}

/// Probe a relay for **liveness + proof-of-possession** in a single step.
///
/// The directory authority calls this before listing a self-enrolled relay.
/// It opens a QUIC connection to `addr` and runs the Noise-XK initiator
/// handshake, pinning `expected_pk` as the responder's static key. Noise XK
/// only completes if the responder performs the DH with the secret for
/// `expected_pk` — so a successful handshake proves at once that:
///
/// 1. something is reachable at `addr` (liveness), and
/// 2. it holds the X25519 secret for `expected_pk` (possession) — an attacker
///    cannot enroll a key it does not control, even with a valid enroll token.
///
/// `initiator_sk` is the authority's own (ephemeral) X25519 secret; the relay
/// responder accepts any initiator, so it need not be a registered key. The
/// entire probe is bounded by `timeout`.
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
        // The handshake completing IS the proof — we don't send any frames.
        let _ = noise_initiator_handshake(initiator_sk, expected_pk, &mut send, &mut recv).await?;
        conn.close(0u32.into(), b"probe ok");
        endpoint.wait_idle().await;
        Ok::<(), TransportError>(())
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        // Nothing came back at all. Reporting that as a handshake failure names
        // the symptom this code saw, not the cause the operator has to fix.
        Err(_) => Err(TransportError::Unreachable(timeout)),
    }
}

// ─── Noise-encrypted Gotham frame I/O ───────────────────────────────────────

/// Encrypt one Gotham packet and write the resulting `FRAME_LEN` bytes
/// to the stream.
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

/// Read one Noise-encrypted Gotham frame from the stream and return the
/// `PACKET_SIZE`-byte plaintext packet.
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

// ─── Mailbox control protocol (ALPN gotham-mbx/1) ──────────────────────────

/// Current unix time in seconds (the mailbox TTL clock). Saturates to 0 if the
/// system clock is before the epoch (never in practice).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write one chunked Noise message framed as `[u16 BE ciphertext-len][ct]`.
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

/// Read one chunked Noise message, appending its plaintext to `out`. Returns
/// the number of plaintext bytes appended.
async fn read_one_noise_msg(
    transport: &mut TransportState,
    recv: &mut RecvStream,
    out: &mut Vec<u8>,
) -> Result<usize, TransportError> {
    let mut len_bytes = [0u8; 2];
    recv.read_exact(&mut len_bytes).await?;
    let clen = u16::from_be_bytes(len_bytes) as usize;
    // A legitimate framed chunk always carries ≥1 plaintext byte: the 4-byte
    // length header, or a non-empty body chunk (write_noise_blob never emits an
    // empty chunk). REJECT a tag-only (0-plaintext) frame — otherwise it would
    // advance read_noise_blob's accumulator by 0 and let an unauthenticated
    // client pin the connection task in an infinite loop (DoS).
    if !((NOISE_TAG_LEN + 1)..=NOISE_CHUNK + NOISE_TAG_LEN).contains(&clen) {
        return Err(TransportError::BadHandshake);
    }
    let mut cbuf = vec![0u8; clen];
    recv.read_exact(&mut cbuf).await?;
    let start = out.len();
    out.resize(start + clen, 0); // ≥ plaintext length (clen − tag)
    let n = transport.read_message(&cbuf, &mut out[start..])?;
    out.truncate(start + n);
    Ok(n)
}

/// Send a variable-length blob over the Noise transport: a 4-byte length
/// header message followed by `NOISE_CHUNK`-sized body messages. Used for
/// mailbox control frames, which (unlike mixnet packets) are not fixed size.
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

/// Read a variable-length blob written by [`write_noise_blob`], enforcing the
/// [`MAX_MAILBOX_FRAME`] ceiling. Use [`read_noise_blob_capped`] for a tighter
/// per-protocol limit (the gossip path uses [`MAX_GOSSIP_FRAME`]).
pub async fn read_noise_blob(
    transport: &mut TransportState,
    recv: &mut RecvStream,
) -> Result<Vec<u8>, TransportError> {
    read_noise_blob_capped(transport, recv, MAX_MAILBOX_FRAME).await
}

/// Like [`read_noise_blob`] but rejects any frame larger than `max_frame`
/// before committing to its length — lets each protocol bound the buffer (and
/// downstream work) a peer can force.
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
        // Defence in depth: a chunk that made no forward progress (should be
        // impossible given the ≥1-plaintext-byte floor above) must not loop.
        if out.len() <= before || out.len() > total {
            return Err(TransportError::BadHandshake);
        }
    }
    Ok(out)
}

/// Bytes drained per `Fetch` response. Bounded so one response blob stays
/// modest; the client loops while the response's `more` flag is set.
const MAILBOX_FETCH_BUDGET: usize = 1024 * 1024;

/// Bytes drained per `FetchWithSurb` response. The SURB reply must fit ONE
/// mixnet packet (no chunking on the return path), so this is the one-packet
/// payload budget minus headroom for the MessagePack `Delivery` framing. The
/// `more` flag drives the client to fetch again for the remainder.
const SURB_FETCH_BUDGET: usize = crate::client::MAX_PAYLOAD_SIZE - 256;

/// Requests served on ONE mailbox control connection before it is closed.
///
/// The connection loop is driven entirely by the peer, and the peer is
/// unauthenticated (Noise XK authenticates the RELAY, not the client). Without
/// a cap, one connection is an unbounded work source: deposits are cheap for
/// the attacker and expensive for us. Draining a full mailbox needs
/// `max_msgs_per_mailbox` fetches at worst, so this leaves ample headroom for
/// a legitimate client while forcing a flooder to pay for a new QUIC + Noise
/// handshake every 512 requests.
const MAX_MAILBOX_REQUESTS_PER_CONN: usize = 512;

/// Operator escape hatch for the SEC-MBX-01 fetch possession proof.
///
/// Default `false` = fail-closed: a relay refuses any `Fetch` that cannot prove
/// it holds the recipient's secret key. Set it only while already-shipped
/// clients that predate the proof are still in the field; leaving it on lets
/// anyone holding a recipient's *public* key delete that user's offline
/// messages. A process-global rather than a parameter so the three public
/// `serve_endpoint*` signatures stay source-compatible for downstream users.
static ALLOW_UNAUTH_MAILBOX_FETCH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Enable/disable the SEC-MBX-01 escape hatch. See
/// [`ALLOW_UNAUTH_MAILBOX_FETCH`].
pub fn set_allow_unauthenticated_mailbox_fetch(yes: bool) {
    ALLOW_UNAUTH_MAILBOX_FETCH.store(yes, std::sync::atomic::Ordering::Relaxed);
}

/// Is the SEC-MBX-01 escape hatch currently enabled?
#[must_use]
pub fn allow_unauthenticated_mailbox_fetch() -> bool {
    ALLOW_UNAUTH_MAILBOX_FETCH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Serve one inbound mailbox-control connection (ALPN `gotham-mbx/1`).
///
/// After the Noise XK responder handshake, reads length-framed
/// [`MailboxRequest`]s and answers each with a [`MailboxResponse`], holding the
/// shared [`Mailbox`] only for the duration of one deposit/fetch. The relay
/// only ever handles opaque sealed bytes — it cannot read message content. The
/// loop ends when the client closes the stream, or after
/// [`MAX_MAILBOX_REQUESTS_PER_CONN`] requests.
///
/// A `Fetch` must carry a [`FetchAuth`] possession proof (SEC-MBX-01) unless
/// `allow_unauthenticated_fetch` is set — see the enforcement arm below for
/// what that flag re-opens.
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
            Ok(MailboxRequest::Fetch { id, auth }) => {
                // SEC-MBX-01. `fetch_batch` REMOVES what it returns, and the
                // mailbox address is `blake3(domain || recipient_pk)` over a
                // public key. Without a possession proof, anyone ever handed a
                // user's Gotham public key — every contact, anyone with an
                // invitation URI — can drain that user's offline messages:
                // silent, deniable, remote message deletion. Require proof that
                // the requester holds the recipient SECRET key.
                //
                // The tag is bound to this Noise session's handshake hash, so a
                // proof captured from one connection cannot be replayed on
                // another.
                match auth {
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
                        // Transition escape hatch (`--allow-unauthenticated-mailbox-fetch`).
                        // Loud on purpose: this re-opens remote message deletion
                        // for every user hosted here.
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
                }
            }
            // A SURB fetch only makes sense over the mixnet (its whole point is
            // to hide the fetcher's IP); on this DIRECT control path the host
            // already sees the client IP, so refuse it rather than pretend.
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

/// Serve one inbound directory-**gossip** connection (ALPN `gotham-dir/1`).
///
/// Push-pull anti-entropy: after the Noise handshake, the peer pushes its
/// roster, we merge it into the shared roster (each entry re-verified against
/// our pinned [`AuthoritySet`] via [`Roster::merge_admitted`] — an unadmitted or
/// forged entry is dropped), then we reply with our roster so the peer converges
/// too. The loop ends when the peer closes the stream.
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
        // Tight frame cap for gossip — far below the mailbox's 16 MiB.
        let blob = match read_noise_blob_capped(&mut noise, &mut recv, MAX_GOSSIP_FRAME).await {
            Ok(b) => b,
            Err(TransportError::Read(_)) | Err(TransportError::Io(_)) => break,
            Err(e) => return Err(e),
        };
        // Merge the peer's pushed roster. Verification (the expensive ed25519
        // work) runs OFF the lock and is bounded to MAX_GOSSIP_ENTRIES, so a
        // hostile peer pushing a junk-packed roster can't stall the subsystem
        // on the roster lock. A malformed blob is ignored — we still reply.
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
        // Reply with our roster so the peer converges too.
        let ours = { roster.lock().await.clone() };
        let bytes = rmp_serde::to_vec_named(&ours).map_err(|_| TransportError::BadHandshake)?;
        write_noise_blob(&mut noise, &mut send, &bytes).await?;
    }
    Ok(())
}

/// Extract the ALPN negotiated on `conn` (server side), if any. Used by the
/// accept loop to route a connection to the mixnet, mailbox, or gossip handler.
fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    let data = conn.handshake_data()?;
    let hd = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    hd.protocol
}

// ─── Server: serve one incoming connection ──────────────────────────────────

/// Handle one inbound QUIC connection: complete the Noise handshake then
/// process each frame the client sends, dispatching the resulting
/// [`ProcessOutcome`] (drop / forward / deliver-local).
///
/// Forwarding goes through the shared [`ConnectionPool`] — repeated
/// hops to the same next-hop reuse a single QUIC + Noise XK
/// connection, amortising the per-packet handshake cost.
///
/// `delivery` is invoked for every `DeliverLocal` outcome; pass `None`
/// to discard local-delivery packets (useful for pure-relay nodes that
/// never act as recipients).
pub async fn serve_connection(
    conn: quinn::Connection,
    static_sk: [u8; 32],
    relay: Arc<Mutex<Relay>>,
    pool: Arc<ConnectionPool>,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut noise = noise_responder_handshake(&static_sk, &mut send, &mut recv).await?;
    debug!("noise handshake completed for inbound conn");

    loop {
        let packet = match read_noise_frame(&mut noise, &mut recv).await {
            Ok(p) => p,
            Err(TransportError::Read(_)) | Err(TransportError::Io(_)) => break,
            Err(e) => return Err(e),
        };

        // Process under the lock — held only for the time of one
        // `relay.process()` call (≪ 1 ms typical).
        let outcome = {
            let mut r = relay.lock().await;
            // Each call needs a fresh RNG seed for the Poisson sample. We
            // use thread_rng so concurrent connections don't share state.
            let mut rng = rand::thread_rng();
            r.process(&mut rng, &packet)
        };

        match outcome {
            ProcessOutcome::Drop(reason) => {
                debug!(?reason, "dropped");
            }
            ProcessOutcome::DeliverLocal { delay, payload } => {
                // The Loopix hold MUST NOT be awaited inline. `delay` is
                // SENDER-chosen (process.rs honours `record.delay_micros`,
                // clamped only by MAX_HOP_DELAY), and nothing else is read from
                // this connection while we sleep. Because ConnectionPool
                // multiplexes every packet between a pair of relays onto ONE
                // QUIC + Noise connection, a single packet asking for the max
                // delay would head-of-line-block that entire link for every
                // other user's traffic on it. Spawn, exactly as the Forward arm
                // below already does.
                let delivery = delivery.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    debug!(payload_len = payload.len(), "delivered locally");
                    if let Some(handler) = &delivery {
                        // Handler runs synchronously on this worker — it should
                        // be a quick `send` to an mpsc channel or a Tauri event
                        // emission, NOT a blocking call.
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
                // Anonymity hard-rule: never log the next-hop address (routing
                // metadata = who talks to whom). Log only opaque outcomes.
                debug!("forward outcome");
                let pool = Arc::clone(&pool);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if via_rendezvous {
                        // RFC B3: the next hop is a CGNAT relay reachable only via
                        // OUR rendezvous tunnel. Push by identity; never dial the
                        // sentinel address. A missing tunnel = the hosted relay is
                        // offline → drop (we never fall back to dialing it).
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

/// Open a fresh QUIC connection to `addr`, complete a Noise XK handshake
/// against the peer's pinned `peer_pk`, send the packet, and close.
///
/// v0.1 opens one connection per forwarded packet — costly but correct.
/// v0.2 will introduce a connection pool keyed by `(addr, peer_pk)`.
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
    // Wait for the peer to acknowledge all stream data before letting
    // `conn` drop. Without this, dropping the Connection right after
    // write_all+finish races the CONNECTION_CLOSE frame against the
    // in-flight stream bytes and the peer may never see them.
    let _ = send.stopped().await;
    Ok(())
}

/// RFC B3, **N side**: run a CGNAT relay whose ONLY inbound path is its
/// rendezvous tunnel. A relay behind CGNAT cannot accept inbound QUIC, so it
/// does not run the normal listener; instead it dials its rendezvous relay R,
/// keeps the tunnel warm, and processes every packet R pushes to it — peeling
/// its Sphinx layer and forwarding onward over its OWN outbound (which NAT
/// permits). Runs until aborted.
pub async fn run_rendezvous_relay(
    r_addr: SocketAddr,
    r_pk: [u8; 32],
    my_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = build_client_endpoint()?;
    let pool = Arc::new(ConnectionPool::new(client, my_sk));
    let relay = Arc::new(Mutex::new(relay));
    let (tx, rx) = tokio::sync::mpsc::channel(crate::rendezvous::RENDEZVOUS_INBOUND_QUEUE);
    info!(r = %r_addr, "starting as a CGNAT (rendezvous-hosted) relay — inbound via R only");
    tokio::spawn(crate::rendezvous::run_rendezvous_client(
        r_addr, r_pk, my_sk, tx,
    ));
    run_rendezvous_inbound(rx, relay, pool, delivery).await;
    Ok(())
}

/// RFC B3, **N side**: drain packets pushed down our rendezvous tunnel(s) and
/// process each one exactly as if it had arrived on an inbound connection — peel
/// our Sphinx layer and forward it onward (or deliver locally). A CGNAT relay
/// spawns this alongside [`crate::rendezvous::run_rendezvous_client`], whose
/// sender feeds `inbound_rx`. Runs until the channel closes.
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

// ─── Public listener entrypoint ─────────────────────────────────────────────

/// Bind a QUIC server endpoint on `listen_addr`, then accept connections
/// forever, dispatching each to [`serve_connection`].
///
/// `delivery` is plumbed through to every `serve_connection` call —
/// pass `Some(handler)` to receive local-delivery payloads (typical
/// for hybrid relay+client nodes), or `None` for pure relays.
///
/// Returns only on fatal endpoint error (e.g. socket close).
pub async fn run_relay_listener(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    run_relay_listener_with_mailbox(listen_addr, static_sk, relay, delivery, None).await
}

/// Like [`run_relay_listener`], but additionally hosts a store-and-forward
/// [`Mailbox`] when `mailbox` is `Some`. Connections that negotiate the
/// mailbox ALPN (`gotham-mbx/1`) are routed to [`serve_mailbox_connection`];
/// everything else is handled as a mixnet packet stream exactly as before.
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

/// Like [`run_relay_listener_with_mailbox`], but also serves directory gossip
/// (`gotham-dir/1`) when `gossip` is `Some`. This is the entrypoint a full
/// relay node uses (mixnet + optional mailbox + optional gossip).
pub async fn run_relay_listener_with_services(
    listen_addr: SocketAddr,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
    gossip: Option<GossipService>,
    authority_pop_pk: Option<[u8; 32]>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server = build_server_endpoint(listen_addr)?;
    serve_endpoint_with_services(
        server,
        static_sk,
        relay,
        delivery,
        mailbox,
        gossip,
        authority_pop_pk,
    )
    .await
}

/// Run the accept loop against an already-built server `endpoint`. Use
/// this when the caller needs to learn the bound address (e.g. with
/// `listen_addr.port() == 0`) *before* spawning the listener as a
/// background task — `build_server_endpoint` + `endpoint.local_addr()` +
/// `serve_endpoint` avoids the rebind race that a port-0 retry would
/// otherwise introduce.
pub async fn serve_endpoint(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
) -> Result<(), TransportError> {
    serve_endpoint_with_services(endpoint, static_sk, relay, delivery, None, None, None).await
}

/// Like [`serve_endpoint`], but routes connections negotiating the mailbox
/// ALPN to [`serve_mailbox_connection`] when a [`Mailbox`] is provided.
pub async fn serve_endpoint_with_mailbox(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
) -> Result<(), TransportError> {
    serve_endpoint_with_services(endpoint, static_sk, relay, delivery, mailbox, None, None).await
}

/// A relay's directory-gossip state: the shared roster plus the pinned
/// [`AuthoritySet`] it verifies incoming admissions against. Pass `Some(..)` to
/// [`serve_endpoint_with_services`] to serve `gotham-dir/1` gossip.
#[derive(Clone)]
pub struct GossipService {
    /// The shared roster (also driven by the gossip node's outbound loop).
    pub roster: Arc<Mutex<Roster>>,
    /// The pinned authority set used to verify incoming admissions.
    pub authority_set: Arc<AuthoritySet>,
}

/// The full accept loop: dispatches each connection by negotiated ALPN to the
/// mixnet forwarder, the mailbox handler (if `mailbox` is `Some`), or the
/// directory-gossip handler (if `gossip` is `Some`).
pub async fn serve_endpoint_with_services(
    endpoint: Endpoint,
    static_sk: [u8; 32],
    relay: Relay,
    delivery: Option<DeliveryHandler>,
    mailbox: Option<Arc<Mutex<Mailbox>>>,
    gossip: Option<GossipService>,
    // The authority's PoP public key, pinned so only the authority can run the
    // `gotham-rdvq/1` presence query against us. `None` ⇒ we answer no query
    // (fail-closed), which is correct for a relay that never hosts rendezvous.
    authority_pop_pk: Option<[u8; 32]>,
) -> Result<(), TransportError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = build_client_endpoint()?;
    let relay = Arc::new(Mutex::new(relay));
    let pool = Arc::new(ConnectionPool::new(client, static_sk));
    let bound = endpoint.local_addr().ok();
    info!(
        ?bound,
        mailbox = mailbox.is_some(),
        gossip = gossip.is_some(),
        "gotham-relay QUIC listener accepting (pooled forwards)"
    );

    // Cap concurrent connection handlers so a burst of half-open / slow
    // handshakes can't exhaust tasks and memory. Each handler holds one permit
    // for its whole lifetime; at the cap we SHED new connections (fail-closed)
    // rather than queue them. Combined with HANDSHAKE_READ_TIMEOUT this bounds
    // in-flight handshake memory to MAX_INFLIGHT_CONNS × per-handshake buffers.
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
        tokio::spawn(async move {
            let _permit = permit; // released when this handler finishes
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
                        // RFC B3: a CGNAT relay opening its persistent reverse
                        // tunnel. Register it in the shared rendezvous table (held
                        // by the pool) so the forwarder can push packets to it.
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
                        // RFC B3: the authority asking whether we host a given
                        // CGNAT relay (liveness proof without dialing it).
                        Some(a) if a == RENDEZVOUS_QUERY_ALPN => {
                            if let Err(e) = serve_rendezvous_query(
                                conn,
                                sk,
                                authority_pop_pk,
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

// ─── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// A closed UDP port must be reported as unreachable, not as a protocol
    /// fault. This exact confusion cost an afternoon: the authority answered
    /// "malformed handshake message" for a relay whose provider firewall was
    /// dropping the packets, which points an operator at the wrong thing
    /// entirely. The message has to name the firewall.
    #[tokio::test]
    async fn an_unreachable_relay_says_so_instead_of_blaming_the_handshake() {
        // TEST-NET-1 (RFC 5737) — reserved for documentation, never routed, so
        // this cannot reach a real host or depend on the network.
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

    /// Build a 2-hop Gotham packet whose last hop is `last_relay_sk`.
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
        // LIONESS-wrap the payload for both hops (innermost first), mirroring
        // the real sender.
        for sub in sub_keys.iter().rev() {
            crypto_gotham::lioness::encrypt(&sub.k_payload, &mut packet[HEADER_LEN..]);
        }
        packet
    }

    /// Spawn a relay binding to an ephemeral port; return its actual bound
    /// address.
    async fn spawn_relay(sk: [u8; 32]) -> (SocketAddrV4, tokio::task::JoinHandle<()>) {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = build_server_endpoint(listen).unwrap();
        let bound = server.local_addr().unwrap();
        let client = build_client_endpoint().unwrap();
        let relay = Relay::new(
            sk,
            1000,
            std::time::Duration::from_secs(60),
            0, // no Poisson delay in tests
        );
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

        // Correct key + reachable → probe succeeds (liveness + possession).
        probe_relay_liveness(
            SocketAddr::V4(addr),
            &pk,
            &initiator,
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("probe should succeed against a live relay that holds the key");

        // Wrong key → handshake can't complete → probe fails. An attacker
        // cannot enroll a key it does not control.
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
        // Nothing listening here → probe fails (not live).
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

        // R (rendezvous host), the authority PoP key, and an impostor. Pubkeys are
        // derived the same way Noise clamps them, so they match the IK pin check.
        let mut r_sk = [0u8; 32];
        r.fill_bytes(&mut r_sk);
        let r_pk = PublicKey::from(&StaticSecret::from(r_sk)).to_bytes();
        let mut auth_sk = [0u8; 32];
        r.fill_bytes(&mut auth_sk);
        let auth_pk = PublicKey::from(&StaticSecret::from(auth_sk)).to_bytes();
        let mut imp_sk = [0u8; 32];
        r.fill_bytes(&mut imp_sk);
        let mut n_pk = [0u8; 32];
        r.fill_bytes(&mut n_pk); // a queried identity R does not host

        // R answers rdvq queries, pinning the authority key, with an empty table.
        let server = build_server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let bound = server.local_addr().unwrap();
        let serve_table = crate::rendezvous::RendezvousTable::new();
        let handle = tokio::spawn(async move {
            while let Some(connecting) = server.accept().await {
                let table = serve_table.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = connecting.await {
                        let _ = serve_rendezvous_query(conn, r_sk, Some(auth_pk), table).await;
                    }
                });
            }
        });

        // 1. The authority (correct PoP key) is served: n_pk isn't hosted → false.
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

        // 2. An impostor (any non-authority key) is rejected by the pin check.
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

    /// Spawn a relay with a delivery handler. Returns the bound address
    /// and a receiver for delivered payloads.
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

        // Build a 1-hop packet whose only hop is this relay (last hop).
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
        // Apply the (single) sender LIONESS layer so the last hop peels back to
        // `marker` on delivery.
        crypto_gotham::lioness::encrypt(&sub_keys[0].k_payload, &mut packet[HEADER_LEN..]);

        // Send it.
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

        // Wait for the delivery callback to fire.
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

        // Use clamped X25519 secret keys (snow validates this).
        let mut sk1 = [0u8; 32];
        let mut sk2 = [0u8; 32];
        r.fill_bytes(&mut sk1);
        r.fill_bytes(&mut sk2);
        for sk in [&mut sk1, &mut sk2] {
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
        }

        // Start relay 2 first (so we know its address before building
        // relay 1's routing record).
        let (addr2, _h2) = spawn_relay(sk2).await;
        let (addr1, _h1) = spawn_relay(sk1).await;

        // Build a packet routed: client → relay1 → relay2 (deliver-local).
        let packet = build_2hop_packet(&mut r, sk1, sk2, addr2);

        // Open a client connection to relay 1, do Noise XK, send.
        let client = build_client_endpoint().unwrap();
        let conn = client
            .connect(SocketAddr::V4(addr1), "gotham-relay.local")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        // The client's Noise XK identity isn't pinned (Gotham's anonymity
        // model) — we generate an ephemeral keypair just for the XK
        // handshake's `s, se` step.
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

        // Give the relays time to forward + deliver. (No assertion on the
        // payload because we don't have a hook for "deliver-local" yet in
        // v0.1; the test passes if no panic or error reaches us.)
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
                // Echo one frame back to the client.
                let packet = read_noise_frame(&mut noise, &mut recv).await.unwrap();
                write_noise_frame(&mut noise, &mut send, &packet)
                    .await
                    .unwrap();
                // Keep the stream open: do NOT call finish(). The client
                // signals completion by dropping the connection, which
                // we observe via `conn.closed().await`.
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

        // Send a packet of known shape.
        let mut packet = vec![0u8; PACKET_SIZE];
        for (i, b) in packet.iter_mut().enumerate() {
            *b = ((i * 31) % 256) as u8;
        }
        write_noise_frame(&mut noise, &mut send, &packet)
            .await
            .unwrap();

        // Read echo.
        let echoed = read_noise_frame(&mut noise, &mut recv).await.unwrap();
        assert_eq!(echoed, packet);

        // Drop the client side to let the server's `conn.closed()` await
        // resolve, then await the spawned task.
        drop(send);
        drop(recv);
        drop(conn);
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
    }
}
