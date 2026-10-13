// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use ed25519_dalek::SigningKey;
use tracing::{info, warn};

use crypto_gotham::enroll::{Registry, RelayEnrollment};
use crypto_gotham_directory::{
    AdmissionCert, AdmissionEntry, EnrollResponse, ADMISSION_CLOCK_SKEW_SECS,
};

const RATE_MAP_MAX: usize = 100_000;
const MAX_INFLIGHT_PROBES: usize = 128;
const ADMISSIONS_CACHE_TTL_SECS: u64 = 5;
const DIRECTORY_CACHE_TTL_SECS: u64 = 5;

const ATTEST_ACCEPT_PAST_SECS: u64 = 2 * crypto_gotham::enroll::ATTEST_EPOCH_BUCKET_SECS;

fn epoch_acceptable(epoch: u64, now: u64) -> bool {
    epoch <= now.saturating_add(ADMISSION_CLOCK_SKEW_SECS)
        && epoch.saturating_add(ATTEST_ACCEPT_PAST_SECS) >= now
}

#[derive(Parser, Debug)]
#[command(
    name = "gotham-directory-authority",
    version,
    about = "Gotham directory authority (auto-enrollment + signed directory)"
)]
struct Cli {
    #[arg(
        help = "Ed25519 authority signing key — 32 raw bytes or 64 hex chars. The app pins the matching PUBLIC key, so keep this secret and stable",
        long
    )]
    authority_key: PathBuf,

    #[arg(
        help = "Socket address to bind the HTTP service on",
        long,
        default_value = "0.0.0.0:8443"
    )]
    listen: SocketAddr,

    #[arg(
        help = "Bearer token required on `/enroll`. If empty, enrollment is OPEN (only acceptable behind a private network) — a warning is logged",
        long,
        env = "GOTHAM_ENROLL_TOKEN",
        default_value = ""
    )]
    enroll_token: String,

    #[arg(
        help = "How long each published directory is valid (seconds). Default 1 h — short, because relays heartbeat and the app refetches",
        long,
        default_value_t = 3600
    )]
    valid_secs: u64,

    #[arg(
        help = "Max `/enroll` requests accepted per IP per 60 s window",
        long,
        default_value_t = 30
    )]
    enroll_rate_per_min: u32,

    #[arg(
        help = "Skip the Noise-XK liveness/proof-of-possession probe (testing only). By default the authority connects back to each enrollee's advertised address and completes a Noise-XK handshake against the claimed key — proving reachability AND that the relay holds the X25519 secret — before listing it. Disable only on a trusted private network",
        long,
        default_value_t = false
    )]
    skip_liveness_probe: bool,

    #[arg(
        help = "TRANSITION ONLY — also accept the legacy `(kem‖seq)`-only possession proof from relays that predate transcript binding",
        long,
        default_value_t = false
    )]
    accept_legacy_pop: bool,

    #[arg(
        help = "Seconds to allow for the liveness probe before giving up",
        long,
        default_value_t = 10
    )]
    probe_timeout_secs: u64,

    #[arg(
        help = "Optional: TURN server URL(s) to hand out to callers via `GET /turn`, e.g. `turns:relay.example:5349`. Repeat for several. Requires `--turn-secret-file`. Enables private (relay-only) calls without a third-party STUN/TURN",
        long
    )]
    turn_url: Vec<String>,

    #[arg(
        help = "Optional: path to the coturn shared secret (the same value passed to coturn as `static-auth-secret`). When set together with `--turn-url`, `GET /turn` issues short-lived HMAC credentials. The secret NEVER leaves the server — clients only ever receive a per-request expiring credential",
        long
    )]
    turn_secret_file: Option<PathBuf>,

    #[arg(
        help = "How long an issued TURN credential stays valid (seconds). Short by design — clients re-fetch per call",
        long,
        default_value_t = 300
    )]
    turn_cred_ttl_secs: u64,

    #[arg(help = "Verbosity", long, env = "RUST_LOG", default_value = "info")]
    log: String,
}

struct AppState {
    registry: Mutex<Registry>,
    authority: SigningKey,
    enroll_token: Option<String>,
    valid_secs: u64,
    rate_per_min: u32,
    rate: Mutex<HashMap<IpAddr, (u64, u32)>>,
    require_liveness: bool,
    pop_sk: [u8; 32],
    accept_legacy_pop: bool,
    probe_sk: [u8; 32],
    probe_timeout: std::time::Duration,
    probe_limit: tokio::sync::Semaphore,
    turn_urls: Vec<String>,
    turn_secret: Option<Vec<u8>>,
    turn_ttl: u64,
    admissions_cache: Mutex<Option<(u64, std::sync::Arc<Vec<u8>>)>>,
    directory_cache: Mutex<Option<(u64, std::sync::Arc<Vec<u8>>)>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl AppState {
    fn token_ok(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.enroll_token.as_deref() else {
            return true;
        };
        let presented = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        ct_eq(presented.as_bytes(), expected.as_bytes())
    }

    fn rate_ok(&self, ip: IpAddr, now: u64) -> bool {
        let mut map = match self.rate.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        let window = now / 60;
        if map.len() >= RATE_MAP_MAX {
            map.retain(|_, (w, _)| *w == window);
            if map.len() >= RATE_MAP_MAX && !map.contains_key(&ip) {
                return false;
            }
        }
        let entry = map.entry(ip).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.rate_per_min {
            return false;
        }
        entry.1 += 1;
        true
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn pop(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(state.pop_sk));
    hex::encode(pk.to_bytes())
}

fn turn_credential(secret: &[u8], username: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = <Hmac<Sha1>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

async fn turn(
    State(state): State<std::sync::Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let Some(secret) = state.turn_secret.as_deref() else {
        return (StatusCode::NOT_FOUND, "TURN issuance not configured").into_response();
    };
    if state.turn_urls.is_empty() {
        return (StatusCode::NOT_FOUND, "TURN issuance not configured").into_response();
    }
    if !state.rate_ok(peer.ip(), now_unix()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let username = (now_unix() + state.turn_ttl).to_string();
    let credential = turn_credential(secret, &username);
    let ice_servers: Vec<serde_json::Value> = state
        .turn_urls
        .iter()
        .map(|u| {
            serde_json::json!({
                "urls": [u],
                "username": username,
                "credential": credential,
            })
        })
        .collect();
    let expires_at = now_unix() + state.turn_ttl;
    let signed_bytes = turn_signed_bytes(&ice_servers, expires_at);
    let sig = {
        use ed25519_dalek::Signer as _;
        state.authority.sign(&signed_bytes)
    };
    Json(serde_json::json!({
        "ice_servers": ice_servers,
        "ttl": state.turn_ttl,
        "expires_at": expires_at,
        "sig": hex::encode(sig.to_bytes()),
    }))
    .into_response()
}

pub fn turn_signed_bytes(ice_servers: &[serde_json::Value], expires_at: u64) -> Vec<u8> {
    let body = serde_json::to_vec(ice_servers).unwrap_or_default();
    let mut out = Vec::with_capacity(body.len() + 40);
    out.extend_from_slice(b"gotham-turn-v1");
    out.extend_from_slice(&expires_at.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

async fn enroll(
    State(state): State<std::sync::Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RelayEnrollment>,
) -> impl IntoResponse {
    if !state.token_ok(&headers) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid enroll token").into_response();
    }
    if !state.rate_ok(peer.ip(), now_unix()) {
        return (StatusCode::TOO_MANY_REQUESTS, "enroll rate limit exceeded").into_response();
    }

    let addr = match payload.validate() {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("rejected: {e}")).into_response(),
    };

    if state.require_liveness {
        let n_pk: [u8; 32] = match hex::decode(&payload.kem_pubkey_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(p) => p,
            None => return (StatusCode::BAD_REQUEST, "rejected: bad kem_pubkey").into_response(),
        };

        let shared = x25519_dalek::StaticSecret::from(state.pop_sk)
            .diffie_hellman(&x25519_dalek::PublicKey::from(n_pk));
        let pop_ok = payload.verify_pop_v2(shared.as_bytes())
            || (state.accept_legacy_pop && payload.verify_pop(shared.as_bytes()));
        if !pop_ok {
            return (
                StatusCode::BAD_REQUEST,
                "rejected: missing or invalid possession proof (pop_proof)",
            )
                .into_response();
        }

        let _probe_permit = match state.probe_limit.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "probe capacity reached; retry shortly",
                )
                    .into_response()
            }
        };

        match addr {
            Some(sa) => {
                if let Err(e) = crypto_gotham_relay::transport::probe_relay_liveness(
                    sa,
                    &n_pk,
                    &state.probe_sk,
                    state.probe_timeout,
                )
                .await
                {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("liveness/proof-of-possession probe failed: {e}"),
                    )
                        .into_response();
                }
            }
            None => {
                let r_kem = payload.rendezvous.clone().unwrap_or_default();
                let r = {
                    let reg = match state.registry.lock() {
                        Ok(r) => r,
                        Err(p) => p.into_inner(),
                    };
                    reg.rendezvous_point(&r_kem)
                };
                let Some((r_addr, r_pk)) = r else {
                    return (
                        StatusCode::BAD_REQUEST,
                        "rejected: rendezvous relay not found or not rendezvous-capable",
                    )
                        .into_response();
                };
                match crypto_gotham_relay::transport::probe_rendezvous_hosting(
                    r_addr,
                    &r_pk,
                    &state.pop_sk,
                    &n_pk,
                    state.probe_timeout,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "rejected: rendezvous relay does not host this relay",
                        )
                            .into_response()
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("rendezvous liveness query failed: {e}"),
                        )
                            .into_response()
                    }
                }
            }
        }
    }

    let attest_epoch = payload.attest_epoch;
    let identity_hex = payload.kem_pubkey_hex.clone();
    let operator = payload.operator.clone();

    let enrolled = {
        let mut reg = match state.registry.lock() {
            Ok(r) => r,
            Err(p) => p.into_inner(),
        };
        reg.enroll(payload)
    };
    match enrolled {
        Ok(()) => {
            let now = now_unix();
            let (attestation, epoch) = match attest_epoch {
                Some(ep) if epoch_acceptable(ep, now) => (
                    Some(AdmissionCert::attest(
                        &state.authority,
                        &identity_hex,
                        ep,
                        operator.as_deref(),
                    )),
                    Some(ep),
                ),
                _ => (None, None),
            };
            Json(EnrollResponse { attestation, epoch }).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("rejected: {e}")).into_response(),
    }
}

async fn admissions(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let now = now_unix();
    if let Some((built, bytes)) = state
        .admissions_cache
        .lock()
        .ok()
        .and_then(|g| (*g).clone())
    {
        if now.saturating_sub(built) < ADMISSIONS_CACHE_TTL_SECS {
            return admissions_response(&bytes);
        }
    }

    let inputs = {
        let mut reg = match state.registry.lock() {
            Ok(r) => r,
            Err(p) => p.into_inner(),
        };
        reg.prune_at(now);
        reg.admission_inputs()
    };
    let entries: Vec<AdmissionEntry> = inputs
        .into_iter()
        .filter(|(_, epoch, _)| epoch_acceptable(*epoch, now))
        .map(|(identity_pk_hex, epoch, operator)| {
            let attestation = AdmissionCert::attest(
                &state.authority,
                &identity_pk_hex,
                epoch,
                operator.as_deref(),
            );
            AdmissionEntry {
                identity_pk_hex,
                epoch,
                operator,
                attestation,
            }
        })
        .collect();
    let bytes = std::sync::Arc::new(serde_json::to_vec(&entries).unwrap_or_default());
    if let Ok(mut g) = state.admissions_cache.lock() {
        *g = Some((now, bytes.clone()));
    }
    admissions_response(&bytes)
}

fn admissions_response(bytes: &[u8]) -> axum::response::Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes.to_vec(),
    )
        .into_response()
}

async fn directory(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let now = now_unix();
    if let Ok(g) = state.directory_cache.lock() {
        if let Some((built, body)) = g.as_ref() {
            if now.saturating_sub(*built) < DIRECTORY_CACHE_TTL_SECS {
                return (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body.as_ref().clone(),
                )
                    .into_response();
            }
        }
    }
    let signed = {
        let mut reg = match state.registry.lock() {
            Ok(r) => r,
            Err(p) => p.into_inner(),
        };
        let pruned = reg.prune_at(now);
        if pruned > 0 {
            info!(pruned, live = reg.len(), "pruned silent relays");
        }
        reg.build_signed(&state.authority, state.valid_secs)
    };
    let signed = match signed {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot build directory: {e}"),
            )
                .into_response()
        }
    };
    let body = match serde_json::to_vec(&signed) {
        Ok(b) => std::sync::Arc::new(b),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot serialize directory: {e}"),
            )
                .into_response()
        }
    };
    if let Ok(mut g) = state.directory_cache.lock() {
        *g = Some((now, std::sync::Arc::clone(&body)));
    }
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.as_ref().clone(),
    )
        .into_response()
}

fn build_router(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/pop", get(pop))
        .route("/turn", get(turn))
        .route("/enroll", post(enroll))
        .route("/directory", get(directory))
        .route("/admissions", get(admissions))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

fn read_ed25519_seed(path: &PathBuf) -> std::io::Result<[u8; 32]> {
    let raw = std::fs::read(path)?;
    let bytes: Vec<u8> = if raw
        .iter()
        .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
    {
        let s = std::str::from_utf8(&raw)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8 key"))?
            .trim();
        hex::decode(s).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad hex: {e}"))
        })?
    } else {
        raw
    };
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authority key must be 32 bytes (or 64 hex chars)",
        )
    })?;
    Ok(arr)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&cli.log))
        .with_target(false)
        .try_init();

    let seed = read_ed25519_seed(&cli.authority_key)?;
    let authority = SigningKey::from_bytes(&seed);
    let authority_pub = hex::encode(authority.verifying_key().to_bytes());

    let enroll_token = if cli.enroll_token.is_empty() {
        warn!("no --enroll-token set: /enroll is OPEN — only run this behind a private network");
        None
    } else {
        Some(cli.enroll_token.clone())
    };

    let mut probe_sk = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut probe_sk);
    probe_sk[0] &= 248;
    probe_sk[31] &= 127;
    probe_sk[31] |= 64;

    if cli.skip_liveness_probe {
        warn!("liveness/proof-of-possession probe DISABLED — only acceptable on a trusted private network");
    }

    let pop_sk = crypto_gotham::enroll::derive_authority_pop_sk(&authority.to_bytes());
    let pop_pubkey = hex::encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(pop_sk)).to_bytes(),
    );
    info!(
        pop_pubkey = %pop_pubkey,
        "RFC B3 rendezvous PoP pubkey — give this to CGNAT relays as --authority-pop-key"
    );

    let turn_secret: Option<Vec<u8>> = match &cli.turn_secret_file {
        Some(path) => {
            let s = std::fs::read_to_string(path)?.trim().to_string();
            (!s.is_empty()).then(|| s.into_bytes())
        }
        None => None,
    };
    match (turn_secret.is_some(), cli.turn_url.is_empty()) {
        (true, false) => info!(
            urls = ?cli.turn_url,
            ttl = cli.turn_cred_ttl_secs,
            "TURN issuance enabled — /turn hands out short-lived relay-only call credentials"
        ),
        (true, true) => warn!("--turn-secret-file set but no --turn-url — /turn stays disabled"),
        (false, false) => warn!("--turn-url set but no --turn-secret-file — /turn stays disabled"),
        (false, true) => {}
    }

    let state = std::sync::Arc::new(AppState {
        registry: Mutex::new(Registry::new()),
        authority,
        enroll_token,
        valid_secs: cli.valid_secs,
        rate_per_min: cli.enroll_rate_per_min,
        rate: Mutex::new(HashMap::new()),
        require_liveness: !cli.skip_liveness_probe,
        accept_legacy_pop: cli.accept_legacy_pop,
        pop_sk,
        probe_sk,
        probe_timeout: std::time::Duration::from_secs(cli.probe_timeout_secs.max(1)),
        probe_limit: tokio::sync::Semaphore::new(MAX_INFLIGHT_PROBES),
        turn_urls: cli.turn_url.clone(),
        turn_secret,
        turn_ttl: cli.turn_cred_ttl_secs.max(60),
        admissions_cache: Mutex::new(None),
        directory_cache: Mutex::new(None),
    });

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    info!(
        listen = %cli.listen,
        authority_pubkey = %authority_pub,
        valid_secs = cli.valid_secs,
        "gotham directory authority started — pin this authority pubkey in the app"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod turn_tests {
    use super::turn_credential;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn credential_matches_rfc2202_hmac_sha1_vector() {
        let expected =
            STANDARD.encode(hex::decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap());
        assert_eq!(
            turn_credential(b"Jefe", "what do ya want for nothing?"),
            expected
        );
    }

    #[test]
    fn credential_is_deterministic_and_username_bound() {
        let secret = b"shared-coturn-secret";
        let a = turn_credential(secret, "1893456000");
        assert_eq!(a, turn_credential(secret, "1893456000"), "deterministic");
        assert_ne!(a, turn_credential(secret, "1893456001"), "binds the expiry");
        assert_ne!(
            a,
            turn_credential(b"other-secret", "1893456000"),
            "binds the secret"
        );
    }
}

#[cfg(test)]
mod kofn_tests {

    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use crypto_gotham::directory::RelayTier;
    use crypto_gotham_directory::{AdmissionCert, Attestation, AuthoritySet};
    use tower::ServiceExt;

    fn test_state(authority: SigningKey) -> std::sync::Arc<AppState> {
        let pop_sk = crypto_gotham::enroll::derive_authority_pop_sk(&authority.to_bytes());
        std::sync::Arc::new(AppState {
            registry: Mutex::new(Registry::new()),
            authority,
            enroll_token: None,
            valid_secs: 3600,
            rate_per_min: 100_000,
            rate: Mutex::new(HashMap::new()),
            require_liveness: false,
            accept_legacy_pop: false,
            pop_sk,
            probe_sk: [0u8; 32],
            probe_timeout: std::time::Duration::from_secs(1),
            probe_limit: tokio::sync::Semaphore::new(8),
            turn_urls: vec![],
            turn_secret: None,
            turn_ttl: 300,
            admissions_cache: Mutex::new(None),
            directory_cache: Mutex::new(None),
        })
    }

    async fn body_of(resp: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    async fn post_enroll(state: std::sync::Arc<AppState>, e: &RelayEnrollment) -> EnrollResponse {
        let req = Request::builder()
            .method("POST")
            .uri("/enroll")
            .header("content-type", "application/json")
            .extension(ConnectInfo("127.0.0.1:5555".parse::<SocketAddr>().unwrap()))
            .body(Body::from(serde_json::to_vec(e).unwrap()))
            .unwrap();
        let resp = build_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "enroll should succeed");
        serde_json::from_slice(&body_of(resp).await).unwrap()
    }

    async fn get_admissions(state: std::sync::Arc<AppState>) -> Vec<AdmissionEntry> {
        let req = Request::builder()
            .uri("/admissions")
            .body(Body::empty())
            .unwrap();
        let resp = build_router(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice(&body_of(resp).await).unwrap()
    }

    #[tokio::test]
    async fn three_authorities_attest_and_a_quorum_verifies() {
        let auths: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
            .collect();
        let vks: Vec<_> = auths.iter().map(|a| a.verifying_key()).collect();
        let set = AuthoritySet::new(&vks, 2).unwrap();

        let kem_hex = hex::encode([0x42u8; 32]);
        let epoch = crypto_gotham::enroll::current_attest_epoch(now_unix());
        let enrollment = RelayEnrollment::new(
            kem_hex.clone(),
            "203.0.113.7:443".into(),
            RelayTier::Mix,
            None,
            Some("acme".into()),
            1,
        )
        .with_attest_epoch(epoch);

        let mut from_enroll: Vec<Attestation> = Vec::new();
        let mut from_admissions: Vec<Attestation> = Vec::new();
        for a in &auths {
            let state = test_state(a.clone());
            let resp = post_enroll(state.clone(), &enrollment).await;
            let att = resp
                .attestation
                .expect("authority must attest a proposed epoch");
            assert_eq!(resp.epoch, Some(epoch));
            from_enroll.push(att);

            let adm = get_admissions(state).await;
            assert_eq!(adm.len(), 1, "the live relay is served at /admissions");
            assert_eq!(adm[0].identity_pk_hex, kem_hex);
            assert_eq!(adm[0].epoch, epoch);
            from_admissions.push(adm[0].attestation.clone());
        }

        let cert = AdmissionCert::assemble(
            kem_hex.clone(),
            epoch,
            Some("acme".into()),
            from_admissions.clone(),
        );
        assert!(cert.is_fresh(now_unix()));
        assert_eq!(
            cert.verify(&set).unwrap(),
            3,
            "all three distinct authorities count"
        );

        assert_eq!(from_enroll, from_admissions);

        let one = AdmissionCert::assemble(
            kem_hex.clone(),
            epoch,
            Some("acme".into()),
            vec![from_admissions[0].clone()],
        );
        assert!(
            one.verify(&set).is_err(),
            "1 of 3 must not meet a 2-of-3 quorum"
        );
    }

    #[tokio::test]
    async fn legacy_enrollment_without_epoch_gets_no_attestation() {
        let state = test_state(SigningKey::from_bytes(&[7u8; 32]));
        let enrollment = RelayEnrollment::new(
            hex::encode([0x24u8; 32]),
            "203.0.113.8:443".into(),
            RelayTier::Mix,
            None,
            None,
            1,
        );
        let resp = post_enroll(state.clone(), &enrollment).await;
        assert!(
            resp.attestation.is_none(),
            "no epoch proposed → no attestation"
        );
        assert!(
            get_admissions(state).await.is_empty(),
            "and nothing to serve"
        );
    }

    #[tokio::test]
    async fn a_far_future_epoch_is_not_attested() {
        let state = test_state(SigningKey::from_bytes(&[8u8; 32]));
        let enrollment = RelayEnrollment::new(
            hex::encode([0x25u8; 32]),
            "203.0.113.9:443".into(),
            RelayTier::Mix,
            None,
            None,
            1,
        )
        .with_attest_epoch(now_unix() + 10 * 86_400);
        let resp = post_enroll(state, &enrollment).await;
        assert!(
            resp.attestation.is_none(),
            "out-of-window epoch is declined"
        );
    }
}
