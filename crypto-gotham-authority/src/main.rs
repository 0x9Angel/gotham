// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! `gotham-directory-authority` — the Level-1 automated directory service.
//!
//! Relays POST their [`RelayEnrollment`] to `/enroll` (and re-POST it as a
//! heartbeat); the authority keeps the live set in a [`Registry`], evicts
//! silent relays, and serves an authority-signed directory at `/directory`
//! that the Crypto app fetches and verifies. This removes the v0.1 manual
//! "email me your key, I hand-edit the directory" step.
//!
//! Anti-Sybil for the closed test:
//! - `/enroll` requires a bearer token (operator-issued to trusted volunteers)
//!   when `--enroll-token` is set;
//! - per-IP fixed-window rate limit on `/enroll`.

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

/// Hard cap on the per-IP rate-limit map. An attacker rotating source
/// addresses (trivial over IPv6) would otherwise grow it without bound. Once
/// exceeded we drop every entry from an expired 60 s window (they can no
/// longer affect the current window's budget), bounding memory to roughly the
/// number of distinct IPs seen within a single window.
const RATE_MAP_MAX: usize = 100_000;
/// Max concurrent outbound liveness probes (see `AppState::probe_limit`).
const MAX_INFLIGHT_PROBES: usize = 128;
/// How long a built `/admissions` payload is served from cache before it is
/// re-signed. `/admissions` signs one Ed25519 attestation per listed relay; a
/// short cache bounds that work to at most once per this window regardless of
/// GET rate, so the (unauthenticated) endpoint can't be a signing-amplifier DoS.
/// Ed25519 is deterministic and attestations are day-stable, so a few seconds of
/// staleness is harmless (relays heartbeat far slower).
const ADMISSIONS_CACHE_TTL_SECS: u64 = 5;
/// Same rationale as [`ADMISSIONS_CACHE_TTL_SECS`], for `GET /directory`.
const DIRECTORY_CACHE_TTL_SECS: u64 = 5;

/// Widest past age (seconds) for which the authority will still sign a relay's
/// proposed k-of-n admission epoch: two [`crypto_gotham::enroll::ATTEST_EPOCH_BUCKET_SECS`]
/// buckets (~2 days). A live relay refreshes its epoch daily and heartbeats well
/// within the 30 min staleness window, so its proposed epoch is always ≲ 1 day
/// old — inside this bound. Refusing older-or-future epochs stops a relay from
/// banking a pre-dated attestation that would only become "fresh" later.
const ATTEST_ACCEPT_PAST_SECS: u64 = 2 * crypto_gotham::enroll::ATTEST_EPOCH_BUCKET_SECS;

/// Whether the authority will attest a relay-proposed admission `epoch` at
/// `now`: not too far in the future (bounded by the app's freshness skew) and
/// not older than [`ATTEST_ACCEPT_PAST_SECS`].
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
    /// Ed25519 authority signing key — 32 raw bytes or 64 hex chars. The app
    /// pins the matching PUBLIC key, so keep this secret and stable.
    #[arg(long)]
    authority_key: PathBuf,

    /// Socket address to bind the HTTP service on.
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Bearer token required on `/enroll`. If empty, enrollment is OPEN
    /// (only acceptable behind a private network) — a warning is logged.
    #[arg(long, env = "GOTHAM_ENROLL_TOKEN", default_value = "")]
    enroll_token: String,

    /// How long each published directory is valid (seconds). Default 1 h —
    /// short, because relays heartbeat and the app refetches.
    #[arg(long, default_value_t = 3600)]
    valid_secs: u64,

    /// Max `/enroll` requests accepted per IP per 60 s window.
    #[arg(long, default_value_t = 30)]
    enroll_rate_per_min: u32,

    /// Skip the Noise-XK liveness/proof-of-possession probe (testing only).
    /// By default the authority connects back to each enrollee's advertised
    /// address and completes a Noise-XK handshake against the claimed key —
    /// proving reachability AND that the relay holds the X25519 secret — before
    /// listing it. Disable only on a trusted private network.
    #[arg(long, default_value_t = false)]
    skip_liveness_probe: bool,

    /// TRANSITION ONLY — also accept the legacy `(kem‖seq)`-only possession
    /// proof from relays that predate transcript binding.
    ///
    /// Enrollments arrive as JSON over plain HTTP, and the legacy proof does NOT
    /// cover `addr`, `tier`, `operator`, `country`, `mailbox` or
    /// `rendezvous_capable`. With this flag set, an on-path attacker can rewrite
    /// any of those in flight and this authority will sign the tampered
    /// descriptor into the directory every client trusts. Drop it as soon as the
    /// relays have updated.
    #[arg(long, default_value_t = false)]
    accept_legacy_pop: bool,

    /// Seconds to allow for the liveness probe before giving up.
    #[arg(long, default_value_t = 10)]
    probe_timeout_secs: u64,

    /// Optional: TURN server URL(s) to hand out to callers via `GET /turn`, e.g.
    /// `turns:relay.example:5349`. Repeat for several. Requires
    /// `--turn-secret-file`. Enables private (relay-only) calls without a
    /// third-party STUN/TURN.
    #[arg(long)]
    turn_url: Vec<String>,

    /// Optional: path to the coturn shared secret (the same value passed to
    /// coturn as `static-auth-secret`). When set together with `--turn-url`,
    /// `GET /turn` issues short-lived HMAC credentials. The secret NEVER leaves
    /// the server — clients only ever receive a per-request expiring credential.
    #[arg(long)]
    turn_secret_file: Option<PathBuf>,

    /// How long an issued TURN credential stays valid (seconds). Short by design
    /// — clients re-fetch per call.
    #[arg(long, default_value_t = 300)]
    turn_cred_ttl_secs: u64,

    /// Verbosity.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log: String,
}

/// Shared service state.
struct AppState {
    registry: Mutex<Registry>,
    authority: SigningKey,
    enroll_token: Option<String>,
    valid_secs: u64,
    rate_per_min: u32,
    /// `ip -> (window_start_unix, count_in_window)`.
    rate: Mutex<HashMap<IpAddr, (u64, u32)>>,
    /// Whether to run the Noise-XK liveness/PoP probe before listing a relay.
    require_liveness: bool,
    /// RFC B3 §4: the authority's STABLE X25519 PoP secret. A CGNAT relay proves
    /// key possession by a DH-MAC against its public half — no dial-back needed.
    pop_sk: [u8; 32],
    /// Accept the legacy `(kem‖seq)`-only possession proof in addition to the
    /// transcript-bound v2 proof. TRANSITION ONLY: the legacy proof survives an
    /// on-path rewrite of `addr` / `tier` / `operator` / `country` / `mailbox`,
    /// which we would then sign into the directory. Default `false`.
    accept_legacy_pop: bool,
    /// Ephemeral X25519 secret used as the probe's initiator identity.
    probe_sk: [u8; 32],
    /// Probe timeout.
    probe_timeout: std::time::Duration,
    /// Bounds concurrent outbound liveness probes. Each enroll can trigger one
    /// outbound QUIC dial to a caller-named address; without a cap a flood of
    /// enrollments (esp. from rotating source IPs) turns the authority into a
    /// reflection amplifier and pins its handler tasks. At the cap we shed the
    /// enroll (fail-closed) rather than dial.
    probe_limit: tokio::sync::Semaphore,
    /// Optional TURN issuance for private (relay-only) calls. `turn_urls` are the
    /// coturn endpoints handed to callers; `turn_secret` is the coturn
    /// `static-auth-secret` (server-side only) used to sign short-lived
    /// credentials; `turn_ttl` is how long each credential is valid.
    turn_urls: Vec<String>,
    turn_secret: Option<Vec<u8>>,
    turn_ttl: u64,
    /// Cached `(built_at_unix, serialized_json)` for `GET /admissions` — bounds
    /// per-request signing to once per [`ADMISSIONS_CACHE_TTL_SECS`].
    admissions_cache: Mutex<Option<(u64, std::sync::Arc<Vec<u8>>)>>,
    /// Cached `(built_at_unix, serialized_json)` for `GET /directory`, for the
    /// same reason as [`AppState::admissions_cache`]: the handler prunes the
    /// registry, projects every descriptor, sorts, applies diversity caps,
    /// serialises and Ed25519-SIGNS the whole roster — all while holding the
    /// registry mutex, and on an endpoint with no token check and no rate
    /// limit. Uncached, anyone on the internet could pin that mutex and the
    /// authority's CPU at will, taking `/enroll` heartbeats and `/turn` down
    /// with it — and the authority is a single point of failure for the whole
    /// network. `/admissions` beside it was already protected; this was not.
    directory_cache: Mutex<Option<(u64, std::sync::Arc<Vec<u8>>)>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time byte-equality (avoid leaking the token via timing).
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
    /// `true` if the request carries the configured bearer token (or no token
    /// is configured at all).
    fn token_ok(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.enroll_token.as_deref() else {
            return true; // open mode
        };
        let presented = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        ct_eq(presented.as_bytes(), expected.as_bytes())
    }

    /// Fixed-window per-IP rate limit. Returns `true` if the request is within
    /// budget (and counts it).
    fn rate_ok(&self, ip: IpAddr, now: u64) -> bool {
        let mut map = match self.rate.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        let window = now / 60;
        // Bound memory against IP rotation (esp. IPv6). First drop entries from
        // expired windows — the normal case, cheap, leaves only this window. If
        // the map is STILL at the cap after that, we are under an IP-rotation
        // flood WITHIN a single window (cross-window pruning can't help), so shed
        // genuinely-new IPs (fail-closed) rather than let the map grow into an
        // OOM. IPs already counted this window stay in the map and still pass, so
        // relays that already enrolled this minute are unaffected.
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

/// Serve the authority's PoP PUBLIC key (32-byte X25519, hex) so relays can
/// auto-provision it instead of being handed `--authority-pop-key` by hand. The
/// key is public by construction — it is only an input to relays' possession
/// proofs (the matching secret never leaves the authority), so serving it
/// openly weakens nothing: forging a proof still requires the relay's own key.
async fn pop(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(state.pop_sk));
    hex::encode(pk.to_bytes())
}

/// coturn `use-auth-secret` (TURN REST) credential:
/// `credential = base64(HMAC-SHA1(secret, username))`, where `username` is the
/// UNIX expiry timestamp. Only the holder of the shared secret can mint one, and
/// coturn independently re-checks the HMAC + expiry — so the secret never has to
/// leave the server and a leaked credential dies at `username`'s timestamp.
fn turn_credential(secret: &[u8], username: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = <Hmac<Sha1>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

/// Issue a short-lived TURN credential for a private (relay-only) call. Returns
/// 404 when TURN issuance isn't configured (the default), so callers can probe
/// it harmlessly. The response mirrors an `RTCIceServer`, so the app merges it
/// straight into its ICE list.
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
    // Rate-limit like /enroll. Every call mints a working coturn credential for
    // the operator's servers, bound to nothing but its expiry — so an
    // unthrottled endpoint is a free, refreshable relay for arbitrary
    // third-party traffic on the operator's bandwidth and under the operator's
    // abuse attribution. It cannot be authenticated without deanonymising
    // callers (there is no account to bind a credential to), so throttling per
    // source IP is the available control.
    if !state.rate_ok(peer.ip(), now_unix()) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let username = (now_unix() + state.turn_ttl).to_string();
    let credential = turn_credential(secret, &username);
    // One entry PER server (all share the ephemeral credential, since every
    // coturn runs the same static-auth-secret). The app can then pin the caller
    // and callee to DIFFERENT servers so no single TURN sees both real IPs, or
    // use them all for redundancy.
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
    // SIGN the response with the authority's Ed25519 key — the same key every
    // app pins for the directory.
    //
    // This endpoint is served over plain HTTP from a baked-in IP, and the app
    // feeds the result straight into its ICE configuration with
    // `call_relay_only = true` by default, i.e. it FORCES all call media
    // through whatever server this response names. An on-path attacker who
    // answered first therefore became the media relay for every call — seeing
    // both peers' IPs and the full timing of the conversation — with no
    // transport authentication to stop them. TLS is not available here (an IP
    // literal, no certificate), so authenticity comes from the signature
    // instead: the client verifies it against the key it already pins.
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

/// Canonical byte encoding signed by [`turn`] and verified by the app.
///
/// Domain-separated and length-prefixed so no other signature this authority
/// produces (directory, admission attestation) can be replayed as a TURN
/// response, and so `expires_at` cannot be shifted into the server list.
/// `expires_at` is inside the signature, which is what stops an attacker from
/// replaying a genuine but stale response indefinitely.
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

    // Validate shape and recover the advertised address before any network I/O.
    // `None` = an RFC B3 rendezvous-hosted (CGNAT) relay with no dialable addr.
    let addr = match payload.validate() {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("rejected: {e}")).into_response(),
    };

    // Liveness + proof-of-possession. This is what lets ANYONE run a relay
    // safely — a key the enrollee does not control can't pass. Done before
    // taking the registry lock (it is network I/O).
    if state.require_liveness {
        let n_pk: [u8; 32] = match hex::decode(&payload.kem_pubkey_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(p) => p,
            None => return (StatusCode::BAD_REQUEST, "rejected: bad kem_pubkey").into_response(),
        };

        // POSSESSION PROOF — MANDATORY for EVERY enrollment, direct or CGNAT.
        // The POST originator proves it holds the relay secret via a DH-MAC
        // (`pop_proof`) bound to (kem‖seq) against the authority's stable PoP
        // key. This is the ONLY thing that binds the enrollment to the key
        // owner. The liveness checks below (dial-back for direct relays,
        // R-query for CGNAT ones) only prove that SOMETHING answers at an
        // address — and both `addr` and `kem_pubkey_hex` are published verbatim
        // in the signed /directory, so an off-path attacker could name a
        // victim's real endpoint and pass the dial-back while overwriting the
        // victim's entry (seq-lockout DoS + tier/operator rewrite). Requiring
        // the DH-MAC first — which the attacker cannot forge without the relay
        // secret, and which is bound to `seq` so a captured proof can't be
        // replayed at a higher seq — closes that hijack for both branches.
        //
        // The proof is verified against the WHOLE enrollment transcript, not
        // just (kem‖seq). Enrollments arrive as JSON over plain HTTP, so an
        // on-path attacker can rewrite `addr`, `tier`, `operator`, `country`,
        // `mailbox` or `rendezvous_capable` in flight while leaving
        // `kem_pubkey_hex` / `seq` / `pop_proof` untouched — and we would then
        // Ed25519-SIGN the tampered descriptor, laundering the tampering into a
        // document every client trusts. Transcript binding is what stops that;
        // the liveness dial below cannot, since it only proves something at
        // `addr` speaks Noise-XK as this key (a plain UDP forwarder in front of
        // the real relay passes it) and says nothing about the other fields.
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

        // Bound concurrent outbound probes: acquire a permit for the duration of
        // whichever liveness dial runs below. Fail-closed at the cap so a burst
        // of enrollments can't fan out into unbounded outbound dials.
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
            // Directly-reachable relay: dial back and complete Noise-XK against
            // the claimed key. Possession is already proven above; this is a
            // LIVENESS/reachability check so we never advertise a dead endpoint.
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
            // RFC B3 §4 CGNAT relay: it cannot be dialed. Possession is already
            // proven by the mandatory DH-MAC above (a malicious rendezvous relay
            // cannot forge it). Here we only confirm LIVENESS by asking R whether
            // it currently hosts a tunnel for this relay (availability, not
            // possession).
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

    // Capture the k-of-n admission inputs before `enroll` moves the payload. The
    // relay proposes ONE `attest_epoch` (identical across every authority it
    // enrolls with) so their independent attestations sign the same message and
    // combine into one quorum certificate on the app side.
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
            // Sign the admission attestation OUTSIDE the registry lock. It's
            // issued only for a proposed epoch inside the acceptance window; a
            // legacy relay proposes none and gets a bare receipt (old clients
            // ignore the body entirely and only read the 2xx status).
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
        // Never echo the peer address back into logs/metadata.
        Err(e) => (StatusCode::BAD_REQUEST, format!("rejected: {e}")).into_response(),
    }
}

/// Serve THIS authority's k-of-n admission attestations for every live relay
/// that proposed an epoch — one signed `(identity, epoch, operator)` tuple each.
///
/// The authority stores no attestations: it recomputes them from the live
/// registry on demand, so a pruned relay disappears here too. Nothing served
/// here is trusted on its own — the app collects these across the pinned
/// authorities and admits a relay only once a quorum verifies against its pinned
/// [`AuthoritySet`](crypto_gotham_directory::AuthoritySet). A MITM can only strip
/// entries (censorship it could do at the network layer anyway), never forge one
/// (that needs the authorities' secret keys), so the response needs no signature
/// of its own.
async fn admissions(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let now = now_unix();
    // Serve a recently-built payload from cache if still fresh — this is what
    // bounds the signing work under a GET flood (see ADMISSIONS_CACHE_TTL_SECS).
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
    // Sign each tuple outside the lock. Skip any epoch outside the acceptance
    // window (belt-and-suspenders: live relays keep their epoch current). The
    // input set is already bounded to the diversity-capped roster by
    // `admission_inputs`, so this is O(capped relays) signs, then cached.
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

/// Serve a pre-serialized `/admissions` JSON body with the right content type.
fn admissions_response(bytes: &[u8]) -> axum::response::Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes.to_vec(),
    )
        .into_response()
}

async fn directory(State(state): State<std::sync::Arc<AppState>>) -> impl IntoResponse {
    let now = now_unix();
    // Serve from cache when fresh. Bounds the sign-and-serialise work to at most
    // once per DIRECTORY_CACHE_TTL_SECS regardless of request rate, so this
    // unauthenticated endpoint cannot be used as a signing amplifier against the
    // authority (or to hold its registry mutex). Relays heartbeat on the order
    // of minutes, so a few seconds of staleness is invisible.
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

/// Assemble the HTTP router over a shared [`AppState`]. Extracted so tests can
/// drive the real handlers (`/enroll`, `/admissions`, …) via `oneshot`.
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

/// Read an Ed25519 seed from `path`: 32 raw bytes or 64 hex chars.
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

    // Ephemeral X25519 secret for the probe's initiator role (X25519-clamped).
    let mut probe_sk = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut probe_sk);
    probe_sk[0] &= 248;
    probe_sk[31] &= 127;
    probe_sk[31] |= 64;

    if cli.skip_liveness_probe {
        warn!("liveness/proof-of-possession probe DISABLED — only acceptable on a trusted private network");
    }

    // RFC B3 §4: stable X25519 PoP key derived from the authority's signing
    // identity, so its public half is fixed across restarts. CGNAT relays pin it
    // (`--authority-pop-key`) and DH against it to prove key possession.
    let pop_sk = crypto_gotham::enroll::derive_authority_pop_sk(&authority.to_bytes());
    let pop_pubkey = hex::encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(pop_sk)).to_bytes(),
    );
    info!(
        pop_pubkey = %pop_pubkey,
        "RFC B3 rendezvous PoP pubkey — give this to CGNAT relays as --authority-pop-key"
    );

    // Optional TURN issuance for private (relay-only) calls. The shared secret
    // is the same string coturn is started with (`static-auth-secret`); it stays
    // server-side and is used only to sign short-lived credentials.
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

    // ConnectInfo gives handlers the peer IP for rate limiting.
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

    // RFC 2202 HMAC-SHA1 test case #2 — proves turn_credential is exactly
    // base64(HMAC-SHA1(secret, username)), the coturn `use-auth-secret` format.
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
    //! k-of-n end-to-end over the REAL axum handlers, with THREE simulated
    //! authorities driven via `oneshot` (no sockets). Proves the producer wire
    //! path: each authority attests on `/enroll` and serves it on `/admissions`,
    //! and the collected attestations form a quorum the pinned `AuthoritySet`
    //! verifies — exactly what the app's admission check consumes.

    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use crypto_gotham::directory::RelayTier;
    use crypto_gotham_directory::{AdmissionCert, Attestation, AuthoritySet};
    use tower::ServiceExt; // for `oneshot`

    fn test_state(authority: SigningKey) -> std::sync::Arc<AppState> {
        let pop_sk = crypto_gotham::enroll::derive_authority_pop_sk(&authority.to_bytes());
        std::sync::Arc::new(AppState {
            registry: Mutex::new(Registry::new()),
            authority,
            enroll_token: None,
            valid_secs: 3600,
            rate_per_min: 100_000,
            rate: Mutex::new(HashMap::new()),
            // Skip the dial-back probe + possession proof: this test targets the
            // ATTESTATION wire path (possession is covered by enroll.rs tests).
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
        // The relay proposes ONE epoch to every authority (identical message).
        let enrollment = RelayEnrollment::new(
            kem_hex.clone(),
            "203.0.113.7:443".into(),
            RelayTier::Mix,
            None,
            Some("acme".into()),
            1,
        )
        .with_attest_epoch(epoch);

        // Enroll with all three; collect each authority's attestation two ways:
        // from the /enroll receipt AND from /admissions (they must match).
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

        // A quorum (2 of 3) assembled from the SERVED attestations verifies.
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

        // The /enroll receipts carry the same attestations.
        assert_eq!(from_enroll, from_admissions);

        // Sub-quorum: a single authority's attestation is below threshold.
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
        // A relay that proposes no epoch (old client) still enrolls, but the
        // authority issues no attestation and serves none — the transition path.
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
        // A relay cannot bank a pre-dated attestation: an epoch far past the
        // acceptance window yields no attestation.
        let state = test_state(SigningKey::from_bytes(&[8u8; 32]));
        let enrollment = RelayEnrollment::new(
            hex::encode([0x25u8; 32]),
            "203.0.113.9:443".into(),
            RelayTier::Mix,
            None,
            None,
            1,
        )
        .with_attest_epoch(now_unix() + 10 * 86_400); // 10 days ahead
        let resp = post_enroll(state, &enrollment).await;
        assert!(
            resp.attestation.is_none(),
            "out-of-window epoch is declined"
        );
    }
}
