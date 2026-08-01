// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! `gotham-relay` — standalone Gotham mixnet relay daemon.
//!
//! v0.1 status: configuration + key management + relay loop scaffold.
//! Transport layer (QUIC + Noise XK) lands in P2.next — until then the
//! relay binary boots, exposes its public key, and stays idle.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use crypto_gotham::mailbox::{Mailbox, MailboxPolicy, MailboxSnapshot};
use rand::{rngs::OsRng, RngCore};
use tokio::sync::Mutex;
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crypto_gotham::directory::{DirectoryDoc, RelayDescriptor, RelayTier, SignedDirectory};
use crypto_gotham_relay::Relay;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

/// UPnP port-mapping lease TTL (seconds); renewed at half-life.
const UPNP_LEASE_SECS: u32 = 3600;

/// Resolve on the first OS shutdown signal.
///
/// On Unix this covers both Ctrl-C (`SIGINT`) and `SIGTERM` — the latter is
/// what `systemd stop`, launchd, and Windows-service shims send — so a
/// service-manager stop unwinds cleanly (the final mailbox snapshot is
/// persisted) instead of being hard-killed. On non-Unix it awaits Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                warn!(error = %e, "cannot install SIGTERM handler; Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[derive(Parser, Debug)]
#[command(name = "gotham-relay", version, about = "Gotham mixnet relay")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Verbosity (set `RUST_LOG=info|debug|trace`).
    #[arg(long, env = "RUST_LOG", default_value = "info", global = true)]
    log: String,
}

#[derive(Subcommand, Debug)]
// The `Run` variant carries all the daemon flags, so it dwarfs `Keygen`/`Pubkey`.
// This enum is parsed once at startup and never stored in bulk, so boxing the
// large variant would only add indirection for no real benefit.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Generate a fresh X25519 identity keypair and write it to `--key-file`.
    Keygen {
        /// Destination path. Aborts if file already exists.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Print the public key associated with `--key-file` (hex).
    Pubkey {
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Say whether this relay is actually carrying traffic, in plain language.
    ///
    /// A volunteer who runs the installer gets a binary that starts, a service
    /// that reports "active", and no way whatsoever to tell that the network is
    /// ignoring them. Enrolling with one authority is not enough (clients need
    /// a quorum), an unlabelled relay is never selected, and a relay whose UDP
    /// port is filtered by the provider looks healthy from the inside. All of
    /// those produce a relay that runs and carries nothing.
    Doctor {
        /// Path to the X25519 identity secret key.
        #[arg(long)]
        key_file: PathBuf,

        /// Directory authorities to ask. Repeat the flag; defaults to the
        /// three that ship with the app.
        #[arg(long)]
        authority_url: Vec<String>,

        /// How many authorities must list us for clients to accept the relay.
        #[arg(long, default_value_t = 2)]
        quorum: usize,
    },
    /// Run the relay daemon.
    Run {
        /// Path to the X25519 identity secret key.
        #[arg(long)]
        key_file: PathBuf,

        /// UDP/QUIC listen port (will become the QUIC port in P2.next).
        #[arg(long, default_value_t = 443)]
        listen_port: u16,

        /// Interface to bind, as a numeric IP. Default `::` = all
        /// interfaces (dual-stack, reachable from other machines). Pin to a
        /// specific LAN/public IP to restrict the NIC. Hostnames are NOT
        /// resolved — the routing layer addresses relays by IP. The address
        /// you ADVERTISE in the signed directory must be reachable by peers
        /// (a public IP or port-forwarded NAT mapping), which may differ
        /// from the bind interface.
        #[arg(long, default_value = "::")]
        listen_host: String,

        /// Mean Poisson delay in microseconds.
        #[arg(long, default_value_t = 20_000)]
        delay_micros: u64,

        /// Max entries in the replay cache.
        #[arg(long, default_value_t = 1_000_000)]
        replay_size: usize,

        /// TTL of replay cache entries, seconds.
        #[arg(long, default_value_t = 300)]
        replay_ttl_secs: u64,

        /// Max inbound packets/sec before shedding (token bucket, burst =
        /// 2×). Protects CPU and connection from a flood. `0` = unlimited.
        /// Default 2000 pps (~4 MB/s) is far above any realistic per-relay
        /// load yet caps egregious abuse.
        #[arg(long, default_value_t = 2000.0)]
        max_pps: f64,

        /// Rolling 24 h wire-byte budget before shedding. The real guard
        /// for metered/capped links (mobile, Freebox data plans). `0` =
        /// unlimited (default). Example: `--max-bytes-per-day 5000000000`
        /// caps the relay at ~5 GB/day.
        #[arg(long, default_value_t = 0)]
        max_bytes_per_day: u64,

        /// Directory authority base URL (e.g. `https://dir.example.org`). When
        /// set, the relay auto-enrolls and heartbeats so the network forms
        /// itself — no manual directory editing. Requires `--advertise-addr`.
        #[arg(long)]
        authority_url: Option<String>,

        /// k-of-n admission: ADDITIONAL directory authority base URLs to also
        /// enroll with (repeat the flag). The relay sends every authority the
        /// same enrollment so their independent attestations combine into one
        /// quorum certificate — a consuming app admits this relay only once `k`
        /// distinct authorities have vouched for it. Each authority's PoP key is
        /// auto-fetched from its own `/pop`. No effect without `--authority-url`.
        #[arg(long)]
        extra_authority_url: Vec<String>,

        /// Public `ip:port` peers should reach this relay on (e.g.
        /// `203.0.113.7:443`). May differ from `--listen-host` under
        /// NAT/port-forward. When `--authority-url` is set and this is omitted,
        /// the relay tries UPnP-IGD auto-configuration (see `--no-upnp`).
        #[arg(long)]
        advertise_addr: Option<String>,

        /// Disable automatic UPnP-IGD NAT port-mapping. By default, when
        /// `--authority-url` is set but `--advertise-addr` is omitted, the relay
        /// asks the local router (UPnP) to open its UDP port and auto-detects
        /// the public address — so a volunteer behind a home NAT needs no manual
        /// port-forward. Pass this on hosts with a public IP or a manual mapping.
        #[arg(long, default_value_t = false)]
        no_upnp: bool,

        /// RFC B3: run as a CGNAT relay reachable ONLY via a rendezvous relay R.
        /// Value is R's X25519 key (64-hex). Requires `--rendezvous-addr`. The
        /// relay dials R, keeps a persistent reverse tunnel, and enrolls with no
        /// dialable address (the authority proves liveness by asking R). Use this
        /// when you have no public IP / cannot port-forward (mobile, Freebox with
        /// broken UPnP, double-NAT). Mutually exclusive with `--rendezvous-capable`.
        #[arg(long)]
        rendezvous_key: Option<String>,

        /// RFC B3: `ip:port` of the rendezvous relay R to dial (with `--rendezvous-key`).
        #[arg(long)]
        rendezvous_addr: Option<String>,

        /// RFC B3: advertise that this directly-reachable relay is willing to
        /// serve as a rendezvous point for CGNAT relays.
        #[arg(long, default_value_t = false)]
        rendezvous_capable: bool,

        /// RFC B3 §4: the directory authority's X25519 PoP public key (64-hex),
        /// used to compute the DH-MAC possession proof for a CGNAT (rendezvous)
        /// enrollment. The authority prints this at startup. Required with
        /// `--rendezvous-key`.
        #[arg(long)]
        authority_pop_key: Option<String>,

        /// Bearer token for the authority's `/enroll` (closed test). Also read
        /// from `GOTHAM_ENROLL_TOKEN`.
        #[arg(long, env = "GOTHAM_ENROLL_TOKEN")]
        enroll_token: Option<String>,

        /// Tier to advertise: `entry|mix|exit`. Default `mix` (a middle hop
        /// sees neither the client nor the recipient — safest for volunteers).
        #[arg(long, default_value = "mix")]
        tier: String,

        /// Optional ISO 3166-1 country code to publish (e.g. `FR`).
        #[arg(long)]
        country: Option<String>,

        /// Optional operator nickname to publish (transparency only).
        #[arg(long)]
        operator: Option<String>,

        /// Seconds between enrollment heartbeats.
        #[arg(long, default_value_t = 300)]
        heartbeat_secs: u64,

        /// Host a store-and-forward mailbox so messages to offline peers
        /// survive until they reconnect (the always-on relays run with this).
        /// Clients discover mailbox hosts via the directory `mailbox` flag.
        #[arg(long, default_value_t = false)]
        mailbox: bool,

        /// Persist the mailbox store to this path (MessagePack snapshot) so it
        /// survives a relay restart. Only used with `--mailbox`; if unset the
        /// mailbox is memory-only (messages are lost on restart).
        #[arg(long)]
        mailbox_store: Option<PathBuf>,

        /// TRANSITION ONLY — serve mailbox fetches that carry no possession
        /// proof (SEC-MBX-01).
        ///
        /// A fetch REMOVES the messages it returns, and a mailbox address is
        /// just `blake3(domain || recipient_pubkey)` over a PUBLIC key. With
        /// this flag set, anyone ever handed a user's Gotham public key — every
        /// contact, anyone holding an invitation URI — can silently delete that
        /// user's offline messages. Set it only while clients that predate the
        /// proof are still in the field, and drop it as soon as they update.
        #[arg(long, default_value_t = false)]
        allow_unauthenticated_mailbox_fetch: bool,

        /// Enable peer-to-peer directory gossip (serves `gotham-dir/1` and runs
        /// anti-entropy). Requires `--advert-key`, `--admission-cert`,
        /// `--authority-set`, and `--advertise-addr`.
        #[arg(long, default_value_t = false)]
        gossip: bool,

        /// Ed25519 advertisement signing key (the relay's gossip identity),
        /// 64-hex or 32-byte raw. Distinct from the X25519 `--key-file`.
        #[arg(long)]
        advert_key: Option<PathBuf>,

        /// JSON `AdmissionCert` issued by the k-of-n authorities for this relay.
        #[arg(long)]
        admission_cert: Option<PathBuf>,

        /// JSON `AuthoritySet` to pin (the k-of-n directory authorities).
        #[arg(long)]
        authority_set: Option<PathBuf>,

        /// Bootstrap gossip peer as `ip:port@<x25519-kem-pubkey-hex>`
        /// (repeatable). Lets a fresh node join before its roster is populated.
        #[arg(long = "gossip-seed")]
        gossip_seeds: Vec<String>,

        /// Capabilities to advertise over gossip: `entry|mix|exit|all`.
        /// Defaults to `all`.
        #[arg(long, default_value = "all")]
        gossip_caps: String,

        /// Seconds between gossip rounds.
        #[arg(long, default_value_t = 60)]
        gossip_interval_secs: u64,
    },
    /// Sign a directory document (Ed25519) from a JSON list of relays.
    /// Used by `infra/scripts/sign-directory.sh` to produce a
    /// `gotham-bootstrap.json` that each Crypto app instance trusts.
    SignDirectory {
        /// Ed25519 signing key (X25519 secret key reinterpreted as
        /// Ed25519 seed). Generate with `keygen`.
        #[arg(long)]
        authority_key: PathBuf,
        /// Input JSON: a list of `{ node_id_hex, addr, capabilities }`
        /// objects (one per relay).
        #[arg(long)]
        relays: PathBuf,
        /// Output path for the signed directory JSON.
        #[arg(long)]
        output: PathBuf,
        /// How long the directory is valid (seconds). Default: 30 days.
        #[arg(long, default_value_t = 2_592_000)]
        valid_secs: u64,
    },
}

/// Build the relay's listen [`SocketAddr`] from a numeric host + port.
/// Accepts IPv4 or IPv6 literals; `::` binds all interfaces (dual-stack).
/// Hostnames are deliberately NOT resolved — the Sphinx routing record
/// addresses the next hop by raw IPv4 octets, so relays are pinned by IP.
fn parse_listen_addr(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let ip: IpAddr = host.trim().parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("--listen-host must be a numeric IP (v4/v6), got `{host}`"),
        )
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn init_logging(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .try_init();
}

fn read_key_file(path: &PathBuf) -> std::io::Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad hex: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "secret key file must be 64 hex chars (32 bytes)",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn write_key_file(path: &PathBuf, sk: &[u8; 32]) -> std::io::Result<()> {
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "key file already exists — refusing to overwrite",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // On Unix, lock the secret key to owner-only (0600) at creation time.
    // On Windows the file inherits the directory ACL — operators must keep
    // it on a non-shared profile (documented in docs/gotham/README.md).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write;
    let hex = hex::encode(sk);
    f.write_all(hex.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

/// Current unix time in seconds (mailbox TTL clock).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load a mailbox from a snapshot file, dropping entries already expired.
/// Returns a fresh default mailbox if the path is unset, missing, or corrupt
/// (corruption must never take the relay down — it just starts empty).
fn load_mailbox(path: Option<&PathBuf>) -> Mailbox {
    let Some(path) = path else {
        return Mailbox::with_defaults();
    };
    match std::fs::read(path) {
        Ok(bytes) => match rmp_serde::from_slice::<MailboxSnapshot>(&bytes) {
            Ok(snap) => {
                let m = Mailbox::from_snapshot(MailboxPolicy::default(), snap, now_unix());
                info!(pending = m.total(), "loaded mailbox snapshot from disk");
                m
            }
            Err(e) => {
                warn!(error = %e, "mailbox snapshot corrupt — starting empty");
                Mailbox::with_defaults()
            }
        },
        Err(_) => Mailbox::with_defaults(),
    }
}

/// Atomically persist a mailbox snapshot to `path` (temp file + rename).
fn persist_mailbox(path: &PathBuf, snap: &MailboxSnapshot) -> std::io::Result<()> {
    let bytes = rmp_serde::to_vec_named(snap).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("serialize mailbox snapshot: {e}"),
        )
    })?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Background task: every 5 minutes prune expired mailbox entries and (if a
/// store path is configured) persist a fresh snapshot.
fn spawn_mailbox_maintenance(handle: Arc<Mutex<Mailbox>>, store_path: Option<PathBuf>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            let snap = {
                let mut mb = handle.lock().await;
                let removed = mb.prune_expired(now_unix());
                if removed > 0 {
                    info!(removed, "mailbox: pruned expired entries");
                }
                store_path.as_ref().map(|_| mb.snapshot())
            };
            if let (Some(snap), Some(path)) = (snap, store_path.as_ref()) {
                if let Err(e) = persist_mailbox(path, &snap) {
                    warn!(error = %e, "mailbox: periodic snapshot failed");
                }
            }
        }
    });
}

/// A short helper for `InvalidInput` config errors.
fn io_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

/// Build the directory-gossip service (and spawn its outbound loop) when
/// `--gossip` is set, returning the [`GossipService`] the listener serves.
/// Returns `Ok(None)` when gossip is disabled. All missing/malformed inputs are
/// surfaced as clear `InvalidInput` errors — a misconfigured gossip flag must
/// fail loudly, not silently degrade.
#[allow(clippy::too_many_arguments)]
fn build_gossip(
    enabled: bool,
    x25519_sk: [u8; 32],
    kem_pubkey_hex: String,
    advertise_addr: Option<String>,
    advert_key: Option<PathBuf>,
    admission_cert: Option<PathBuf>,
    authority_set: Option<PathBuf>,
    gossip_seeds: Vec<String>,
    gossip_caps: &str,
    interval_secs: u64,
) -> std::io::Result<Option<crypto_gotham_relay::GossipService>> {
    if !enabled {
        return Ok(None);
    }
    use crypto_gotham_directory::{AdmissionCert, AuthoritySet, Capabilities, Roster};

    let advertise =
        advertise_addr.ok_or_else(|| io_err("--advertise-addr is required with --gossip"))?;
    let advert_key = advert_key.ok_or_else(|| io_err("--advert-key is required with --gossip"))?;
    let cert_path =
        admission_cert.ok_or_else(|| io_err("--admission-cert is required with --gossip"))?;
    let set_path =
        authority_set.ok_or_else(|| io_err("--authority-set is required with --gossip"))?;

    let identity = SigningKey::from_bytes(&read_ed25519_seed(&advert_key)?);
    let set: AuthoritySet = serde_json::from_slice(&std::fs::read(&set_path)?)
        .map_err(|e| io_err(format!("authority-set JSON: {e}")))?;
    let admission: AdmissionCert = serde_json::from_slice(&std::fs::read(&cert_path)?)
        .map_err(|e| io_err(format!("admission-cert JSON: {e}")))?;

    let capabilities = match gossip_caps {
        "entry" => Capabilities::Entry,
        "mix" => Capabilities::Mix,
        "exit" => Capabilities::Exit,
        "all" => Capabilities::All,
        other => {
            return Err(io_err(format!(
                "unknown --gossip-caps `{other}` (entry|mix|exit|all)"
            )))
        }
    };

    let mut bootstrap = Vec::new();
    for s in &gossip_seeds {
        let (addr_s, kem_s) = s
            .split_once('@')
            .ok_or_else(|| io_err(format!("--gossip-seed `{s}` must be ip:port@<kem-hex>")))?;
        let addr: SocketAddr = addr_s
            .parse()
            .map_err(|_| io_err(format!("bad --gossip-seed addr `{addr_s}`")))?;
        let kem: [u8; 32] = hex::decode(kem_s)
            .map_err(|_| io_err("--gossip-seed kem is not hex"))?
            .as_slice()
            .try_into()
            .map_err(|_| io_err("--gossip-seed kem must be 32 bytes"))?;
        bootstrap.push((addr, kem));
    }

    let cfg = crypto_gotham_relay::GossipConfig {
        identity,
        kem_pubkey_hex,
        advertise_addr: advertise,
        capabilities,
        admission,
        noise_sk: x25519_sk,
        bootstrap,
    };
    let set = Arc::new(set);
    let roster = Arc::new(Mutex::new(Roster::new()));
    let node = crypto_gotham_relay::GossipNode::new(cfg, Arc::clone(&roster), Arc::clone(&set))
        .map_err(|e| io_err(format!("gossip node: {e}")))?;
    let service = node.service();
    crypto_gotham_relay::spawn_gossip_loop(
        Arc::new(node),
        Duration::from_secs(interval_secs.max(5)),
    );
    info!(caps = %gossip_caps, "directory gossip enabled");
    Ok(Some(service))
}

/// Keep checking that we are still in the signed directory, and say so loudly
/// when we are not.
///
/// Enrolling once is not a guarantee of anything: a provider firewall change, a
/// router reboot, an expired lease or an authority that stops attesting all
/// leave a relay running, reporting itself healthy, and carrying nothing. That
/// is the "phantom relay" the operator only discovers by asking someone else.
/// The relay is the one process in a position to notice, so it does.
///
/// Deliberately quiet on the happy path: one line when the state CHANGES, never
/// a periodic heartbeat in the log. An operator who reads a warning here should
/// be able to trust that it means something.
async fn watch_own_listing(pk_hex: String, authority_urls: Vec<String>) {
    // Long enough that a restart or a slow re-enrolment does not trip it.
    const PERIOD: Duration = Duration::from_secs(300);
    // Clients need a quorum; being in one directory is not enough to be usable.
    const QUORUM: usize = 2;

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "self-check disabled: could not build an HTTP client");
            return;
        }
    };

    let mut was_listed: Option<bool> = None;
    loop {
        tokio::time::sleep(PERIOD).await;

        let mut seen = 0usize;
        let mut asked = 0usize;
        for url in &authority_urls {
            let Ok(resp) = client.get(format!("{url}/directory")).send().await else {
                continue;
            };
            asked += 1;
            let Ok(body) = resp.text().await else {
                continue;
            };
            if body.contains(&pk_hex) {
                seen += 1;
            }
        }

        // Every authority unreachable says nothing about us — do not cry wolf.
        if asked == 0 {
            continue;
        }

        let listed = seen >= QUORUM;
        if was_listed == Some(listed) {
            continue;
        }
        was_listed = Some(listed);

        if listed {
            info!(
                authorities = seen,
                "self-check: this relay is listed and can carry traffic"
            );
        } else {
            warn!(
                listed_by = seen,
                quorum = QUORUM,
                "SELF-CHECK FAILED: clients are NOT using this relay. It is running, \
                 but fewer than the required number of authorities list it, so no \
                 message will be routed through it. Run `gotham-relay doctor \
                 --key-file <your key>` for the likely cause."
            );
        }
    }
}

/// The authorities that ship with the application. A volunteer who runs
/// `doctor` with no arguments must be asking the same set the clients ask,
/// otherwise the answer means nothing.
const DEFAULT_AUTHORITIES: [&str; 3] = [
    "http://144.24.205.188:8443",
    "http://84.235.232.196:8443",
    "http://84.235.228.107:8443",
];

/// What one authority says about us.
struct AuthorityView {
    url: String,
    reachable: bool,
    listed: bool,
    tier: Option<String>,
    operator: Option<String>,
    addr: Option<String>,
    rendezvous_capable: bool,
}

async fn ask_authority(url: &str, pk_hex: &str) -> AuthorityView {
    let mut view = AuthorityView {
        url: url.to_string(),
        reachable: false,
        listed: false,
        tier: None,
        operator: None,
        addr: None,
        rendezvous_capable: false,
    };
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return view,
    };
    let body = match client.get(format!("{url}/directory")).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return view,
        },
        Err(_) => return view,
    };
    view.reachable = true;
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) else {
        return view;
    };
    let relays = doc
        .get("doc")
        .and_then(|d| d.get("relays"))
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    for r in relays {
        if r.get("id_pubkey_hex").and_then(|v| v.as_str()) == Some(pk_hex) {
            view.listed = true;
            view.tier = r.get("tier").and_then(|v| v.as_str()).map(String::from);
            view.operator = r.get("operator").and_then(|v| v.as_str()).map(String::from);
            view.addr = r.get("addr").and_then(|v| v.as_str()).map(String::from);
            view.rendezvous_capable = r
                .get("rendezvous_capable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            break;
        }
    }
    view
}

/// Print a verdict a non-specialist can act on. Returns the process exit code:
/// 0 when the relay is genuinely usable, 1 otherwise — so it can be dropped
/// into a cron job or a health check without parsing the text.
async fn run_doctor(pk_hex: &str, authorities: &[String], quorum: usize) -> i32 {
    println!("Relais {pk_hex}");
    println!();

    let mut views = Vec::new();
    for url in authorities {
        views.push(ask_authority(url, pk_hex).await);
    }

    let unreachable: Vec<&AuthorityView> = views.iter().filter(|v| !v.reachable).collect();
    let listed: Vec<&AuthorityView> = views.iter().filter(|v| v.listed).collect();

    println!("Autorites interrogees :");
    for v in &views {
        let state = if !v.reachable {
            "INJOIGNABLE".to_string()
        } else if v.listed {
            "vous connait".to_string()
        } else {
            "ne vous connait PAS".to_string()
        };
        println!("  {:<32} {}", v.url, state);
    }
    println!();

    if !unreachable.is_empty() {
        println!(
            "  {} autorite(s) injoignable(s) : le diagnostic est partiel.",
            unreachable.len()
        );
        println!("  Verifiez votre connexion sortante avant de conclure.");
        println!();
    }

    // The one number that decides whether clients will use this relay.
    let n = listed.len();
    if n < quorum {
        println!("VERDICT : ce relais N'EST PAS UTILISE.");
        println!();
        println!("  {n} autorite(s) vous listent, il en faut {quorum}. Les applications",);
        println!("  n'acceptent un relais que lorsqu'un quorum d'autorites l'a atteste,");
        println!("  donc en l'etat aucun message ne passera par vous.");
        println!();
        if n == 0 {
            println!("  Aucune autorite ne vous connait. Les causes, par frequence :");
            println!("    1. Votre port UDP n'est pas joignable depuis l'exterieur.");
            println!("       Sur un VPS, pensez au pare-feu du FOURNISSEUR (groupe de");
            println!("       securite / security list), pas seulement a celui de la machine.");
            println!("       Derriere une box : relancez l'installeur avec GOTHAM_RENDEZVOUS=on,");
            println!("       aucune redirection de port n'est alors necessaire.");
            println!("    2. Le service ne tourne pas : systemctl status 'gotham-relay-*'");
            println!("    3. Enrolement refuse : journalctl -u 'gotham-relay-*' | grep -i reject");
        } else {
            println!("  Certaines autorites vous voient et d'autres non : l'enrolement");
            println!("  n'a ete fait qu'aupres d'une partie d'entre elles. Relancez");
            println!("  l'installeur, il les contacte toutes.");
        }
        return 1;
    }

    // Listed by a quorum — but that is not sufficient on its own.
    let sample = listed[0];
    println!(
        "Vu par {n} autorite(s) sur {} (quorum {quorum}) :",
        views.len()
    );
    println!(
        "  adresse            : {}",
        sample.addr.as_deref().unwrap_or("?")
    );
    println!(
        "  role               : {}",
        sample.tier.as_deref().unwrap_or("?")
    );
    println!(
        "  point de rendez-vous : {}",
        if sample.rendezvous_capable {
            "oui"
        } else {
            "non"
        }
    );
    println!(
        "  operateur          : {}",
        sample.operator.as_deref().unwrap_or("AUCUN")
    );
    println!();

    if sample.operator.is_none() {
        println!("VERDICT : ce relais NE SERA JAMAIS CHOISI.");
        println!();
        println!("  Il est bien enrole, mais sans etiquette d'operateur. La selection");
        println!("  de chemin refuse deux sauts dont elle ne peut pas PROUVER qu'ils");
        println!("  appartiennent a des operateurs differents, donc un relais sans");
        println!("  etiquette n'entre dans aucun chemin.");
        println!();
        println!("  Relancez l'installeur, ou ajoutez --operator <votre-nom> au service.");
        return 1;
    }

    println!("VERDICT : ce relais fonctionne et peut acheminer du trafic.");
    println!();
    println!("  Merci : chaque relais independant agrandit la foule dans laquelle");
    println!("  chaque message se fond.");
    0
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log);

    match cli.cmd {
        Cmd::Keygen { key_file } => {
            let mut sk = [0u8; 32];
            OsRng.fill_bytes(&mut sk);
            // X25519 clamping.
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            write_key_file(&key_file, &sk)?;
            let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
            sk.zeroize();
            println!("public key: {}", hex::encode(pk));
            info!("wrote secret key to {}", key_file.display());
            Ok(())
        }

        Cmd::Pubkey { key_file } => {
            let sk = read_key_file(&key_file)?;
            let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
            // sk is plain [u8; 32] — drop will leave bytes on the stack. For
            // a one-shot CLI invocation this is acceptable.
            println!("{}", hex::encode(pk));
            Ok(())
        }

        Cmd::Doctor {
            key_file,
            authority_url,
            quorum,
        } => {
            let sk = read_key_file(&key_file)?;
            let pk = PublicKey::from(&StaticSecret::from(sk)).to_bytes();
            let pk_hex = hex::encode(pk);
            let authorities = if authority_url.is_empty() {
                DEFAULT_AUTHORITIES.iter().map(|s| s.to_string()).collect()
            } else {
                authority_url
            };
            let code = run_doctor(&pk_hex, &authorities, quorum).await;
            std::process::exit(code);
        }
        Cmd::Run {
            key_file,
            listen_port,
            listen_host,
            delay_micros,
            replay_size,
            replay_ttl_secs,
            max_pps,
            max_bytes_per_day,
            authority_url,
            extra_authority_url,
            advertise_addr,
            no_upnp,
            enroll_token,
            tier,
            country,
            operator,
            heartbeat_secs,
            mailbox,
            mailbox_store,
            allow_unauthenticated_mailbox_fetch,
            gossip,
            advert_key,
            admission_cert,
            authority_set,
            gossip_seeds,
            gossip_caps,
            gossip_interval_secs,
            rendezvous_key,
            rendezvous_addr,
            rendezvous_capable,
            authority_pop_key,
        } => {
            let sk = read_key_file(&key_file)?;
            let advertise_for_gossip = advertise_addr.clone();
            let relay = Relay::new(
                sk,
                replay_size,
                Duration::from_secs(replay_ttl_secs),
                delay_micros,
            )
            .with_rate_limit(max_pps, max_bytes_per_day);

            let pk_hex = hex::encode(relay.identity_public_key());

            // The authority's stable PoP public key (if pinned via
            // --authority-pop-key). Used BOTH to build the enrollment possession
            // proof AND — when this relay is a rendezvous host — to authenticate
            // the authority's presence queries (ALPN gotham-rdvq/1), so only the
            // authority can probe which CGNAT relays we host.
            let authority_pop_pk = authority_pop_key
                .as_deref()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok());

            // Auto-enrollment: if an authority URL is configured, announce
            // ourselves (and heartbeat) so the network self-forms. Never fatal.
            if let Some(url) = authority_url {
                // Resolve the address peers reach us on. Priority:
                //   1. explicit --advertise-addr (public host / manual forward),
                //   2. UPnP-IGD auto-config (home router opens the port + tells
                //      us our public IP) unless --no-upnp,
                //   3. otherwise a clear error.
                // RFC B3: a CGNAT relay hosted via a rendezvous point has NO
                // dialable address of its own — skip advertise resolution.
                let advertise = if rendezvous_key.is_some() {
                    String::new()
                } else {
                    match advertise_addr {
                        Some(a) => {
                            // Reject an unparseable advertise address early.
                            let _: SocketAddr = a.parse().map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    format!("--advertise-addr must be ip:port, got `{a}`"),
                                )
                            })?;
                            a
                        }
                        None if !no_upnp => {
                            info!(
                            "no --advertise-addr set — attempting UPnP-IGD NAT auto-configuration…"
                        );
                            let mapping = crypto_gotham_relay::nat::upnp_autoconfigure(
                                listen_port,
                                UPNP_LEASE_SECS,
                            )
                            .await
                            .map_err(|e| {
                                std::io::Error::other(format!(
                                    "{e}. Set --advertise-addr <ip:port> manually (public IP or a \
                                 port-forwarded mapping), or pass --no-upnp to skip this."
                                ))
                            })?;
                            mapping.external.to_string()
                        }
                        None => {
                            return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "--advertise-addr is required with --authority-url (UPnP disabled via --no-upnp)",
                        ));
                        }
                    }
                };
                let tier = crypto_gotham_relay::enroll_client::parse_tier(&tier)
                    .map_err(std::io::Error::other)?;
                let cfg = crypto_gotham_relay::enroll_client::EnrollConfig {
                    authority_url: url,
                    extra_authority_urls: extra_authority_url,
                    advertise_addr: advertise,
                    kem_pubkey_hex: pk_hex.clone(),
                    tier,
                    token: enroll_token,
                    country,
                    operator,
                    heartbeat: Duration::from_secs(heartbeat_secs.max(1)),
                    rendezvous: rendezvous_key.clone(),
                    rendezvous_capable,
                    mailbox,
                    relay_sk: sk,
                    authority_pop_pk,
                };
                info!("auto-enrollment enabled — announcing to directory authority");
                let watch_urls: Vec<String> = std::iter::once(cfg.authority_url.clone())
                    .chain(cfg.extra_authority_urls.iter().cloned())
                    .collect();
                let watch_pk = pk_hex.clone();
                tokio::spawn(crypto_gotham_relay::enroll_client::run_enrollment_loop(cfg));
                tokio::spawn(watch_own_listing(watch_pk, watch_urls));
            } else {
                warn!(
                    "no --authority-url set: this relay will forward packets but will \
                     NOT enroll in any directory, so clients cannot discover it. Pass \
                     --authority-url <url> --advertise-addr <ip:port> to join the network."
                );
            }
            info!(
                listen_port,
                delay_micros,
                replay_size,
                replay_ttl_secs,
                max_pps,
                max_bytes_per_day,
                "gotham-relay starting"
            );
            info!("identity public key: {pk_hex}");

            // Optional store-and-forward mailbox. Loads a prior snapshot from
            // disk (if configured), then runs a background prune + periodic
            // snapshot task so restarts don't lose pending offline messages.
            let mailbox_handle = if mailbox {
                let store = load_mailbox(mailbox_store.as_ref());
                let handle = Arc::new(Mutex::new(store));
                spawn_mailbox_maintenance(Arc::clone(&handle), mailbox_store.clone());
                // SEC-MBX-01: fail-closed by default. The flag exists only so an
                // operator can keep serving pre-proof clients during a rollout.
                crypto_gotham_relay::set_allow_unauthenticated_mailbox_fetch(
                    allow_unauthenticated_mailbox_fetch,
                );
                if allow_unauthenticated_mailbox_fetch {
                    warn!(
                        "--allow-unauthenticated-mailbox-fetch is SET: any holder of a \
                         recipient's PUBLIC key can delete their offline messages. \
                         Drop this flag once clients have updated."
                    );
                }
                info!(persist = mailbox_store.is_some(), "mailbox hosting enabled");
                Some(handle)
            } else {
                None
            };

            // Optional peer-to-peer directory gossip (serves gotham-dir/1 +
            // runs anti-entropy). `pk_hex` is our X25519 routing key.
            let gossip_service = build_gossip(
                gossip,
                sk,
                pk_hex.clone(),
                advertise_for_gossip,
                advert_key,
                admission_cert,
                authority_set,
                gossip_seeds,
                &gossip_caps,
                gossip_interval_secs,
            )?;

            // A mailbox host also accepts deposits over the MIXNET (hides the
            // depositor's IP) AND anonymous SURB fetches (reply routed back
            // through the mixnet, hiding the fetcher's IP) via a delivery handler
            // on the mixnet path, in addition to the direct gotham-mbx/1 endpoint.
            let mailbox_delivery = mailbox_handle
                .as_ref()
                .map(|mb| crypto_gotham_relay::make_mailbox_service_handler(sk, Arc::clone(mb)))
                .transpose()
                .map_err(std::io::Error::other)?;

            // RFC B3: resolve the rendezvous relay to dial, if configured. A
            // CGNAT relay runs the reverse-tunnel client INSTEAD of the (useless,
            // unreachable) inbound listener.
            let rendezvous_dial: Option<(SocketAddr, [u8; 32])> =
                match (&rendezvous_key, &rendezvous_addr) {
                    (Some(k), Some(a)) => {
                        let r_pk: [u8; 32] = hex::decode(k)
                            .ok()
                            .and_then(|v| v.try_into().ok())
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "--rendezvous-key must be 32-byte hex",
                                )
                            })?;
                        let r_addr: SocketAddr = a.parse().map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "--rendezvous-addr must be ip:port",
                            )
                        })?;
                        Some((r_addr, r_pk))
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "--rendezvous-key and --rendezvous-addr must be set together",
                        ));
                    }
                    (None, None) => None,
                };

            let listen_addr = parse_listen_addr(&listen_host, listen_port)?;

            // Run the relay (inbound listener, OR the RFC B3 rendezvous client for
            // a CGNAT relay) and the SIGINT watcher concurrently; the first to
            // complete shuts the process down.
            tokio::select! {
                res = async {
                    if let Some((r_addr, r_pk)) = rendezvous_dial {
                        crypto_gotham_relay::transport::run_rendezvous_relay(
                            r_addr, r_pk, sk, relay, mailbox_delivery,
                        )
                        .await
                    } else {
                        info!(%listen_addr, "binding QUIC listener");
                        crypto_gotham_relay::run_relay_listener_with_services(
                            listen_addr, sk, relay, mailbox_delivery, mailbox_handle.clone(),
                            gossip_service, authority_pop_pk,
                        )
                        .await
                    }
                } => {
                    if let Err(e) = res {
                        warn!(error = ?e, "relay exited with error");
                    }
                }
                _ = shutdown_signal() => {
                    info!("shutdown signal received (SIGINT/SIGTERM)");
                }
            }

            // Best-effort final snapshot on clean shutdown.
            if let (Some(handle), Some(path)) = (&mailbox_handle, &mailbox_store) {
                let snap = handle.lock().await.snapshot();
                if let Err(e) = persist_mailbox(path, &snap) {
                    warn!(?e, "failed to persist mailbox on shutdown");
                }
            }

            Ok(())
        }

        Cmd::SignDirectory {
            authority_key,
            relays,
            output,
            valid_secs,
        } => {
            // Read authority key — accepts either 64-hex or 32-byte raw.
            let auth_bytes = read_ed25519_seed(&authority_key)?;
            let signing_key = SigningKey::from_bytes(&auth_bytes);

            // Parse the relays JSON. Format matches what
            // `infra/scripts/sign-directory.sh` produces.
            let raw = std::fs::read_to_string(&relays)?;
            let entries: Vec<RelayJsonEntry> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("relays JSON: {e}"))
            })?;
            if entries.len() < 3 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "need at least 3 relays for a working mixnet",
                ));
            }

            // Map JSON entries → RelayDescriptor. Capability strings:
            //   "entry" | "mix" | "exit" | "all" (rotated across all 3 tiers).
            let mut descriptors = Vec::with_capacity(entries.len());
            for (i, e) in entries.iter().enumerate() {
                let tier = match e.capabilities.as_str() {
                    "entry" => RelayTier::Entry,
                    "mix" => RelayTier::Mix,
                    "exit" => RelayTier::Exit,
                    "all" | "" => match i % 3 {
                        0 => RelayTier::Entry,
                        1 => RelayTier::Mix,
                        _ => RelayTier::Exit,
                    },
                    other => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("unknown capability `{other}` — use entry|mix|exit|all"),
                        ))
                    }
                };
                descriptors.push(RelayDescriptor {
                    id_pubkey_hex: e.node_id_hex.clone(),
                    kem_pubkey_hex: e.node_id_hex.clone(),
                    addr: e.addr.clone(),
                    tier,
                    country: e.country.clone(),
                    asn: e.asn,
                    operator: e.operator.clone(),
                    uptime_pct: Some(100.0),
                    mailbox: e.mailbox,
                    rendezvous: None,
                    rendezvous_capable: false,
                });
            }

            let doc = DirectoryDoc::new(descriptors, Duration::from_secs(valid_secs))
                .map_err(|e| std::io::Error::other(format!("DirectoryDoc::new: {e:?}")))?;
            let signed = SignedDirectory::sign(doc, &signing_key)
                .map_err(|e| std::io::Error::other(format!("SignedDirectory::sign: {e:?}")))?;
            let json = signed
                .to_json_pretty()
                .map_err(|e| std::io::Error::other(format!("to_json_pretty: {e:?}")))?;
            std::fs::write(&output, json)?;
            info!(
                relays = entries.len(),
                valid_secs,
                "wrote signed directory to {}",
                output.display()
            );
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
struct RelayJsonEntry {
    node_id_hex: String,
    addr: String,
    #[serde(default)]
    capabilities: String,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    asn: Option<u32>,
    #[serde(default)]
    operator: Option<String>,
    /// Whether this relay hosts a store-and-forward mailbox (offline delivery).
    #[serde(default)]
    mailbox: bool,
}

/// Read an Ed25519 seed from `path`. Accepts either a 32-byte raw file
/// or a 64-hex-char text file (with optional trailing newline).
fn read_ed25519_seed(path: &PathBuf) -> std::io::Result<[u8; 32]> {
    let raw = std::fs::read(path)?;
    let trimmed: Vec<u8> = if raw
        .iter()
        .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
    {
        let s = std::str::from_utf8(&raw)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-utf8"))?
            .trim();
        hex::decode(s).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad hex: {e}"))
        })?
    } else {
        raw
    };
    if trimmed.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "authority key must be 32 bytes (or 64 hex chars)",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&trimmed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_addr_accepts_v4_v6_and_all_interfaces() {
        let v4 = parse_listen_addr("203.0.113.7", 443).unwrap();
        assert_eq!(v4.to_string(), "203.0.113.7:443");

        // Default `::` = all interfaces (dual-stack), preserves prior bind.
        let any = parse_listen_addr("::", 5223).unwrap();
        assert!(any.ip().is_unspecified());
        assert_eq!(any.port(), 5223);

        let v6 = parse_listen_addr("2001:db8::1", 443).unwrap();
        assert_eq!(v6.port(), 443);
    }

    #[test]
    fn listen_addr_rejects_hostnames() {
        // The routing layer pins relays by IP — hostnames are not resolved.
        assert!(parse_listen_addr("relay.example.com", 443).is_err());
        assert!(parse_listen_addr("", 443).is_err());
    }
}
