//! Store-and-forward mailbox for offline delivery.
//!
//! Gotham relays route but do not store, so a message to an offline peer is
//! lost once the sender's retry window closes (both sides must be online at
//! once). A **mailbox** lets a sender DEPOSIT a sealed envelope for a recipient
//! who is offline, and the recipient RETRIEVE it on reconnect.
//!
//! ## Metadata hygiene
//! To preserve Gotham's unlinkability the store is addressed by an opaque
//! 32-byte [`MailboxId`] derived from the recipient's public key
//! ([`mailbox_id_for`]) — never a plaintext identity — and holds only
//! already-sealed ciphertext. Deposits and retrievals themselves travel through
//! the mixnet, so the host sees mailbox IDs and blob sizes but not *who*
//! deposits or reads. (The id is a domain-separated hash of the recipient key,
//! which the sender already knows; it is not a strong blinding against an
//! adversary who can enumerate candidate keys — a per-epoch blinded address is
//! future work, see the module tests and GOTHAM notes.)
//!
//! ## Abuse resistance
//! [`MailboxPolicy`] bounds memory and blunts flooding: a max message size, a
//! per-mailbox message cap, a global message cap, a max mailbox count, and a
//! TTL (default + hard ceiling) after which entries are dropped.
//!
//! This module is the pure, side-effect-free core (no I/O, no wire, no clock):
//! the caller supplies `now` (unix seconds) and drives deposit/fetch/prune. The
//! relay endpoint, mixnet deposit/retrieve messages, and client wiring
//! (sender deposits on delivery failure; recipient polls on connect) are the
//! integration layer built on top.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Opaque 32-byte mailbox address. Derived from the recipient's public key via
/// [`mailbox_id_for`] so the store never holds a plaintext identity.
pub type MailboxId = [u8; 32];

/// Domain-separation tag for mailbox-id derivation (versioned).
const MAILBOX_ID_DOMAIN: &[u8] = b"gotham-mailbox-id-v1";

/// Derive the opaque mailbox address for a recipient public key. Deterministic
/// and domain-separated, so it can never collide with another hash use of the
/// same key material.
pub fn mailbox_id_for(recipient_pubkey: &[u8]) -> MailboxId {
    let mut h = blake3::Hasher::new();
    h.update(MAILBOX_ID_DOMAIN);
    h.update(recipient_pubkey);
    *h.finalize().as_bytes()
}

/// Domain-separation label for the mailbox **fetch possession proof**.
const MAILBOX_FETCH_AUTH_DOMAIN: &str = "gotham-mailbox-fetch-v1";

/// Proof that the fetcher holds the recipient *secret* key, not merely the
/// public one.
///
/// A [`MailboxId`] is `blake3(domain || recipient_pk)` and `recipient_pk` is
/// public — it travels in every invitation URI and every contact card. Without
/// this proof, anyone who has ever been handed a user's Gotham public key can
/// address that user's mailbox and issue a [`MailboxRequest::Fetch`], which is
/// *destructive*: [`Mailbox::fetch_batch`] removes what it returns. The victim
/// then never receives those messages and sees no error — silent, deniable,
/// remote message deletion (and, since mailbox blobs are sealed to the
/// recipient, the thief cannot read them, but the recipient still loses them).
///
/// The proof is a DH-MAC in the same shape as the RFC B3 enrollment
/// possession tag: the fetcher computes `shared = X25519(recipient_sk,
/// relay_static_pk)` and the relay recomputes `shared = X25519(relay_static_sk,
/// recipient_pk)`. Only a holder of `recipient_sk` can produce it.
///
/// ## Disclosure trade-off
/// `pk` is on the wire so the relay can perform its half of the DH. The relay
/// previously saw `blake3(domain || pk)`; it now sees `pk` itself. That is not
/// a new *identity* disclosure — the hash is a deterministic function of a
/// public value, invertible by anyone holding a candidate key list — but it
/// does remove the (weak) work factor of enumerating candidates. Accepted:
/// protecting delivery from a trivial remote-deletion attack outweighs a
/// pre-image cost that never was a security boundary. A per-epoch blinded
/// mailbox address would restore it; see the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchAuth {
    /// The recipient's Gotham X25519 public key (the mailbox owner).
    pub pk: [u8; 32],
    /// DH-MAC over the channel binding and the mailbox id, see
    /// [`fetch_auth_tag`].
    pub tag: [u8; 32],
}

/// Compute the [`FetchAuth`] tag.
///
/// `shared` is the raw X25519 shared secret between the mailbox owner and the
/// relay's static key (either direction yields the same value). `binding` ties
/// the tag to one transport context so a captured tag cannot be replayed
/// elsewhere: on the direct control path it is the Noise handshake hash (unique
/// per connection); on the mixnet SURB path it is derived from the reply block,
/// so a tag cannot be lifted onto a SURB pointing somewhere else.
///
/// The length prefix domain-separates `binding` from `id`, so no two different
/// `(binding, id)` pairs can produce the same hash input.
#[must_use]
pub fn fetch_auth_tag(shared: &[u8; 32], binding: &[u8], id: &MailboxId) -> [u8; 32] {
    let k = blake3::derive_key(MAILBOX_FETCH_AUTH_DOMAIN, shared);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(&(binding.len() as u64).to_le_bytes());
    h.update(binding);
    h.update(id);
    *h.finalize().as_bytes()
}

impl FetchAuth {
    /// Verify this proof against the relay's side of the DH.
    ///
    /// Checks BOTH that `pk` actually owns `id` (so a valid proof for one's own
    /// mailbox cannot be replayed against someone else's) and that the tag
    /// matches, in constant time.
    #[must_use]
    pub fn verify(&self, shared: &[u8; 32], binding: &[u8], id: &MailboxId) -> bool {
        if mailbox_id_for(&self.pk) != *id {
            return false;
        }
        let expected = fetch_auth_tag(shared, binding, id);
        // Constant-time: fold every byte, never short-circuit.
        let diff = self
            .tag
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }
}

/// Build the channel binding for a SURB (mixnet) fetch from the serialized
/// reply block. There is no Noise handshake on that path, so the reply block
/// itself is the context: a captured tag is useless against any other SURB, and
/// replaying the *identical* `(surb, tag)` pair only re-delivers to the SURB's
/// own — legitimate — destination.
#[must_use]
pub fn surb_fetch_binding(surb_bytes: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"gotham-mailbox-surb-binding-v1");
    h.update(surb_bytes);
    h.finalize().as_bytes().to_vec()
}

/// Domain-separation tag for mailbox-host rendezvous scoring.
const MAILBOX_RENDEZVOUS_DOMAIN: &[u8] = b"gotham-mailbox-rendezvous-v1";

/// Score a candidate mailbox host for a recipient, for Highest-Random-Weight
/// (rendezvous) host selection: pick the host with the MAXIMUM score.
///
/// The sender (who knows `recipient_pubkey`) and the recipient (who knows its
/// own key) both compute the same maximum, so they agree on the host **without
/// communicating**. Crucially, different recipients map to different hosts, so
/// no single mailbox operator sees the whole population's `IP ↔ identity` graph
/// — only the ~1/n of recipients that hash to it. Adding or removing a host
/// remaps only ~1/n of recipients (HRW stability), unlike "always the first
/// host", which funnels everyone to one operator.
pub fn mailbox_host_score(recipient_pubkey: &[u8], host_id: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MAILBOX_RENDEZVOUS_DOMAIN);
    h.update(recipient_pubkey);
    h.update(host_id);
    *h.finalize().as_bytes()
}

/// One stored, sealed envelope with its expiry.
#[derive(Clone, Debug)]
struct Entry {
    sealed: Vec<u8>,
    expires_at: u64,
}

/// Resource limits — bound memory and blunt flooding / DoS.
#[derive(Clone, Debug)]
pub struct MailboxPolicy {
    /// Maximum number of distinct mailboxes held at once.
    pub max_mailboxes: usize,
    /// Maximum live messages a single mailbox may hold.
    pub max_msgs_per_mailbox: usize,
    /// Maximum live messages across the whole store.
    pub max_total_msgs: usize,
    /// Maximum size of a single sealed envelope, in bytes.
    pub max_msg_bytes: usize,
    /// Maximum **live sealed bytes** held across the whole store.
    ///
    /// The message-count caps alone do not bound memory: `max_total_msgs`
    /// messages of `max_msg_bytes` each is the real ceiling, and at the
    /// defaults that product is hundreds of gigabytes. Deposits are accepted
    /// from unauthenticated clients (a depositor is by definition a *sender*,
    /// who cannot hold the recipient's secret), so this is the guard that
    /// actually stops a remote attacker from exhausting a volunteer's RAM.
    pub max_total_bytes: usize,
    /// TTL applied when a deposit passes `ttl_secs == 0`.
    pub default_ttl_secs: u64,
    /// Hard upper bound on any deposit's TTL.
    pub max_ttl_secs: u64,
}

impl Default for MailboxPolicy {
    fn default() -> Self {
        Self {
            max_mailboxes: 100_000,
            // A week of TTL at 256 messages is not much for an active
            // conversation, and a full mailbox does not degrade — it REJECTS,
            // so the sender's messages stop arriving entirely. 1000 gives real
            // usage room without costing memory, because of the byte cap below.
            max_msgs_per_mailbox: 1000,
            max_total_msgs: 1_000_000,
            // 16 KiB. The old 256 KiB was 150x larger than anything the
            // protocol can produce: a deposit is a sealed Gotham payload, so it
            // is bounded by MAX_PAYLOAD_SIZE (1664) plus ~60 bytes of seal
            // overhead — under 1.8 KiB. That gap was pure attacker headroom,
            // since a depositor is unauthenticated by design (a sender cannot
            // hold the recipient's secret). 16 KiB keeps ~10x margin for
            // protocol changes and nothing more.
            max_msg_bytes: 16 * 1024,
            // 512 MiB of live sealed bytes, unchanged — this is the guard that
            // actually bounds a volunteer relay's RAM.
            //
            // Worst case for ONE mailbox moves from 256 x 256 KiB = 64 MiB to
            // 1000 x 16 KiB = 16 MiB. So a single flooded mailbox now costs a
            // QUARTER of what it used to while holding four times as many real
            // messages, and it takes 32 saturated mailboxes to exhaust the
            // global budget instead of 8.
            max_total_bytes: 512 * 1024 * 1024,
            default_ttl_secs: 7 * 24 * 3600, // 7 days
            max_ttl_secs: 30 * 24 * 3600,    // 30 days
        }
    }
}

/// Why a [`Mailbox::deposit`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositError {
    /// Sealed payload exceeds `max_msg_bytes`.
    TooLarge,
    /// This mailbox already holds `max_msgs_per_mailbox` live messages.
    MailboxFull,
    /// The store is at `max_total_msgs` or `max_mailboxes` capacity.
    StoreFull,
}

impl core::fmt::Display for DepositError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            DepositError::TooLarge => "sealed envelope too large",
            DepositError::MailboxFull => "mailbox is full",
            DepositError::StoreFull => "mailbox store is at capacity",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DepositError {}

/// In-memory store-and-forward mailbox. See the module docs.
pub struct Mailbox {
    boxes: HashMap<MailboxId, Vec<Entry>>,
    policy: MailboxPolicy,
    total: usize,
    /// Live sealed bytes across all mailboxes; kept in step with `boxes` by
    /// every mutating method so the byte cap can be enforced in O(1).
    bytes: usize,
}

impl Mailbox {
    /// Create a mailbox with the given policy.
    ///
    /// `max_msg_bytes` is clamped below [`MAX_MAILBOX_FRAME`] (with headroom for
    /// MessagePack framing): because [`Mailbox::fetch_batch`] may return a
    /// single message alone (forward-progress guarantee), that message must fit
    /// one wire frame — otherwise a `Delivery` carrying it would exceed the
    /// frame ceiling and the message would be permanently un-fetchable.
    pub fn new(policy: MailboxPolicy) -> Self {
        let mut policy = policy;
        let ceiling = MAX_MAILBOX_FRAME.saturating_sub(4096);
        if policy.max_msg_bytes > ceiling {
            policy.max_msg_bytes = ceiling;
        }
        Self {
            boxes: HashMap::new(),
            policy,
            total: 0,
            bytes: 0,
        }
    }

    /// Create a mailbox with [`MailboxPolicy::default`].
    pub fn with_defaults() -> Self {
        Self::new(MailboxPolicy::default())
    }

    /// The active policy.
    pub fn policy(&self) -> &MailboxPolicy {
        &self.policy
    }

    /// Total live messages currently stored across all mailboxes.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Total live sealed bytes currently stored across all mailboxes.
    pub fn total_bytes(&self) -> usize {
        self.bytes
    }

    /// Number of distinct mailboxes currently held.
    pub fn mailbox_count(&self) -> usize {
        self.boxes.len()
    }

    /// Deposit a sealed envelope for `id`, expiring after `ttl_secs` (clamped to
    /// `[1, max_ttl_secs]`; `0` ⇒ `default_ttl_secs`). Expired entries in the
    /// target mailbox are pruned first, and the store-wide cap prunes globally
    /// under pressure, so the caps count only live messages.
    pub fn deposit(
        &mut self,
        id: MailboxId,
        sealed: Vec<u8>,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(), DepositError> {
        if sealed.len() > self.policy.max_msg_bytes {
            return Err(DepositError::TooLarge);
        }
        let ttl = if ttl_secs == 0 {
            self.policy.default_ttl_secs
        } else {
            ttl_secs.min(self.policy.max_ttl_secs).max(1)
        };
        let expires_at = now.saturating_add(ttl);

        // Reject a brand-new mailbox once the store is at its mailbox ceiling.
        let is_new = !self.boxes.contains_key(&id);
        if is_new && self.boxes.len() >= self.policy.max_mailboxes {
            return Err(DepositError::StoreFull);
        }

        // Prune the target mailbox's expired entries first (a separate borrow).
        if let Some(v) = self.boxes.get_mut(&id) {
            let before = v.len();
            let before_bytes: usize = v.iter().map(|e| e.sealed.len()).sum();
            v.retain(|e| e.expires_at > now);
            let after_bytes: usize = v.iter().map(|e| e.sealed.len()).sum();
            self.total -= before - v.len();
            self.bytes -= before_bytes - after_bytes;
        }

        let cur = self.boxes.get(&id).map_or(0, Vec::len);
        if cur >= self.policy.max_msgs_per_mailbox {
            return Err(DepositError::MailboxFull);
        }
        // Reclaim expired occupancy store-wide before rejecting on EITHER
        // global cap, so both reflect LIVE messages (their documented
        // semantics) rather than locking out deposits on stale-but-unpruned
        // entries in other mailboxes.
        if self.total >= self.policy.max_total_msgs
            || self.bytes + sealed.len() > self.policy.max_total_bytes
        {
            self.prune_expired(now);
        }
        if self.total >= self.policy.max_total_msgs {
            return Err(DepositError::StoreFull);
        }
        // The byte ceiling is the one that actually bounds memory: the count
        // caps alone permit `max_total_msgs * max_msg_bytes`, which at any
        // sane default is orders of magnitude more RAM than a volunteer has.
        if self.bytes + sealed.len() > self.policy.max_total_bytes {
            return Err(DepositError::StoreFull);
        }

        self.bytes += sealed.len();
        self.boxes
            .entry(id)
            .or_default()
            .push(Entry { sealed, expires_at });
        self.total += 1;
        Ok(())
    }

    /// Retrieve and REMOVE all non-expired messages for `id`, in deposit (FIFO)
    /// order. Expired entries are silently dropped. An unknown mailbox yields an
    /// empty vec.
    pub fn fetch(&mut self, id: &MailboxId, now: u64) -> Vec<Vec<u8>> {
        let Some(entries) = self.boxes.remove(id) else {
            return Vec::new();
        };
        self.total -= entries.len();
        self.bytes -= entries.iter().map(|e| e.sealed.len()).sum::<usize>();
        entries
            .into_iter()
            .filter(|e| e.expires_at > now)
            .map(|e| e.sealed)
            .collect()
    }

    /// Number of live (non-expired) messages currently waiting for `id`.
    pub fn pending(&self, id: &MailboxId, now: u64) -> usize {
        self.boxes
            .get(id)
            .map_or(0, |v| v.iter().filter(|e| e.expires_at > now).count())
    }

    /// Drop expired entries across all mailboxes (and any mailbox left empty);
    /// returns the number of messages removed. Call periodically.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let mut removed = 0usize;
        let mut removed_bytes = 0usize;
        self.boxes.retain(|_, entries| {
            let before = entries.len();
            let before_bytes: usize = entries.iter().map(|e| e.sealed.len()).sum();
            entries.retain(|e| e.expires_at > now);
            removed += before - entries.len();
            removed_bytes += before_bytes - entries.iter().map(|e| e.sealed.len()).sum::<usize>();
            !entries.is_empty()
        });
        self.total -= removed;
        self.bytes -= removed_bytes;
        removed
    }

    /// Drain up to `max_total_bytes` of the oldest non-expired sealed
    /// envelopes for `id`, in deposit (FIFO) order, removing them from the
    /// store. Returns `(batch, more_remaining)` where `more_remaining` is true
    /// if live envelopes are still waiting after this batch (the client should
    /// fetch again). Expired entries are silently dropped.
    ///
    /// Forward-progress guarantee: the FIRST live message is always returned
    /// even if it alone exceeds `max_total_bytes` — otherwise an
    /// over-budget-but-valid message could never be retrieved. This is why the
    /// wire frame cap ([`MAX_MAILBOX_FRAME`]) is chosen ≥ the deposit size cap.
    pub fn fetch_batch(
        &mut self,
        id: &MailboxId,
        now: u64,
        max_total_bytes: usize,
    ) -> (Vec<Vec<u8>>, bool) {
        let Some(entries) = self.boxes.get_mut(id) else {
            return (Vec::new(), false);
        };
        // Drop expired first so the batch and the `more` flag reflect only
        // live messages.
        let before = entries.len();
        let before_bytes: usize = entries.iter().map(|e| e.sealed.len()).sum();
        entries.retain(|e| e.expires_at > now);
        let expired = before - entries.len();
        let expired_bytes = before_bytes - entries.iter().map(|e| e.sealed.len()).sum::<usize>();

        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut used = 0usize;
        while let Some(front) = entries.first() {
            let len = front.sealed.len();
            if !batch.is_empty() && used + len > max_total_bytes {
                break; // budget reached — leave the remainder for next fetch
            }
            let e = entries.remove(0);
            used += e.sealed.len();
            batch.push(e.sealed);
        }
        let more = !entries.is_empty();
        let taken = batch.len();
        if entries.is_empty() {
            self.boxes.remove(id);
        }
        self.total -= expired + taken;
        self.bytes -= expired_bytes + used;
        (batch, more)
    }

    /// Capture the live store as a serializable snapshot for disk persistence
    /// (survives a mailbox relay restart). Holds only sealed ciphertext +
    /// expiries — never plaintext or identities.
    pub fn snapshot(&self) -> MailboxSnapshot {
        let boxes = self
            .boxes
            .iter()
            .map(|(id, v)| {
                (
                    *id,
                    v.iter().map(|e| (e.sealed.clone(), e.expires_at)).collect(),
                )
            })
            .collect();
        MailboxSnapshot { boxes }
    }

    /// Rebuild a mailbox from a [`MailboxSnapshot`] under `policy`, dropping
    /// any entry already expired at `now` and re-deriving the live total.
    pub fn from_snapshot(policy: MailboxPolicy, snap: MailboxSnapshot, now: u64) -> Self {
        let mut boxes = HashMap::new();
        let mut total = 0usize;
        let mut bytes = 0usize;
        for (id, entries) in snap.boxes {
            let live: Vec<Entry> = entries
                .into_iter()
                .filter(|(_, exp)| *exp > now)
                .map(|(sealed, expires_at)| Entry { sealed, expires_at })
                .collect();
            if !live.is_empty() {
                total += live.len();
                bytes += live.iter().map(|e| e.sealed.len()).sum::<usize>();
                boxes.insert(id, live);
            }
        }
        Self {
            boxes,
            policy,
            total,
            bytes,
        }
    }
}

/// Maximum size of a single length-framed mailbox control frame, in bytes
/// (16 MiB). Bounds the buffer a relay or client allocates for one
/// request/response. Chosen comfortably above the default per-message deposit
/// cap so [`Mailbox::fetch_batch`]'s forward-progress guarantee (always return
/// the first live message) never produces an un-sendable frame.
pub const MAX_MAILBOX_FRAME: usize = 16 * 1024 * 1024;

/// A client → mailbox-relay control request.
///
/// Carried length-framed over a dedicated QUIC + Noise XK stream (ALPN
/// `gotham-mbx/1`), NOT through the mixnet: a store-and-forward *fetch* needs a
/// reply, and a one-way mixnet cannot route a reply back anonymously (that
/// needs single-use reply blocks — future work). The direct connection means
/// the chosen mailbox host learns `client-IP ↔ mailbox_id`; the tradeoff and
/// its hardening path are documented in `docs/gotham/README.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxRequest {
    /// Store `sealed` for `id`, expiring after `ttl_secs` (`0` ⇒ policy
    /// default). The relay only ever holds the opaque sealed bytes.
    Deposit {
        /// Opaque recipient mailbox address.
        id: MailboxId,
        /// Already-sealed envelope bytes (the relay never sees plaintext).
        sealed: Vec<u8>,
        /// Requested time-to-live in seconds (clamped by policy).
        ttl_secs: u64,
    },
    /// Drain a bounded batch of pending sealed envelopes for `id`.
    Fetch {
        /// Opaque recipient mailbox address.
        id: MailboxId,
        /// Proof that the requester holds the recipient *secret* key. A fetch
        /// is destructive, so without this any holder of the (public)
        /// recipient key could silently delete someone's offline messages.
        ///
        /// `Option` + `serde(default)` keeps the field wire-compatible in both
        /// directions: an already-deployed relay ignores it as an unknown map
        /// key, and an already-shipped client that omits it still decodes here
        /// — where the relay's `require_fetch_auth` policy decides whether to
        /// serve it. See [`FetchAuth`].
        #[serde(default)]
        auth: Option<FetchAuth>,
    },
    /// Anonymous fetch: drain a batch for `id` and send it back through the
    /// mixnet using the enclosed single-use reply block, so the host never
    /// learns the fetcher's IP or the `IP ↔ mailbox_id` link. `surb` is an
    /// opaque, serialized reply block (built by the recipient; the mailbox crate
    /// treats it as bytes to avoid a dependency on the relay crate).
    FetchWithSurb {
        /// Opaque recipient mailbox address.
        id: MailboxId,
        /// Serialized single-use reply block.
        surb: Vec<u8>,
        /// Possession proof, bound to `surb` via [`surb_fetch_binding`].
        /// Same wire-compatibility rationale as [`MailboxRequest::Fetch`].
        #[serde(default)]
        auth: Option<FetchAuth>,
    },
}

/// A mailbox-relay → client control response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxResponse {
    /// A deposit was accepted and stored.
    Ack,
    /// The drained sealed envelopes (FIFO order).
    Delivery {
        /// Sealed envelopes, oldest first.
        sealed: Vec<Vec<u8>>,
        /// True if the mailbox still holds envelopes that did not fit this
        /// batch — the client should issue another `Fetch`.
        more: bool,
    },
    /// The request was refused; see [`MailboxWireError`].
    Error(MailboxWireError),
}

/// Wire-level error returned inside [`MailboxResponse::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxWireError {
    /// Sealed payload exceeded the per-message size cap.
    TooLarge,
    /// The target mailbox is at its per-mailbox capacity.
    MailboxFull,
    /// The store is at global capacity.
    StoreFull,
    /// The frame could not be parsed, or exceeded [`MAX_MAILBOX_FRAME`].
    Malformed,
    /// The request carried no valid [`FetchAuth`] possession proof. Returned
    /// for a fetch that cannot prove it holds the recipient's secret key.
    Unauthorized,
    /// Too many requests on one connection — slow down or reconnect.
    RateLimited,
}

impl From<DepositError> for MailboxWireError {
    fn from(e: DepositError) -> Self {
        match e {
            DepositError::TooLarge => MailboxWireError::TooLarge,
            DepositError::MailboxFull => MailboxWireError::MailboxFull,
            DepositError::StoreFull => MailboxWireError::StoreFull,
        }
    }
}

impl MailboxRequest {
    /// Serialize to MessagePack (name-tagged — matches the suite convention so
    /// the wire tag is a stable field name, not a fragile variant index).
    pub fn to_bytes(&self) -> Result<Vec<u8>, MailboxWireError> {
        rmp_serde::to_vec_named(self).map_err(|_| MailboxWireError::Malformed)
    }
    /// Parse from MessagePack bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, MailboxWireError> {
        rmp_serde::from_slice(b).map_err(|_| MailboxWireError::Malformed)
    }
}

impl MailboxResponse {
    /// Serialize to MessagePack (name-tagged).
    pub fn to_bytes(&self) -> Result<Vec<u8>, MailboxWireError> {
        rmp_serde::to_vec_named(self).map_err(|_| MailboxWireError::Malformed)
    }
    /// Parse from MessagePack bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, MailboxWireError> {
        rmp_serde::from_slice(b).map_err(|_| MailboxWireError::Malformed)
    }
}

/// One persisted entry: `(sealed_bytes, expires_at_unix)`.
pub type SnapshotEntry = (Vec<u8>, u64);
/// One persisted mailbox: its opaque id plus its ordered live entries.
pub type SnapshotBox = (MailboxId, Vec<SnapshotEntry>);

/// A serializable point-in-time image of a [`Mailbox`], for disk persistence
/// across relay restarts. Holds only sealed ciphertext + expiries.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MailboxSnapshot {
    /// One entry per non-empty mailbox, each with its ordered live messages.
    pub boxes: Vec<SnapshotBox>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3600;

    fn id(n: u8) -> MailboxId {
        [n; 32]
    }

    #[test]
    fn deposit_then_fetch_is_fifo_and_draining() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"first".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(1), b"second".to_vec(), 0, HOUR).unwrap();
        assert_eq!(mb.pending(&id(1), 0), 2);
        assert_eq!(mb.total(), 2);

        let got = mb.fetch(&id(1), 0);
        assert_eq!(got, vec![b"first".to_vec(), b"second".to_vec()]);
        // Fetch drains: a second fetch is empty and the store is back to zero.
        assert!(mb.fetch(&id(1), 0).is_empty());
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.mailbox_count(), 0);
    }

    #[test]
    fn expired_messages_are_not_returned_and_get_pruned() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"old".to_vec(), 0, HOUR).unwrap(); // expires at 3600
        mb.deposit(id(1), b"fresh".to_vec(), 0, 10 * HOUR).unwrap();
        // At t = 2*HOUR the first is expired.
        let now = 2 * HOUR;
        assert_eq!(mb.pending(&id(1), now), 1);
        let got = mb.fetch(&id(1), now);
        assert_eq!(got, vec![b"fresh".to_vec()]);
        assert_eq!(mb.total(), 0);
    }

    #[test]
    fn prune_expired_reclaims_and_empties() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(2), b"b".to_vec(), 0, 10 * HOUR).unwrap();
        let removed = mb.prune_expired(2 * HOUR);
        assert_eq!(removed, 1);
        assert_eq!(mb.total(), 1);
        assert_eq!(mb.mailbox_count(), 1); // box 1 emptied and dropped
        assert_eq!(mb.pending(&id(2), 2 * HOUR), 1);
    }

    /// The default caps have to stay consistent with each other and with what
    /// the transport can actually carry. They drifted apart once already: the
    /// per-message cap sat 150x above the largest deposit the protocol can
    /// produce, which is headroom for a flooder and for nobody else.
    #[test]
    fn default_caps_stay_proportionate_to_the_protocol() {
        let p = MailboxPolicy::default();
        // A deposit is a sealed Gotham payload: MAX_PAYLOAD_SIZE plus seal
        // overhead. Anything an honest client sends fits well inside this.
        const LARGEST_REAL_DEPOSIT: usize = 1664 + 60;
        assert!(
            p.max_msg_bytes >= LARGEST_REAL_DEPOSIT * 4,
            "the per-message cap must leave room for protocol growth"
        );
        assert!(
            p.max_msg_bytes <= LARGEST_REAL_DEPOSIT * 16,
            "a cap far above the largest real deposit only buys an attacker room"
        );
        // One saturated mailbox must not be able to swallow the whole store —
        // otherwise a single flooded recipient locks every other one out.
        let worst_one_mailbox = p.max_msgs_per_mailbox * p.max_msg_bytes;
        assert!(
            worst_one_mailbox * 16 <= p.max_total_bytes,
            "one full mailbox is {worst_one_mailbox} bytes of a {} byte budget — \
             too few mailboxes would exhaust the relay",
            p.max_total_bytes
        );
        // And it has to hold enough for real use: a week of TTL at a few
        // hundred messages is not a lot for an active conversation.
        assert!(p.max_msgs_per_mailbox >= 1000);
    }

    #[test]
    fn rejects_oversize_payload() {
        let policy = MailboxPolicy {
            max_msg_bytes: 8,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        assert_eq!(
            mb.deposit(id(1), vec![0u8; 9], 0, HOUR),
            Err(DepositError::TooLarge)
        );
        assert_eq!(mb.total(), 0);
    }

    #[test]
    fn enforces_per_mailbox_cap() {
        let policy = MailboxPolicy {
            max_msgs_per_mailbox: 2,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        mb.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        mb.deposit(id(1), b"b".to_vec(), 0, HOUR).unwrap();
        assert_eq!(
            mb.deposit(id(1), b"c".to_vec(), 0, HOUR),
            Err(DepositError::MailboxFull)
        );
        // A cap frees up once the older entries expire.
        assert!(mb.deposit(id(1), b"d".to_vec(), 2 * HOUR, HOUR).is_ok());
    }

    #[test]
    fn enforces_store_and_mailbox_ceilings() {
        let policy = MailboxPolicy {
            max_mailboxes: 1,
            max_total_msgs: 1,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        mb.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        // Second mailbox blocked by max_mailboxes.
        assert_eq!(
            mb.deposit(id(2), b"b".to_vec(), 0, HOUR),
            Err(DepositError::StoreFull)
        );
        // Same mailbox blocked by max_total_msgs.
        let policy2 = MailboxPolicy {
            max_mailboxes: 10,
            max_total_msgs: 1,
            ..MailboxPolicy::default()
        };
        let mut mb2 = Mailbox::new(policy2);
        mb2.deposit(id(1), b"a".to_vec(), 0, HOUR).unwrap();
        assert_eq!(
            mb2.deposit(id(1), b"b".to_vec(), 0, HOUR),
            Err(DepositError::StoreFull)
        );
    }

    #[test]
    fn ttl_is_clamped_to_ceiling_and_default_applies() {
        let policy = MailboxPolicy {
            default_ttl_secs: 100,
            max_ttl_secs: 1000,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        // ttl 0 → default (100): alive at 50, gone at 150.
        mb.deposit(id(1), b"def".to_vec(), 0, 0).unwrap();
        assert_eq!(mb.pending(&id(1), 50), 1);
        assert_eq!(mb.pending(&id(1), 150), 0);
        // ttl above ceiling clamps to max_ttl (1000): expiry is exclusive, so
        // it is alive at 999 and gone at 1000.
        mb.deposit(id(2), b"clamp".to_vec(), 0, 1_000_000).unwrap();
        assert_eq!(mb.pending(&id(2), 999), 1);
        assert_eq!(mb.pending(&id(2), 1000), 0);
    }

    #[test]
    fn rendezvous_host_selection_is_deterministic_and_spreads() {
        // Eight candidate hosts; pick = argmax score.
        let hosts: Vec<[u8; 32]> = (0..8u8).map(|i| [i + 100; 32]).collect();
        let pick = |r: &[u8]| {
            *hosts
                .iter()
                .max_by_key(|h| mailbox_host_score(r, *h))
                .unwrap()
        };
        // Sender and recipient agree (same key → same host), every time.
        assert_eq!(pick(&[7u8; 32]), pick(&[7u8; 32]));
        // Recipients spread across hosts — NOT funnelled to a single operator.
        let picked: std::collections::HashSet<_> = (0..64u8).map(|n| pick(&[n; 32])).collect();
        assert!(
            picked.len() > 1,
            "rendezvous must spread recipients, not funnel them to one host"
        );
    }

    #[test]
    fn mailbox_id_is_deterministic_domain_separated_and_key_specific() {
        let k1 = [7u8; 32];
        let k2 = [8u8; 32];
        assert_eq!(mailbox_id_for(&k1), mailbox_id_for(&k1)); // deterministic
        assert_ne!(mailbox_id_for(&k1), mailbox_id_for(&k2)); // key-specific
                                                              // Domain-separated: not a bare blake3 of the key.
        assert_ne!(mailbox_id_for(&k1), *blake3::hash(&k1).as_bytes());
    }

    #[test]
    fn fetch_batch_honours_byte_budget_and_reports_more() {
        let mut mb = Mailbox::with_defaults();
        // Four 100-byte messages; a 250-byte budget takes the first two.
        for _ in 0..4 {
            mb.deposit(id(1), vec![0u8; 100], 0, HOUR).unwrap();
        }
        let (batch, more) = mb.fetch_batch(&id(1), 0, 250);
        assert_eq!(batch.len(), 2, "250B budget fits two 100B msgs, not three");
        assert!(more, "two of four remain");
        assert_eq!(mb.total(), 2);
        // Second fetch drains the rest.
        let (batch2, more2) = mb.fetch_batch(&id(1), 0, 250);
        assert_eq!(batch2.len(), 2);
        assert!(!more2);
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.mailbox_count(), 0);
    }

    #[test]
    fn fetch_batch_always_makes_progress_on_oversized_first_message() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), vec![0u8; 5000], 0, HOUR).unwrap();
        // Budget below the single message's size — it must still come back
        // alone, else it could never be retrieved.
        let (batch, more) = mb.fetch_batch(&id(1), 0, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].len(), 5000);
        assert!(!more);
        assert_eq!(mb.total(), 0);
        assert_eq!(mb.total_bytes(), 0, "byte accounting follows the drain");
    }

    /// Deposits are UNAUTHENTICATED by construction — a depositor is a sender,
    /// who cannot hold the recipient's secret. So memory must be bounded by
    /// policy, and the message-COUNT caps alone do not do that: at the defaults
    /// `max_total_msgs * max_msg_bytes` is hundreds of gigabytes. The byte
    /// ceiling is the guard that actually stops a remote flooder.
    #[test]
    fn a_flooder_cannot_exceed_the_global_byte_ceiling() {
        let policy = MailboxPolicy {
            max_total_bytes: 10_000,
            max_msg_bytes: 4_000,
            // Deliberately generous count caps: this proves the BYTE cap is
            // what stops the flood, not the count caps.
            max_msgs_per_mailbox: 1_000_000,
            max_total_msgs: 1_000_000,
            ..MailboxPolicy::default()
        };
        let mut mb = Mailbox::new(policy);
        // Two 4 KB deposits fit (8000 ≤ 10000); the third would reach 12000.
        mb.deposit(id(1), vec![0u8; 4_000], 0, HOUR).unwrap();
        mb.deposit(id(2), vec![0u8; 4_000], 0, HOUR).unwrap();
        assert_eq!(mb.total_bytes(), 8_000);
        assert_eq!(
            mb.deposit(id(3), vec![0u8; 4_000], 0, HOUR),
            Err(DepositError::StoreFull),
            "the byte ceiling must refuse the deposit that would cross it"
        );
        // Still under the ceiling for a smaller message — the cap bounds bytes,
        // it does not wedge the mailbox shut.
        mb.deposit(id(3), vec![0u8; 2_000], 0, HOUR).unwrap();
        assert_eq!(mb.total_bytes(), 10_000);
        assert_eq!(mb.total(), 3);

        // Draining frees the budget again.
        let (batch, _) = mb.fetch_batch(&id(1), 0, usize::MAX);
        assert_eq!(batch.len(), 1);
        assert_eq!(mb.total_bytes(), 6_000);
        mb.deposit(id(4), vec![0u8; 4_000], 0, HOUR).unwrap();
    }

    /// Byte accounting must survive every removal path, or the ceiling drifts
    /// and eventually locks a healthy relay out of accepting any deposit.
    #[test]
    fn byte_accounting_stays_exact_across_expiry_prune_and_fetch() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), vec![0u8; 100], 0, 10).unwrap(); // expires at 10
        mb.deposit(id(1), vec![0u8; 250], 0, HOUR).unwrap();
        mb.deposit(id(2), vec![0u8; 400], 0, 10).unwrap(); // expires at 10
        assert_eq!(mb.total_bytes(), 750);

        // prune_expired drops the two short-TTL entries.
        assert_eq!(mb.prune_expired(20), 2);
        assert_eq!(mb.total_bytes(), 250);
        assert_eq!(mb.total(), 1);

        // fetch (the whole-mailbox variant) also settles the byte count.
        assert_eq!(mb.fetch(&id(1), 20).len(), 1);
        assert_eq!(mb.total_bytes(), 0);
        assert_eq!(mb.total(), 0);

        // …and so does a snapshot round-trip.
        mb.deposit(id(5), vec![0u8; 333], 0, HOUR).unwrap();
        let restored = Mailbox::from_snapshot(MailboxPolicy::default(), mb.snapshot(), 0);
        assert_eq!(restored.total_bytes(), 333);
    }

    #[test]
    fn fetch_batch_skips_expired_and_unknown_is_empty() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"old".to_vec(), 0, HOUR).unwrap(); // expires at 3600
        mb.deposit(id(1), b"fresh".to_vec(), 0, 10 * HOUR).unwrap();
        let (batch, more) = mb.fetch_batch(&id(1), 2 * HOUR, MAX_MAILBOX_FRAME);
        assert_eq!(batch, vec![b"fresh".to_vec()]);
        assert!(!more);
        assert_eq!(mb.total(), 0);
        // Unknown mailbox → empty, no panic.
        assert_eq!(mb.fetch_batch(&id(2), 0, 1024), (Vec::new(), false));
    }

    #[test]
    fn wire_requests_and_responses_round_trip() {
        let reqs = [
            MailboxRequest::Deposit {
                id: id(1),
                sealed: vec![1, 2, 3, 4],
                ttl_secs: 3600,
            },
            MailboxRequest::Fetch {
                id: id(2),
                auth: None,
            },
        ];
        for r in &reqs {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(&MailboxRequest::from_bytes(&bytes).unwrap(), r);
        }
        let resps = [
            MailboxResponse::Ack,
            MailboxResponse::Delivery {
                sealed: vec![vec![9, 9], vec![8]],
                more: true,
            },
            MailboxResponse::Error(MailboxWireError::StoreFull),
        ];
        for r in &resps {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(&MailboxResponse::from_bytes(&bytes).unwrap(), r);
        }
    }

    #[test]
    fn snapshot_round_trips_and_drops_expired_on_restore() {
        let mut mb = Mailbox::with_defaults();
        mb.deposit(id(1), b"keep".to_vec(), 0, 10 * HOUR).unwrap();
        mb.deposit(id(1), b"stale".to_vec(), 0, HOUR).unwrap(); // expires at 3600
        mb.deposit(id(2), b"other".to_vec(), 0, 10 * HOUR).unwrap();

        let snap = mb.snapshot();
        // Serialize like the relay would persist it, then restore at t=2h.
        let bytes = rmp_serde::to_vec_named(&snap).unwrap();
        let restored: MailboxSnapshot = rmp_serde::from_slice(&bytes).unwrap();
        let mb2 = Mailbox::from_snapshot(MailboxPolicy::default(), restored, 2 * HOUR);

        assert_eq!(mb2.total(), 2, "the stale entry is dropped on restore");
        assert_eq!(mb2.pending(&id(1), 2 * HOUR), 1);
        assert_eq!(mb2.pending(&id(2), 2 * HOUR), 1);
    }
}
