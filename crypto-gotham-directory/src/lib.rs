// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! # crypto-gotham-directory — distributed Gotham relay roster
//!
//! CRDT-style gossip directory replacing the v0.1 static signed
//! directory. Each Crypto app instance acts as both a directory client
//! (consumes roster updates from peers) and a directory publisher
//! (emits its own [`Advertisement`] every ~5 min).
//!
//! ## Status
//!
//! What this crate currently provides:
//!
//! - [`Advertisement`] — the wire format a relay signs to claim it
//!   exists.
//! - [`Roster`] — the in-memory set of active relays with merge-on-
//!   insert semantics (last-writer-wins on `seq`).
//! - [`Roster::merge`] — CRDT-style merge with anti-replay via the
//!   monotonic `seq` field.
//! - [`Roster::save_to`] / [`Roster::load_from`] — JSON file roundtrip.
//! - **k-of-n authority attestation** ([`AuthoritySet`], [`AdmissionCert`]) —
//!   the Sybil-resistance trust anchor. A relay is admissible only if a quorum
//!   of pinned directory authorities has signed its identity. The gated
//!   [`Roster::insert_admitted`] / [`Roster::merge_admitted`] enforce this, so
//!   a peer cannot inject fake relays without `k` authority compromises.
//!
//! What this crate does NOT yet provide (Chantier 3.next):
//!
//! - **Gossip transport** — actual P2P exchange of admitted rosters between
//!   relays. Requires the embedded relay to expose a "directory port" + a poll
//!   loop; the verification layer above is now in place, so this is a
//!   transport-plumbing task (mirror the mailbox ALPN split).
//! - **Reputation scoring** — uptime / latency weighting on top of admission.
//! - **Bootstrap seeds** — a shipped list of first-contact authorities +
//!   relays the app pins to learn the initial peer set.

#![warn(missing_docs)]
// Worm-resistance: no memory-unsafe code on the gossip/roster path.
#![forbid(unsafe_code)]
// Deny panics in production code only — test modules legitimately use
// `unwrap()`/`expect()` as their assertion mechanism. Mirrors the
// convention already used by crypto-gotham and crypto-gotham-relay.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

mod advertisement;
mod attestation;
mod error;
mod roster;
mod wire;

pub use advertisement::{Advertisement, Capabilities};
pub use attestation::{
    AdmissionCert, Attestation, AuthoritySet, ADMISSION_CLOCK_SKEW_SECS, MAX_ADMISSION_AGE_SECS,
};
pub use error::{DirectoryError, Result};
pub use roster::{Roster, STALE_AFTER_SECS};
pub use wire::{AdmissionEntry, EnrollResponse};

/// Wire format version. Bump on any breaking change to
/// [`Advertisement`] or [`Roster`] serialisation. v2 added the X25519
/// `kem_pubkey_hex` routing key to [`Advertisement`]; v3 added the RFC B3
/// `rendezvous` / `rendezvous_capable` reverse-transport fields.
pub const WIRE_VERSION: u8 = 3;
