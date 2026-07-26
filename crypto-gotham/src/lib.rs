// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! # Gotham
//!
//! Low-latency, post-quantum-hybrid mixnet protocol for the Crypto suite.
//!
//! Gotham is a Sphinx-style onion-routed packet format with built-in cover
//! traffic and Poisson-delay mixing. It is designed to deliver:
//!
//! - **Anonymity** at the level of single-relay collusion (resistance to GPA
//!   is explicitly out of scope — see [`THREAT_MODEL`](crate::THREAT_MODEL)).
//! - **Low latency** — 100-300 ms median round-trip (vs 800-2000 ms for Tor).
//! - **Post-quantum hybrid** key encapsulation (X25519 + ML-KEM-768).
//! - **Stateless relays** with replay protection (5 min HMAC cache).
//! - **Fixed-size packets** (2048 bytes) — traffic analysis resistant by
//!   construction.
//!
//! ## Crate structure
//!
//! | Module            | Role                                                    |
//! |-------------------|---------------------------------------------------------|
//! | [`packet`]        | Sphinx packet format (wrap / unwrap)                    |
//! | [`header`]        | Header construction + MAC chain                         |
//! | [`hybrid`]        | X25519 + ML-KEM-768 hybrid KEM primitive                |
//! | [`route`]         | Path selection + route descriptor                       |
//! | [`relay`]         | Relay-side packet processor + replay cache              |
//! | [`cover`]         | Cover traffic Poisson scheduler                         |
//! | [`directory`]     | Signed relay directory parsing + verification           |
//! | [`error`]         | All `Result<T, Error>` types                            |
//!
//! ## Status
//!
//! **Pre-alpha, do not deploy.** See `docs/gotham/README.md` for the spec and
//! `docs/gotham/README.md` for the implementation roadmap.

// Crate-level lint policy: production code MUST NOT call unwrap()/expect()
// on Result/Option, because a panic on a crypto primitive's hot path leaks
// timing + crashes the relay. Tests get an `allow` because property-based +
// round-trip assertions are clearer with unwrap on known-good fixtures.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![warn(missing_docs)]
// Worm-resistance: the packet path must never contain memory-unsafe code, so a
// crafted packet can never corrupt memory / achieve RCE on a relay. `forbid`
// (stronger than `deny`) means no inner `allow` can ever re-enable unsafe.
#![forbid(unsafe_code)]

pub mod cover;
pub mod directory;
pub mod enroll;
pub mod error;
pub mod header;
pub mod hybrid;
pub mod lioness;
pub mod mailbox;
pub mod packet;
pub mod relay;
pub mod route;
pub mod sealed;

pub use error::{Error, Result};

/// Protocol version identifier — bumped on any wire-format change.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fixed Gotham packet size in bytes.
///
/// All packets — real, dummy, loop, ack — are exactly this size after
/// padding. This is the cornerstone of traffic analysis resistance.
pub const PACKET_SIZE: usize = 2048;

/// Header size within a packet.
pub const HEADER_SIZE: usize = 384;

/// Payload size = `PACKET_SIZE - HEADER_SIZE`.
pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

/// Maximum number of hops a Gotham packet may traverse.
///
/// The protocol supports 3..=5 hops; client selects per-packet based on the
/// configured anonymity mode (`low-latency` / `balanced` / `paranoid`).
pub const MAX_HOPS: usize = 5;

/// Inline threat model summary. The full document lives in `docs/gotham/README.md` §9.
pub const THREAT_MODEL: &str = "\
Gotham resists:                                                              \n\
  - Passive network observers (ISP, café WiFi)                               \n\
  - Single-relay compromise (any tier)                                       \n\
  - Replay attacks (5-min HMAC cache)                                        \n\
  - Tagging attacks (MAC chain)                                              \n\
  - Timing correlation < state scale (Poisson delays + cover traffic)        \n\
  - Quantum adversary (X25519 + ML-KEM-768 hybrid)                           \n\
                                                                             \n\
Gotham does NOT resist:                                                      \n\
  - Global Passive Adversary (NSA-level, 5-Eyes)                             \n\
  - Majority-relay compromise (> 60% of pool hostile)                        \n\
  - Endpoint compromise (malware on user device)                             \n\
  - Forced key disclosure with non-ephemeral material                        \n\
                                                                             \n\
No production deployment without third-party audit (Trail of Bits / NCC /    \n\
Quarkslab / Synacktiv).";
