// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
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

pub const PROTOCOL_VERSION: u8 = 1;

pub const PACKET_SIZE: usize = 2048;

pub const HEADER_SIZE: usize = 384;

pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

pub const MAX_HOPS: usize = 5;

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
