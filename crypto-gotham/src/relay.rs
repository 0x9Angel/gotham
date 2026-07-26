// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Relay-side packet processing.
//!
//! A Gotham relay is **stateless** by design — beyond a small in-memory
//! replay cache, it holds nothing persistent about the packets it forwards.
//! This is the key property that makes legal compulsion attacks fruitless.

// TODO P2.1: ReplayCache (HashSet<[u8; 32]> with bounded size + 5-min TTL)
// TODO P2.2: Relay::process(packet) -> Action { Forward | Drop | DeliverLocal }
// TODO P2.3: Per-hop Poisson delay scheduler (lambda configurable)
// TODO P2.4: Link-layer Noise XK handler (one session per peer)
