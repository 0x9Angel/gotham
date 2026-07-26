// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Gotham packet — full 2048 B wire format and wrap/unwrap pipeline.
//!
//! See `docs/gotham/README.md` §3 for the format and §4 for the cryptographic operations.

// TODO P1.8: GothamPacket::wrap(payload, route, rng) -> [u8; PACKET_SIZE]
// TODO P1.9: GothamPacket::unwrap_at_relay(packet, relay_keys)
//             -> Forward { next_hop, packet_out } | DeliverLocal { plaintext }
// TODO P1.10: Padding strategy (zero-fill + length-hiding)
