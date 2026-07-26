// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Route selection — picks an entry/mix/exit tuple from the directory.
//!
//! Path-selection constraints:
//! - No two hops from the same operator (when known)
//! - No two hops in the same /16 IPv4 or /48 IPv6 block
//! - Prefer geographically distributed relays (different countries)
//! - Per-packet path randomization in `paranoid` mode

// TODO P3.1: RelayDescriptor { id_pubkey, kem_pubkey, addr, tier, country }
// TODO P3.2: Route::pick(directory, mode = LowLatency | Balanced | Paranoid)
// TODO P3.3: constraint checking (operator diversity, AS diversity)
