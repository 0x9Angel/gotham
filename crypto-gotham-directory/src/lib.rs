// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

#![forbid(unsafe_code)]
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

pub const WIRE_VERSION: u8 = 3;
