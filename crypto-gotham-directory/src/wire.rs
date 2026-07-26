// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

//! Shared HTTP wire types for k-of-n decentralised admission, used by BOTH the
//! directory authority (producer) and the Crypto app (consumer). Keeping them in
//! one place stops the two sides from drifting out of sync.
//!
//! The trust model: an authority never asserts a global roster the app must
//! believe. Instead each authority independently signs one relay's
//! `(identity, epoch, operator)` tuple (an [`Attestation`]) and serves it at
//! `GET /admissions`. The app pins the [`AuthoritySet`](crate::AuthoritySet),
//! collects these across the pinned authorities, assembles an
//! [`AdmissionCert`](crate::AdmissionCert) per relay identity, and admits the
//! relay only if a quorum verifies — so forging a relay costs `k` authority
//! compromises, and no single serving authority is trusted for admission.

use serde::{Deserialize, Serialize};

use crate::attestation::Attestation;

/// Response body from an authority's `POST /enroll`.
///
/// Additive by design: a legacy relay that only checks the HTTP status code
/// ignores this body. A decentralised relay reads `attestation` as a receipt
/// that this authority vouched for it at `epoch` — present iff the relay
/// proposed an `attest_epoch` the authority accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EnrollResponse {
    /// This authority's admission attestation for the just-enrolled relay, or
    /// `None` when the relay proposed no epoch (legacy) or the authority
    /// declined the proposed epoch (out of its acceptance window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    /// The epoch the attestation is bound to, echoed for the relay's records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

/// One relay's admission attestation as served by a single authority at
/// `GET /admissions`.
///
/// The app collects these across the pinned authorities and, per
/// `identity_pk_hex`, assembles an [`AdmissionCert`](crate::AdmissionCert) whose
/// attestations it checks against the pinned [`AuthoritySet`](crate::AuthoritySet).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdmissionEntry {
    /// The relay's identity — its hex X25519 kem/id key. The app matches this to
    /// a directory descriptor's `kem_pubkey_hex` (a self-enrolled relay uses one
    /// key for both slots).
    pub identity_pk_hex: String,
    /// The epoch the relay proposed and this authority signed.
    pub epoch: u64,
    /// The operator label this authority attested (echoed from the enrollment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// This authority's signature over `(identity, epoch, operator)`.
    pub attestation: Attestation,
}
