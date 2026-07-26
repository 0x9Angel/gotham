// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.
// See LICENSE-AGPL and LICENSE-COMMERCIAL in this crate's root.

//! Error types for the Gotham protocol.

use thiserror::Error;

/// Result alias for Gotham operations.
pub type Result<T> = std::result::Result<T, Error>;

/// All error categories that may arise during packet processing.
#[derive(Debug, Error)]
pub enum Error {
    /// The packet's header MAC failed verification. Drop silently in
    /// production paths — never log the source IP, as logging is an
    /// observation channel that defeats anonymity.
    #[error("header MAC verification failed")]
    BadMac,

    /// The packet was seen recently and is being silently dropped.
    #[error("replayed packet (already in 5-min cache)")]
    Replay,

    /// The packet contained an invalid version byte or shape.
    #[error("malformed packet: {0}")]
    Malformed(&'static str),

    /// A cryptographic primitive failed (e.g. KEM decapsulation, AEAD decrypt).
    #[error("crypto operation failed: {0}")]
    Crypto(&'static str),

    /// Routing information could not be parsed.
    #[error("routing error: {0}")]
    Routing(&'static str),

    /// Directory entry validation failed.
    #[error("directory entry invalid: {0}")]
    Directory(&'static str),

    /// I/O error from the transport layer.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Serde/MessagePack encoding error.
    #[error("encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    /// Serde/MessagePack decoding error.
    #[error("decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}
