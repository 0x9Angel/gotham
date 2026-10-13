// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Gotham-Commercial
// Copyright (C) 2026 0x9Angel.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("header MAC verification failed")]
    BadMac,

    #[error("replayed packet (already in 5-min cache)")]
    Replay,

    #[error("malformed packet: {0}")]
    Malformed(&'static str),

    #[error("crypto operation failed: {0}")]
    Crypto(&'static str),

    #[error("routing error: {0}")]
    Routing(&'static str),

    #[error("directory entry invalid: {0}")]
    Directory(&'static str),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),

    #[error("decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}
