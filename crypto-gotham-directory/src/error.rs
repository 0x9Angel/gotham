//! Error types for the gossip directory.

use thiserror::Error;

/// All errors the directory crate can return.
#[derive(Debug, Error)]
pub enum DirectoryError {
    /// I/O error reading/writing the roster file.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialisation/deserialisation error.
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Ed25519 signature did not verify against the claimed identity.
    #[error("signature verify failed")]
    BadSignature,

    /// Advertisement carried a sequence number ≤ the one we already
    /// have for this identity — anti-replay rejection.
    #[error("advertisement seq {got} not greater than current {have}")]
    StaleSeq {
        /// The seq number on the rejected advertisement.
        got: u64,
        /// The seq number we already have for this identity.
        have: u64,
    },

    /// Wire format version mismatch.
    #[error("wire version mismatch: got {0}, expected {expected}", expected = crate::WIRE_VERSION)]
    WireVersionMismatch(u8),

    /// Hex decoding error (used for pubkey + signature fields).
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A relay's k-of-n admission certificate carried fewer valid, distinct
    /// authority signatures than the pinned [`AuthoritySet`](crate::AuthoritySet)
    /// threshold requires — Sybil-resistance rejection.
    #[error("admission quorum not met: {got} valid authority signatures, need {need}")]
    InsufficientQuorum {
        /// Distinct valid authority signatures found.
        got: usize,
        /// Threshold `k` required by the authority set.
        need: usize,
    },

    /// An admission certificate's `identity_pk_hex` did not match the
    /// advertisement it was presented with.
    #[error("admission identity does not match advertisement")]
    IdentityMismatch,

    /// An admission certificate's epoch is outside the accepted freshness
    /// window (too old — revoked-by-non-renewal — or implausibly far future).
    #[error("admission certificate epoch is not fresh")]
    AdmissionExpired,

    /// Generic catch-all with a free-form message.
    #[error("{0}")]
    Other(String),
}

/// Shorthand `Result` type for the directory crate.
pub type Result<T> = std::result::Result<T, DirectoryError>;
