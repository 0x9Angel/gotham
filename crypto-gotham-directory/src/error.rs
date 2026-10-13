use thiserror::Error;

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("signature verify failed")]
    BadSignature,

    #[error("advertisement seq {got} not greater than current {have}")]
    StaleSeq { got: u64, have: u64 },

    #[error("wire version mismatch: got {0}, expected {expected}", expected = crate::WIRE_VERSION)]
    WireVersionMismatch(u8),

    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("admission quorum not met: {got} valid authority signatures, need {need}")]
    InsufficientQuorum { got: usize, need: usize },

    #[error("admission identity does not match advertisement")]
    IdentityMismatch,

    #[error("admission certificate epoch is not fresh")]
    AdmissionExpired,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DirectoryError>;
