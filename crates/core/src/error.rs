//! Errors when reading the 1Password format.

use thiserror::Error;

/// Result of an operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A failure while reading the format.
#[derive(Debug, Error)]
pub enum Error {
    /// Database or file not found.
    #[error("no such path: {0}")]
    NotFound(String),

    /// Less data than parsing needs.
    #[error("data truncated: got {have}, need {need}")]
    Truncated {
        /// How many bytes are present.
        have: usize,
        /// How many are required.
        need: usize,
    },

    /// SQLite failure.
    #[error("SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Cryptography failure or malformed blob.
    #[error("crypto/format: {0}")]
    Crypto(String),

    /// HMAC did not match — decryption would be meaningless.
    #[error("HMAC mismatch ({0}), decryption is impossible")]
    HmacNotVerified(String),

    /// The `opdata01` header was not recognized.
    #[error("expected opdata01 magic, got {0:?}")]
    BadMagic([u8; 8]),

    /// Key unavailable: the KDF has not been recovered yet.
    #[error("key unavailable: {0}")]
    KeyUnavailable(String),

    /// I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse failure.
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}
