//! Errors — port of `core/error.ts` (+ `CryptoError` from the encryption engine).
//!
//! The TS lib has one `MajikKeyError` class carrying a message and an optional
//! `cause`. In Rust that becomes a single `thiserror` enum: the common failure
//! modes get their own variants (so callers can `match` instead of
//! string-comparing), everything else goes through [`MajikKeyError::Message`].

use thiserror::Error;

pub type MajikKeyResult<T> = Result<T, MajikKeyError>;

#[derive(Debug, Error)]
pub enum MajikKeyError {
    /// Generic error with a human-readable message (TS: `new MajikKeyError(msg)`).
    #[error("{0}")]
    Message(String),

    /// A message plus the underlying error (TS: `new MajikKeyError(msg, cause)`).
    #[error("{message}: {source}")]
    WithCause {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("MajikKey is locked. Call unlock() first.")]
    Locked,

    #[error("MajikKey is already unlocked")]
    AlreadyUnlocked,

    #[error("No \"{0}\" key on this account")]
    KeyNotFound(String),

    #[error("Invalid BIP39 mnemonic phrase")]
    InvalidMnemonic,

    #[error("Invalid MajikKey JSON: {0}")]
    InvalidJson(String),

    /// AES-GCM authentication failed (wrong passphrase / corrupted blob).
    #[error("Failed to decrypt {0} — incorrect passphrase or corrupted data")]
    DecryptionFailed(String),

    /// Mirrors the TS `CryptoError` thrown by the encryption engine.
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl MajikKeyError {
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn with_cause(
        message: impl Into<String>,
        cause: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::WithCause {
            message: message.into(),
            source: Box::new(cause),
        }
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }
}
