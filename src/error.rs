use thiserror::Error;

/// Mirrors `MajikKeyError` from the TS lib. `thiserror` gives us a proper
/// error enum instead of a single class with an `unknown` cause — each
/// variant documents exactly what can go wrong, and `#[from]` lets us use
/// `?` to propagate underlying crate errors without manual wrapping.
#[derive(Debug, Error)]
pub enum MajikKeyError {
    #[error("Invalid BIP39 mnemonic phrase")]
    InvalidMnemonic,

    #[error("Invalid BIP39 mnemonic language: {0}")]
    InvalidMnemonicLanguage(String),

    #[error("Mnemonic does not match the specified wordlist language")]
    MnemonicLanguageMismatch,

    #[error("Passphrase validation failed: {0}")]
    InvalidPassphrase(String),

    #[error("Label validation failed: {0}")]
    InvalidLabel(String),

    #[error("MajikKey is locked. Call unlock() first.")]
    Locked,

    #[error("MajikKey is already unlocked")]
    AlreadyUnlocked,

    #[error("Decryption failed — incorrect passphrase or corrupted data")]
    DecryptionFailed,

    #[error("Failed to decrypt ML-KEM secret key")]
    MlKemDecryptionFailed,

    #[error("Failed to decrypt signing key")]
    SigningKeyDecryptionFailed,

    #[error("MajikKey is missing secret keys — re-import via importFromMnemonicBackup() first")]
    MissingSecretKeys,

    #[error("No {0} secret key — re-import via importFromMnemonicBackup() for full migration")]
    MissingKeyMaterial(&'static str),

    #[error("Invalid backup format")]
    InvalidBackupFormat,

    #[error("Failed to decrypt backup — invalid mnemonic or corrupted data")]
    BackupDecryptionFailed,

    #[error("Invalid MajikKeyJSON — missing required fields")]
    InvalidJson,

    #[error("Invalid MajikKeyDangerousJSON — missing required fields")]
    InvalidDangerousJson,

    #[error("Unsupported mnemonic language")]
    UnsupportedLanguage,

    #[error("Failed to derive Bitcoin keypair from seed")]
    BitcoinDerivationFailed,

    #[error("Bitcoin address derivation requires the `bitcoin` feature")]
    BitcoinFeatureDisabled,

    #[error("Expected a 64-byte Ed25519 secret key, got {0} bytes")]
    InvalidEd25519SecretKeyLength(usize),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),

    #[error("{0}")]
    InvalidId(String),
}

pub type MajikKeyResult<T> = Result<T, MajikKeyError>;
