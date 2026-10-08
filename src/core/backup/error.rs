//! Port of `core/backup/error.ts`. One enum instead of an exception hierarchy —
//! `match` on the variant instead of `instanceof`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MajikKeyBackupError {
    /// A capability the TS lib pulls from an optional peer dependency wasn't supplied
    /// (here: a [`PngCodec`](crate::core::backup::utils::PngCodec) for the MajikByte PNG format).
    #[error("\"{pkg}\" is required to {feature}.")]
    MissingOptionalDependency { pkg: String, feature: String },

    /// A JSON payload (bare, or decoded from a PNG/zip) failed shape validation.
    #[error("Invalid backup JSON: {0}")]
    InvalidBackupJson(String),

    /// A PNG file wasn't a valid MajikByte, or its decoded payload wasn't a valid backup.
    #[error("Invalid backup PNG: {0}")]
    InvalidBackupPng(String),

    /// A .zip archive contained no valid backup.png or backup.json anywhere inside it.
    #[error("Invalid backup archive: {0}")]
    InvalidBackupZip(String),

    /// A zip contained both a valid PNG and a valid JSON backup, but they describe different accounts.
    #[error("Backup archive contains conflicting payloads: {0}")]
    BackupIntegrityMismatch(String),
}

pub type BackupResult<T> = Result<T, MajikKeyBackupError>;
