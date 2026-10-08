//! Port of `core/backup/types.ts`.

use crate::core::crypto::wordlist::MnemonicLanguage;

/// Bump this whenever the *shape* of `MnemonicJson` or the zip layout changes in
/// a way that could break parsing of older backups.
pub const BACKUP_FORMAT_VERSION: u32 = 1;

/// Which artifact inside a parsed backup archive supplied the winning payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupSource {
    Png,
    Json,
}

/// Either the full mnemonic string or a pre-split word array.
#[derive(Debug, Clone)]
pub enum BackupSeed {
    Phrase(String),
    Words(Vec<String>),
}

impl From<&str> for BackupSeed {
    fn from(s: &str) -> Self {
        BackupSeed::Phrase(s.to_string())
    }
}
impl From<String> for BackupSeed {
    fn from(s: String) -> Self {
        BackupSeed::Phrase(s)
    }
}
impl From<Vec<String>> for BackupSeed {
    fn from(w: Vec<String>) -> Self {
        BackupSeed::Words(w)
    }
}

#[derive(Debug, Clone)]
pub struct CreateBackupParams {
    pub seed: BackupSeed,
    pub id: String,
    pub language: MnemonicLanguage,
    pub phrase: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ToZipOptions {
    /// Used only to build the human-facing filename hint; purely cosmetic.
    pub label: Option<String>,
}
