//! Port of `core/crypto/constants.ts`.

use serde::{Deserialize, Serialize};

// ── Salts ─────────────────────────────────────────────────────────────────────
// Current names (MajikKey). Used for everything written by this version.
pub const MAJIK_SALT: &str = "MajikKeySalt";
pub const MAJIK_MNEMONIC_SALT: &str = "MajikKeyMnemonicSalt";

/// Pre-0.8 salts ("MajikMessage…"). READ-ONLY: kept so backups and data
/// written by older versions still decrypt. Never use for new writes.
pub const LEGACY_MAJIK_SALT: &str = "MajikMessageSalt";
/// See [`LEGACY_MAJIK_SALT`]. Existing mnemonic backups were encrypted with this salt.
pub const LEGACY_MAJIK_MNEMONIC_SALT: &str = "MajikMessageMnemonicSalt";

/// Mnemonic-backup salt generations. The backup blob records which one it used
/// (`backupSaltVersion`); blobs without the field are generation 1.
pub struct BackupSaltVersion;
impl BackupSaltVersion {
    /// → [`LEGACY_MAJIK_MNEMONIC_SALT`] (every backup written before 0.8)
    pub const LEGACY: u8 = 1;
    /// → [`MAJIK_MNEMONIC_SALT`] (written by 0.8+)
    pub const CURRENT: u8 = 2;
}

/// Which generation NEW backups are written with. Readers handle both.
///
/// ⚠️ Older library versions (and the 0.0.1 Rust port) can only read
/// generation 1. Set this to [`BackupSaltVersion::LEGACY`] to keep newly
/// created backups readable by them.
pub const BACKUP_SALT_WRITE_VERSION: u8 = BackupSaltVersion::CURRENT;

pub fn backup_salt_for(v: Option<u8>) -> &'static str {
    if v == Some(BackupSaltVersion::CURRENT) {
        MAJIK_MNEMONIC_SALT
    } else {
        LEGACY_MAJIK_MNEMONIC_SALT
    }
}

/// ⚠️ FROZEN. Part of the legacy-v1 ML-DSA-87 derivation
/// (`sha256(seed || this)`). Changing it changes every existing user's ML-DSA key.
/// It intentionally still says "Majik…" and must NOT be renamed.
pub const MAJIK_SIGNATURE_SEED: &str = "MajikSignatureSeedDSA";

/// KDF version identifiers, stored alongside every encrypted blob so the
/// correct derivation function is always used on decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
#[repr(u8)]
pub enum KdfVersion {
    /// legacy — read-only support for existing accounts
    Pbkdf2 = 1,
    /// current — all new accounts and re-encryptions
    Argon2id = 2,
}

impl KdfVersion {
    /// Mirrors the TS truthiness check: anything that isn't `2` is the legacy KDF.
    pub fn from_u8(v: u8) -> Self {
        if v == 2 {
            KdfVersion::Argon2id
        } else {
            KdfVersion::Pbkdf2
        }
    }
}

impl From<u8> for KdfVersion {
    fn from(v: u8) -> Self {
        Self::from_u8(v)
    }
}

impl From<KdfVersion> for u8 {
    fn from(v: KdfVersion) -> u8 {
        v as u8
    }
}

/// Argon2id parameters.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// memory in KiB
    pub mem_cost_kib: u32,
    /// time cost (passes)
    pub time_cost: u32,
    /// parallelism (lanes)
    pub parallelism: u32,
    /// output length in bytes (256-bit AES key)
    pub output_len: usize,
}

pub const ARGON2_PASSPHRASE_PARAMS: Argon2Params = Argon2Params {
    mem_cost_kib: 65536, // 64 MB
    time_cost: 3,
    parallelism: 4,
    output_len: 32,
};

pub const ARGON2_MNEMONIC_PARAMS: Argon2Params = Argon2Params {
    mem_cost_kib: 65536,
    time_cost: 3,
    parallelism: 2,
    output_len: 32,
};

/// PBKDF2-SHA256 iteration counts for the legacy (KDF v1) derivations.
pub const PBKDF2_PASSPHRASE_ITERATIONS: u32 = 250_000;
pub const PBKDF2_MNEMONIC_ITERATIONS: u32 = 200_000;

/// Per-account random salt length.
pub const SALT_SIZE: usize = 32;
/// Schema version of the `keys` array in `MajikKeyJson`.
pub const KEYS_VERSION: u32 = 1;
