/// Domain-separation strings — identical values to the TS `constants.ts`,
/// kept byte-for-byte the same so accounts stay cross-compatible between
/// the TS and Rust implementations.
pub const MAJIK_SALT: &str = "MajikMessageSalt";
pub const MAJIK_MNEMONIC_SALT: &str = "MajikMessageMnemonicSalt";
pub const MAJIK_SIGNATURE_SEED: &str = "MajikSignatureSeedDSA";

/// KDF version identifiers, stored alongside every encrypted blob so the
/// correct derivation function is always used on decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum KdfVersion {
    /// legacy — read-only support for existing accounts
    Pbkdf2 = 1,
    /// current — all new accounts and re-encryptions
    Argon2id = 2,
}

impl KdfVersion {
    pub fn from_u8(v: u8) -> Self {
        match v {
            2 => KdfVersion::Argon2id,
            _ => KdfVersion::Pbkdf2, // default matches TS `?? KDF_VERSION.PBKDF2`
        }
    }
}

/// Argon2id parameters. Values match `ARGON2_PARAMS` in the TS lib exactly —
/// same memory/time/parallelism cost so a passphrase produces the same key
/// on both implementations.
pub struct Argon2Params {
    pub mem_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_len: usize,
}

pub const ARGON2_PASSPHRASE_PARAMS: Argon2Params = Argon2Params {
    mem_cost_kib: 65536, // 64 MB
    time_cost: 3,
    parallelism: 4,
    output_len: 32,
};

pub const ARGON2_MNEMONIC_PARAMS: Argon2Params = Argon2Params {
    mem_cost_kib: 65536, // 64 MB
    time_cost: 3,
    parallelism: 2,
    output_len: 32,
};

/// AES-GCM IV length in bytes — matches `IV_LENGTH` in crypto-provider.ts.
pub const IV_LENGTH: usize = 12;

/// Salt size used for the shared per-identity Argon2id salt.
pub const SALT_SIZE: usize = 32;
