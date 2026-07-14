use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::constants::KdfVersion;
use crate::crypto::wordlist::MnemonicLanguage;

/// Base64-encoded SHA-256 digest of a MajikKey's X25519 public key.
/// Doubles as the account `id`. Mirrors `MajikKeyFingerprint` in types.ts.
pub type MajikKeyFingerprint = String;

/// Base64-encoded public key material. Mirrors `MajikKeyAddress`.
pub type MajikKeyAddress = String;

/// Safe, serializable snapshot of a MajikKey — what `to_json()` /
/// `to_string()` produce. Every `encrypted_*` field is an AES-256-GCM
/// ciphertext (IV + ciphertext, base64), protected by a passphrase-derived
/// Argon2id key (or legacy PBKDF2 — see `kdf_version`). None of these
/// fields ever contain raw private key material.
///
/// `#[serde(rename_all = "camelCase")]` keeps the wire format identical to
/// the TS lib's `MajikKeyJSON` — this matters for cross-compatibility:
/// a JSON blob produced by either implementation must be loadable by both.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikKeyJson {
    pub id: String,
    pub label: String,
    /// X25519 public key, base64.
    pub public_key: MajikKeyAddress,
    pub fingerprint: MajikKeyFingerprint,
    /// AES-256-GCM-encrypted X25519 private key (IV + ciphertext), base64.
    pub encrypted_private_key: String,
    /// Random salt used to derive the passphrase-based encryption key.
    /// Shared across all key types on this account.
    pub salt: String,
    /// Encrypted mnemonic-verification blob (base64 JSON). Decryptable
    /// only with the original mnemonic.
    pub backup: String,
    /// Account creation time, ISO 8601.
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_version: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_kem_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_ml_kem_secret_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_ed_secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_dsa_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_ml_dsa_secret_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_btc_secret_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_language: Option<MnemonicLanguage>,
}

/// ⚠️ DANGEROUS. Every `*_base64` field below is a *raw, unencrypted*
/// private key — no passphrase, no KDF, no AES-GCM. Mirrors
/// `MajikKeyDangerousJSON`. Server-side secret injection only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikKeyDangerousJson {
    #[serde(flatten)]
    pub base: MajikKeyJson,

    pub private_key_base64: String,
    pub ml_kem_secret_key_base64: String,
    pub ed_secret_key_base64: String,
    pub ml_dsa_secret_key_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btc_secret_key_base64: Option<String>,
}

/// Lightweight, non-secret summary of a MajikKey — no key bytes at all,
/// encrypted or otherwise. Mirrors `MajikKeyMetadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikKeyMetadata {
    pub id: String,
    pub fingerprint: MajikKeyFingerprint,
    pub label: String,
    /// ISO 8601 — kept as a String here rather than pulling in a datetime
    /// crate; callers needing a real `DateTime` can parse it themselves.
    pub timestamp: String,
    pub is_locked: bool,
    pub kdf_version: u8,
    pub has_ml_kem: bool,
    pub web3: Web3Metadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_language: Option<MnemonicLanguage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_bitcoin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_solana: Option<bool>,
}

/// Portable seed export — the format behind `to_mnemonic_json()` /
/// `MajikKey::from_mnemonic_json()`.
///
/// ⚠️ Unlike `MajikKeyJson`, this is **not** an encrypted-at-rest format.
/// `seed` is the raw mnemonic, split into words, in plaintext. Treat any
/// `MnemonicJson` exactly like the mnemonic itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicJson {
    /// Raw mnemonic, split into individual words. ⚠️ Plaintext.
    pub seed: Vec<String>,
    /// The account's encrypted backup blob, carried along so this object
    /// alone is enough to call `import_from_mnemonic_backup()`.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
}

/// In-memory identity bundle for an unlocked MajikKey.
/// Mirrors the TS lib's `MajikKeyIdentity` shape as closely as possible.
pub struct MajikKeyIdentity {
    pub id: String,
    pub public_key: [u8; 32],
    pub fingerprint: String,
    pub private_key: Zeroizing<[u8; 32]>,
    pub encrypted_private_key: Vec<u8>,
    pub salt: String,
    pub kdf_version: u8,
    pub ml_kem_public_key: Vec<u8>,
    pub ml_kem_secret_key: Zeroizing<[u8; 64]>,
}

/// Lightweight serialized identity suitable for transport/storage.
/// Mirrors the TS lib's `SerializedIdentity` shape.
pub struct SerializedIdentity {
    pub id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub encrypted_private_key: String,
    pub salt: String,
}

impl From<KdfVersion> for u8 {
    fn from(v: KdfVersion) -> Self {
        v as u8
    }
}
