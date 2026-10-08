//! Port of `core/types.ts`. TS interfaces become serde structs (camelCase on the
//! wire, so JSON is interchangeable with the TypeScript library).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::core::crypto::wordlist::MnemonicLanguage;
use crate::core::keys::key_id::KeyId;
use crate::core::keys::types::KeyEntryJson;

/// Owned secret bytes that are wiped on drop.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// ISO 8601 timestamp string, e.g. `"2026-07-11T00:00:00.000Z"`.
pub type ISODateString = String;
/// Base64-encoded public key material. Safe to store, log, or transmit.
pub type MajikKeyAddress = String;
/// Base64-encoded SHA-256 digest of a MajikKey's X25519 public key. Doubles as the account `id`.
pub type MajikKeyFingerprint = String;

pub type ED25519PublicKey = String;
pub type MLKEM768PublicKey = String;
pub type MLDSA87PublicKey = String;
pub type BitcoinPublicKey = String;

pub type ED25519RawPublicKey = [u8; 32];
pub type MLKEM768RawPublicKey = Vec<u8>;
pub type MLDSA87RawPublicKey = Vec<u8>;
pub type BitcoinRawPublicKey = Vec<u8>;

/// An X25519 key as raw bytes (TS: `{ raw: Uint8Array }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519RawKey {
    pub raw: [u8; 32],
}

/// Safe, serializable snapshot of a MajikKey — what `to_json()` produces.
///
/// Every `encrypted*` field is an AES-256-GCM ciphertext (IV + ciphertext,
/// base64) protected by a passphrase-derived Argon2id key (or legacy PBKDF2,
/// see `kdf_version`). None of these fields ever contain raw private key
/// material, so this shape is safe to persist at rest.
///
/// Notes on optionality (the TS interface over-promises): `encrypted_private_key`
/// is absent when serialized with `legacy: false`, and registry-shaped JSON
/// need not carry the flat legacy fields at all.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikKeyJson {
    /// Account identifier. Equal to `fingerprint` for accounts created by this library.
    pub id: MajikKeyFingerprint,
    /// Human-readable, user-editable account name.
    #[serde(default)]
    pub label: String,
    /// X25519 public key, base64.
    #[serde(default)]
    pub public_key: MajikKeyAddress,
    /// SHA-256 fingerprint of `public_key`.
    pub fingerprint: MajikKeyFingerprint,
    /// Random salt for the passphrase-derived key. Shared across all key types on this account.
    pub salt: String,
    /// Encrypted mnemonic-verification blob (base64 JSON).
    pub backup: String,
    /// Account creation time, ISO 8601.
    pub timestamp: ISODateString,
    /// `1` = legacy PBKDF2 (read-only), `2` = Argon2id (current). Defaults to `1` if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_version: Option<u8>,
    /// BIP-39 wordlist language of the original mnemonic. Defaults to `"en"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic_language: Option<MnemonicLanguage>,

    /// Registry schema version. Absent on pre-registry JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys_version: Option<u32>,
    /// Every keypair on the account (public key + passphrase-encrypted secret + derivation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<KeyEntryJson>>,

    // ── flat pre-registry fields (written when `legacy: true`) ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_kem_public_key: Option<MLKEM768PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_ml_kem_secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed_public_key: Option<ED25519PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_ed_secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_public_key: Option<MLDSA87PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_ml_dsa_secret_key: Option<String>,
    /// @experimental secp256k1 Bitcoin public key, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btc_public_key: Option<BitcoinPublicKey>,
    /// @experimental
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_btc_secret_key: Option<String>,
}

/// ⚠️ DANGEROUS. Every `*_base64` field below is a *raw, unencrypted* private
/// key — no passphrase, no KDF, no AES-GCM. Anyone with this object has full
/// control of the account. Intended only for injecting a pre-unlocked key into
/// a server process at boot (e.g. from a secrets manager).
///
/// The secret strings are zeroized on drop.
///
/// Produced by `to_dangerous_json()`, consumed by `MajikKey::from_dangerous_json()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikKeyDangerousJson {
    #[serde(flatten)]
    pub base: MajikKeyJson,
    /// ⚠️ Raw X25519 private key, base64.
    pub private_key_base64: String,
    /// ⚠️ Raw ML-KEM-768 secret key (2400-byte expanded form), base64.
    pub ml_kem_secret_key_base64: String,
    /// ⚠️ Raw Ed25519 secret key (64 bytes), base64.
    pub ed_secret_key_base64: String,
    /// ⚠️ Raw ML-DSA-87 secret key (4896 bytes), base64.
    pub ml_dsa_secret_key_base64: String,
    /// @experimental ⚠️ Raw Bitcoin private key, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btc_secret_key_base64: Option<String>,
    /// ⚠️ Raw secret of every stored key, base64, keyed by namespaced id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_keys: Option<BTreeMap<String, String>>,
}

impl Drop for MajikKeyDangerousJson {
    fn drop(&mut self) {
        self.private_key_base64.zeroize();
        self.ml_kem_secret_key_base64.zeroize();
        self.ed_secret_key_base64.zeroize();
        self.ml_dsa_secret_key_base64.zeroize();
        self.btc_secret_key_base64.zeroize();
        if let Some(m) = self.secret_keys.as_mut() {
            for v in m.values_mut() {
                v.zeroize();
            }
        }
    }
}

/// Presence flags for optional Web3 key material (@experimental).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_bitcoin: Option<bool>,
    /// `true` if this account can derive a Solana keypair (has Ed25519 and is unlocked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_solana: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_ethereum: Option<bool>,
}

/// Lightweight, non-secret summary of a MajikKey — contains no key bytes at all.
/// Get one via `MajikKey::metadata()`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikKeyMetadata {
    pub id: String,
    pub fingerprint: MajikKeyFingerprint,
    pub label: String,
    pub timestamp: ISODateString,
    /// `true` if private key material is currently purged from memory.
    pub is_locked: bool,
    /// `1` = legacy PBKDF2, `2` = Argon2id.
    pub kdf_version: u8,
    /// `true` if this account has ML-KEM-768 keys.
    pub has_ml_kem: bool,
    pub web3: Web3Metadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic_language: Option<MnemonicLanguage>,
    /// Namespaced ids of every key available on the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<KeyId>>,
}

/// Portable seed export — the format behind `to_mnemonic_json()` / `MajikKey::from_mnemonic_json()`.
///
/// ⚠️ **Not an encrypted-at-rest format.** `seed` is the raw mnemonic, split
/// into words, in plaintext (and `phrase`, if present, too). Treat it exactly
/// like the mnemonic itself. Zeroized on drop.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicJson {
    /// Raw mnemonic, split into individual words. ⚠️ Plaintext — this *is* the recovery phrase.
    pub seed: Vec<String>,
    /// The account's encrypted backup blob (`MajikKeyJson.backup`).
    pub id: String,
    /// Optional passphrase, carried in plaintext. ⚠️ Not encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<MnemonicLanguage>,
    /// Backup format version this payload was written with. See `BACKUP_FORMAT_VERSION`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl Drop for MnemonicJson {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.phrase.zeroize();
    }
}
