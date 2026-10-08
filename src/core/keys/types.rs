//! Port of `core/keys/types.ts`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::keys::key_id::{KeyFamily, KeyId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPurpose {
    Kem,
    KeyAgreement,
    Signature,
    Wallet,
}

/// * `Stable` — standardized or production-grade, safe to enable
/// * `Experimental` — works, but the spec/impl may change
/// * `Reserved` — id is claimed but cannot be enabled yet
/// * `Unsupported` — deliberately not offered (see `note`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Stable,
    Experimental,
    Reserved,
    Unsupported,
}

/// `"stored"` = encrypted at rest in `keys`; `"derived"` = computed on demand from another key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Stored,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDerivation {
    /// `"legacy-v1"` | `"hkdf-sha512-v1"` | `"bip32"` | `"ed2curve"` | `"derived-view"`
    pub scheme: String,
    pub version: u32,
    /// HKDF info string, e.g. `"majik/v1/pq:ml-kem-1024"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
    /// BIP-32 path for web3 keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Free-form human note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Fields written by newer library versions — preserved, never interpreted.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One stored entry inside `MajikKeyJson.keys`. No raw secret ever lives here.
///
/// `id` is a plain `String` (not [`KeyId`]) on purpose: entries from NEWER
/// library versions carry ids this build doesn't know, and must round-trip
/// untouched. Use [`KeyId::parse`] to interpret it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEntryJson {
    pub id: String,
    /// Base64 public key.
    pub public_key: String,
    /// Base64 AES-256-GCM (IV ‖ ciphertext) under the account's passphrase-derived key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_secret_key: Option<String>,
    pub derivation: KeyDerivation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAlgorithmDefinition {
    pub id: KeyId,
    pub family: KeyFamily,
    pub purpose: KeyPurpose,
    pub kind: KeyKind,
    pub status: KeyStatus,
    /// True once derive/encrypt/decrypt are wired up in THIS crate.
    pub implemented: bool,
    /// Standard / spec this follows.
    pub standard: String,
    /// Recipe used when this key is derived for NEW accounts. Legacy accounts keep `"legacy-v1"`.
    pub derivation: KeyDerivation,
    /// For derived views: the stored key it is computed from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<KeyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
