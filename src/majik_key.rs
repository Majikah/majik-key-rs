//! `majik-key.ts` — seed phrase account library for the Majikah ecosystem.
//!
//! Every account stores a set of keypairs in a [`KeyStore`], addressed by namespaced
//! [`KeyId`]. The core four (`classic:x25519`, `classic:ed25519`, `pq:ml-kem-768`,
//! `pq:ml-dsa-87`) are always present on new accounts; anything else is opt-in via
//! `options.keys` / [`MajikKey::add_keys`].
//!
//! Differences from TS, all deliberate:
//!  * **Sync API.** There's no WASM/WebCrypto to await. Argon2id blocks for a few hundred
//!    ms — call from `spawn_blocking` in async/UI contexts.
//!  * **`&str` inputs.** Pass `&Zeroizing<String>` freely (deref coercion); the library
//!    never keeps copies of mnemonics or passphrases, and every derived key is `Zeroizing`.
//!  * **`get_private_key(id)` always takes an id** (no no-arg X25519 overload).
//!  * Secrets returned to callers are owned `Zeroizing<Vec<u8>>` copies, wiped on drop.

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::core::crypto::constants::LEGACY_MAJIK_MNEMONIC_SALT;
use crate::core::crypto::constants::{
    backup_salt_for, KdfVersion, BACKUP_SALT_WRITE_VERSION, KEYS_VERSION, SALT_SIZE,
};
use crate::core::crypto::crypto_provider::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_key_from_mnemonic, derive_key_from_mnemonic_argon2,
    derive_key_from_passphrase, derive_key_from_passphrase_argon2, fingerprint_from_public_raw,
    generate_random_bytes, mnemonic_to_seed, validate_mnemonic_in, IV_LENGTH,
};
use crate::core::crypto::wordlist::MnemonicLanguage;
use crate::core::database::system::identity::{
    IdentityOptions, MajikContactData, MajikMessageIdentity, MajikUserRef,
};
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::keys::key_id::{KeyFamily, KeyId, CORE_KEYS};
use crate::core::keys::key_impls::derive_keys;
use crate::core::keys::key_store::{KeySlot, KeyStore, LegacyKeyJson, VaultKeys};
use crate::core::keys::keypair_handle::{KeyInfo, MajikKeypair};
use crate::core::keys::registry::{
    algorithm, enableable_key_ids, known_key_ids, resolve_requested_keys,
};
use crate::core::keys::types::KeyKind;
use crate::core::types::{
    MajikKeyAddress, MajikKeyDangerousJson, MajikKeyFingerprint, MajikKeyJson, MajikKeyMetadata,
    MnemonicJson, SecretBytes, Web3Metadata, X25519RawKey,
};
use crate::core::utils::{
    array_to_base64, base64_to_array_buffer, base64_to_uint8array, base64_to_utf8, format_iso8601,
    seed_array_to_string, seed_string_to_array, utf8_to_base64,
};
use crate::core::validator::MajikKeyValidator;
use crate::core::web3::bitcoin::bitcoin::{
    derive_bitcoin_keypair_from_seed, to_wif, BitcoinDerivationOptions, BitcoinKeypairMaterial,
};
use crate::core::web3::bitcoin::types::MajikKeyBitcoinNamespace;
use crate::core::web3::ethereum::ethereum::{
    ethereum_address_from_public_key, to_ethereum_private_key_hex, EthereumKeypairMaterial,
};
use crate::core::web3::ethereum::types::MajikKeyEthereumNamespace;
use crate::core::web3::solana::solana::{
    derive_solana_keypair_from_ed_secret_key, solana_address_from_public_key,
    solana_material_from_ed25519_secret_key, SolanaDerivationOptions, SolanaKeypairMaterial,
};
use crate::core::web3::solana::types::MajikKeySolanaNamespace;
use crate::core::web3::types::MajikKeyWeb3Namespace;

// ─── Public option / identity types ─────────────────────────────────────────

/// In-memory identity bundle for an *unlocked* MajikKey (`to_key_identity()`).
/// Kept for backward compatibility; prefer `get_keypair()` / `get_public_key()` / `get_private_key(id)`.
pub struct MajikKeyIdentity {
    pub id: MajikKeyFingerprint,
    pub public_key: X25519RawKey,
    pub fingerprint: MajikKeyFingerprint,
    pub private_key: Zeroizing<[u8; 32]>,
    pub encrypted_private_key: Vec<u8>,
    pub salt: String,
    pub kdf_version: KdfVersion,
    pub ml_kem_public_key: Option<Vec<u8>>,
    pub ml_kem_secret_key: Option<SecretBytes>,
    pub ed_public_key: Option<Vec<u8>>,
    pub ed_secret_key: Option<SecretBytes>,
    pub ml_dsa_public_key: Option<Vec<u8>>,
    pub ml_dsa_secret_key: Option<SecretBytes>,
    /// @experimental
    pub btc_public_key: Option<Vec<u8>>,
    /// @experimental
    pub btc_secret_key: Option<SecretBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerializedIdentity {
    pub id: String,
    pub public_key: MajikKeyAddress,
    pub fingerprint: MajikKeyFingerprint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
}

/// Options for `create()`, `from_mnemonic_json()` and `import_from_mnemonic_backup()`.
#[derive(Debug, Clone, Default)]
pub struct MajikKeyCreateOptions {
    /// `None` → English (or the language embedded in a `MnemonicJson`).
    pub mnemonic_language: Option<MnemonicLanguage>,
    /// Extra keypairs to create ON TOP of the core four (always included). Default: none.
    pub keys: Vec<KeyId>,
    /// @deprecated Use `keys: vec![KeyId::Btc]`. `true` adds `web3:btc`.
    pub derive_bitcoin: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct MajikKeyToJsonOptions {
    /// Also write the pre-registry flat fields (`encryptedMlKemSecretKey`, …) so older
    /// library versions / ports can read the export. Defaults to `true`.
    pub legacy: bool,
}
impl Default for MajikKeyToJsonOptions {
    fn default() -> Self {
        Self { legacy: true }
    }
}

/// Encrypted mnemonic-verification blob (base64 JSON on the wire).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupBlob {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default)]
    iv: String,
    #[serde(default)]
    ciphertext: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_kdf_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_salt_version: Option<u8>,
}

struct DerivedAccount {
    store: KeyStore,
    salt: String,
    fingerprint: String,
    x_public: Vec<u8>,
    x_secret: SecretBytes,
}

// ─── MajikKey ───────────────────────────────────────────────────────────────

/// Registry of keypairs deterministically derived from one BIP-39 mnemonic.
/// See `core::keys::registry` for every supported algorithm and its status.
pub struct MajikKey {
    id: String,
    public_key: X25519RawKey,
    public_key_base64: String,
    fingerprint: String,
    backup: String,
    timestamp: Timestamp,
    mnemonic_language: MnemonicLanguage,

    store: KeyStore,
    salt: String,
    label: String,
    kdf_version: KdfVersion,
}

struct MajikKeyInit {
    id: String,
    fingerprint: String,
    salt: String,
    backup: String,
    label: Option<String>,
    timestamp: Timestamp,
    kdf_version: KdfVersion,
    mnemonic_language: MnemonicLanguage,
    store: KeyStore,
}

impl MajikKey {
    fn new(init: MajikKeyInit) -> MajikKeyResult<Self> {
        let x_pub: [u8; 32] = init
            .store
            .get_public_key(KeyId::X25519)?
            .try_into()
            .map_err(|_| {
                MajikKeyError::InvalidJson("classic:x25519 public key must be 32 bytes".into())
            })?;
        Ok(Self {
            id: init.id,
            public_key: X25519RawKey { raw: x_pub },
            public_key_base64: array_to_base64(&x_pub),
            fingerprint: init.fingerprint,
            salt: init.salt,
            backup: init.backup,
            label: init.label.unwrap_or_default(),
            timestamp: init.timestamp,
            kdf_version: init.kdf_version,
            mnemonic_language: init.mnemonic_language,
            store: init.store,
        })
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// X25519 public key. Always available, even when locked.
    pub fn public_key(&self) -> &X25519RawKey {
        &self.public_key
    }
    pub fn public_key_base64(&self) -> &str {
        &self.public_key_base64
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn mnemonic_language(&self) -> MnemonicLanguage {
        self.mnemonic_language
    }
    pub fn backup(&self) -> &str {
        &self.backup
    }
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
    pub fn kdf_version(&self) -> KdfVersion {
        self.kdf_version
    }
    pub fn is_argon2id(&self) -> bool {
        self.kdf_version == KdfVersion::Argon2id
    }
    pub fn is_locked(&self) -> bool {
        !self.store.is_unlocked()
    }
    pub fn is_unlocked(&self) -> bool {
        self.store.is_unlocked()
    }

    /// `true` if this account holds every key in `CORE_KEYS`. Legacy accounts may not.
    pub fn is_core_complete(&self) -> bool {
        self.store.has_all(&CORE_KEYS)
    }

    /// `true` if this account is on Argon2id *and* has ML-KEM-768 keys.
    pub fn is_fully_upgraded(&self) -> bool {
        self.is_argon2id() && self.store.has(KeyId::MlKem768)
    }

    // ── Registry accessors ───────────────────────────────────────────────────

    /// Is this key present on the account? Works while locked. Derived views (`web3:sol`)
    /// count when their source key exists.
    pub fn has_key(&self, id: KeyId) -> bool {
        if self.store.has(id) {
            return true;
        }
        let def = algorithm(id);
        def.kind == KeyKind::Derived && def.derived_from.is_some_and(|src| self.store.has(src))
    }

    pub fn has_keys(&self, ids: &[KeyId]) -> bool {
        ids.iter().all(|i| self.has_key(*i))
    }

    /// Which of `ids` (default: the core four) are NOT on this account.
    pub fn missing_keys(&self, ids: Option<&[KeyId]>) -> Vec<KeyId> {
        ids.unwrap_or(&CORE_KEYS)
            .iter()
            .copied()
            .filter(|i| !self.has_key(*i))
            .collect()
    }

    /// Namespaced ids of every key available on this account, in canonical order.
    pub fn available_keys(&self, family: Option<KeyFamily>) -> Vec<KeyId> {
        known_key_ids(family)
            .into_iter()
            .filter(|id| self.has_key(*id))
            .collect()
    }

    /// Metadata for every available key. No secret material.
    pub fn list_keys(&self) -> Vec<KeyInfo> {
        self.available_keys(None)
            .into_iter()
            .map(|id| {
                let d = algorithm(id);
                KeyInfo {
                    id,
                    family: d.family,
                    purpose: d.purpose,
                    kind: d.kind,
                    status: d.status,
                    public_key_base64: self.get_public_key(id).ok().map(|p| array_to_base64(&p)),
                }
            })
            .collect()
    }

    /// Every algorithm id this library version can create/enable.
    pub fn supported_keys() -> Vec<KeyId> {
        enableable_key_ids()
    }

    /// Public key bytes for `id`. Works while locked (derived views need an unlocked account).
    pub fn get_public_key(&self, id: KeyId) -> MajikKeyResult<Vec<u8>> {
        if self.store.has(id) {
            return Ok(self.store.get_public_key(id)?.to_vec());
        }
        if id == KeyId::Sol && self.store.has(KeyId::Ed25519) {
            return Ok(self.get_solana_keypair_material(None)?.public_key.to_vec());
        }
        Err(MajikKeyError::KeyNotFound(id.to_string()))
    }

    /// Secret key bytes for `id` (zeroizing copy). Errors if locked or absent. ⚠️ Live key material.
    pub fn get_private_key(&self, id: KeyId) -> MajikKeyResult<SecretBytes> {
        if id == KeyId::Sol && self.store.has(KeyId::Ed25519) {
            return Ok(Zeroizing::new(
                self.get_solana_keypair_material(None)?.secret_key.to_vec(),
            ));
        }
        Ok(Zeroizing::new(self.require_secret(id, None)?.to_vec()))
    }

    /// A live handle with `.public()` / `.private()`. Borrows the account, so `lock()` can't
    /// run while it's alive — the compile-time analogue of TS's "never goes stale across lock()".
    pub fn get_keypair(&self, id: KeyId) -> MajikKeyResult<MajikKeypair<'_>> {
        if !self.has_key(id) {
            return Err(MajikKeyError::KeyNotFound(id.to_string()));
        }
        Ok(MajikKeypair::new(id, self))
    }

    fn require_secret(&self, id: KeyId, missing_message: Option<&str>) -> MajikKeyResult<&[u8]> {
        if self.is_locked() {
            return Err(MajikKeyError::Locked);
        }
        if self.store.slot(id).is_none() {
            return Err(MajikKeyError::msg(missing_message.map(str::to_string).unwrap_or_else(|| {
                format!("No \"{id}\" key on this account — add it with add_keys(), which requires the mnemonic.")
            })));
        }
        self.store.peek_secret_key(id).ok_or_else(|| {
            MajikKeyError::msg(if id == KeyId::Btc {
                "Bitcoin private key material is unavailable; re-import via import_from_mnemonic_backup.".to_string()
            } else {
                missing_message.map(str::to_string).unwrap_or_else(|| {
                    format!("Private key material for \"{id}\" is unavailable. Re-import the account from its mnemonic backup.")
                })
            })
        })
    }

    // ── Deprecated per-algorithm getters (wrappers over the registry) ────────

    #[deprecated(note = "use get_public_key(KeyId::MlKem768)")]
    pub fn ml_kem_public_key(&self) -> Option<Vec<u8>> {
        self.store
            .get_public_key(KeyId::MlKem768)
            .ok()
            .map(<[u8]>::to_vec)
    }
    #[deprecated(note = "use get_private_key(KeyId::MlKem768)")]
    pub fn ml_kem_secret_key(&self) -> Option<&[u8]> {
        self.store.peek_secret_key(KeyId::MlKem768)
    }
    #[deprecated(note = "use has_key(KeyId::MlKem768)")]
    pub fn has_ml_kem(&self) -> bool {
        self.store.has(KeyId::MlKem768)
    }
    #[deprecated(note = "use get_public_key(KeyId::Ed25519)")]
    pub fn ed_public_key(&self) -> Option<Vec<u8>> {
        self.store
            .get_public_key(KeyId::Ed25519)
            .ok()
            .map(<[u8]>::to_vec)
    }
    #[deprecated(note = "use get_public_key(KeyId::MlDsa87)")]
    pub fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        self.store
            .get_public_key(KeyId::MlDsa87)
            .ok()
            .map(<[u8]>::to_vec)
    }
    #[deprecated(note = "use has_keys(&[KeyId::Ed25519, KeyId::MlDsa87])")]
    pub fn has_signing_keys(&self) -> bool {
        self.store.has(KeyId::Ed25519) && self.store.has(KeyId::MlDsa87)
    }
    #[deprecated(note = "use get_public_key(KeyId::Btc)")]
    pub fn btc_public_key(&self) -> Option<Vec<u8>> {
        self.store
            .get_public_key(KeyId::Btc)
            .ok()
            .map(<[u8]>::to_vec)
    }
    #[deprecated(note = "use has_key(KeyId::Btc)")]
    pub fn has_bitcoin(&self) -> bool {
        self.store.has(KeyId::Btc)
    }

    #[deprecated(note = "use get_private_key(KeyId::MlKem768)")]
    pub fn get_ml_kem_secret_key(&self) -> MajikKeyResult<SecretBytes> {
        Ok(Zeroizing::new(
            self.require_secret(
                KeyId::MlKem768,
                Some("No ML-KEM secret key — add it with add_keys() (requires the mnemonic)."),
            )?
            .to_vec(),
        ))
    }
    #[deprecated(note = "use get_private_key(KeyId::Ed25519)")]
    pub fn get_ed_secret_key(&self) -> MajikKeyResult<SecretBytes> {
        Ok(Zeroizing::new(
            self.require_secret(
                KeyId::Ed25519,
                Some("No Ed25519 secret key — add it with add_keys() (requires the mnemonic)."),
            )?
            .to_vec(),
        ))
    }
    #[deprecated(note = "use get_private_key(KeyId::MlDsa87)")]
    pub fn get_ml_dsa_secret_key(&self) -> MajikKeyResult<SecretBytes> {
        Ok(Zeroizing::new(
            self.require_secret(
                KeyId::MlDsa87,
                Some("No ML-DSA secret key — add it with add_keys() (requires the mnemonic)."),
            )?
            .to_vec(),
        ))
    }
    #[deprecated(note = "use get_private_key(KeyId::Btc)")]
    pub fn get_btc_secret_key(&self) -> MajikKeyResult<SecretBytes> {
        Ok(Zeroizing::new(self.require_secret(KeyId::Btc, Some("No Bitcoin secret key — add it with add_keys(&[KeyId::Btc], mnemonic, passphrase)."))?.to_vec()))
    }
    #[deprecated(note = "use get_private_key(KeyId::X25519)")]
    pub fn get_private_key_base64(&self) -> MajikKeyResult<Zeroizing<String>> {
        Ok(Zeroizing::new(array_to_base64(
            self.require_secret(KeyId::X25519, None)?,
        )))
    }

    /// Non-secret snapshot of this account's state.
    pub fn metadata(&self) -> MajikKeyMetadata {
        MajikKeyMetadata {
            id: self.id.clone(),
            fingerprint: self.fingerprint.clone(),
            label: self.label.clone(),
            timestamp: format_iso8601(self.timestamp),
            is_locked: self.is_locked(),
            kdf_version: self.kdf_version as u8,
            has_ml_kem: self.store.has(KeyId::MlKem768),
            web3: Web3Metadata {
                has_ethereum: Some(self.has_ethereum()),
                has_bitcoin: Some(self.store.has(KeyId::Btc)),
                has_solana: Some(self.has_solana_keypair()),
            },
            keys: Some(self.available_keys(None)),
            mnemonic_language: Some(self.mnemonic_language),
        }
    }

    // ── CREATE ───────────────────────────────────────────────────────────────

    /// Creates a brand-new MajikKey from a BIP-39 mnemonic and returns it UNLOCKED.
    ///
    /// Always derives the core four. Pass `options.keys` for more, e.g. `keys: vec![KeyId::Btc]`.
    pub fn create(
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        options: &MajikKeyCreateOptions,
    ) -> MajikKeyResult<MajikKey> {
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        MajikKeyValidator::validate_passphrase(passphrase, "Passphrase")?;
        MajikKeyValidator::validate_label(label)?;

        let language = options.mnemonic_language.unwrap_or_default();
        let ids = Self::resolve_create_keys(options)?;
        validate_mnemonic_in(mnemonic, language)?;

        let d = Self::derive_from_mnemonic(mnemonic, language, passphrase, &ids)?;
        let backup = Self::export_mnemonic_backup_inner(
            &d.fingerprint,
            &d.fingerprint,
            &d.x_public,
            &d.x_secret,
            mnemonic,
        )?;

        Self::new(MajikKeyInit {
            id: d.fingerprint.clone(),
            fingerprint: d.fingerprint,
            salt: d.salt,
            backup,
            label: label.map(str::to_string),
            timestamp: Timestamp::now(),
            kdf_version: KdfVersion::Argon2id,
            mnemonic_language: language,
            store: d.store,
        })
    }

    fn resolve_create_keys(options: &MajikKeyCreateOptions) -> MajikKeyResult<Vec<KeyId>> {
        let mut requested = options.keys.clone();
        if options.derive_bitcoin {
            requested.push(KeyId::Btc);
        }
        resolve_requested_keys(&requested)
    }

    // ── READ ─────────────────────────────────────────────────────────────────

    /// Parse a MajikKey from JSON text. See [`MajikKey::from_json`].
    pub fn from_json_str(json: &str) -> MajikKeyResult<MajikKey> {
        let parsed: MajikKeyJson = serde_json::from_str(json)
            .map_err(|e| MajikKeyError::with_cause("Failed to parse MajikKey from JSON", e))?;
        Self::from_json(&parsed)
    }

    /// Parse a MajikKey from JSON. Accepts BOTH shapes:
    ///  - registry JSON (has `keys`) → used as-is
    ///  - legacy flat JSON (no `keys`) → auto-migrated in memory (no secrets, passphrase or
    ///    mnemonic needed). Re-serialize with `to_json()` to persist the upgraded shape.
    pub fn from_json(parsed: &MajikKeyJson) -> MajikKeyResult<MajikKey> {
        let store = if let Some(keys) = &parsed.keys {
            for (v, f) in [
                (&parsed.id, "id"),
                (&parsed.fingerprint, "fingerprint"),
                (&parsed.salt, "salt"),
                (&parsed.backup, "backup"),
                (&parsed.timestamp, "timestamp"),
            ] {
                if v.is_empty() {
                    return Err(MajikKeyError::msg(format!(
                        "Invalid MajikKey JSON: missing \"{f}\""
                    )));
                }
            }
            if let Some(v) = parsed.keys_version {
                if v > KEYS_VERSION {
                    return Err(MajikKeyError::msg(format!(
                        "This MajikKey JSON uses keys schema v{v}; this library supports up to v{KEYS_VERSION}. Upgrade the library."
                    )));
                }
            }
            let store = KeyStore::from_entries(keys)?;
            if !store.has(KeyId::X25519) {
                return Err(MajikKeyError::msg(
                    "Invalid MajikKey JSON: `keys` has no classic:x25519 entry",
                ));
            }
            // If the flat legacy field is also present it must agree (corruption/tamper check).
            if !parsed.public_key.is_empty()
                && parsed.public_key != array_to_base64(store.get_public_key(KeyId::X25519)?)
            {
                return Err(MajikKeyError::msg(
                    "Invalid MajikKey JSON: `publicKey` does not match the classic:x25519 entry",
                ));
            }
            store
        } else {
            MajikKeyValidator::validate_json(parsed)?;
            KeyStore::from_legacy_json(&LegacyKeyJson::from_majik_json(parsed))?
        };

        let timestamp: Timestamp = parsed
            .timestamp
            .parse()
            .map_err(|_| MajikKeyError::InvalidJson("invalid timestamp".into()))?;

        Self::new(MajikKeyInit {
            id: parsed.id.clone(),
            fingerprint: parsed.fingerprint.clone(),
            salt: parsed.salt.clone(),
            backup: parsed.backup.clone(),
            label: Some(parsed.label.clone()),
            timestamp,
            kdf_version: KdfVersion::from_u8(parsed.kdf_version.unwrap_or(1)),
            mnemonic_language: parsed.mnemonic_language.unwrap_or_default(),
            store,
        })
    }

    /// Export a fully unlocked MajikKey with all raw private keys.
    /// ⚠️ DANGEROUS — output contains unencrypted private key material.
    pub fn to_dangerous_json(&self) -> MajikKeyResult<MajikKeyDangerousJson> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "MajikKey must be unlocked to export dangerous JSON.",
            ));
        }
        if !self.has_keys(&CORE_KEYS) {
            return Err(MajikKeyError::msg(
                "MajikKey is missing core keys — add them with add_keys(&CORE_KEYS, mnemonic, passphrase) first.",
            ));
        }
        let secret_keys: BTreeMap<String, String> = self
            .store
            .export_secrets()?
            .into_iter()
            .map(|(id, s)| (id.to_string(), array_to_base64(s)))
            .collect();
        let s = |id: KeyId| -> MajikKeyResult<String> {
            Ok(array_to_base64(self.store.get_secret_key(id)?))
        };
        Ok(MajikKeyDangerousJson {
            base: self.to_json(),
            private_key_base64: s(KeyId::X25519)?,
            ml_kem_secret_key_base64: s(KeyId::MlKem768)?,
            ed_secret_key_base64: s(KeyId::Ed25519)?,
            ml_dsa_secret_key_base64: s(KeyId::MlDsa87)?,
            btc_secret_key_base64: if self.store.has(KeyId::Btc) {
                Some(s(KeyId::Btc)?)
            } else {
                None
            },
            secret_keys: Some(secret_keys),
        })
    }

    /// Reconstruct a fully unlocked MajikKey from a dangerous JSON export.
    /// ⚠️ DANGEROUS — input contains unencrypted private key material. No KDF involved.
    pub fn from_dangerous_json(parsed: &MajikKeyDangerousJson) -> MajikKeyResult<MajikKey> {
        let b = &parsed.base;
        if b.id.is_empty()
            || b.fingerprint.is_empty()
            || b.public_key.is_empty()
            || parsed.private_key_base64.is_empty()
            || b.ed_public_key.is_none()
            || parsed.ed_secret_key_base64.is_empty()
            || b.ml_dsa_public_key.is_none()
            || parsed.ml_dsa_secret_key_base64.is_empty()
            || b.ml_kem_public_key.is_none()
            || parsed.ml_kem_secret_key_base64.is_empty()
        {
            return Err(MajikKeyError::msg(
                "Invalid MajikKeyDangerousJSON — missing required fields",
            ));
        }

        let mut store = match &b.keys {
            Some(keys) => KeyStore::from_entries(keys)?,
            None => KeyStore::from_legacy_json(&LegacyKeyJson::from_majik_json(b))?,
        };

        let mut secrets: BTreeMap<KeyId, SecretBytes> = BTreeMap::new();
        let mut put = |id: KeyId, b64: &str| -> MajikKeyResult<()> {
            if !b64.is_empty() && store.has(id) {
                secrets.insert(id, Zeroizing::new(base64_to_uint8array(b64)?));
            }
            Ok(())
        };
        put(KeyId::X25519, &parsed.private_key_base64)?;
        put(KeyId::MlKem768, &parsed.ml_kem_secret_key_base64)?;
        put(KeyId::Ed25519, &parsed.ed_secret_key_base64)?;
        put(KeyId::MlDsa87, &parsed.ml_dsa_secret_key_base64)?;
        if let Some(btc) = &parsed.btc_secret_key_base64 {
            put(KeyId::Btc, btc)?;
        }
        if let Some(map) = &parsed.secret_keys {
            for (id, b64) in map {
                if let Some(k) = KeyId::parse(id) {
                    put(k, b64)?;
                }
            }
        }
        store.attach_secrets(secrets)?;

        Self::new(MajikKeyInit {
            id: b.id.clone(),
            fingerprint: b.fingerprint.clone(),
            salt: b.salt.clone(),
            backup: b.backup.clone(),
            label: Some(b.label.clone()),
            timestamp: b.timestamp.parse().unwrap_or_else(|_| Timestamp::now()),
            kdf_version: KdfVersion::from_u8(b.kdf_version.unwrap_or(2)),
            mnemonic_language: b.mnemonic_language.unwrap_or_default(),
            store,
        })
    }

    // ── MnemonicJSON ─────────────────────────────────────────────────────────

    pub fn to_mnemonic_json(
        &self,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> MajikKeyResult<MnemonicJson> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "Cannot export locked MajikKey to MnemonicJSON. Unlock first.",
            ));
        }
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        if let Some(p) = passphrase {
            MajikKeyValidator::validate_passphrase(p, "Passphrase")?;
        }
        Ok(MnemonicJson {
            id: self.backup.clone(),
            seed: seed_string_to_array(mnemonic.trim()),
            phrase: passphrase
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty()),
            language: Some(self.mnemonic_language),
            version: None,
        })
    }

    pub fn from_mnemonic_json(
        json: &MnemonicJson,
        passphrase: &str,
        label: Option<&str>,
        options: &MajikKeyCreateOptions,
    ) -> MajikKeyResult<MajikKey> {
        if json.id.is_empty() || json.seed.is_empty() {
            return Err(MajikKeyError::msg("Invalid MnemonicJSON"));
        }
        let mnemonic = Zeroizing::new(seed_array_to_string(&json.seed));
        MajikKeyValidator::validate_mnemonic(&mnemonic)?;

        // Explicit caller option wins; otherwise preserve the language embedded in the MnemonicJSON.
        let language = options
            .mnemonic_language
            .or(json.language)
            .unwrap_or_default();
        validate_mnemonic_in(&mnemonic, language)?;

        let mut opts = options.clone();
        opts.mnemonic_language = Some(language);
        Self::create(&mnemonic, passphrase, label, &opts)
    }

    pub fn from_mnemonic_json_str(
        json: &str,
        passphrase: &str,
        label: Option<&str>,
        options: &MajikKeyCreateOptions,
    ) -> MajikKeyResult<MajikKey> {
        let parsed: MnemonicJson = serde_json::from_str(json)
            .map_err(|e| MajikKeyError::with_cause("Failed to import MnemonicJSON", e))?;
        Self::from_mnemonic_json(&parsed, passphrase, label, options)
    }

    // ── UPDATE ───────────────────────────────────────────────────────────────

    pub fn update_label(&mut self, new_label: &str) -> MajikKeyResult<&mut Self> {
        MajikKeyValidator::validate_label(Some(new_label))?;
        self.label = new_label.to_string();
        Ok(self)
    }

    pub fn update_passphrase(
        &mut self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> MajikKeyResult<&mut Self> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "MajikKey must be unlocked to update passphrase",
            ));
        }
        MajikKeyValidator::validate_passphrase(current_passphrase, "Current passphrase")?;
        MajikKeyValidator::validate_passphrase(new_passphrase, "New passphrase")?;
        self.reencrypt_all(current_passphrase, new_passphrase)?;
        Ok(self)
    }

    /// Migrate KDF from PBKDF2 to Argon2id without changing the passphrase.
    /// Does not add new key types — use [`add_keys`](Self::add_keys) (requires the mnemonic).
    pub fn migrate(&mut self, passphrase: &str) -> MajikKeyResult<&mut Self> {
        MajikKeyValidator::validate_passphrase(passphrase, "Passphrase")?;
        if self.kdf_version == KdfVersion::Argon2id {
            return Ok(self);
        }
        self.reencrypt_all(passphrase, passphrase)?;
        Ok(self)
    }

    /// Add keypairs this account doesn't have yet. Requires the original MNEMONIC (new keys
    /// derive from the seed, which is never stored) and the current passphrase.
    ///
    /// Safe by construction: the mnemonic must reproduce this account's X25519 key, and the
    /// passphrase must decrypt it, before anything is added. Account must be on Argon2id.
    ///
    /// Returns the ids that were added.
    pub fn add_keys(
        &mut self,
        ids: &[KeyId],
        mnemonic: &str,
        passphrase: &str,
    ) -> MajikKeyResult<Vec<KeyId>> {
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        MajikKeyValidator::validate_passphrase(passphrase, "Passphrase")?;
        if !self.is_argon2id() {
            return Err(MajikKeyError::msg(
                "Account is on the legacy KDF. Call migrate(passphrase) before add_keys().",
            ));
        }

        let resolved = resolve_requested_keys(ids)?;
        let mut to_add: Vec<KeyId> = Vec::new();
        for &id in ids {
            if resolved.contains(&id) && !self.store.has(id) && !to_add.contains(&id) {
                to_add.push(id);
            }
        }
        if to_add.is_empty() {
            return Ok(vec![]);
        }

        validate_mnemonic_in(mnemonic, self.mnemonic_language)?;

        let salt = base64_to_array_buffer(&self.salt)?;
        let aes_key = Self::derive_vault_key(passphrase, &salt, KdfVersion::Argon2id)?;
        let seed64 = mnemonic_to_seed(mnemonic, self.mnemonic_language)?;

        // 1) passphrase must be right
        let x_blob = self
            .store
            .slot(KeyId::X25519)
            .and_then(|s| s.encrypted_secret_key.as_ref())
            .ok_or_else(|| MajikKeyError::msg("Account has no encrypted X25519 key"))?;
        KeyStore::open(&aes_key, x_blob, "classic:x25519 secret key")?;

        // 2) mnemonic must belong to this account
        let probe = derive_keys(&seed64[..], &[KeyId::X25519])?;
        if fingerprint_from_public_raw(&probe[&KeyId::X25519].public_key) != self.fingerprint {
            return Err(MajikKeyError::msg(
                "That mnemonic does not belong to this account",
            ));
        }

        // 3) derive + seal + add
        let derived = derive_keys(&seed64[..], &to_add)?;
        let unlocked = self.is_unlocked();
        for (id, kp) in derived {
            self.store.add(KeySlot {
                id,
                public_key: kp.public_key.clone(),
                encrypted_secret_key: Some(KeyStore::seal(&aes_key, &kp.secret_key)?),
                secret_key: if unlocked {
                    Some(Zeroizing::new(kp.secret_key.to_vec()))
                } else {
                    None
                },
                derivation: algorithm(id).derivation.clone(),
                created_at: Some(crate::core::utils::now_iso8601()),
            })?;
        }
        Ok(to_add)
    }

    // ── LOCK / UNLOCK ────────────────────────────────────────────────────────

    pub fn lock(&mut self) -> &mut Self {
        self.store.lock();
        self
    }

    /// One KDF run decrypts every key. Atomic: a failure leaves the account fully locked.
    pub fn unlock(&mut self, passphrase: &str) -> MajikKeyResult<&mut Self> {
        if self.is_unlocked() {
            return Err(MajikKeyError::AlreadyUnlocked);
        }
        MajikKeyValidator::validate_passphrase(passphrase, "Passphrase")?;

        let salt = base64_to_array_buffer(&self.salt)?;
        let primary = Self::derive_vault_key(passphrase, &salt, self.kdf_version)?;
        let argon: Option<Zeroizing<[u8; 32]>> =
            if !self.is_argon2id() && self.has_non_x25519_blobs() {
                Some(Self::derive_vault_key(
                    passphrase,
                    &salt,
                    KdfVersion::Argon2id,
                )?)
            } else {
                None
            };
        let keys = if self.is_argon2id() {
            VaultKeys::uniform(&primary)
        } else {
            VaultKeys::split(&primary, argon.as_deref())
        };
        self.store.unlock(&keys)?;
        Ok(self)
    }

    pub fn verify(&self, passphrase: &str) -> bool {
        let Ok(salt) = base64_to_array_buffer(&self.salt) else {
            return false;
        };
        let Ok(key) = Self::derive_vault_key(passphrase, &salt, self.kdf_version) else {
            return false;
        };
        match self
            .store
            .slot(KeyId::X25519)
            .and_then(|s| s.encrypted_secret_key.as_ref())
        {
            Some(blob) => KeyStore::open(&key, blob, "private key").is_ok(),
            None => false,
        }
    }

    /// Runs `operation` against an already-unlocked MajikKey and locks it again when the
    /// operation completes — even if it panics.
    pub fn with_auto_lock<T>(
        &mut self,
        operation: impl FnOnce(&mut MajikKey) -> T,
    ) -> MajikKeyResult<T> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "MajikKey must be unlocked before calling with_auto_lock()",
            ));
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&mut *self)));
        self.lock();
        match result {
            Ok(v) => Ok(v),
            Err(p) => std::panic::resume_unwind(p),
        }
    }

    fn has_non_x25519_blobs(&self) -> bool {
        self.store.ids().into_iter().any(|id| {
            id != KeyId::X25519
                && self
                    .store
                    .slot(id)
                    .is_some_and(|s| s.encrypted_secret_key.is_some())
        })
    }

    /// Decrypt every blob under (current passphrase, current salt/KDF), re-encrypt under
    /// (new passphrase, fresh salt, Argon2id), then commit atomically. Doesn't need the
    /// account to be unlocked.
    fn reencrypt_all(
        &mut self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> MajikKeyResult<()> {
        let old_salt = base64_to_array_buffer(&self.salt)?;
        let new_salt = generate_random_bytes(SALT_SIZE);

        let old_primary = Self::derive_vault_key(current_passphrase, &old_salt, self.kdf_version)?;
        let old_argon: Option<Zeroizing<[u8; 32]>> =
            if !self.is_argon2id() && self.has_non_x25519_blobs() {
                Some(Self::derive_vault_key(
                    current_passphrase,
                    &old_salt,
                    KdfVersion::Argon2id,
                )?)
            } else {
                None
            };
        let new_key = Self::derive_vault_key(new_passphrase, &new_salt, KdfVersion::Argon2id)?;

        let old_keys = if self.is_argon2id() {
            VaultKeys::uniform(&old_primary)
        } else {
            VaultKeys::split(&old_primary, old_argon.as_deref())
        };
        let blobs = self.store.prepare_reseal(&old_keys, &new_key)?;
        self.store.commit_reseal(blobs);
        self.salt = array_to_base64(&new_salt);
        self.kdf_version = KdfVersion::Argon2id;
        Ok(())
    }

    // ── SERIALIZATION ────────────────────────────────────────────────────────

    /// Serialize (safe at rest: only passphrase-encrypted secrets). Writes the registry
    /// (`keys`) AND the pre-registry flat fields for compatibility.
    pub fn to_json(&self) -> MajikKeyJson {
        self.to_json_with(&MajikKeyToJsonOptions::default())
    }

    pub fn to_json_with(&self, options: &MajikKeyToJsonOptions) -> MajikKeyJson {
        let mut j = MajikKeyJson {
            id: self.id.clone(),
            label: self.label.clone(),
            public_key: self.public_key_base64.clone(),
            fingerprint: self.fingerprint.clone(),
            salt: self.salt.clone(),
            backup: self.backup.clone(),
            timestamp: format_iso8601(self.timestamp),
            kdf_version: Some(self.kdf_version as u8),
            mnemonic_language: Some(self.mnemonic_language),
            keys_version: Some(KEYS_VERSION),
            keys: Some(self.store.to_entries()),
            ..Default::default()
        };
        if options.legacy {
            let l = self.store.to_legacy_json();
            j.encrypted_private_key = l.encrypted_private_key;
            j.ml_kem_public_key = l.ml_kem_public_key;
            j.encrypted_ml_kem_secret_key = l.encrypted_ml_kem_secret_key;
            j.ed_public_key = l.ed_public_key;
            j.encrypted_ed_secret_key = l.encrypted_ed_secret_key;
            j.ml_dsa_public_key = l.ml_dsa_public_key;
            j.encrypted_ml_dsa_secret_key = l.encrypted_ml_dsa_secret_key;
            j.btc_public_key = l.btc_public_key;
            j.encrypted_btc_secret_key = l.encrypted_btc_secret_key;
        }
        j
    }

    pub fn to_json_string(&self, pretty: bool) -> MajikKeyResult<String> {
        let j = self.to_json();
        Ok(if pretty {
            serde_json::to_string_pretty(&j)?
        } else {
            serde_json::to_string(&j)?
        })
    }

    // ── UTILITY ──────────────────────────────────────────────────────────────

    pub fn generate_mnemonic(strength: u32, language: MnemonicLanguage) -> MajikKeyResult<String> {
        if strength != 128 && strength != 256 {
            return Err(MajikKeyError::msg("Strength must be 128 or 256"));
        }
        let entropy = crate::core::crypto::crypto_provider::generate_random_bytes_protected(
            (strength / 8) as usize,
        );
        let m = bip39::Mnemonic::from_entropy_in(language.to_bip39(), &entropy)
            .map_err(|_| MajikKeyError::msg("Failed to generate mnemonic"))?;
        Ok(m.words()
            .collect::<Vec<_>>()
            .join(language.word_separator()))
    }

    /// Non-empty check only (same as TS). Use `validate_mnemonic_in` for a wordlist/checksum check.
    pub fn validate_mnemonic(mnemonic: &str) -> bool {
        MajikKeyValidator::validate_mnemonic(mnemonic).is_ok()
    }

    /// Public-key bundle as a contact. (`MajikContact` itself has no Rust crate yet — see
    /// `database::system::identity::MajikContactData`.)
    pub fn to_contact(&self, label_override: Option<&str>) -> MajikContactData {
        let b64 = |id| self.store.get_public_key(id).ok().map(array_to_base64);
        MajikContactData {
            id: self.id.clone(),
            public_key_base64: self.public_key_base64.clone(),
            fingerprint: self.fingerprint.clone(),
            label: label_override.unwrap_or(&self.label).to_string(),
            ml_key: b64(KeyId::MlKem768).unwrap_or_default(),
            ed_public_key_base64: b64(KeyId::Ed25519),
            ml_dsa_public_key_base64: b64(KeyId::MlDsa87),
        }
    }

    pub fn to_key_identity(&self) -> MajikKeyResult<MajikKeyIdentity> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "Cannot convert locked MajikKey to KeyIdentity. Unlock first.",
            ));
        }
        let blob = self
            .store
            .slot(KeyId::X25519)
            .and_then(|s| s.encrypted_secret_key.clone())
            .unwrap_or_default();
        let mut private_key = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(self.require_secret(KeyId::X25519, None)?);
        let peek = |id| {
            self.store
                .peek_secret_key(id)
                .map(|s| Zeroizing::new(s.to_vec()))
        };
        let pubk = |id| self.store.get_public_key(id).ok().map(<[u8]>::to_vec);
        Ok(MajikKeyIdentity {
            id: self.id.clone(),
            public_key: self.public_key.clone(),
            fingerprint: self.fingerprint.clone(),
            private_key,
            encrypted_private_key: blob,
            salt: self.salt.clone(),
            kdf_version: self.kdf_version,
            ml_kem_public_key: pubk(KeyId::MlKem768),
            ml_kem_secret_key: peek(KeyId::MlKem768),
            ed_public_key: pubk(KeyId::Ed25519),
            ed_secret_key: peek(KeyId::Ed25519),
            ml_dsa_public_key: pubk(KeyId::MlDsa87),
            ml_dsa_secret_key: peek(KeyId::MlDsa87),
            btc_public_key: pubk(KeyId::Btc),
            btc_secret_key: peek(KeyId::Btc),
        })
    }

    pub fn to_serialized_identity(&self) -> MajikKeyResult<SerializedIdentity> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "Cannot convert locked MajikKey to SerializedIdentity. Unlock first.",
            ));
        }
        Ok(SerializedIdentity {
            id: self.id.clone(),
            public_key: self.public_key_base64.clone(),
            fingerprint: self.fingerprint.clone(),
            encrypted_private_key: self
                .store
                .slot(KeyId::X25519)
                .and_then(|s| s.encrypted_secret_key.as_deref())
                .map(array_to_base64),
            salt: Some(self.salt.clone()),
        })
    }

    pub fn to_majik_message_identity(
        &self,
        user: &MajikUserRef,
        options: Option<IdentityOptions>,
    ) -> MajikKeyResult<MajikMessageIdentity> {
        let errors = user.validate();
        if !errors.is_empty() {
            return Err(MajikKeyError::msg(format!(
                "Invalid MajikUser: {}",
                errors.join(", ")
            )));
        }
        MajikMessageIdentity::create(user, &self.to_contact(None), options)
    }

    // ── BACKUP ───────────────────────────────────────────────────────────────

    pub fn export_mnemonic_backup(&self, mnemonic: &str) -> MajikKeyResult<String> {
        if self.is_locked() {
            return Err(MajikKeyError::msg(
                "MajikKey must be unlocked to export backup",
            ));
        }
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        Self::export_mnemonic_backup_inner(
            &self.id,
            &self.fingerprint,
            &self.public_key.raw,
            self.require_secret(KeyId::X25519, None)?,
            mnemonic,
        )
    }

    /// Import a MajikKey from a mnemonic-encrypted backup. Re-derives the account from the
    /// mnemonic: the core four (plus `options.keys`) under a new passphrase.
    pub fn import_from_mnemonic_backup(
        backup: &str,
        mnemonic: &str,
        passphrase: &str,
        label: Option<&str>,
        options: &MajikKeyCreateOptions,
    ) -> MajikKeyResult<MajikKey> {
        if backup.is_empty() {
            return Err(MajikKeyError::msg("Backup must be a non-empty string"));
        }
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        MajikKeyValidator::validate_passphrase(passphrase, "Passphrase")?;
        MajikKeyValidator::validate_label(label)?;

        let language = options.mnemonic_language.unwrap_or_default();
        let ids = Self::resolve_create_keys(options)?;
        validate_mnemonic_in(mnemonic, language)?;

        let parsed: BackupBlob = serde_json::from_str(&base64_to_utf8(backup)?)
            .map_err(|e| MajikKeyError::with_cause("Invalid backup format", e))?;
        if parsed.iv.is_empty()
            || parsed.ciphertext.is_empty()
            || parsed.public_key.is_empty()
            || parsed.fingerprint.is_empty()
        {
            return Err(MajikKeyError::msg("Invalid backup format"));
        }
        let backup_kdf = KdfVersion::from_u8(parsed.backup_kdf_version.unwrap_or(1));

        // Verify the mnemonic is correct before the expensive re-derivation.
        Self::verify_backup_decryption(
            &parsed.iv,
            &parsed.ciphertext,
            mnemonic,
            backup_kdf,
            parsed.backup_salt_version,
        )?;

        let d = Self::derive_from_mnemonic(mnemonic, language, passphrase, &ids)?;
        Self::new(MajikKeyInit {
            id: parsed
                .id
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| d.fingerprint.clone()),
            fingerprint: d.fingerprint,
            salt: d.salt,
            backup: backup.to_string(),
            label: label.map(str::to_string),
            timestamp: Timestamp::now(),
            kdf_version: KdfVersion::Argon2id,
            mnemonic_language: language,
            store: d.store,
        })
    }

    // ── PRIVATE: derivation + vault crypto ───────────────────────────────────

    /// Derive `ids` from the mnemonic and seal each secret under ONE Argon2id key
    /// (single salt, single KDF run). Returns an UNLOCKED store.
    fn derive_from_mnemonic(
        mnemonic: &str,
        language: MnemonicLanguage,
        passphrase: &str,
        ids: &[KeyId],
    ) -> MajikKeyResult<DerivedAccount> {
        let derived = {
            let seed64 = mnemonic_to_seed(mnemonic, language)?;
            derive_keys(&seed64[..], ids)?
        }; // seed zeroized here

        let salt = generate_random_bytes(SALT_SIZE);
        let aes_key = Self::derive_vault_key(passphrase, &salt, KdfVersion::Argon2id)?;
        let store = KeyStore::from_derived(&derived, &aes_key)?;
        let x = derived
            .get(&KeyId::X25519)
            .ok_or_else(|| MajikKeyError::msg("X25519 key was not derived"))?;
        Ok(DerivedAccount {
            store,
            salt: array_to_base64(&salt),
            fingerprint: fingerprint_from_public_raw(&x.public_key),
            x_public: x.public_key.clone(),
            x_secret: Zeroizing::new(x.secret_key.to_vec()),
        })
    }

    /// One KDF run. `Pbkdf2` = legacy (X25519 blob of old accounts only).
    fn derive_vault_key(
        passphrase: &str,
        salt: &[u8],
        kdf: KdfVersion,
    ) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
        match kdf {
            KdfVersion::Argon2id => derive_key_from_passphrase_argon2(passphrase, salt),
            KdfVersion::Pbkdf2 => Ok(derive_key_from_passphrase(passphrase, salt)),
        }
    }

    // ── PRIVATE: backup ──────────────────────────────────────────────────────

    fn verify_backup_decryption(
        iv_b64: &str,
        ct_b64: &str,
        mnemonic: &str,
        kdf: KdfVersion,
        salt_version: Option<u8>,
    ) -> MajikKeyResult<()> {
        let iv = base64_to_array_buffer(iv_b64)?;
        let ct = base64_to_array_buffer(ct_b64)?;
        let fail =
            || MajikKeyError::msg("Failed to decrypt backup — invalid mnemonic or corrupted data");

        let key = match kdf {
            KdfVersion::Argon2id => {
                derive_key_from_mnemonic_argon2(mnemonic, backup_salt_for(salt_version).as_bytes())?
            }
            // PBKDF2 backups predate salt versioning: always the legacy salt.
            KdfVersion::Pbkdf2 => {
                derive_key_from_mnemonic(mnemonic, LEGACY_MAJIK_MNEMONIC_SALT.as_bytes())
            }
        };
        aes_gcm_decrypt(&key, &iv, &ct).map(|_| ()).ok_or_else(fail)
    }

    fn export_mnemonic_backup_inner(
        id: &str,
        fingerprint: &str,
        public_raw: &[u8],
        private_raw: &[u8],
        mnemonic: &str,
    ) -> MajikKeyResult<String> {
        let salt = backup_salt_for(Some(BACKUP_SALT_WRITE_VERSION));
        let key = derive_key_from_mnemonic_argon2(mnemonic, salt.as_bytes())?;
        let iv = generate_random_bytes(IV_LENGTH);
        let ciphertext = aes_gcm_encrypt(&key, &iv, private_raw)?;
        let blob = BackupBlob {
            id: Some(id.to_string()),
            iv: array_to_base64(&iv),
            ciphertext: array_to_base64(&ciphertext),
            public_key: array_to_base64(public_raw),
            fingerprint: fingerprint.to_string(),
            backup_kdf_version: Some(KdfVersion::Argon2id as u8),
            backup_salt_version: Some(BACKUP_SALT_WRITE_VERSION),
        };
        Ok(utf8_to_base64(&serde_json::to_string(&blob)?))
    }

    // ── WEB3 (EXPERIMENTAL) ──────────────────────────────────────────────────

    /// @experimental `None` unless the account is unlocked and has an Ed25519 key.
    pub fn web3(&self) -> Option<MajikKeyWeb3Namespace> {
        if !self.has_solana_keypair() {
            return None;
        }
        let solana = MajikKeySolanaNamespace::new(self.get_solana_keypair_material(None).ok()?);

        let bitcoin = self
            .get_bitcoin_keypair_material(None)
            .ok()
            .map(MajikKeyBitcoinNamespace::new);
        let ethereum = self
            .get_ethereum_keypair_material()
            .ok()
            .and_then(|m| MajikKeyEthereumNamespace::new(m).ok());

        Some(MajikKeyWeb3Namespace {
            solana,
            bitcoin,
            ethereum,
        })
    }

    // ── BITCOIN ──

    /// @experimental True if this MajikKey can currently produce Bitcoin material (unlocked + has a Bitcoin key).
    pub fn has_bitcoin_keypair(&self) -> bool {
        self.store.peek_secret_key(KeyId::Btc).is_some()
    }

    /// @experimental Raw material for the stored (domain-separated) key. The REAL BIP-84 key
    /// needs the mnemonic: use [`MajikKey::derive_standard_bitcoin_from_mnemonic`].
    pub fn get_bitcoin_keypair_material(
        &self,
        options: Option<&BitcoinDerivationOptions>,
    ) -> MajikKeyResult<BitcoinKeypairMaterial> {
        if self.is_locked() {
            return Err(MajikKeyError::Locked);
        }
        if options.is_some_and(|o| o.standard || o.path.is_some()) {
            return Err(MajikKeyError::msg(
                "Deriving the standard BIP-84 path requires the mnemonic — use MajikKey::derive_standard_bitcoin_from_mnemonic(mnemonic, language) instead.",
            ));
        }
        let secret = self.require_secret(
            KeyId::Btc,
            Some("No Bitcoin secret key — add it with add_keys(&[KeyId::Btc], mnemonic, passphrase)."),
        )?;
        let mut private_key = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(
            secret
                .get(..32)
                .filter(|_| secret.len() == 32)
                .ok_or_else(|| MajikKeyError::msg("Invalid stored Bitcoin private key"))?,
        );
        let public_key: [u8; 33] = self
            .store
            .get_public_key(KeyId::Btc)?
            .try_into()
            .map_err(|_| MajikKeyError::msg("Invalid stored Bitcoin public key"))?;
        Ok(BitcoinKeypairMaterial {
            private_key,
            public_key,
        })
    }

    /// @experimental Derive the REAL BIP-84 mainnet keypair straight from a mnemonic.
    pub fn derive_standard_bitcoin_from_mnemonic(
        mnemonic: &str,
        language: MnemonicLanguage,
    ) -> MajikKeyResult<BitcoinKeypairMaterial> {
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        validate_mnemonic_in(mnemonic, language)?;
        let seed = mnemonic_to_seed(mnemonic, language)?;
        derive_bitcoin_keypair_from_seed(
            &seed[..],
            Some(&BitcoinDerivationOptions {
                standard: true,
                path: None,
            }),
        )
    }

    /// @experimental WIF export of the stored (domain-separated) Bitcoin key.
    pub fn get_bitcoin_wif(&self, compressed: Option<bool>) -> MajikKeyResult<String> {
        Ok(to_wif(
            &self.get_bitcoin_keypair_material(None)?,
            compressed,
        ))
    }

    // ── ETHEREUM ──

    /// @experimental True if this account has a stored Ethereum key (works while locked).
    pub fn has_ethereum(&self) -> bool {
        self.store.has(KeyId::Eth)
    }

    /// @experimental EIP-55 address (standard `m/44'/60'/0'/0/0`). Public-only, works while locked.
    pub fn get_ethereum_address(&self) -> MajikKeyResult<String> {
        if !self.store.has(KeyId::Eth) {
            return Err(MajikKeyError::msg(
                "No Ethereum key — add it with add_keys(&[KeyId::Eth], mnemonic, passphrase).",
            ));
        }
        ethereum_address_from_public_key(self.store.get_public_key(KeyId::Eth)?)
    }

    /// @experimental Raw Ethereum keypair material. Requires an unlocked account.
    pub fn get_ethereum_keypair_material(&self) -> MajikKeyResult<EthereumKeypairMaterial> {
        let secret = self.require_secret(KeyId::Eth, None)?;
        let mut private_key = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(
            secret
                .get(..32)
                .filter(|_| secret.len() == 32)
                .ok_or_else(|| MajikKeyError::msg("Invalid stored Ethereum private key"))?,
        );
        Ok(EthereumKeypairMaterial {
            private_key,
            public_key: self.store.get_public_key(KeyId::Eth)?.to_vec(),
        })
    }

    /// @experimental 0x-prefixed private key hex, for wallet "import private key".
    pub fn get_ethereum_private_key_hex(&self) -> MajikKeyResult<String> {
        Ok(to_ethereum_private_key_hex(
            &self.get_ethereum_keypair_material()?,
        ))
    }

    // ── SOLANA ──

    /// @experimental True if this MajikKey can currently produce a Solana keypair (unlocked + has Ed25519).
    pub fn has_solana_keypair(&self) -> bool {
        self.store.peek_secret_key(KeyId::Ed25519).is_some()
    }

    /// @experimental Raw Solana keypair material. Derived on demand (cheap: one SHA-256 and a
    /// scalar mult), so nothing extra is cached — or needs wiping — beyond what the caller holds.
    pub fn get_solana_keypair_material(
        &self,
        options: Option<&SolanaDerivationOptions>,
    ) -> MajikKeyResult<SolanaKeypairMaterial> {
        let ed = self.require_secret(
            KeyId::Ed25519,
            Some("No Ed25519 secret key — add it with add_keys() (requires the mnemonic)."),
        )?;
        if options.is_some_and(|o| o.reuse_message_key) {
            solana_material_from_ed25519_secret_key(ed)
        } else {
            derive_solana_keypair_from_ed_secret_key(ed)
        }
    }

    /// @experimental Base58 Solana address.
    pub fn get_solana_address(
        &self,
        options: Option<&SolanaDerivationOptions>,
    ) -> MajikKeyResult<String> {
        Ok(solana_address_from_public_key(
            &self.get_solana_keypair_material(options)?.public_key,
        ))
    }
}

#[doc(hidden)]
impl MajikKey {
    /// Test helper: is a stored slot present for `id`?
    pub fn store_has(&self, id: KeyId) -> bool {
        self.store.has(id)
    }
}
