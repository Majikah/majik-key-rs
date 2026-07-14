use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bip39::Mnemonic;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::constants::{KdfVersion, IV_LENGTH, MAJIK_MNEMONIC_SALT, SALT_SIZE};
use crate::crypto::encryption_engine::{derive_identity_from_mnemonic, EncryptionIdentity};
use crate::crypto::provider::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_key_from_mnemonic_argon2,
    derive_key_from_passphrase_argon2, derive_key_from_passphrase_pbkdf2, generate_random_bytes,
};
use crate::crypto::wordlist::MnemonicLanguage;
use crate::error::{MajikKeyError, MajikKeyResult};
use crate::types::{
    MajikKeyDangerousJson, MajikKeyIdentity, MajikKeyJson, MajikKeyMetadata, MnemonicJson,
    SerializedIdentity, Web3Metadata,
};
use crate::validator::MajikKeyValidator;
use crate::web3::bitcoin::bitcoin::{
    bitcoin_public_key_from_private_key, derive_bitcoin_keypair_from_seed,
    BitcoinDerivationOptions, BitcoinKeypairMaterial,
};
use crate::web3::solana::solana::{
    derive_solana_keypair_from_ed_secret_key, solana_material_from_ed25519_secret_key,
    SolanaDerivationOptions, SolanaKeypairMaterial,
};

/// Options accepted by `MajikKey::create()` / `MajikKey::import_from_mnemonic_backup()`.
/// Mirrors the `options` object in the TS lib's equivalent factory methods.
#[derive(Debug, Clone, Copy)]
pub struct MajikKeyCreateOptions {
    pub mnemonic_language: MnemonicLanguage,
    /// @experimental — currently always ignored. Bitcoin derivation isn't
    /// wired up yet (see the `web3` stub methods below); this flag exists
    /// now so callers won't need to change their call sites once it is.
    pub derive_bitcoin: bool,
}

impl Default for MajikKeyCreateOptions {
    fn default() -> Self {
        Self {
            mnemonic_language: MnemonicLanguage::En,
            derive_bitcoin: true,
        }
    }
}

/// Internal shape for the encrypted-mnemonic-verification backup blob.
/// Mirrors the anonymous object TS builds in `_exportMnemonicBackup` /
/// parses in `importFromMnemonicBackup`.
#[derive(Debug, Serialize, Deserialize)]
struct BackupBlob {
    id: String,
    iv: String,
    ciphertext: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    fingerprint: String,
    #[serde(rename = "backupKdfVersion")]
    backup_kdf_version: u8,
}

/// MajikKey
/// ---
/// Rust port of the TS `MajikKey` class. See `crypto::encryption_engine`
/// for the underlying key derivation and `crypto::provider` for the raw
/// crypto primitives this struct orchestrates.
///
/// Unlike the TS version, there's no `CryptoKey | { raw }` union anywhere
/// here — every key is just a fixed-size byte array, since Rust has no
/// WebCrypto/Node inconsistency to paper over.
pub struct MajikKey {
    id: String,
    public_key: [u8; 32],
    fingerprint: String, // base64 SHA-256 digest; equals `id` for keys created by this crate
    backup: String,      // base64-encoded `BackupBlob` JSON
    timestamp: String,   // ISO 8601 — see `now_iso8601()` note below
    mnemonic_language: MnemonicLanguage,

    encrypted_private_key: Vec<u8>, // IV || ciphertext
    salt: Vec<u8>,
    label: String,
    kdf_version: KdfVersion,

    ml_kem_public_key: Vec<u8>,
    /// Stored as the 64-byte FIPS 203 seed, NOT the legacy 2400-byte
    /// expanded secret key the TS lib's `getMlKemSecretKey()` returns.
    /// Both fully reconstruct the same decapsulation key — this is a
    /// deliberate, documented storage-format difference, not a bug.
    ml_kem_secret_key: Option<Zeroizing<[u8; 64]>>,
    encrypted_ml_kem_secret_key: Option<Vec<u8>>,

    private_key: Option<Zeroizing<[u8; 32]>>, // X25519 private scalar, present only when unlocked

    ed_public_key: Option<[u8; 32]>,
    /// nacl/stablelib-compatible 64-byte form (seed || public key), matching
    /// the TS lib's `edSecretKey` shape exactly.
    ed_secret_key: Option<Zeroizing<[u8; 64]>>,
    encrypted_ed_secret_key: Option<Vec<u8>>,

    ml_dsa_public_key: Option<Vec<u8>>,
    /// Stored as the 32-byte FIPS 204 seed (ξ), not an expanded key — same
    /// rationale as `ml_kem_secret_key` above.
    ml_dsa_secret_key: Option<Zeroizing<[u8; 32]>>,
    encrypted_ml_dsa_secret_key: Option<Vec<u8>>,

    // ── Web3 (Bitcoin/Solana) — PLACEHOLDER FIELDS ──────────────────────
    // Bitcoin/Solana derivation isn't ported yet (see `web3` module TODO).
    // These fields exist so `MajikKeyJson` round-trips without data loss
    // for keys that already have Bitcoin material from the TS lib, but
    // nothing in this file currently populates or decrypts them.
    btc_public_key: Option<Vec<u8>>,
    btc_secret_key: Option<Zeroizing<Vec<u8>>>,
    encrypted_btc_secret_key: Option<Vec<u8>>,
}

impl MajikKey {
    // ── Getters ──────────────────────────────────────────────────────────

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn public_key_base64(&self) -> String {
        B64.encode(self.public_key)
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

    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }

    pub fn kdf_version(&self) -> KdfVersion {
        self.kdf_version
    }

    pub fn is_argon2id(&self) -> bool {
        self.kdf_version == KdfVersion::Argon2id
    }

    pub fn is_locked(&self) -> bool {
        self.private_key.is_none()
    }

    pub fn is_unlocked(&self) -> bool {
        self.private_key.is_some()
    }

    pub fn ml_kem_public_key(&self) -> &[u8] {
        &self.ml_kem_public_key
    }

    pub fn has_ml_kem(&self) -> bool {
        !self.ml_kem_public_key.is_empty()
    }

    pub fn is_fully_upgraded(&self) -> bool {
        self.is_argon2id() && self.has_ml_kem()
    }

    pub fn ed_public_key(&self) -> Option<[u8; 32]> {
        self.ed_public_key
    }

    pub fn ml_dsa_public_key(&self) -> Option<&[u8]> {
        self.ml_dsa_public_key.as_deref()
    }

    pub fn has_signing_keys(&self) -> bool {
        self.ed_public_key.is_some() && self.ml_dsa_public_key.is_some()
    }

    pub fn btc_public_key(&self) -> Option<&[u8]> {
        self.btc_public_key.as_deref()
    }

    pub fn has_bitcoin(&self) -> bool {
        self.btc_public_key.is_some()
    }

    pub fn metadata(&self) -> MajikKeyMetadata {
        MajikKeyMetadata {
            id: self.id.clone(),
            fingerprint: self.fingerprint.clone(),
            label: self.label.clone(),
            timestamp: self.timestamp.clone(),
            is_locked: self.is_locked(),
            kdf_version: self.kdf_version as u8,
            has_ml_kem: self.has_ml_kem(),
            web3: Web3Metadata {
                has_bitcoin: Some(self.has_bitcoin()),
                // Placeholder: Solana capability depends on an unlocked
                // Ed25519 key once web3 is wired up. Reflects Ed25519
                // *public* key presence for now as the closest available
                // signal — revisit once `web3::solana` exists.
                has_solana: Some(self.ed_public_key.is_some()),
            },
            mnemonic_language: Some(self.mnemonic_language),
        }
    }

    // ── CREATE ───────────────────────────────────────────────────────────

    pub fn create(
        mnemonic: Zeroizing<String>,
        passphrase: Zeroizing<String>,
        label: Option<&str>, // Labels aren't secrets; standard &str is fine
        options: MajikKeyCreateOptions,
    ) -> MajikKeyResult<Self> {
        MajikKeyValidator::validate_mnemonic(&mnemonic)?;
        MajikKeyValidator::validate_passphrase(&passphrase, "Passphrase")?;
        MajikKeyValidator::validate_label(label)?;
        MajikKeyValidator::validate_mnemonic_language(&mnemonic, options.mnemonic_language)?;

        let identity = derive_identity_from_mnemonic(&mnemonic, options.mnemonic_language)?;
        let (encrypted, salt) = Self::encrypt_all_secrets(&identity, &passphrase)?;
        let backup = Self::build_mnemonic_backup(&identity, &mnemonic)?;

        let (btc_public_key, btc_secret_key, encrypted_btc_secret_key) = if options.derive_bitcoin {
            let bip39_lang = options.mnemonic_language.to_bip39()?;
            let parsed = Mnemonic::parse_in_normalized(bip39_lang, &mnemonic)
                .map_err(|_| MajikKeyError::InvalidMnemonic)?;
            let seed = parsed.to_seed("");
            let btc_material = derive_bitcoin_keypair_from_seed(&seed, None)?;
            let encrypted_btc =
                Self::encrypt_with_argon2(&*btc_material.private_key, &passphrase, &salt)?;
            (
                Some(btc_material.public_key.to_vec()),
                Some(Zeroizing::new((*btc_material.private_key).to_vec())),
                Some(encrypted_btc),
            )
        } else {
            (None, None, None)
        };

        Ok(Self {
            id: hex_or_b64_fingerprint(&identity.fingerprint),
            public_key: identity.public_key,
            fingerprint: B64.encode(identity.fingerprint),
            backup,
            timestamp: now_iso8601(),
            mnemonic_language: options.mnemonic_language,

            encrypted_private_key: encrypted.private_key,
            salt: salt.to_vec(),
            label: label.unwrap_or("").to_string(),
            kdf_version: KdfVersion::Argon2id,

            ml_kem_public_key: identity.ml_kem_public_key.clone(),
            ml_kem_secret_key: Some(identity.ml_kem_secret_seed), // no Zeroizing::new — already wrapped
            encrypted_ml_kem_secret_key: Some(encrypted.ml_kem_secret_key),

            private_key: Some(identity.private_key), // no Zeroizing::new — already wrapped

            ed_public_key: Some(identity.ed_public_key),
            ed_secret_key: Some(identity.ed_secret_key), // no Zeroizing::new — already wrapped
            encrypted_ed_secret_key: Some(encrypted.ed_secret_key),

            ml_dsa_public_key: Some(identity.ml_dsa_public_key.clone()),
            ml_dsa_secret_key: Some(identity.ml_dsa_secret_seed), // no Zeroizing::new — already wrapped
            encrypted_ml_dsa_secret_key: Some(encrypted.ml_dsa_secret_key),

            btc_public_key,
            btc_secret_key,
            encrypted_btc_secret_key,
        })
    }

    // ── LOCK / UNLOCK ────────────────────────────────────────────────────

    pub fn lock(&mut self) -> &mut Self {
        self.private_key = None;
        self.ml_kem_secret_key = None;
        self.ed_secret_key = None;
        self.ml_dsa_secret_key = None;
        self.btc_secret_key = None;
        self
    }
    pub fn unlock(&mut self, passphrase: Zeroizing<String>) -> MajikKeyResult<&mut Self> {
        if self.is_unlocked() {
            return Err(MajikKeyError::AlreadyUnlocked);
        }
        MajikKeyValidator::validate_passphrase(&passphrase, "Passphrase")?;

        let salt = self.salt.clone();

        let private_key_bytes = Self::decrypt_private_key(
            &self.encrypted_private_key,
            &passphrase,
            &salt,
            self.kdf_version,
        )?;

        let pk_arr: [u8; 32] = private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::Other("decrypted private key was not 32 bytes".into()))?;
        self.private_key = Some(Zeroizing::new(pk_arr));

        if let Some(enc) = &self.encrypted_ml_kem_secret_key {
            let plain = Self::decrypt_with_argon2(enc, &passphrase, &salt)
                .ok_or(MajikKeyError::MlKemDecryptionFailed)?;
            let arr: [u8; 64] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("ML-KEM seed was not 64 bytes".into()))?;
            self.ml_kem_secret_key = Some(Zeroizing::new(arr));
        }

        if let Some(enc) = &self.encrypted_ed_secret_key {
            let plain = Self::decrypt_with_argon2(enc, &passphrase, &salt)
                .ok_or(MajikKeyError::SigningKeyDecryptionFailed)?;
            let arr: [u8; 64] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("Ed25519 secret key was not 64 bytes".into()))?;
            self.ed_secret_key = Some(Zeroizing::new(arr));
        }

        if let Some(enc) = &self.encrypted_ml_dsa_secret_key {
            let plain = Self::decrypt_with_argon2(enc, &passphrase, &salt)
                .ok_or(MajikKeyError::SigningKeyDecryptionFailed)?;
            let arr: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("ML-DSA seed was not 32 bytes".into()))?;
            self.ml_dsa_secret_key = Some(Zeroizing::new(arr));
        }

        if let Some(enc) = &self.encrypted_btc_secret_key {
            let plain = Self::decrypt_with_argon2(enc, &passphrase, &salt)
                .ok_or(MajikKeyError::SigningKeyDecryptionFailed)?;
            let arr: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("Bitcoin secret key was not 32 bytes".into()))?;
            self.btc_secret_key = Some(Zeroizing::new(arr.to_vec()));
            if self.btc_public_key.is_none() {
                self.btc_public_key = Some(bitcoin_public_key_from_private_key(&arr)?.to_vec());
            }
        }

        Ok(self)
    }

    pub fn verify(&self, passphrase: &str) -> bool {
        Self::decrypt_private_key(
            &self.encrypted_private_key,
            passphrase,
            &self.salt,
            self.kdf_version,
        )
        .is_ok()
    }

    // ── Restricted getters (require unlocked) ───────────────────────────

    pub fn get_private_key(&self) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
        self.private_key.clone().ok_or(MajikKeyError::Locked)
    }

    pub fn get_ml_kem_secret_key(&self) -> MajikKeyResult<Zeroizing<[u8; 64]>> {
        self.ml_kem_secret_key
            .clone()
            .ok_or(MajikKeyError::MissingKeyMaterial("ML-KEM"))
    }

    pub fn get_ed_secret_key(&self) -> MajikKeyResult<Zeroizing<[u8; 64]>> {
        self.ed_secret_key
            .clone()
            .ok_or(MajikKeyError::MissingKeyMaterial("Ed25519"))
    }

    pub fn get_ml_dsa_secret_key(&self) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
        self.ml_dsa_secret_key
            .clone()
            .ok_or(MajikKeyError::MissingKeyMaterial("ML-DSA"))
    }

    // ── UPDATE ───────────────────────────────────────────────────────────

    pub fn update_label(&mut self, new_label: &str) -> MajikKeyResult<&mut Self> {
        MajikKeyValidator::validate_label(Some(new_label))?;
        self.label = new_label.to_string();
        Ok(self)
    }

    // ── UPDATE ───────────────────────────────────────────────────────────

    pub fn update_passphrase(
        &mut self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> MajikKeyResult<&mut Self> {
        MajikKeyValidator::validate_passphrase(current_passphrase, "Current passphrase")?;
        MajikKeyValidator::validate_passphrase(new_passphrase, "New passphrase")?;

        let old_salt = self.salt.clone();

        let private_key_bytes = Self::decrypt_private_key(
            &self.encrypted_private_key,
            current_passphrase,
            &old_salt,
            self.kdf_version,
        )?;

        let ml_kem_plain = self
            .encrypted_ml_kem_secret_key
            .as_ref()
            .and_then(|e| Self::decrypt_with_argon2(e, current_passphrase, &old_salt));
        let ed_plain = self
            .encrypted_ed_secret_key
            .as_ref()
            .and_then(|e| Self::decrypt_with_argon2(e, current_passphrase, &old_salt));
        let ml_dsa_plain = self
            .encrypted_ml_dsa_secret_key
            .as_ref()
            .and_then(|e| Self::decrypt_with_argon2(e, current_passphrase, &old_salt));

        let btc_plain: Option<Zeroizing<Vec<u8>>> =
            if let Some(enc) = self.encrypted_btc_secret_key.as_ref() {
                Self::decrypt_with_argon2(enc, current_passphrase, &old_salt)
            } else if let Some(btc) = self.btc_secret_key.as_ref() {
                Some((*btc).clone())
            } else {
                None
            };

        let new_salt = generate_random_bytes(SALT_SIZE);

        self.encrypted_private_key =
            Self::encrypt_with_argon2(&private_key_bytes, new_passphrase, &new_salt)?;

        if let Some(plain) = &ml_kem_plain {
            let enc = Self::encrypt_with_argon2(plain, new_passphrase, &new_salt)?;
            self.encrypted_ml_kem_secret_key = Some(enc);
            let arr: [u8; 64] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("ML-KEM seed was not 64 bytes".into()))?;
            self.ml_kem_secret_key = Some(Zeroizing::new(arr));
        }
        if let Some(plain) = &ed_plain {
            let enc = Self::encrypt_with_argon2(plain, new_passphrase, &new_salt)?;
            self.encrypted_ed_secret_key = Some(enc);
            let arr: [u8; 64] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("Ed25519 secret key was not 64 bytes".into()))?;
            self.ed_secret_key = Some(Zeroizing::new(arr));
        }
        if let Some(plain) = &ml_dsa_plain {
            let enc = Self::encrypt_with_argon2(plain, new_passphrase, &new_salt)?;
            self.encrypted_ml_dsa_secret_key = Some(enc);
            let arr: [u8; 32] = plain
                .as_slice()
                .try_into()
                .map_err(|_| MajikKeyError::Other("ML-DSA seed was not 32 bytes".into()))?;
            self.ml_dsa_secret_key = Some(Zeroizing::new(arr));
        }
        if let Some(plain) = &btc_plain {
            let enc = Self::encrypt_with_argon2(plain.as_slice(), new_passphrase, &new_salt)?;
            self.encrypted_btc_secret_key = Some(enc);
            self.btc_secret_key = Some((*plain).clone());
        }

        let pk_arr: [u8; 32] = private_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::Other("private key was not 32 bytes".into()))?;
        self.private_key = Some(Zeroizing::new(pk_arr));

        self.salt = new_salt.to_vec();
        self.kdf_version = KdfVersion::Argon2id;

        Ok(self)
    }

    /// Migrate KDF from PBKDF2 to Argon2id without changing passphrase.
    /// Matches the TS lib's limited scope exactly: X25519 only, does NOT
    /// add ML-KEM/Ed25519/ML-DSA — use `import_from_mnemonic_backup()` for
    /// a full upgrade.
    pub fn migrate(&mut self, passphrase: &str) -> MajikKeyResult<&mut Self> {
        MajikKeyValidator::validate_passphrase(passphrase, "Passphrase")?;
        if self.kdf_version == KdfVersion::Argon2id {
            return Ok(self);
        }

        let private_key_bytes = Self::decrypt_private_key(
            &self.encrypted_private_key,
            passphrase,
            &self.salt,
            KdfVersion::Pbkdf2,
        )?;

        let new_salt = generate_random_bytes(SALT_SIZE);
        self.encrypted_private_key =
            Self::encrypt_with_argon2(&private_key_bytes, passphrase, &new_salt)?;
        self.salt = new_salt.to_vec();
        self.kdf_version = KdfVersion::Argon2id;

        Ok(self)
    }

    // ── SERIALIZATION ────────────────────────────────────────────────────

    pub fn to_json(&self) -> MajikKeyJson {
        MajikKeyJson {
            id: self.id.clone(),
            label: self.label.clone(),
            public_key: self.public_key_base64(),
            fingerprint: self.fingerprint.clone(),
            encrypted_private_key: B64.encode(&self.encrypted_private_key),
            salt: B64.encode(&self.salt),
            backup: self.backup.clone(),
            timestamp: self.timestamp.clone(),
            kdf_version: Some(self.kdf_version as u8),
            ml_kem_public_key: Some(B64.encode(&self.ml_kem_public_key)),
            encrypted_ml_kem_secret_key: self
                .encrypted_ml_kem_secret_key
                .as_ref()
                .map(|v| B64.encode(v)),
            ed_public_key: self.ed_public_key.map(|k| B64.encode(k)),
            encrypted_ed_secret_key: self.encrypted_ed_secret_key.as_ref().map(|v| B64.encode(v)),
            ml_dsa_public_key: self.ml_dsa_public_key.as_ref().map(|v| B64.encode(v)),
            encrypted_ml_dsa_secret_key: self
                .encrypted_ml_dsa_secret_key
                .as_ref()
                .map(|v| B64.encode(v)),
            btc_public_key: self.btc_public_key.as_ref().map(|v| B64.encode(v)),
            encrypted_btc_secret_key: self
                .encrypted_btc_secret_key
                .as_ref()
                .map(|v| B64.encode(v)),
            mnemonic_language: Some(self.mnemonic_language),
        }
    }

    pub fn to_string_pretty(&self) -> MajikKeyResult<String> {
        serde_json::to_string_pretty(&self.to_json()).map_err(MajikKeyError::from)
    }

    pub fn from_json(json: &MajikKeyJson) -> MajikKeyResult<Self> {
        MajikKeyValidator::validate_json(json)?;

        let public_key: [u8; 32] = B64
            .decode(&json.public_key)?
            .try_into()
            .map_err(|_| MajikKeyError::InvalidJson)?;

        Ok(Self {
            id: json.id.clone(),
            public_key,
            fingerprint: json.fingerprint.clone(),
            backup: json.backup.clone(),
            timestamp: json.timestamp.clone(),
            mnemonic_language: json.mnemonic_language.unwrap_or(MnemonicLanguage::En),

            encrypted_private_key: B64.decode(&json.encrypted_private_key)?,
            salt: B64.decode(&json.salt)?,
            label: json.label.clone(),
            kdf_version: KdfVersion::from_u8(json.kdf_version.unwrap_or(1)),

            ml_kem_public_key: json
                .ml_kem_public_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?
                .unwrap_or_default(),
            ml_kem_secret_key: None,
            encrypted_ml_kem_secret_key: json
                .encrypted_ml_kem_secret_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?,

            private_key: None,

            ed_public_key: json
                .ed_public_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?
                .map(|v| v.try_into().map_err(|_| MajikKeyError::InvalidJson))
                .transpose()?,
            ed_secret_key: None,
            encrypted_ed_secret_key: json
                .encrypted_ed_secret_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?,

            ml_dsa_public_key: json
                .ml_dsa_public_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?,
            ml_dsa_secret_key: None,
            encrypted_ml_dsa_secret_key: json
                .encrypted_ml_dsa_secret_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?,

            btc_public_key: json
                .btc_public_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?,
            btc_secret_key: None,
            encrypted_btc_secret_key: json
                .encrypted_btc_secret_key
                .as_ref()
                .map(|s| B64.decode(s))
                .transpose()?,
        })
    }

    // ── DANGEROUS JSON ───────────────────────────────────────────────────

    pub fn to_dangerous_json(&self) -> MajikKeyResult<MajikKeyDangerousJson> {
        let private_key = self.private_key.as_ref().ok_or(MajikKeyError::Locked)?;
        let ml_kem = self
            .ml_kem_secret_key
            .as_ref()
            .ok_or(MajikKeyError::MissingSecretKeys)?;
        let ed = self
            .ed_secret_key
            .as_ref()
            .ok_or(MajikKeyError::MissingSecretKeys)?;
        let ml_dsa = self
            .ml_dsa_secret_key
            .as_ref()
            .ok_or(MajikKeyError::MissingSecretKeys)?;

        Ok(MajikKeyDangerousJson {
            base: self.to_json(),
            private_key_base64: B64.encode(&**private_key),
            ml_kem_secret_key_base64: B64.encode(&**ml_kem),
            ed_secret_key_base64: B64.encode(&**ed),
            ml_dsa_secret_key_base64: B64.encode(&**ml_dsa),
            btc_secret_key_base64: self.btc_secret_key.as_ref().map(|v| B64.encode(&**v)),
        })
    }

    // ── DANGEROUS JSON ───────────────────────────────────────────────────

    // ... [Keep to_dangerous_json as is] ...

    pub fn from_dangerous_json(json: &MajikKeyDangerousJson) -> MajikKeyResult<Self> {
        let mut key = Self::from_json(&json.base)?;

        let pk_buf = Self::safe_b64_decode(&json.private_key_base64)?;
        let pk_arr: [u8; 32] = pk_buf
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::InvalidDangerousJson)?;
        key.private_key = Some(Zeroizing::new(pk_arr));

        let ml_kem_buf = Self::safe_b64_decode(&json.ml_kem_secret_key_base64)?;
        let ml_kem_arr: [u8; 64] = ml_kem_buf
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::InvalidDangerousJson)?;
        key.ml_kem_secret_key = Some(Zeroizing::new(ml_kem_arr));

        let ed_buf = Self::safe_b64_decode(&json.ed_secret_key_base64)?;
        let ed_arr: [u8; 64] = ed_buf
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::InvalidDangerousJson)?;
        key.ed_secret_key = Some(Zeroizing::new(ed_arr));

        let ml_dsa_buf = Self::safe_b64_decode(&json.ml_dsa_secret_key_base64)?;
        let ml_dsa_arr: [u8; 32] = ml_dsa_buf
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::InvalidDangerousJson)?;
        key.ml_dsa_secret_key = Some(Zeroizing::new(ml_dsa_arr));

        if let Some(btc) = &json.btc_secret_key_base64 {
            key.btc_secret_key = Some(Self::safe_b64_decode(btc)?);
        }

        if key.btc_public_key.is_none() {
            if let Some(secret) = &key.btc_secret_key {
                let arr: [u8; 32] = secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| MajikKeyError::InvalidDangerousJson)?;
                key.btc_public_key = Some(bitcoin_public_key_from_private_key(&arr)?.to_vec());
            }
        }

        Ok(key)
    }
    // ── MnemonicJSON ─────────────────────────────────────────────────────

    pub fn to_mnemonic_json(
        &self,
        mnemonic: &str,
        passphrase: Option<&str>,
    ) -> MajikKeyResult<MnemonicJson> {
        if self.is_locked() {
            return Err(MajikKeyError::Locked);
        }
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        if let Some(p) = passphrase {
            MajikKeyValidator::validate_passphrase(p, "Passphrase")?;
        }

        Ok(MnemonicJson {
            id: self.backup.clone(),
            seed: mnemonic
                .trim()
                .split_whitespace()
                .map(|w| w.to_lowercase())
                .collect(),
            phrase: passphrase.map(|p| p.trim().to_string()),
        })
    }

    pub fn from_mnemonic_json(
        json: &MnemonicJson,
        passphrase: Zeroizing<String>,
        label: Option<&str>,
        options: MajikKeyCreateOptions,
    ) -> MajikKeyResult<Self> {
        if json.seed.is_empty() {
            return Err(MajikKeyError::Other("Invalid MnemonicJSON".into()));
        }
        // Wrap the join result in Zeroizing immediately
        let mnemonic = Zeroizing::new(json.seed.join(" "));

        MajikKeyValidator::validate_mnemonic(&mnemonic)?;
        Self::create(mnemonic, passphrase, label, options)
    }
    // ── BACKUP ───────────────────────────────────────────────────────────

    pub fn export_mnemonic_backup(&self, mnemonic: Zeroizing<String>) -> MajikKeyResult<String> {
        if self.is_locked() {
            return Err(MajikKeyError::Locked);
        }
        MajikKeyValidator::validate_mnemonic(&mnemonic)?;

        let identity = derive_identity_from_mnemonic(&mnemonic, self.mnemonic_language)?;
        Self::build_mnemonic_backup(&identity, &mnemonic)
    }

    pub fn import_from_mnemonic_backup(
        backup: &str,
        mnemonic: Zeroizing<String>,
        passphrase: Zeroizing<String>,
        label: Option<&str>,
        options: MajikKeyCreateOptions,
    ) -> MajikKeyResult<Self> {
        if backup.is_empty() {
            return Err(MajikKeyError::Other(
                "Backup must be a non-empty string".into(),
            ));
        }

        // Pass references to the Zeroizing wrappers (via Deref) to validators
        MajikKeyValidator::validate_mnemonic(&mnemonic)?;
        MajikKeyValidator::validate_passphrase(&passphrase, "Passphrase")?;
        MajikKeyValidator::validate_label(label)?;
        MajikKeyValidator::validate_mnemonic_language(&mnemonic, options.mnemonic_language)?;

        let backup_json = String::from_utf8(B64.decode(backup)?)
            .map_err(|_| MajikKeyError::InvalidBackupFormat)?;
        let parsed: BackupBlob =
            serde_json::from_str(&backup_json).map_err(|_| MajikKeyError::InvalidBackupFormat)?;

        Self::verify_backup_decryption(&parsed, &mnemonic)?;

        // Pass the Zeroizing variables directly to create
        let mut key = Self::create(mnemonic, passphrase, label, options)?;

        if !parsed.id.is_empty() {
            key.id = parsed.id.clone();
        }
        key.backup = backup.to_string();
        Ok(key)
    }

    // ── UTILITY (static) ─────────────────────────────────────────────────

    pub fn generate_mnemonic(strength: u32, language: MnemonicLanguage) -> MajikKeyResult<String> {
        if strength != 128 && strength != 256 {
            return Err(MajikKeyError::Other("Strength must be 128 or 256".into()));
        }
        let bip39_lang = language.to_bip39()?;
        let entropy_len = (strength / 8) as usize;
        let entropy = generate_random_bytes(entropy_len);
        let m = Mnemonic::from_entropy_in(bip39_lang, &entropy)
            .map_err(|_| MajikKeyError::Other("Failed to generate mnemonic".into()))?;
        Ok(m.to_string())
    }

    pub fn validate_mnemonic_str(mnemonic: &str) -> bool {
        MajikKeyValidator::validate_mnemonic(mnemonic).is_ok()
    }

    // ── toKeyIdentity / toSerializedIdentity ─────────────────────────────
    // (No `toContact()` here yet — that needs `MajikContact`, which lives
    // in a separate not-yet-ported crate/module. Add it once that exists.)

    /// Returns `(public_key, private_key, fingerprint, ml_kem_public_key,
    /// ml_kem_secret_key)` — the Rust equivalent of `toKeyIdentity()`.
    /// Named-tuple-ish rather than a dedicated `MajikKeyIdentity` struct
    /// since Rust doesn't need a separate constructor-options shape the
    /// way the TS lib does — `MajikKey`'s own fields already are that shape.
    pub fn to_key_identity(&self) -> MajikKeyResult<MajikKeyIdentity> {
        let private_key = self.private_key.clone().ok_or(MajikKeyError::Locked)?;
        let ml_kem_secret = self
            .ml_kem_secret_key
            .clone()
            .ok_or(MajikKeyError::Locked)?;

        Ok(MajikKeyIdentity {
            id: self.id.clone(),
            public_key: self.public_key,
            fingerprint: self.fingerprint.clone(),
            private_key,
            encrypted_private_key: self.encrypted_private_key.clone(),
            salt: B64.encode(&self.salt),
            kdf_version: self.kdf_version as u8,
            ml_kem_public_key: self.ml_kem_public_key.clone(),
            ml_kem_secret_key: ml_kem_secret,
        })
    }

    pub fn to_serialized_identity(&self) -> MajikKeyResult<SerializedIdentity> {
        let _ = self.private_key.as_ref().ok_or(MajikKeyError::Locked)?;
        Ok(SerializedIdentity {
            id: self.id.clone(),
            public_key: B64.encode(&self.public_key),
            fingerprint: self.fingerprint.clone(),
            encrypted_private_key: B64.encode(&self.encrypted_private_key),
            salt: B64.encode(&self.salt),
        })
    }
    // ── PLACEHOLDERS — need modules not yet ported ───────────────────────

    /// TODO: needs `MajikContact` (separate crate/module, not yet ported).
    /// Mirrors `toContact()` in the TS lib.
    pub fn to_contact(&self) -> MajikKeyResult<()> {
        Err(MajikKeyError::Other(
            "to_contact() requires the majik-contact module, not yet ported".into(),
        ))
    }

    /// TODO: needs `MajikMessageIdentity` (database::system::identity,
    /// not yet ported) and `MajikUser`. Mirrors `toMajikMessageIdentity()`.
    pub fn to_majik_message_identity(&self) -> MajikKeyResult<()> {
        Err(MajikKeyError::Other(
            "to_majik_message_identity() requires database::system::identity, not yet ported"
                .into(),
        ))
    }

    /// Mirrors `getBitcoinKeypairMaterial()` in the TS lib.
    pub fn get_bitcoin_keypair_material(
        &self,
        options: Option<&BitcoinDerivationOptions>,
    ) -> MajikKeyResult<BitcoinKeypairMaterial> {
        if self.is_locked() {
            return Err(MajikKeyError::Locked);
        }

        if let Some(opts) = options {
            if opts.standard || opts.path.is_some() {
                return Err(MajikKeyError::Other(
                    "Deriving the standard BIP-84 path requires the mnemonic — use MajikKey::derive_standard_bitcoin_from_mnemonic(mnemonic, language) instead.".into(),
                ));
            }
        }

        let public_key = self
            .btc_public_key
            .as_ref()
            .ok_or(MajikKeyError::MissingKeyMaterial("Bitcoin"))?;
        let private_key_vec = self
            .btc_secret_key
            .clone()
            .ok_or(MajikKeyError::MissingKeyMaterial("Bitcoin"))?;

        let public_key: [u8; 33] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::Other("Invalid stored Bitcoin public key".into()))?;

        let pk_arr: [u8; 32] = private_key_vec
            .as_slice()
            .try_into()
            .map_err(|_| MajikKeyError::Other("Invalid stored Bitcoin private key".into()))?;

        Ok(BitcoinKeypairMaterial {
            public_key,
            private_key: Zeroizing::new(pk_arr),
        })
    }

    /// Mirror of `MajikKey.deriveStandardBitcoinFromMnemonic()` in the TS lib.
    pub fn derive_standard_bitcoin_from_mnemonic(
        mnemonic: &str,
        mnemonic_language: MnemonicLanguage,
    ) -> MajikKeyResult<BitcoinKeypairMaterial> {
        MajikKeyValidator::validate_mnemonic(mnemonic)?;
        MajikKeyValidator::validate_mnemonic_language(mnemonic, mnemonic_language)?;

        let bip39_lang = mnemonic_language.to_bip39()?;
        let parsed = Mnemonic::parse_in_normalized(bip39_lang, mnemonic)
            .map_err(|_| MajikKeyError::InvalidMnemonic)?;
        let seed = parsed.to_seed("");

        let options = BitcoinDerivationOptions {
            standard: true,
            path: None,
        };

        derive_bitcoin_keypair_from_seed(&seed, Some(&options))
    }

    /// Mirrors `getSolanaKeypairMaterial()` in the TS lib.
    pub fn get_solana_keypair_material(
        &self,
        options: Option<&SolanaDerivationOptions>,
    ) -> MajikKeyResult<SolanaKeypairMaterial> {
        if self.is_locked() {
            return Err(MajikKeyError::Locked);
        }

        let secret = self
            .ed_secret_key
            .as_ref()
            .ok_or(MajikKeyError::MissingKeyMaterial("Ed25519"))?;

        if options.map(|opts| opts.reuse_message_key).unwrap_or(false) {
            solana_material_from_ed25519_secret_key(&**secret)
        } else {
            derive_solana_keypair_from_ed_secret_key(&**secret)
        }
    }

    // ── PRIVATE HELPERS ──────────────────────────────────────────────────

    // Add this to your PRIVATE HELPERS section
    fn safe_b64_decode(input: &str) -> MajikKeyResult<Zeroizing<Vec<u8>>> {
        // Calculate max possible length to pre-allocate
        let max_len = (input.len() + 3) / 4 * 3;
        let mut buffer = Zeroizing::new(vec![0u8; max_len]);

        // Decode directly into the protected heap allocation
        let actual_len = B64
            .decode_slice(input, &mut *buffer)
            .map_err(|_| MajikKeyError::Other("Safe Base64 decode failed".into()))?;

        buffer.truncate(actual_len);
        Ok(buffer)
    }

    fn encrypt_with_argon2(plain: &[u8], passphrase: &str, salt: &[u8]) -> MajikKeyResult<Vec<u8>> {
        let key = derive_key_from_passphrase_argon2(passphrase, salt)?;
        let iv = generate_random_bytes(IV_LENGTH);
        let ciphertext = aes_gcm_encrypt(&*key, &iv, plain)?; // &*key, was &key
        let mut blob = iv;
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    fn decrypt_with_argon2(
        blob: &[u8],
        passphrase: &str,
        salt: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        if blob.len() < IV_LENGTH {
            return None;
        }
        let key = derive_key_from_passphrase_argon2(passphrase, salt).ok()?;
        let (iv, ciphertext) = blob.split_at(IV_LENGTH);
        aes_gcm_decrypt(&*key, iv, ciphertext) // &*key, and NO .map(Zeroizing::new) — already wrapped
    }

    fn decrypt_private_key(
        blob: &[u8],
        passphrase: &str,
        salt: &[u8],
        kdf_version: KdfVersion,
    ) -> MajikKeyResult<Zeroizing<Vec<u8>>> {
        if blob.len() < IV_LENGTH {
            return Err(MajikKeyError::DecryptionFailed);
        }
        let (iv, ciphertext) = blob.split_at(IV_LENGTH);
        // type annotation changed: both arms now return Zeroizing<[u8;32]>, not [u8;32]
        let key: Zeroizing<[u8; 32]> = match kdf_version {
            KdfVersion::Argon2id => derive_key_from_passphrase_argon2(passphrase, salt)?,
            KdfVersion::Pbkdf2 => derive_key_from_passphrase_pbkdf2(passphrase, salt, 250_000),
        };
        aes_gcm_decrypt(&*key, iv, ciphertext) // &*key, no .map(Zeroizing::new) — already wrapped
            .ok_or(MajikKeyError::DecryptionFailed)
    }

    /// Encrypts every secret in `identity` under one freshly generated
    /// salt — mirrors `_deriveAndEncryptFromMnemonic`'s "single salt, one
    /// Argon2id derivation unlocks every key" design.
    fn encrypt_all_secrets(
        identity: &EncryptionIdentity,
        passphrase: &str,
    ) -> MajikKeyResult<(EncryptedSecrets, [u8; SALT_SIZE])> {
        let salt: [u8; SALT_SIZE] = generate_random_bytes(SALT_SIZE)
            .try_into()
            .map_err(|_| MajikKeyError::Other("salt generation failed".into()))?;

        Ok((
            EncryptedSecrets {
                private_key: Self::encrypt_with_argon2(
                    &identity.private_key[..],
                    passphrase,
                    &salt,
                )?,
                ml_kem_secret_key: Self::encrypt_with_argon2(
                    &identity.ml_kem_secret_seed[..],
                    passphrase,
                    &salt,
                )?,
                ed_secret_key: Self::encrypt_with_argon2(
                    &identity.ed_secret_key[..],
                    passphrase,
                    &salt,
                )?,
                ml_dsa_secret_key: Self::encrypt_with_argon2(
                    &identity.ml_dsa_secret_seed[..],
                    passphrase,
                    &salt,
                )?,
            },
            salt,
        ))
    }

    fn build_mnemonic_backup(
        identity: &EncryptionIdentity,
        mnemonic: &str,
    ) -> MajikKeyResult<String> {
        let mnemonic_salt = MAJIK_MNEMONIC_SALT.as_bytes();
        let key = derive_key_from_mnemonic_argon2(mnemonic, mnemonic_salt)?;
        let iv = generate_random_bytes(IV_LENGTH);
        let ciphertext = aes_gcm_encrypt(&*key, &iv, &identity.private_key[..])?; // both fixed

        let blob = BackupBlob {
            id: B64.encode(identity.fingerprint),
            iv: B64.encode(&iv),
            ciphertext: B64.encode(&ciphertext),
            public_key: B64.encode(identity.public_key),
            fingerprint: B64.encode(identity.fingerprint),
            backup_kdf_version: KdfVersion::Argon2id as u8,
        };
        let json = serde_json::to_string(&blob)?;
        Ok(B64.encode(json))
    }

    fn verify_backup_decryption(parsed: &BackupBlob, mnemonic: &str) -> MajikKeyResult<()> {
        let iv = B64.decode(&parsed.iv)?;
        let ciphertext = B64.decode(&parsed.ciphertext)?;
        let mnemonic_salt = MAJIK_MNEMONIC_SALT.as_bytes();

        let plain = if parsed.backup_kdf_version == KdfVersion::Argon2id as u8 {
            let key = derive_key_from_mnemonic_argon2(mnemonic, mnemonic_salt)?;
            aes_gcm_decrypt(&*key, &iv, &ciphertext) // &*key
        } else {
            None
        };

        plain
            .map(|_| ())
            .ok_or(MajikKeyError::BackupDecryptionFailed)
    }
}

struct EncryptedSecrets {
    private_key: Vec<u8>,
    ml_kem_secret_key: Vec<u8>,
    ed_secret_key: Vec<u8>,
    ml_dsa_secret_key: Vec<u8>,
}

fn now_iso8601() -> String {
    // Timestamp::now() creates a UTC timestamp
    Timestamp::now().to_string()
}

fn hex_or_b64_fingerprint(fingerprint_bytes: &[u8; 32]) -> String {
    B64.encode(fingerprint_bytes)
}
