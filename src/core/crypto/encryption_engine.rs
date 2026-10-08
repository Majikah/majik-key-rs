//! Port of `core/crypto/encryption-engine.ts`.
//!
//! Since TS 0.8 this DELEGATES to the key registry (`core::keys::key_impls`),
//! the single source of truth for every derivation recipe.
//!
//! One signature difference: the `bip39` crate hangs seed derivation off a
//! *validated* `Mnemonic`, so a [`MnemonicLanguage`] is required here
//! (`@scure/bip39`'s `mnemonicToSeedSync` accepts any string).

use zeroize::Zeroizing;

use crate::core::crypto::crypto_provider::{fingerprint_from_public_raw, mnemonic_to_seed};
use crate::core::crypto::wordlist::MnemonicLanguage;
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::keys::key_id::KeyId;
use crate::core::keys::key_impls::derive_keys;
use crate::core::types::{
    ED25519RawPublicKey, MLDSA87RawPublicKey, MLKEM768RawPublicKey, MajikKeyFingerprint,
    SecretBytes, X25519RawKey,
};

/// The core four, derived from one mnemonic.
pub struct EncryptionIdentity {
    pub public_key: X25519RawKey,
    pub private_key: Zeroizing<[u8; 32]>,
    /// SHA-256 of the X25519 public key, base64.
    pub fingerprint: MajikKeyFingerprint,
    /// ML-KEM-768 public key (1184 bytes).
    pub ml_kem_public_key: MLKEM768RawPublicKey,
    /// ML-KEM-768 secret key, expanded form (2400 bytes).
    pub ml_kem_secret_key: SecretBytes,
    /// Ed25519, 32 bytes — for signing.
    pub ed_public_key: ED25519RawPublicKey,
    /// Ed25519, 64 bytes (`seed ‖ public`).
    pub ed_secret_key: Zeroizing<[u8; 64]>,
    /// ML-DSA-87 public key (2592 bytes).
    pub ml_dsa_public_key: MLDSA87RawPublicKey,
    /// ML-DSA-87 secret key (4896 bytes).
    pub ml_dsa_secret_key: SecretBytes,
}

pub struct EncryptionEngine;

impl EncryptionEngine {
    /// Derive the core identity (X25519, Ed25519, ML-KEM-768, ML-DSA-87) from a BIP-39 mnemonic.
    pub fn derive_identity_from_mnemonic(
        mnemonic: &str,
        language: MnemonicLanguage,
    ) -> MajikKeyResult<EncryptionIdentity> {
        if mnemonic.trim().is_empty() {
            return Err(MajikKeyError::crypto("Mnemonic must be a non-empty string"));
        }
        let seed64 = mnemonic_to_seed(mnemonic, language)?;
        let k = derive_keys(
            &seed64[..],
            &[
                KeyId::X25519,
                KeyId::Ed25519,
                KeyId::MlKem768,
                KeyId::MlDsa87,
            ],
        )
        .map_err(|e| MajikKeyError::with_cause("Failed to derive identity from mnemonic", e))?;

        let arr32 = |v: &[u8]| -> MajikKeyResult<[u8; 32]> {
            v.try_into()
                .map_err(|_| MajikKeyError::crypto("unexpected key length"))
        };
        let x = &k[&KeyId::X25519];
        let ed = &k[&KeyId::Ed25519];
        let kem = &k[&KeyId::MlKem768];
        let dsa = &k[&KeyId::MlDsa87];

        let mut priv32 = Zeroizing::new([0u8; 32]);
        priv32.copy_from_slice(&x.secret_key);
        let mut ed64 = Zeroizing::new([0u8; 64]);
        ed64.copy_from_slice(&ed.secret_key);

        Ok(EncryptionIdentity {
            public_key: X25519RawKey {
                raw: arr32(&x.public_key)?,
            },
            private_key: priv32,
            fingerprint: fingerprint_from_public_raw(&x.public_key),
            ml_kem_public_key: kem.public_key.clone(),
            ml_kem_secret_key: Zeroizing::new(kem.secret_key.to_vec()),
            ed_public_key: arr32(&ed.public_key)?,
            ed_secret_key: ed64,
            ml_dsa_public_key: dsa.public_key.clone(),
            ml_dsa_secret_key: Zeroizing::new(dsa.secret_key.to_vec()),
        })
    }

    /// SHA-256 fingerprint (base64) of a raw public key.
    pub fn fingerprint_from_public_key(public_key: &[u8]) -> String {
        fingerprint_from_public_raw(public_key)
    }
}
