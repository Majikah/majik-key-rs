use bip39::Mnemonic;
use ed25519_dalek::SigningKey as EdSigningKey;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes};
use ml_kem::{FromSeed as _, KeyExport as _, MlKem768};
use zeroize::Zeroizing;

use crate::crypto::provider::{
    ed25519_public_to_x25519, ed25519_seed_to_x25519_secret, sha256_bytes,
};
use crate::crypto::wordlist::MnemonicLanguage;
use crate::error::{MajikKeyError, MajikKeyResult};

const MAJIK_SIGNATURE_SEED: &str = crate::crypto::constants::MAJIK_SIGNATURE_SEED;

pub struct EncryptionIdentity {
    pub public_key: [u8; 32],
    pub private_key: Zeroizing<[u8; 32]>,
    pub fingerprint: [u8; 32],
    pub ml_kem_public_key: Vec<u8>,
    pub ml_kem_secret_seed: Zeroizing<[u8; 64]>,
    pub ed_public_key: [u8; 32],
    pub ed_secret_key: Zeroizing<[u8; 64]>,
    pub ml_dsa_public_key: Vec<u8>,
    pub ml_dsa_secret_seed: Zeroizing<[u8; 32]>,
}

pub fn derive_identity_from_mnemonic(
    mnemonic: &str,
    language: MnemonicLanguage,
) -> MajikKeyResult<EncryptionIdentity> {
    let bip39_lang = language.to_bip39()?;
    let parsed = Mnemonic::parse_in_normalized(bip39_lang, mnemonic)
        .map_err(|_| MajikKeyError::InvalidMnemonic)?;

    let seed64: Zeroizing<[u8; 64]> = Zeroizing::new(parsed.to_seed(""));

    // ─── X25519 / Ed25519 identity (seed[0..32]) ────────────────────────
    let mut seed32 = Zeroizing::new([0u8; 32]);
    seed32.copy_from_slice(&seed64[0..32]); // GenericArray-style indexing, gives &[u8] slice, fine

    // THE FIX for your second error: `EdSigningKey::from_bytes` wants
    // `&[u8; 32]` (a fixed-size array reference), not a slice. `&seed32`
    // alone is `&Zeroizing<[u8;32]>` and doesn't auto-coerce there either —
    // `&*seed32` explicitly dereferences through Zeroizing to the inner
    // `[u8;32]` first, giving exactly the type the function wants with no
    // coercion required at all.
    let ed_signing_key = EdSigningKey::from_bytes(&*seed32);
    let ed_verifying_key = ed_signing_key.verifying_key();
    let ed_public_key: [u8; 32] = ed_verifying_key.to_bytes();

    let mut ed_secret_key = Zeroizing::new([0u8; 64]);
    ed_secret_key[0..32].copy_from_slice(&seed32[..]); // slice target here — explicit [..]
    ed_secret_key[32..64].copy_from_slice(&ed_public_key);

    let x25519_private = ed25519_seed_to_x25519_secret(&*seed32); // fixed-array target — &*
    let x25519_public = ed25519_public_to_x25519(&ed_public_key)?; // plain array already, fine
    let fingerprint = sha256_bytes(&x25519_public); // array->slice unsizing only, no custom Deref, fine as-is

    // ─── ML-KEM-768 (full 64-byte seed = FIPS 203 `d || z`) ─────────────
    let kem_seed: ml_kem::Seed = (*seed64).into(); // explicit deref before .into()
    let (kem_dk, kem_ek) = MlKem768::from_seed(&kem_seed);
    let ml_kem_public_key = kem_ek.to_bytes().to_vec();

    let mut ml_kem_secret_seed = Zeroizing::new([0u8; 64]);
    ml_kem_secret_seed.copy_from_slice(&seed64[..]); // slice target — explicit [..]
    drop(kem_dk);

    // ─── ML-DSA-87 (domain-separated hash of the full seed) ─────────────
    let mut dsa_seed_input: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(64 + MAJIK_SIGNATURE_SEED.len()));
    dsa_seed_input.extend_from_slice(&seed64[..]); // slice target — explicit [..]
    dsa_seed_input.extend_from_slice(MAJIK_SIGNATURE_SEED.as_bytes());
    let ml_dsa_secret_seed = Zeroizing::new(sha256_bytes(&dsa_seed_input[..])); // slice target — explicit [..]

    let (ml_dsa_pk, ml_dsa_sk) = ml_dsa_87::KG::keygen_from_seed(&*ml_dsa_secret_seed); // fixed-array target — &*
    let ml_dsa_public_key = ml_dsa_pk.into_bytes().to_vec();
    drop(ml_dsa_sk);

    Ok(EncryptionIdentity {
        public_key: x25519_public,
        private_key: x25519_private,
        fingerprint,
        ml_kem_public_key,
        ml_kem_secret_seed,
        ed_public_key,
        ed_secret_key,
        ml_dsa_public_key,
        ml_dsa_secret_seed,
    })
}
