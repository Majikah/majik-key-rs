#![allow(deprecated)] // ml-kem's expanded-key encoding is deprecated upstream but is the TS storage format
//! Port of `core/crypto/crypto-provider.ts` — the raw crypto primitives.
//!
//! Differences from the TS version, all deliberate:
//!  * **No WASM.** `hash-wasm` + the `@noble/hashes` fallback collapse into the
//!    pure-Rust `argon2` crate. Output is identical (same Argon2id v1.3).
//!  * **Synchronous.** Argon2id with 64 MiB × 3 passes blocks for a few hundred
//!    ms; from async/UI code (Tauri!) run it on `spawn_blocking`.
//!  * **Zeroize everywhere.** Every derived key / secret is `Zeroizing<_>`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::SigningKey as EdSigningKey;
use ml_kem::kem::{Decapsulate as _, Encapsulate as _, Kem as _};
use ml_kem::{EncapsulationKey, ExpandedKeyEncoding as _, KeyExport as _, MlKem768};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::core::crypto::constants::{
    Argon2Params, ARGON2_MNEMONIC_PARAMS, ARGON2_PASSPHRASE_PARAMS, PBKDF2_MNEMONIC_ITERATIONS,
    PBKDF2_PASSPHRASE_ITERATIONS,
};
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::utils::array_to_base64;

pub const IV_LENGTH: usize = 12;

// ─── Randomness ─────────────────────────────────────────────────────────────

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

pub fn generate_random_bytes_protected(len: usize) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut buf[..]).expect("OS RNG failure");
    buf
}

// ─── Ed25519 / X25519 (ed2curve replacement) ────────────────────────────────

/// Mirrors the object returned by TS `generateEd25519Keypair()` / `deriveEd25519FromSeed()`.
pub struct Ed25519Material {
    pub ed_public: [u8; 32],
    /// nacl/stablelib layout: `seed || public` (64 bytes).
    pub ed_secret: Zeroizing<[u8; 64]>,
    pub x_public: [u8; 32],
    pub x_secret: Zeroizing<[u8; 32]>,
}

pub fn derive_ed25519_from_seed(seed32: &[u8; 32]) -> MajikKeyResult<Ed25519Material> {
    let signing = EdSigningKey::from_bytes(seed32);
    let ed_public = signing.verifying_key().to_bytes();

    let mut ed_secret = Zeroizing::new([0u8; 64]);
    ed_secret[..32].copy_from_slice(seed32);
    ed_secret[32..].copy_from_slice(&ed_public);

    Ok(Ed25519Material {
        x_public: ed25519_public_to_x25519(&ed_public)?,
        x_secret: ed25519_seed_to_x25519_secret(seed32),
        ed_public,
        ed_secret,
    })
}

pub fn generate_ed25519_keypair() -> MajikKeyResult<Ed25519Material> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).expect("OS RNG failure");
    derive_ed25519_from_seed(&seed)
}

/// `ed2curve.convertSecretKey`: `clamp(SHA-512(seed)[0..32])`.
pub fn ed25519_seed_to_x25519_secret(ed_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha512::new();
    hasher.update(ed_seed);
    let mut expanded = hasher.finalize();

    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&expanded[0..32]);
    for b in expanded.iter_mut() {
        *b = 0;
    }

    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// `ed2curve.convertPublicKey`: Edwards → Montgomery.
pub fn ed25519_public_to_x25519(ed_public: &[u8; 32]) -> MajikKeyResult<[u8; 32]> {
    let point = CompressedEdwardsY(*ed_public)
        .decompress()
        .ok_or_else(|| MajikKeyError::crypto("Invalid Ed25519 public key point"))?;
    Ok(point.to_montgomery().to_bytes())
}

/// X25519 Diffie-Hellman. Rejects the all-zero output (small-order input), per RFC 7748 §6.1.
pub fn x25519_shared_secret(
    priv_raw: &[u8; 32],
    pub_raw: &[u8; 32],
) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    let shared = Zeroizing::new(MontgomeryPoint(*pub_raw).mul_clamped(*priv_raw).to_bytes());
    if shared.iter().all(|b| *b == 0) {
        return Err(MajikKeyError::crypto("x25519: invalid shared key"));
    }
    Ok(shared)
}

// ─── Hashing / fingerprints ─────────────────────────────────────────────────

pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Base64 SHA-256 of a UTF-8 string (TS `sha256()`).
pub fn sha256(input: &str) -> String {
    array_to_base64(&sha256_bytes(input.as_bytes()))
}

/// Base64 SHA-256 digest of a raw public key — the account fingerprint / `id`.
pub fn fingerprint_from_public_raw(raw_public: &[u8]) -> String {
    array_to_base64(&sha256_bytes(raw_public))
}

// ─── AES-256-GCM ────────────────────────────────────────────────────────────

pub fn aes_gcm_encrypt(key: &[u8; 32], iv: &[u8], plaintext: &[u8]) -> MajikKeyResult<Vec<u8>> {
    if iv.len() != IV_LENGTH {
        return Err(MajikKeyError::crypto("IV must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| MajikKeyError::crypto(format!("Invalid AES key: {e}")))?;
    let nonce =
        Nonce::try_from(iv).map_err(|_| MajikKeyError::crypto("Invalid AES-GCM nonce"))?;
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &[] })
        .map_err(|_| MajikKeyError::crypto("AES-GCM encryption failed"))
}

/// Returns `None` on authentication failure (wrong key / tampered data) —
/// the TS `aesGcmDecrypt` returns `null` the same way.
pub fn aes_gcm_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if iv.len() != IV_LENGTH {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::try_from(iv).ok()?;
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad: &[] })
        .ok()
        .map(Zeroizing::new)
}

// ─── KDF v2: Argon2id (current) ─────────────────────────────────────────────

fn argon2id(input: &[u8], salt: &[u8], params: &Argon2Params) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    debug_assert_eq!(params.output_len, 32);
    let argon2_params = Params::new(
        params.mem_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|e| MajikKeyError::crypto(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(input, salt, &mut out[..])
        .map_err(|e| MajikKeyError::crypto(format!("Argon2id derivation failed: {e}")))?;
    Ok(out)
}

/// Derive a 32-byte AES key from a user passphrase using Argon2id (m=64 MiB, t=3, p=4).
pub fn derive_key_from_passphrase_argon2(
    passphrase: &str,
    salt: &[u8],
) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    argon2id(passphrase.as_bytes(), salt, &ARGON2_PASSPHRASE_PARAMS)
}

/// Derive a 32-byte AES key from a BIP-39 mnemonic using Argon2id (m=64 MiB, t=3, p=2).
pub fn derive_key_from_mnemonic_argon2(
    mnemonic: &str,
    salt: &[u8],
) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    argon2id(mnemonic.as_bytes(), salt, &ARGON2_MNEMONIC_PARAMS)
}

// ─── KDF v1: PBKDF2-SHA256 (legacy — read-only) ─────────────────────────────

pub fn derive_key_pbkdf2(secret: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, iterations, &mut out[..]);
    out
}

/// KDF v1 for passphrases (250 000 iterations). Legacy accounts only — never for new writes.
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_key_pbkdf2(passphrase, salt, PBKDF2_PASSPHRASE_ITERATIONS)
}

/// KDF v1 for mnemonic backups (200 000 iterations). Legacy backups only.
pub fn derive_key_from_mnemonic(mnemonic: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_key_pbkdf2(mnemonic, salt, PBKDF2_MNEMONIC_ITERATIONS)
}

// ─── ML-KEM-768 ─────────────────────────────────────────────────────────────

/// ML-KEM-768 keypair in the formats the TS lib stores:
/// 1184-byte public key, **2400-byte expanded** secret key.
pub struct MlKemKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

/// Deterministic ML-KEM-768 keypair from the FULL 64-byte BIP-39 seed (FIPS 203 `d ‖ z`).
pub fn derive_ml_kem_keypair_from_seed(bip39_seed: &[u8]) -> MajikKeyResult<MlKemKeypair> {
    if bip39_seed.len() != 64 {
        return Err(MajikKeyError::crypto(format!(
            "ML-KEM seed must be 64 bytes (got {}). Pass the full BIP-39 seed, not a truncated slice.",
            bip39_seed.len()
        )));
    }
    crate::core::keys::key_impls::ml_kem_768_from_seed(bip39_seed)
}

/// Random ML-KEM-768 keypair. Testing only — production identities derive from the mnemonic.
pub fn generate_ml_kem_keypair() -> MlKemKeypair {
    let (dk, ek) = MlKem768::generate_keypair();
    let mut expanded = dk.to_expanded_bytes();
    let secret_key = Zeroizing::new(expanded.to_vec());
    expanded.as_mut_slice().zeroize();
    MlKemKeypair { public_key: ek.to_bytes().to_vec(), secret_key }
}

/// ML-KEM encapsulation → `(shared_secret[32], ciphertext[1088])`.
pub fn ml_kem_encapsulate(recipient_public_key: &[u8]) -> MajikKeyResult<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    let ek = ml_kem_encapsulation_key(recipient_public_key)?;
    let (ct, ss) = ek.encapsulate();
    let mut shared = Zeroizing::new([0u8; 32]);
    shared.copy_from_slice(ss.as_slice());
    Ok((shared, ct.to_vec()))
}

/// ML-KEM decapsulation. Never fails on a wrong key (FIPS 203 implicit rejection) —
/// it returns a useless secret and AES-GCM authentication catches the mismatch.
pub fn ml_kem_decapsulate(
    ciphertext: &[u8],
    recipient_secret_key: &[u8],
) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    let dk = crate::core::keys::key_impls::ml_kem_768_decapsulation_key(recipient_secret_key)?;
    let ss = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| MajikKeyError::crypto("Invalid ML-KEM-768 ciphertext length"))?;
    let mut shared = Zeroizing::new([0u8; 32]);
    shared.copy_from_slice(ss.as_slice());
    Ok(shared)
}

fn ml_kem_encapsulation_key(public_key: &[u8]) -> MajikKeyResult<EncapsulationKey<MlKem768>> {
    use ml_kem::kem::TryKeyInit as _;
    EncapsulationKey::<MlKem768>::new_from_slice(public_key)
        .map_err(|_| MajikKeyError::crypto("Invalid ML-KEM-768 public key"))
}


// ─── BIP-39 ─────────────────────────────────────────────────────────────────

/// Parse + validate `mnemonic` against `language`'s wordlist and checksum.
/// (TS: `validateMnemonic(mnemonic, wordlist)`.) Whitespace-tolerant and NFKD-normalizing.
pub fn validate_mnemonic_in(mnemonic: &str, language: crate::core::crypto::wordlist::MnemonicLanguage) -> MajikKeyResult<()> {
    bip39::Mnemonic::parse_in(language.to_bip39(), mnemonic)
        .map(|_| ())
        .map_err(|_| MajikKeyError::InvalidMnemonic)
}

/// 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, empty passphrase).
/// (TS: `mnemonicToSeed(mnemonic)`.) Validates the mnemonic first.
pub fn mnemonic_to_seed(
    mnemonic: &str,
    language: crate::core::crypto::wordlist::MnemonicLanguage,
) -> MajikKeyResult<Zeroizing<[u8; 64]>> {
    let parsed = bip39::Mnemonic::parse_in(language.to_bip39(), mnemonic)
        .map_err(|_| MajikKeyError::InvalidMnemonic)?;
    Ok(Zeroizing::new(parsed.to_seed("")))
}
