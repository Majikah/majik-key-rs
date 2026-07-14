use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use curve25519_dalek::edwards::CompressedEdwardsY;
use getrandom::fill as getrandom_fill;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::crypto::constants::{Argon2Params as ProviderArgon2Params, IV_LENGTH};
use crate::error::{MajikKeyError, MajikKeyResult};

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom_fill(&mut buf).expect("OS RNG failure");
    buf
}

pub fn generate_random_bytes_protected(len: usize) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    getrandom_fill(&mut buf[..]).expect("OS RNG failure"); // explicit slice
    buf
}

// ─── Argon2id (KDF v2 — current) ────────────────────────────────────────────

fn argon2id(
    input: &[u8],
    salt: &[u8],
    params: &ProviderArgon2Params,
) -> MajikKeyResult<Zeroizing<Vec<u8>>> {
    let argon2_params = Params::new(
        params.mem_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|e| MajikKeyError::Other(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = Zeroizing::new(vec![0u8; params.output_len]);
    argon2
        // explicit slice — output is Zeroizing<Vec<u8>>, function wants &mut [u8]
        .hash_password_into(input, salt, &mut output[..])
        .map_err(|e| MajikKeyError::Other(format!("Argon2id derivation failed: {e}")))?;
    Ok(output)
}

pub fn derive_key_from_passphrase_argon2(
    passphrase: &str,
    salt: &[u8],
) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    let out = argon2id(
        passphrase.as_bytes(),
        salt,
        &crate::crypto::constants::ARGON2_PASSPHRASE_PARAMS,
    )?;
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&out[..]); // explicit slice on the source too
    Ok(arr)
}

pub fn derive_key_from_mnemonic_argon2(
    mnemonic: &str,
    salt: &[u8],
) -> MajikKeyResult<Zeroizing<[u8; 32]>> {
    let out = argon2id(
        mnemonic.as_bytes(),
        salt,
        &crate::crypto::constants::ARGON2_MNEMONIC_PARAMS,
    )?;
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&out[..]);
    Ok(arr)
}

// ─── KDF v1: PBKDF2-SHA256 (legacy — read-only) ─────────────────────────────

pub fn derive_key_from_passphrase_pbkdf2(
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // THE FIX for your first error: explicit &mut out[..], not &mut out.
    // pbkdf2_hmac wants &mut [u8]; &mut out is &mut Zeroizing<[u8;32]>, and
    // that combination of custom-Deref + array-unsizing doesn't coerce
    // automatically in argument position.
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut out[..]);
    out
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

pub fn aes_gcm_encrypt(key: &[u8; 32], iv: &[u8], plaintext: &[u8]) -> MajikKeyResult<Vec<u8>> {
    if iv.len() != IV_LENGTH {
        return Err(MajikKeyError::Other("IV must be 12 bytes".into()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| MajikKeyError::Other(format!("Invalid AES key: {e}")))?;

    let nonce =
        Nonce::try_from(iv).map_err(|_| MajikKeyError::Other("Invalid AES-GCM nonce".into()))?;

    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| MajikKeyError::Other("AES-GCM encryption failed".into()))
}

pub fn aes_gcm_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if iv.len() != IV_LENGTH {
        return None;
    }

    let cipher = Aes256Gcm::new_from_slice(key).ok()?;

    let nonce = Nonce::try_from(iv).ok()?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .ok()
        .map(Zeroizing::new)
}

// ─── SHA-256 fingerprinting ──────────────────────────────────────────────────

pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

// ─── Ed25519 seed → X25519 conversion (ed2curve replacement) ────────────────

const CURVE25519_SCALAR_LEN: usize = 32;

fn clamp_scalar_in_place(bytes: &mut Zeroizing<[u8; CURVE25519_SCALAR_LEN]>) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

pub fn ed25519_seed_to_x25519_secret(ed_seed: &[u8; 32]) -> Zeroizing<[u8; CURVE25519_SCALAR_LEN]> {
    let mut hasher = Sha512::new();
    hasher.update(ed_seed);
    let mut expanded = hasher.finalize(); // GenericArray<u8, U64> — not auto-zeroing

    let mut scalar = Zeroizing::new([0u8; CURVE25519_SCALAR_LEN]);
    scalar.copy_from_slice(&expanded[0..32]); // GenericArray indexing gives &[u8], fine as-is

    for b in expanded.iter_mut() {
        *b = 0;
    }

    clamp_scalar_in_place(&mut scalar);
    scalar
}

pub fn ed25519_public_to_x25519(ed_public: &[u8; 32]) -> MajikKeyResult<[u8; 32]> {
    let compressed = CompressedEdwardsY(*ed_public);
    let point = compressed
        .decompress()
        .ok_or_else(|| MajikKeyError::Other("Invalid Ed25519 public key point".into()))?;
    Ok(point.to_montgomery().to_bytes())
}
