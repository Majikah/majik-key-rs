//! Port of `core/web3/solana/solana.ts` — ⚠️ EXPERIMENTAL.
//!
//! Solana accounts are plain Ed25519 keypairs; `secret_key` is the 64-byte
//! nacl layout (`seed ‖ public`). Two ways to get one from a MajikKey:
//!  1. [`derive_solana_keypair_from_ed_secret_key`] — RECOMMENDED. Domain-separates a
//!     brand-new keypair: `seed' = SHA256(edSeed ‖ "MajikKeySolanaSeed")`.
//!  2. [`solana_material_from_ed25519_secret_key`] — reuses the message-signing key as-is. Opt-in only.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::web3::solana::constants::MAJIK_SOLANA_SEED;
use crate::core::web3::utils::base58_encode;

const ED25519_SECRET_KEY_LENGTH: usize = 64;
const ED25519_SEED_LENGTH: usize = 32;

pub struct SolanaKeypairMaterial {
    pub public_key: [u8; 32],
    /// 64-byte nacl-format secret key (`seed ‖ public`).
    pub secret_key: Zeroizing<[u8; 64]>,
}

fn check_len(ed_secret_key: &[u8]) -> MajikKeyResult<()> {
    if ed_secret_key.len() != ED25519_SECRET_KEY_LENGTH {
        return Err(MajikKeyError::msg(format!(
            "Expected a 64-byte Ed25519 secret key, got {} bytes",
            ed_secret_key.len()
        )));
    }
    Ok(())
}

pub fn derive_solana_keypair_from_ed_secret_key(
    ed_secret_key: &[u8],
) -> MajikKeyResult<SolanaKeypairMaterial> {
    check_len(ed_secret_key)?;
    let mut h = Sha256::new();
    h.update(&ed_secret_key[..ED25519_SEED_LENGTH]);
    h.update(MAJIK_SOLANA_SEED.as_bytes());
    let seed = Zeroizing::new(<[u8; 32]>::from(h.finalize()));

    let signing = SigningKey::from_bytes(&seed);
    let public_key = signing.verifying_key().to_bytes();
    let mut secret_key = Zeroizing::new([0u8; 64]);
    secret_key[..32].copy_from_slice(&*seed);
    secret_key[32..].copy_from_slice(&public_key);
    Ok(SolanaKeypairMaterial {
        public_key,
        secret_key,
    })
}

/// ⚠️ Not recommended: the same private key would secure both Majik message signing AND Solana.
pub fn solana_material_from_ed25519_secret_key(
    ed_secret_key: &[u8],
) -> MajikKeyResult<SolanaKeypairMaterial> {
    check_len(ed_secret_key)?;
    let mut secret_key = Zeroizing::new([0u8; 64]);
    secret_key.copy_from_slice(ed_secret_key);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&ed_secret_key[ED25519_SEED_LENGTH..]);
    Ok(SolanaKeypairMaterial {
        public_key,
        secret_key,
    })
}

/// Solana address = base58 of the public key.
pub fn solana_address_from_public_key(public_key: &[u8]) -> String {
    base58_encode(public_key)
}

/// Sign an arbitrary message with a Solana keypair's Ed25519 secret key.
pub fn sign_with_solana_material(material: &SolanaKeypairMaterial, message: &[u8]) -> Vec<u8> {
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&material.secret_key[..32]);
    SigningKey::from_bytes(&seed)
        .sign(message)
        .to_bytes()
        .to_vec()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SolanaDerivationOptions {
    /// Reuse the message-signing Ed25519 key as the Solana key (not recommended).
    pub reuse_message_key: bool,
}
