//! web3/solana.rs
//!
//! ⚠️ EXPERIMENTAL — Solana keypair utilities for MajikKey (Rust port of
//! the TS lib's `core/web3/solana.ts`).
//!
//! DEPENDENCY NOTE (checked against your actual Cargo.toml): nothing new
//! is required here either. `ed25519-dalek = { version = "3", features =
//! ["rand_core"] }` and `sha2 = "0.11"` are already always-on core
//! dependencies of this crate (majik-key already uses them for the
//! X25519/Ed25519 identity derivation), and `bs58 = "0.5"` is already
//! declared as the optional dep backing your `solana` feature
//! (`solana = ["dep:bs58"]`). Gate `pub mod solana;` in `web3/mod.rs` with
//! `#[cfg(feature = "solana")]`.
//!
//! ⚠️ `ed25519-dalek` jumped from the 2.x line (which this was originally
//! drafted against) to the 3.x line in your manifest. The calls used below
//! — `SigningKey::from_bytes`, `.verifying_key()`, `.to_keypair_bytes()`,
//! `.sign()` — matched 2.x's stable public API; dalek has historically
//! held that surface steady across majors per their own SemVer policy, but
//! confirm `to_keypair_bytes()` specifically still exists on 3.x before
//! relying on it, the same way you'd double-check any RustCrypto bump.
//!
//! Design (unchanged from TS):
//!   - Solana accounts are plain Ed25519 keypairs — no new key material or
//!     wallet standard is needed, just bytes in the right shape.
//!   - `secret_key` is always the 64-byte nacl/tweetnacl-compatible format
//!     (32-byte seed || 32-byte public key) — exactly what
//!     `@solana/web3.js`'s `Keypair.fromSecretKey()` expects, and exactly
//!     what `ed25519-dalek`'s `SigningKey::to_keypair_bytes()` already
//!     produces.
//!   - There is no Rust equivalent of the TS lib's lazy `import()` of
//!     `@solana/web3.js`/`@solana/kit` — Rust has no runtime-optional
//!     module loading. `get_solana_keypair()` is left as an explicit TODO
//!     stub (see bottom of file) rather than invented against a
//!     `solana-sdk` dependency that isn't in your Cargo.toml. Everything
//!     that doesn't require a Solana SDK — derivation, base58 address, raw
//!     Ed25519 signing — is fully implemented below.
//!
//! Two ways to obtain a Solana identity from a MajikKey (same as TS):
//!   1. `derive_solana_keypair_from_ed_secret_key()` — RECOMMENDED. Domain-
//!      separates a brand-new Ed25519 keypair from the MajikKey's message-
//!      signing Ed25519 secret key, so the Solana key is never reused
//!      elsewhere.
//!   2. `solana_material_from_ed25519_secret_key()` — reuses the MajikKey's
//!      message-signing Ed25519 keypair AS-IS. Simpler, but means the same
//!      private key secures two different protocols. Opt-in only.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    error::{MajikKeyError, MajikKeyResult},
    web3,
};

use web3::constants::MAJIK_SOLANA_SEED;

const ED25519_SECRET_KEY_LENGTH: usize = 64;
const ED25519_SEED_LENGTH: usize = 32;

/// Ed25519 keypair material shaped for direct use as a Solana account.
/// Mirrors the TS lib's `SolanaKeypairMaterial`.
pub struct SolanaKeypairMaterial {
    /// 32-byte Ed25519 / Solana public key.
    pub public_key: [u8; 32],
    /// 64-byte nacl-format secret key (32-byte seed || 32-byte public key).
    /// ⚠️ Live key material.
    pub secret_key: Zeroizing<[u8; 64]>,
}

/// Options accepted by `MajikKey::get_solana_keypair_material()`.
/// Mirrors the TS lib's `{ reuseMessageKey?: boolean }` shape.
#[derive(Debug, Clone, Default)]
pub struct SolanaDerivationOptions {
    pub reuse_message_key: bool,
}

// ─── Derivation ─────────────────────────────────────────────────────────────

/// Derive a Solana keypair domain-separated from the MajikKey's
/// message-signing Ed25519 key, but fully deterministic from it (and
/// therefore ultimately from the mnemonic).
///
///   seed' = SHA256(edSecretKey[0..32] || "MajikKeySolanaSeed")
pub fn derive_solana_keypair_from_ed_secret_key(
    ed_secret_key: &[u8],
) -> MajikKeyResult<SolanaKeypairMaterial> {
    if ed_secret_key.len() != ED25519_SECRET_KEY_LENGTH {
        return Err(MajikKeyError::Other(format!(
            "Expected a 64-byte Ed25519 secret key, got {} bytes",
            ed_secret_key.len()
        )));
    }
    let ed_seed = &ed_secret_key[..ED25519_SEED_LENGTH];

    let mut hasher = Sha256::new();
    hasher.update(ed_seed);
    hasher.update(MAJIK_SOLANA_SEED.as_bytes());
    let solana_seed: [u8; 32] = hasher.finalize().into();

    let signing_key = SigningKey::from_bytes(&solana_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let secret_key = signing_key.to_keypair_bytes(); // seed(32) || public(32)

    Ok(SolanaKeypairMaterial {
        public_key,
        secret_key: Zeroizing::new(secret_key),
    })
}

/// Reuse the MajikKey's existing message-signing Ed25519 keypair directly
/// as a Solana keypair (no re-derivation).
///
/// ⚠️ Not recommended: the same private key would secure both Majik message
/// signing AND any Solana transactions. Prefer
/// `derive_solana_keypair_from_ed_secret_key()` unless you specifically
/// want the identical key on both.
pub fn solana_material_from_ed25519_secret_key(
    ed_secret_key: &[u8],
) -> MajikKeyResult<SolanaKeypairMaterial> {
    if ed_secret_key.len() != ED25519_SECRET_KEY_LENGTH {
        return Err(MajikKeyError::Other(format!(
            "Expected a 64-byte Ed25519 secret key, got {} bytes",
            ed_secret_key.len()
        )));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&ed_secret_key[ED25519_SEED_LENGTH..]);

    let mut secret_key = [0u8; 64];
    secret_key.copy_from_slice(ed_secret_key);

    Ok(SolanaKeypairMaterial {
        public_key,
        secret_key: Zeroizing::new(secret_key),
    })
}

/// Solana address for a given Solana/Ed25519 public key — just its base58
/// encoding. Does NOT require a Solana SDK.
pub fn solana_address_from_public_key(public_key: &[u8; 32]) -> String {
    bs58::encode(public_key).into_string()
}

/// Sign an arbitrary message with a Solana keypair's Ed25519 secret key.
/// Uses `ed25519-dalek` directly — does NOT require a Solana SDK.
pub fn sign_with_solana_material(
    material: &SolanaKeypairMaterial,
    message: &[u8],
) -> MajikKeyResult<[u8; 64]> {
    let seed: [u8; 32] = material.secret_key[..ED25519_SEED_LENGTH]
        .try_into()
        .map_err(|_| MajikKeyError::Other("Malformed Solana secret key".into()))?;
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key.sign(message).to_bytes())
}

// ─── Solana SDK integration — NOT ported ────────────────────────────────────
//
// The TS lib lazily `import()`s `@solana/kit` to hand back a real
// `KeyPairSigner` / on-chain `Address`. There is no equivalent lazy-load
// mechanism in Rust, and no `solana-sdk`/`solana-client` dependency is
// currently part of this crate's Cargo.toml. Rather than guess which
// Solana Rust SDK (and which version — the ecosystem has churned a lot
// here, similarly to the `@noble/curves` v2 situation) you actually want
// wired into the Cloudflare Workers build, these are left as explicit
// stubs — same pattern as `MajikKey::to_contact()` /
// `to_majik_message_identity()` in `majik_key.rs`.

/// TODO: needs a Solana Rust SDK dependency, not yet chosen/ported.
pub fn get_solana_keypair(_material: &SolanaKeypairMaterial) -> MajikKeyResult<()> {
    Err(MajikKeyError::Other(
        "get_solana_keypair() requires a Solana Rust SDK dependency, not yet ported".into(),
    ))
}
