//! Port of `core/web3/bitcoin/bitcoin.ts` — ⚠️ EXPERIMENTAL.
//!
//! Real BIP-32/BIP-84 HD derivation directly off the raw 64-byte BIP-39 seed.
//! Pure Rust: `bip32` + `k256` (RustCrypto), `bech32`, `ripemd`, `bs58`. No
//! libsecp256k1 / C code, and no `@scure/btc-signer` equivalent needed — address
//! encoding is a few lines here.

use bech32::{hrp, segwit};
use bip32::{DerivationPath, XPrv};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use k256::schnorr::SigningKey as SchnorrSigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::core::crypto::crypto_provider::generate_random_bytes;
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::web3::bitcoin::constants::{
    MAJIK_BITCOIN_DOMAIN_PATH, MAJIK_BITCOIN_STANDARD_PATH,
};
use crate::core::web3::utils::base58check_encode;

pub struct BitcoinKeypairMaterial {
    /// 32-byte secp256k1 private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// 33-byte compressed secp256k1 public key.
    pub public_key: [u8; 33],
}

#[derive(Debug, Clone, Default)]
pub struct BitcoinDerivationOptions {
    /// Derive the REAL BIP-84 mainnet path (SLIP-44 coin type 0). Default: Majik's domain-separated path.
    pub standard: bool,
    /// Explicit derivation path — overrides `standard` if provided.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BitcoinSignatureScheme {
    #[default]
    Ecdsa,
    Schnorr,
}

/// Derive a Bitcoin keypair via standard BIP-32/BIP-84 from the raw 64-byte BIP-39 seed.
pub fn derive_bitcoin_keypair_from_seed(
    seed: &[u8],
    options: Option<&BitcoinDerivationOptions>,
) -> MajikKeyResult<BitcoinKeypairMaterial> {
    let path =
        options
            .and_then(|o| o.path.as_deref())
            .unwrap_or(if options.is_some_and(|o| o.standard) {
                MAJIK_BITCOIN_STANDARD_PATH
            } else {
                MAJIK_BITCOIN_DOMAIN_PATH
            });
    let dp: DerivationPath = path
        .parse()
        .map_err(|e| MajikKeyError::crypto(format!("Invalid derivation path {path}: {e}")))?;
    let child = XPrv::derive_from_path(seed, &dp).map_err(|e| {
        MajikKeyError::crypto(format!("Failed to derive Bitcoin keypair from seed: {e}"))
    })?;

    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&child.private_key().to_bytes());
    let public_key = compressed_pubkey(&private_key)?;
    Ok(BitcoinKeypairMaterial {
        private_key,
        public_key,
    })
}

fn compressed_pubkey(private_key: &[u8; 32]) -> MajikKeyResult<[u8; 33]> {
    let sk = SigningKey::from_bytes(private_key.into())
        .map_err(|_| MajikKeyError::crypto("Invalid secp256k1 private key"))?;
    let point = sk.verifying_key().to_sec1_point(true);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| MajikKeyError::crypto("Unexpected public key length"))
}

/// Re-derive the compressed public key from a raw private key (used on unlock).
pub fn bitcoin_public_key_from_private_key(private_key: &[u8; 32]) -> MajikKeyResult<[u8; 33]> {
    compressed_pubkey(private_key)
}

/// Sign a 32-byte message hash (already hashed — e.g. a Bitcoin sighash).
/// ECDSA is deterministic RFC 6979, low-S, 64-byte compact `r ‖ s`.
/// Schnorr is BIP-340 with 32 bytes of fresh aux randomness.
pub fn sign_with_bitcoin_material(
    material: &BitcoinKeypairMaterial,
    message_hash: &[u8],
    scheme: BitcoinSignatureScheme,
) -> MajikKeyResult<Vec<u8>> {
    match scheme {
        BitcoinSignatureScheme::Schnorr => {
            let aux: [u8; 32] = generate_random_bytes(32).try_into().expect("32 bytes");
            sign_schnorr_with_aux(material, message_hash, &aux)
        }
        BitcoinSignatureScheme::Ecdsa => {
            let sk = SigningKey::from_bytes((&*material.private_key).into())
                .map_err(|_| MajikKeyError::crypto("Invalid secp256k1 private key"))?;
            let sig: Signature = sk
                .sign_prehash(message_hash)
                .map_err(|e| MajikKeyError::crypto(format!("ECDSA signing failed: {e}")))?;
            let sig = sig.normalize_s();
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// BIP-340 Schnorr with caller-supplied aux randomness (deterministic — for tests/vectors).
pub fn sign_schnorr_with_aux(
    material: &BitcoinKeypairMaterial,
    message: &[u8],
    aux: &[u8; 32],
) -> MajikKeyResult<Vec<u8>> {
    let sk = SchnorrSigningKey::from_bytes((&*material.private_key).into())
        .map_err(|_| MajikKeyError::crypto("Invalid secp256k1 private key"))?;
    let sig = sk
        .sign_raw(message, aux)
        .map_err(|e| MajikKeyError::crypto(format!("Schnorr signing failed: {e}")))?;
    Ok(sig.to_bytes().to_vec())
}

// ─── WIF export (Wallet Import Format) ──────────────────────────────────────

const WIF_VERSION_MAINNET: u8 = 0x80;

/// Encode a private key as WIF. Deterministic: same private key → same WIF, always.
pub fn to_wif(material: &BitcoinKeypairMaterial, compressed: Option<bool>) -> String {
    let compressed = compressed.unwrap_or(true);
    let mut payload = Zeroizing::new(Vec::with_capacity(34));
    payload.push(WIF_VERSION_MAINNET);
    payload.extend_from_slice(&*material.private_key);
    if compressed {
        payload.push(0x01);
    }
    base58check_encode(&payload)
}

/// Native SegWit (bech32, `bc1…`) mainnet P2WPKH address for this material's public key.
pub fn to_bitcoin_address(material: &BitcoinKeypairMaterial) -> MajikKeyResult<String> {
    let sha = Sha256::digest(material.public_key);
    let h160 = <Ripemd160 as ripemd::Digest>::digest(&sha[..]);
    segwit::encode_v0(hrp::BC, &h160)
        .map_err(|_| MajikKeyError::crypto("Failed to derive Bitcoin address"))
}
