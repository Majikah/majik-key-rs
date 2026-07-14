//! Experimental Bitcoin keypair utilities for MajikKey.
//!
//! This is a Rust port of the TypeScript implementation in the web3 Bitcoin
//! module. The current version uses the existing `bitcoin` crate dependency, so
//! no new Cargo entries are required. It derives BIP-32/BIP-84 key material
//! directly from the raw BIP-39 seed and exposes the resulting secret key in a
//! zeroizing wrapper.
//!
//! The implementation is intentionally conservative. Verify it against known
//! test vectors before using it with real funds.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::Keypair as SchnorrKeypair;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind};
use zeroize::Zeroizing;

use crate::error::{MajikKeyError, MajikKeyResult};
use crate::web3;

use web3::constants::{MAJIK_BITCOIN_DOMAIN_PATH, MAJIK_BITCOIN_STANDARD_PATH};

/// secp256k1 keypair material for a domain-separated (or standard) Bitcoin
/// account. Mirrors the TS lib's `BitcoinKeypairMaterial`.
pub struct BitcoinKeypairMaterial {
    /// 33-byte compressed secp256k1 public key.
    pub public_key: [u8; 33],
    /// 32-byte secp256k1 private key. ⚠️ Live key material.
    pub private_key: Zeroizing<[u8; 32]>,
}

/// Which signature scheme to use for `sign_with_bitcoin_material`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinSignScheme {
    Ecdsa,
    Schnorr,
}

/// Options accepted by `derive_bitcoin_keypair_from_seed`. Mirrors the TS
/// lib's `BitcoinDerivationOptions`.
#[derive(Debug, Clone, Default)]
pub struct BitcoinDerivationOptions {
    /// If true, derive the REAL BIP-84 mainnet path (SLIP-44 coin type 0).
    /// Defaults to false (Majik's domain-separated path).
    pub standard: bool,
    /// Explicit derivation path — overrides `standard` if provided.
    pub path: Option<String>,
}

// ─── Derivation ─────────────────────────────────────────────────────────────

/// Derive a Bitcoin keypair via standard BIP-32/BIP-84 from the raw 64-byte
/// BIP-39 seed. Call this once at account creation/import time — the seed
/// itself is never stored, only the resulting key, encrypted at rest like
/// the other four keypairs.
pub fn derive_bitcoin_keypair_from_seed(
    seed: &Zeroizing<[u8; 64]>,
    options: Option<&BitcoinDerivationOptions>,
) -> MajikKeyResult<BitcoinKeypairMaterial> {
    let standard = options.map(|o| o.standard).unwrap_or(false);
    let path_str: &str = options
        .and_then(|o| o.path.as_deref())
        .unwrap_or(if standard {
            MAJIK_BITCOIN_STANDARD_PATH
        } else {
            MAJIK_BITCOIN_DOMAIN_PATH
        });

    let path = DerivationPath::from_str(path_str).map_err(|_| {
        MajikKeyError::Other(format!("Invalid Bitcoin derivation path: {path_str}"))
    })?;

    let secp = Secp256k1::new();

    // NetworkKind only affects xprv/xpub version-byte serialization, not
    // the key material itself, so it's irrelevant to the derived scalar —
    // Main is fine even though we never serialize to base58 xprv here.
    let master = Xpriv::new_master(NetworkKind::Main, seed.as_ref())
        .map_err(|e| MajikKeyError::Other(format!("Failed to derive Bitcoin master key: {e}")))?;

    let child = master
        .derive_priv(&secp, &path)
        .map_err(|e| MajikKeyError::Other(format!("Failed to derive Bitcoin keypair: {e}")))?;

    let private_key: [u8; 32] = child.private_key.secret_bytes();

    let compressed = CompressedPublicKey::from_private_key(&secp, &child.to_priv())
        .map_err(|e| MajikKeyError::Other(format!("Failed to derive Bitcoin public key: {e}")))?;
    let public_key: [u8; 33] = compressed.to_bytes();

    Ok(BitcoinKeypairMaterial {
        public_key,
        private_key: Zeroizing::new(private_key),
    })
}

/// Re-derive the compressed public key from a raw private key. Used when
/// unlocking — we only encrypt/store the private key, so the public key is
/// recomputed on unlock rather than stored redundantly encrypted.
pub fn bitcoin_public_key_from_private_key(private_key: &[u8; 32]) -> MajikKeyResult<[u8; 33]> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|_| MajikKeyError::Other("Invalid secp256k1 private key".into()))?;
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    Ok(public_key.serialize())
}

/// Sign a 32-byte message hash (already hashed — e.g. a Bitcoin sighash).
///
/// ⚠️ Mirrors the TS lib's `{ prehash: false }` requirement exactly: this
/// function assumes `message_hash` is ALREADY a digest, never raw
/// unhashed data. Passing raw data here is the exact class of silent-
/// correctness bug already flagged for the `@noble/curves` v2 port.
pub fn sign_with_bitcoin_material(
    material: &BitcoinKeypairMaterial,
    message_hash: &[u8; 32],
    scheme: BitcoinSignScheme,
) -> MajikKeyResult<Vec<u8>> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&*material.private_key)
        .map_err(|_| MajikKeyError::Other("Invalid secp256k1 private key".into()))?;

    match scheme {
        BitcoinSignScheme::Ecdsa => {
            let message = Message::from_digest(*message_hash);
            let sig = secp.sign_ecdsa(&message, &secret_key);
            Ok(sig.serialize_compact().to_vec())
        }
        BitcoinSignScheme::Schnorr => {
            // ⚠️ See module-level doc comment — verify against the
            // transitive `secp256k1` version and BIP-340 test vectors.
            let keypair = SchnorrKeypair::from_secret_key(&secp, &secret_key);
            let message = Message::from_digest(*message_hash);
            let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
            Ok(sig.as_ref().to_vec())
        }
    }
}

// ─── WIF export (Wallet Import Format) ──────────────────────────────────────

/// Encode a private key as WIF via `bitcoin::PrivateKey`'s own `Display`
/// impl — no hand-rolled base58check needed, unlike the TS version.
pub fn to_wif(material: &BitcoinKeypairMaterial, compressed: bool) -> MajikKeyResult<String> {
    let secret_key = SecretKey::from_slice(&*material.private_key)
        .map_err(|_| MajikKeyError::Other("Invalid secp256k1 private key".into()))?;
    let priv_key = bitcoin::PrivateKey {
        compressed,
        network: NetworkKind::Main,
        inner: secret_key,
    };
    Ok(priv_key.to_string()) // bitcoin::PrivateKey's Display is WIF.
}

// ─── Native SegWit (bech32) address ─────────────────────────────────────────

/// Native SegWit (bech32, "bc1...") mainnet address for this material's
/// public key.
pub fn to_bitcoin_address(material: &BitcoinKeypairMaterial) -> MajikKeyResult<String> {
    let compressed = CompressedPublicKey::from_slice(&material.public_key)
        .map_err(|_| MajikKeyError::Other("Invalid compressed public key".into()))?;
    let address = Address::p2wpkh(&compressed, Network::Bitcoin);
    Ok(address.to_string())
}
