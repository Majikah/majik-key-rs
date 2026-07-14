//! web3/types.rs
//!
//! Rust port of the TS lib's `web3/bitcoin/types.ts`, `web3/solana/types.ts`,
//! and `web3/types.ts` (the `MajikKeyWeb3Namespace` union type).
//!
//! Difference from TS worth flagging explicitly: the TS namespaces expose
//! `async getBitcoinAddress()` / `async getSolanaKeypair()` because they
//! lazy-`import()` optional peer deps at call time. Rust has no equivalent
//! lazy-module-loading mechanism, so here:
//!   - `get_bitcoin_address()` is synchronous — bech32 encoding is a hard
//!     dependency of `bitcoin.rs`, not an optional one.
//!   - `get_solana_keypair()` stays a stub returning an error (see
//!     `solana.rs` for why), matching `MajikKey::to_contact()`'s existing
//!     "not yet ported" pattern rather than inventing a `solana-sdk` dep.

use zeroize::Zeroizing;

use crate::{
    error::MajikKeyResult,
    web3::{
        bitcoin::bitcoin::{
            sign_with_bitcoin_material, to_bitcoin_address, to_wif, BitcoinKeypairMaterial,
            BitcoinSignScheme,
        },
        solana::solana::{
            self, sign_with_solana_material, solana_address_from_public_key, SolanaKeypairMaterial,
        },
    },
};

/// @experimental By default this is Majik's DOMAIN-SEPARATED Bitcoin key
/// (derived via `MAJIK_BITCOIN_DOMAIN_PATH`) — deterministic and fully
/// standard BIP-32, but not the path a generic wallet would derive by
/// default, so it stays effectively private to Majik. Use
/// `MajikKey::get_bitcoin_keypair_material(Some(&BitcoinDerivationOptions {
/// standard: true, .. }))` for the REAL BIP-84 mainnet key — recoverable in
/// any standard wallet from the same mnemonic alone.
pub struct MajikKeyBitcoinNamespace {
    /// 33-byte compressed secp256k1 public key.
    pub public_key: [u8; 33],
    /// 32-byte secp256k1 private key. Handle with the same care as any
    /// private key.
    pub private_key: Zeroizing<[u8; 32]>,
}

impl MajikKeyBitcoinNamespace {
    pub fn from_material(material: BitcoinKeypairMaterial) -> Self {
        Self {
            public_key: material.public_key,
            private_key: material.private_key,
        }
    }

    fn as_material(&self) -> BitcoinKeypairMaterial {
        BitcoinKeypairMaterial {
            public_key: self.public_key,
            private_key: Zeroizing::new(*self.private_key),
        }
    }

    /// Native SegWit (bech32) address.
    pub fn get_bitcoin_address(&self) -> MajikKeyResult<String> {
        to_bitcoin_address(&self.as_material())
    }

    /// WIF string — pastes directly into any standard Bitcoin wallet.
    pub fn get_wif(&self, compressed: bool) -> MajikKeyResult<String> {
        to_wif(&self.as_material(), compressed)
    }

    /// Sign a 32-byte message hash. ECDSA (default) or Schnorr.
    pub fn sign(
        &self,
        message_hash: &[u8; 32],
        scheme: BitcoinSignScheme,
    ) -> MajikKeyResult<Vec<u8>> {
        sign_with_bitcoin_material(&self.as_material(), message_hash, scheme)
    }
}

/// @experimental Web3 / blockchain integrations are experimental. This
/// namespace's shape may change without a major version bump.
pub struct MajikKeySolanaNamespace {
    /// 32-byte Solana/Ed25519 public key.
    pub public_key: [u8; 32],
    /// 64-byte nacl-format secret key. Handle with the same care as any
    /// private key.
    pub secret_key: Zeroizing<[u8; 64]>,
    /// Base58 Solana address — does not require a Solana SDK.
    pub address: String,
}

impl MajikKeySolanaNamespace {
    pub fn from_material(material: SolanaKeypairMaterial) -> Self {
        let address = solana_address_from_public_key(&material.public_key);
        Self {
            public_key: material.public_key,
            secret_key: material.secret_key,
            address,
        }
    }

    fn as_material(&self) -> SolanaKeypairMaterial {
        SolanaKeypairMaterial {
            public_key: self.public_key,
            secret_key: Zeroizing::new(*self.secret_key),
        }
    }

    /// Sign a message with this Solana keypair's Ed25519 key. No Solana SDK
    /// dependency needed.
    pub fn sign(&self, message: &[u8]) -> MajikKeyResult<[u8; 64]> {
        sign_with_solana_material(&self.as_material(), message)
    }

    /// TODO: real Solana SDK Keypair — see `solana::get_solana_keypair()`.
    pub fn get_solana_keypair(&self) -> MajikKeyResult<()> {
        solana::get_solana_keypair(&self.as_material())
    }
}

/// @experimental
pub struct MajikKeyWeb3Namespace {
    pub solana: MajikKeySolanaNamespace,
    pub bitcoin: Option<MajikKeyBitcoinNamespace>,
}
