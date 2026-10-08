use crate::core::error::MajikKeyResult;
use crate::core::web3::bitcoin::bitcoin::{
    sign_with_bitcoin_material, to_bitcoin_address, to_wif, BitcoinKeypairMaterial,
    BitcoinSignatureScheme,
};

/// @experimental By default this is Majik's DOMAIN-SEPARATED Bitcoin key
/// (`MAJIK_BITCOIN_DOMAIN_PATH`). For the REAL BIP-84 mainnet key use
/// `MajikKey::derive_standard_bitcoin_from_mnemonic`.
pub struct MajikKeyBitcoinNamespace {
    pub(crate) material: BitcoinKeypairMaterial,
}

impl MajikKeyBitcoinNamespace {
    pub fn new(material: BitcoinKeypairMaterial) -> Self {
        Self { material }
    }
    /// 33-byte compressed secp256k1 public key.
    pub fn public_key(&self) -> [u8; 33] {
        self.material.public_key
    }
    /// 32-byte secp256k1 private key (zeroized on drop). Handle with care.
    pub fn private_key(&self) -> &[u8; 32] {
        &self.material.private_key
    }
    /// Native SegWit (bech32) mainnet address.
    pub fn get_bitcoin_address(&self) -> MajikKeyResult<String> {
        to_bitcoin_address(&self.material)
    }
    /// WIF string — pastes directly into any standard Bitcoin wallet.
    pub fn get_wif(&self, compressed: Option<bool>) -> String {
        to_wif(&self.material, compressed)
    }
    /// Sign a 32-byte message hash. ECDSA (default) or Schnorr.
    pub fn sign(
        &self,
        message_hash: &[u8],
        scheme: BitcoinSignatureScheme,
    ) -> MajikKeyResult<Vec<u8>> {
        sign_with_bitcoin_material(&self.material, message_hash, scheme)
    }
}
