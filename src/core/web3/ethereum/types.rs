use serde::{Deserialize, Serialize};

use crate::core::error::MajikKeyResult;
use crate::core::web3::ethereum::ethereum::{
    ethereum_address_from_public_key, sign_ethereum_hash, sign_ethereum_message,
    to_ethereum_private_key_hex, EthereumKeypairMaterial,
};

/// @experimental
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumSignature {
    /// 0x-prefixed 32-byte hex.
    pub r: String,
    /// 0x-prefixed 32-byte hex (low-s normalized, EIP-2).
    pub s: String,
    /// 27 | 28 (Ethereum "v").
    pub v: u8,
    /// Raw recovery id, 0 | 1.
    pub recovery: u8,
    /// `0x` + r ‖ s ‖ v (65 bytes) — what `personal_sign` / `ecrecover` consumers expect.
    pub serialized: String,
}

/// @experimental Ethereum account at the STANDARD path (`m/44'/60'/0'/0/0`):
/// the same address MetaMask and hardware wallets show for this mnemonic.
pub struct MajikKeyEthereumNamespace {
    pub(crate) material: EthereumKeypairMaterial,
    address: String,
}

impl MajikKeyEthereumNamespace {
    pub fn new(material: EthereumKeypairMaterial) -> MajikKeyResult<Self> {
        let address = ethereum_address_from_public_key(&material.public_key)?;
        Ok(Self { material, address })
    }
    pub fn public_key(&self) -> &[u8] {
        &self.material.public_key
    }
    pub fn private_key(&self) -> &[u8; 32] {
        &self.material.private_key
    }
    /// EIP-55 checksummed address.
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn get_private_key_hex(&self) -> String {
        to_ethereum_private_key_hex(&self.material)
    }
    pub fn sign_hash(&self, hash32: &[u8]) -> MajikKeyResult<EthereumSignature> {
        sign_ethereum_hash(&self.material, hash32)
    }
    pub fn sign_message(&self, message: &[u8]) -> MajikKeyResult<EthereumSignature> {
        sign_ethereum_message(&self.material, message)
    }
}
