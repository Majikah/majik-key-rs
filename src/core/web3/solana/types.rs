use zeroize::Zeroizing;

use crate::core::web3::solana::solana::{
    sign_with_solana_material, solana_address_from_public_key, SolanaKeypairMaterial,
};

/// @experimental Web3 integrations are experimental; this shape may change.
///
/// The TS namespace also exposes `getSolanaKeypair()` / `getSolanaAddress()`
/// returning `@solana/kit` objects — JS-only, so not ported. Feed
/// [`secret_key`](Self::secret_key) (nacl 64-byte layout) to `solana-sdk`'s
/// `Keypair::try_from` if you need one.
pub struct MajikKeySolanaNamespace {
    pub(crate) material: SolanaKeypairMaterial,
}

impl MajikKeySolanaNamespace {
    pub fn new(material: SolanaKeypairMaterial) -> Self {
        Self { material }
    }
    /// 32-byte Solana/Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.material.public_key
    }
    /// 64-byte nacl-format secret key. Handle with care.
    pub fn secret_key(&self) -> &Zeroizing<[u8; 64]> {
        &self.material.secret_key
    }
    /// Base58 Solana address.
    pub fn address(&self) -> String {
        solana_address_from_public_key(&self.material.public_key)
    }
    /// Sign a message with this keypair's Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        sign_with_solana_material(&self.material, message)
    }
}
