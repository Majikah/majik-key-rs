//! Port of `core/web3/types.ts`.

use crate::core::web3::bitcoin::types::MajikKeyBitcoinNamespace;
use crate::core::web3::ethereum::types::MajikKeyEthereumNamespace;
use crate::core::web3::solana::types::MajikKeySolanaNamespace;

/// @experimental
pub struct MajikKeyWeb3Namespace {
    pub solana: MajikKeySolanaNamespace,
    pub bitcoin: Option<MajikKeyBitcoinNamespace>,
    pub ethereum: Option<MajikKeyEthereumNamespace>,
}
