/// SLIP-44 coin type 60 = Ethereum. The path MetaMask, Ledger, Trezor, Rabby, etc.
/// derive by default (account 0, address index 0) — so the address from a
/// MajikKey is the SAME address those wallets show for the same mnemonic.
pub const MAJIK_ETHEREUM_STANDARD_PATH: &str = "m/44'/60'/0'/0/0";
