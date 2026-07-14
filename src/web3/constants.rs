//! web3/constants.rs
//!
//! Domain-separation constants for the @experimental web3 (Bitcoin/Solana)
//! namespace. Direct port of the TS lib's `bitcoin/constants.ts` and
//! `solana/constants.ts` — values are unchanged, since domain separation
//! only works if both language SDKs derive the exact same keys from the
//! exact same mnemonic.
//!
//! ⚠️ Do not change these strings/paths without a coordinated version bump
//! across every Majik SDK — doing so silently changes which keys every
//! existing account derives.

/// SLIP-44 coin type 0 = Bitcoin mainnet — the path any standard wallet
/// (Electrum, Sparrow, hardware wallets) derives by default from this mnemonic.
pub const MAJIK_BITCOIN_STANDARD_PATH: &str = "m/84'/0'/0'/0/0";

/// Unregistered/private coin-type index — domain-separates Majik's default
/// Bitcoin key from a user's "real" BTC wallet, while remaining 100%
/// standard BIP-32 math (just a different branch of the same tree).
pub const MAJIK_BITCOIN_DOMAIN_PATH: &str = "m/84'/1971'/0'/0/0";

/// Domain-separation string mixed into the Ed25519 seed before deriving the
/// Solana keypair. NOTE: this is the *correct* constant — matches the
/// actual Rust/TS runtime behavior. (The TS lib's `solana.ts` docstring
/// currently says `"MajikMessageSolanaSeed"` in a comment while the real
/// constant exported from `solana/constants.ts` is `"MajikKeySolanaSeed"`;
/// that's a stale-docstring bug flagged separately, not a behavior
/// difference — this Rust constant matches the real TS constant.)
pub const MAJIK_SOLANA_SEED: &str = "MajikKeySolanaSeed";
