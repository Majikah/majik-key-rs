//! crypto module
//! ---
//! Mirrors the `core/crypto/` folder from the TS lib: low-level primitives
//! (`provider`), domain-separation constants (`constants`), BIP-39
//! wordlist plumbing (`wordlist`), and the full-identity derivation logic
//! (`encryption_engine`).

pub mod constants;
pub mod encryption_engine;
pub mod provider;
pub mod wordlist;

// Re-export the most commonly reached items at `crypto::` level, so callers
// elsewhere in the crate (and integration tests under `tests/`) can write
// `majik_key::crypto::derive_identity_from_mnemonic` instead of reaching
// through the full submodule path every time.
pub use encryption_engine::{derive_identity_from_mnemonic, EncryptionIdentity};
pub use wordlist::MnemonicLanguage;
