//! Port of `core/web3/utils.ts`. The TS file hand-rolls base58 to avoid a
//! dependency; here the `bs58` crate does it.

/// Base58 (Bitcoin alphabet) encoding.
pub fn base58_encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Base58Check: payload ‖ first 4 bytes of double-SHA256.
pub fn base58check_encode(payload: &[u8]) -> String {
    bs58::encode(payload).with_check().into_string()
}
