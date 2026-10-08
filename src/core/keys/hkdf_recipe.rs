//! Port of `core/keys/hkdf-recipe.ts` — the `"hkdf-sha512-v1"` derivation recipe
//! for every key added AFTER the registry. Frozen once released: changing any
//! constant here changes every key derived with it.
//!
//! ```text
//! seed_k = HKDF-SHA512( ikm  = 64-byte BIP-39 seed,
//!                       salt = "MajikKey/hkdf-sha512/v1",
//!                       info = "majik/v1/<namespaced key id>",
//!                       L    = the algorithm's seed length )
//! ```

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::keys::key_id::KeyId;

pub const HKDF_SALT: &str = "MajikKey/hkdf-sha512/v1";

pub fn hkdf_info(id: KeyId) -> String {
    format!("majik/v1/{}", id.as_str())
}

pub fn derive_seed_hkdf(seed64: &[u8], id: KeyId, length: usize) -> MajikKeyResult<Zeroizing<Vec<u8>>> {
    if seed64.len() != 64 {
        return Err(MajikKeyError::msg(format!(
            "Expected the 64-byte BIP-39 seed, got {} bytes",
            seed64.len()
        )));
    }
    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT.as_bytes()), seed64);
    let mut out = Zeroizing::new(vec![0u8; length]);
    hk.expand(hkdf_info(id).as_bytes(), &mut out[..])
        .map_err(|_| MajikKeyError::crypto("HKDF output length is invalid"))?;
    Ok(out)
}
