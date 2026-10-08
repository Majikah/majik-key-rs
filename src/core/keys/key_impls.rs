//! Port of `core/keys/key-impls.ts` — derivation implementations for registry keys.
//!
//! Every function takes the 64-byte BIP-39 seed and returns a keypair. The
//! `"legacy-v1"` recipes are FROZEN and deliberately inlined (domain strings,
//! paths) instead of imported from constants modules, so a refactor of a
//! constants file can never silently change a derivation. They are pinned by
//! the cross-implementation vectors in `tests/vectors/`.
//!
//! **Secret-key encodings match the TS lib byte-for-byte** (this is what lets a
//! `MajikKeyJson` written by TS be unlocked here and vice versa):
//!
//! | key            | secret bytes stored                               |
//! |----------------|---------------------------------------------------|
//! | X25519         | 32-byte clamped scalar                            |
//! | Ed25519        | 64 bytes, `seed ‖ public` (nacl layout)           |
//! | ML-KEM-512/768/1024 | **expanded** FIPS 203 decapsulation key (1632/2400/3168 B) |
//! | ML-DSA-44/65/87 | standard FIPS 204 secret key (2560/4032/4896 B)  |
//! | SLH-DSA-*      | FIPS 205 `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`   |
//! | BTC / ETH      | 32-byte secp256k1 scalar (public key: 33 B compressed) |
//!
//! The 0.0.1 Rust port stored ML-KEM/ML-DSA *seeds* instead. That was
//! incompatible with TS-written JSON and has been dropped.
//!
//! **Falcon (`pq:falcon-512/1024`)** is NOT derivable here: `@noble/post-quantum`
//! uses its own Round-3 bigint keygen from a 48-byte seed, and no pure-Rust crate
//! reproduces it byte-for-byte. Falcon entries created by the TS lib still load,
//! unlock, re-encrypt and serialize here (they are opaque bytes to the store).

#![allow(deprecated)] // ml-kem's expanded-key encoding is deprecated upstream but is the TS storage format.

use std::collections::BTreeMap;
use std::fmt;

use bip32::{DerivationPath, XPrv};
use fips204::traits::{KeyGen as _, SerDes as _};
use fips205::traits::{KeyGen as _, SerDes as _};
use ml_kem::array::Array;
use ml_kem::{
    DecapsulationKey, ExpandedKeyEncoding as _, FromSeed as _, KeyExport as _, MlKem1024, MlKem512,
    MlKem768,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::core::crypto::crypto_provider::{derive_ed25519_from_seed, MlKemKeypair};
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::keys::hkdf_recipe::derive_seed_hkdf;
use crate::core::keys::key_id::KeyId;

// ── frozen legacy-v1 recipe constants (do not "tidy" these) ──
const LEGACY_DSA_DOMAIN: &str = "MajikSignatureSeedDSA";
const LEGACY_BTC_PATH: &str = "m/84'/1971'/0'/0/0";
// Standard Ethereum path (SLIP-44 coin 60): MetaMask / Ledger / Trezor compatible.
const ETH_STANDARD_PATH: &str = "m/44'/60'/0'/0/0";

pub struct DerivedKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for DerivedKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKeypair")
            .field("public_key_len", &self.public_key.len())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

fn assert_seed(seed64: &[u8]) -> MajikKeyResult<()> {
    if seed64.len() != 64 {
        return Err(MajikKeyError::msg(format!(
            "Expected the 64-byte BIP-39 seed, got {} bytes",
            seed64.len()
        )));
    }
    Ok(())
}

fn ed_seed(seed64: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut s = Zeroizing::new([0u8; 32]);
    s.copy_from_slice(&seed64[..32]);
    s
}

// ── classic ─────────────────────────────────────────────────────────────────

fn derive_x25519(seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    let m = derive_ed25519_from_seed(&ed_seed(seed64))?;
    Ok(DerivedKeypair {
        public_key: m.x_public.to_vec(),
        secret_key: Zeroizing::new(m.x_secret.to_vec()),
    })
}

fn derive_ed25519(seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    let m = derive_ed25519_from_seed(&ed_seed(seed64))?; // 32 / 64 bytes
    Ok(DerivedKeypair {
        public_key: m.ed_public.to_vec(),
        secret_key: Zeroizing::new(m.ed_secret.to_vec()),
    })
}

// ── ML-KEM ──────────────────────────────────────────────────────────────────

macro_rules! ml_kem_from_seed {
    ($kem:ty, $seed:expr) => {{
        let seed: ml_kem::Seed = Array::try_from(&$seed[..])
            .map_err(|_| MajikKeyError::crypto("ML-KEM seed must be 64 bytes"))?;
        let (dk, ek) = <$kem>::from_seed(&seed);
        let mut expanded = dk.to_expanded_bytes();
        let secret_key = Zeroizing::new(expanded.to_vec());
        expanded.as_mut_slice().zeroize();
        Ok(MlKemKeypair {
            public_key: ek.to_bytes().to_vec(),
            secret_key,
        })
    }};
}

/// ML-KEM-768 from a 64-byte seed (FIPS 203 `d ‖ z`). Used by `legacy-v1`
/// (the raw BIP-39 seed) and by [`derive_ml_kem_keypair_from_seed`](crate::core::crypto::crypto_provider::derive_ml_kem_keypair_from_seed).
pub fn ml_kem_768_from_seed(seed: &[u8]) -> MajikKeyResult<MlKemKeypair> {
    ml_kem_from_seed!(MlKem768, seed)
}
fn ml_kem_512_from_seed(seed: &[u8]) -> MajikKeyResult<MlKemKeypair> {
    ml_kem_from_seed!(MlKem512, seed)
}
fn ml_kem_1024_from_seed(seed: &[u8]) -> MajikKeyResult<MlKemKeypair> {
    ml_kem_from_seed!(MlKem1024, seed)
}

/// Rebuild an ML-KEM-768 decapsulation key from the TS-format (2400-byte) expanded secret key.
pub fn ml_kem_768_decapsulation_key(expanded: &[u8]) -> MajikKeyResult<DecapsulationKey<MlKem768>> {
    let arr = Array::try_from(expanded)
        .map_err(|_| MajikKeyError::crypto("ML-KEM-768 secret key must be 2400 bytes"))?;
    DecapsulationKey::<MlKem768>::from_expanded_bytes(&arr)
        .map_err(|_| MajikKeyError::crypto("Invalid ML-KEM-768 secret key"))
}

fn derive_ml_kem_768(seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    let kp = ml_kem_768_from_seed(seed64)?; // full 64-byte seed (legacy-v1)
    Ok(DerivedKeypair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    })
}

fn derive_ml_kem_hkdf(id: KeyId, seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    let seed = derive_seed_hkdf(seed64, id, 64)?;
    let kp = match id {
        KeyId::MlKem512 => ml_kem_512_from_seed(&seed)?,
        KeyId::MlKem1024 => ml_kem_1024_from_seed(&seed)?,
        _ => unreachable!("not an hkdf ML-KEM id"),
    };
    Ok(DerivedKeypair {
        public_key: kp.public_key,
        secret_key: kp.secret_key,
    })
}

// ── ML-DSA ──────────────────────────────────────────────────────────────────

macro_rules! ml_dsa_from_xi {
    ($m:ident, $xi:expr) => {{
        let (pk, sk) = fips204::$m::KG::keygen_from_seed($xi);
        let sk_bytes = Zeroizing::new(sk.into_bytes());
        DerivedKeypair {
            public_key: pk.into_bytes().to_vec(),
            secret_key: Zeroizing::new(sk_bytes.to_vec()),
        }
    }};
}

fn derive_ml_dsa_87_legacy(seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    // sha256(seed64 || domain) → 32-byte ξ
    let mut h = Sha256::new();
    h.update(seed64);
    h.update(LEGACY_DSA_DOMAIN.as_bytes());
    let xi = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
    Ok(ml_dsa_from_xi!(ml_dsa_87, &xi))
}

fn derive_ml_dsa_hkdf(id: KeyId, seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    let seed = derive_seed_hkdf(seed64, id, 32)?;
    let mut xi = Zeroizing::new([0u8; 32]);
    xi.copy_from_slice(&seed);
    Ok(match id {
        KeyId::MlDsa44 => ml_dsa_from_xi!(ml_dsa_44, &xi),
        KeyId::MlDsa65 => ml_dsa_from_xi!(ml_dsa_65, &xi),
        _ => unreachable!("not an hkdf ML-DSA id"),
    })
}

// ── SLH-DSA (FIPS 205) ──────────────────────────────────────────────────────

macro_rules! slh_dsa_from_hkdf {
    ($m:ident, $id:expr, $seed64:expr) => {{
        const N: usize = fips205::$m::N;
        let seed = derive_seed_hkdf($seed64, $id, 3 * N)?; // SK.seed ‖ SK.prf ‖ PK.seed
        let a = Zeroizing::new(<[u8; N]>::try_from(&seed[0..N]).unwrap());
        let b = Zeroizing::new(<[u8; N]>::try_from(&seed[N..2 * N]).unwrap());
        let c = Zeroizing::new(<[u8; N]>::try_from(&seed[2 * N..3 * N]).unwrap());
        let (pk, sk) = fips205::$m::KG::keygen_with_seeds(&a, &b, &c);
        let sk_bytes = Zeroizing::new(sk.into_bytes());
        DerivedKeypair {
            public_key: pk.into_bytes().to_vec(),
            secret_key: Zeroizing::new(sk_bytes.to_vec()),
        }
    }};
}

fn derive_slh_dsa(id: KeyId, seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    Ok(match id {
        KeyId::SlhDsaSha2_128s => slh_dsa_from_hkdf!(slh_dsa_sha2_128s, id, seed64),
        KeyId::SlhDsaSha2_128f => slh_dsa_from_hkdf!(slh_dsa_sha2_128f, id, seed64),
        KeyId::SlhDsaSha2_192s => slh_dsa_from_hkdf!(slh_dsa_sha2_192s, id, seed64),
        KeyId::SlhDsaSha2_192f => slh_dsa_from_hkdf!(slh_dsa_sha2_192f, id, seed64),
        KeyId::SlhDsaSha2_256s => slh_dsa_from_hkdf!(slh_dsa_sha2_256s, id, seed64),
        KeyId::SlhDsaSha2_256f => slh_dsa_from_hkdf!(slh_dsa_sha2_256f, id, seed64),
        KeyId::SlhDsaShake128s => slh_dsa_from_hkdf!(slh_dsa_shake_128s, id, seed64),
        KeyId::SlhDsaShake128f => slh_dsa_from_hkdf!(slh_dsa_shake_128f, id, seed64),
        KeyId::SlhDsaShake192s => slh_dsa_from_hkdf!(slh_dsa_shake_192s, id, seed64),
        KeyId::SlhDsaShake192f => slh_dsa_from_hkdf!(slh_dsa_shake_192f, id, seed64),
        KeyId::SlhDsaShake256s => slh_dsa_from_hkdf!(slh_dsa_shake_256s, id, seed64),
        KeyId::SlhDsaShake256f => slh_dsa_from_hkdf!(slh_dsa_shake_256f, id, seed64),
        _ => unreachable!("not an SLH-DSA id"),
    })
}

// ── web3 (BIP-32) ───────────────────────────────────────────────────────────

fn derive_bip32(seed64: &[u8], path: &str, what: &str) -> MajikKeyResult<DerivedKeypair> {
    assert_seed(seed64)?;
    let path: DerivationPath = path
        .parse()
        .map_err(|e| MajikKeyError::crypto(format!("Invalid derivation path {path}: {e}")))?;
    let child = XPrv::derive_from_path(seed64, &path).map_err(|e| {
        MajikKeyError::crypto(format!("Failed to derive {what} keypair from seed: {e}"))
    })?;
    let sk = child.private_key().to_bytes();
    let public_key = child
        .private_key()
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    Ok(DerivedKeypair {
        public_key,
        secret_key: Zeroizing::new(sk.to_vec()),
    })
}

// ── dispatch ────────────────────────────────────────────────────────────────

/// True if this crate can derive `id` from a seed. (Falcon, HQC, FN-DSA, LMS and the
/// derived view `web3:sol` are not stored-key derivations here.)
pub fn is_derivable(id: KeyId) -> bool {
    use KeyId::*;
    matches!(
        id,
        X25519
            | Ed25519
            | MlKem512
            | MlKem768
            | MlKem1024
            | MlDsa44
            | MlDsa65
            | MlDsa87
            | SlhDsaSha2_128s
            | SlhDsaSha2_128f
            | SlhDsaSha2_192s
            | SlhDsaSha2_192f
            | SlhDsaSha2_256s
            | SlhDsaSha2_256f
            | SlhDsaShake128s
            | SlhDsaShake128f
            | SlhDsaShake192s
            | SlhDsaShake192f
            | SlhDsaShake256s
            | SlhDsaShake256f
            | Btc
            | Eth
    )
}

/// Derive one STORED key from the 64-byte BIP-39 seed.
pub fn derive_key(id: KeyId, seed64: &[u8]) -> MajikKeyResult<DerivedKeypair> {
    use KeyId::*;
    match id {
        X25519 => derive_x25519(seed64),
        Ed25519 => derive_ed25519(seed64),
        MlKem768 => derive_ml_kem_768(seed64),
        MlDsa87 => derive_ml_dsa_87_legacy(seed64),
        Btc => derive_bip32(seed64, LEGACY_BTC_PATH, "Bitcoin"),
        Eth => derive_bip32(seed64, ETH_STANDARD_PATH, "Ethereum"),
        MlKem512 | MlKem1024 => derive_ml_kem_hkdf(id, seed64),
        MlDsa44 | MlDsa65 => derive_ml_dsa_hkdf(id, seed64),
        SlhDsaSha2_128s | SlhDsaSha2_128f | SlhDsaSha2_192s | SlhDsaSha2_192f | SlhDsaSha2_256s
        | SlhDsaSha2_256f | SlhDsaShake128s | SlhDsaShake128f | SlhDsaShake192s
        | SlhDsaShake192f | SlhDsaShake256s | SlhDsaShake256f => derive_slh_dsa(id, seed64),
        Falcon512 | Falcon1024 => Err(MajikKeyError::msg(format!(
            "\"{id}\" cannot be derived by the Rust port: no pure-Rust implementation reproduces \
             @noble/post-quantum's Round-3 Falcon keygen byte-for-byte. Falcon keys created by the \
             TS library still load, unlock and re-encrypt here."
        ))),
        _ => Err(MajikKeyError::msg(format!(
            "No derivation implementation registered for \"{id}\""
        ))),
    }
}

/// Derive the requested STORED keys from one BIP-39 seed. Caller zeroizes the seed.
/// Iterates in canonical registry order.
pub fn derive_keys(
    seed64: &[u8],
    ids: &[KeyId],
) -> MajikKeyResult<BTreeMap<KeyId, DerivedKeypair>> {
    let mut out = BTreeMap::new();
    for &id in ids {
        out.insert(id, derive_key(id, seed64)?);
    }
    Ok(out)
}
