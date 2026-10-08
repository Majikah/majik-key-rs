//! Port of `core/web3/ethereum/ethereum.ts` — ⚠️ EXPERIMENTAL.
//!
//! Everything here is pure RustCrypto (`k256`, `sha3`): address derivation
//! (keccak-256 + EIP-55), EIP-191 message hashing, recoverable signing.
//! Transaction building / EIP-712 are out of scope (use `alloy`/`ethers`).

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToSec1Point as _;
use k256::PublicKey;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::web3::ethereum::types::EthereumSignature;

pub struct EthereumKeypairMaterial {
    /// 32-byte secp256k1 private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// 33-byte compressed secp256k1 public key.
    pub public_key: Vec<u8>,
}

fn hex0x(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Uncompressed (65-byte, 0x04-prefixed) form of a compressed or uncompressed public key.
pub fn ethereum_uncompressed_public_key(public_key: &[u8]) -> MajikKeyResult<Vec<u8>> {
    if public_key.len() == 65 && public_key[0] == 0x04 {
        return Ok(public_key.to_vec());
    }
    if public_key.len() != 33 {
        return Err(MajikKeyError::crypto(format!(
            "Expected a 33-byte compressed secp256k1 public key, got {} bytes",
            public_key.len()
        )));
    }
    let pk = PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| MajikKeyError::crypto("Invalid secp256k1 public key"))?;
    Ok(pk.to_sec1_point(false).as_bytes().to_vec())
}

/// EIP-55 mixed-case checksum of a lowercase 40-char hex address (no `0x`).
pub fn to_checksum_address(lower_hex: &str) -> String {
    let h = keccak(lower_hex.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower_hex.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            h[i / 2] >> 4
        } else {
            h[i / 2] & 0x0f
        };
        if nibble >= 8 {
            out.extend(c.to_uppercase())
        } else {
            out.push(c)
        }
    }
    out
}

/// EIP-55 address: last 20 bytes of keccak256(uncompressed pubkey without the 0x04 prefix).
pub fn ethereum_address_from_public_key(public_key: &[u8]) -> MajikKeyResult<String> {
    let unc = ethereum_uncompressed_public_key(public_key)?;
    let h = keccak(&unc[1..]);
    let lower: String = h[12..].iter().map(|b| format!("{b:02x}")).collect();
    Ok(to_checksum_address(&lower))
}

pub fn to_ethereum_private_key_hex(material: &EthereumKeypairMaterial) -> String {
    hex0x(&*material.private_key)
}

/// keccak256("\x19Ethereum Signed Message:\n" + byteLength + message) — EIP-191 version 0x45.
pub fn hash_ethereum_message(message: &[u8]) -> [u8; 32] {
    let mut buf = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    buf.extend_from_slice(message);
    keccak(&buf)
}

/// Sign a 32-byte hash. Deterministic (RFC 6979), low-s, with recovery id.
pub fn sign_ethereum_hash(
    material: &EthereumKeypairMaterial,
    hash32: &[u8],
) -> MajikKeyResult<EthereumSignature> {
    if hash32.len() != 32 {
        return Err(MajikKeyError::crypto(format!(
            "Expected a 32-byte hash, got {} bytes",
            hash32.len()
        )));
    }
    let sk = SigningKey::from_bytes((&*material.private_key).into())
        .map_err(|_| MajikKeyError::crypto("Invalid secp256k1 private key"))?;
    let (sig, rid) = sk.sign_prehash_recoverable(hash32);
    let normalized = sig.normalize_s();
    let rid = if normalized.to_bytes() != sig.to_bytes() {
        RecoveryId::new(!rid.is_y_odd(), rid.is_x_reduced())
    } else {
        rid
    };
    let sig = normalized;
    let recovery = rid.to_byte() & 1;
    let bytes = sig.to_bytes();
    let (r, s) = bytes.split_at(32);
    let v = 27 + recovery;
    Ok(EthereumSignature {
        r: hex0x(r),
        s: hex0x(s),
        v,
        recovery,
        serialized: format!("{}{}{:02x}", hex0x(r), &hex0x(s)[2..], v),
    })
}

pub fn sign_ethereum_message(
    material: &EthereumKeypairMaterial,
    message: &[u8],
) -> MajikKeyResult<EthereumSignature> {
    sign_ethereum_hash(material, &hash_ethereum_message(message))
}

/// Recover the signer's EIP-55 address from a hash and signature (`ecrecover`).
pub fn recover_ethereum_address(hash32: &[u8], sig: &EthereumSignature) -> MajikKeyResult<String> {
    let from_hex = |h: &str| -> MajikKeyResult<Vec<u8>> {
        let h = h.trim_start_matches("0x");
        (0..h.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&h[i..i + 2], 16)
                    .map_err(|_| MajikKeyError::crypto("Invalid hex"))
            })
            .collect()
    };
    let mut rs = from_hex(&sig.r)?;
    rs.extend(from_hex(&sig.s)?);
    let signature =
        Signature::from_slice(&rs).map_err(|_| MajikKeyError::crypto("Invalid signature"))?;
    let rid = RecoveryId::from_byte(sig.recovery)
        .ok_or_else(|| MajikKeyError::crypto("Invalid recovery id"))?;
    let vk = VerifyingKey::recover_from_prehash(hash32, &signature, rid)
        .map_err(|_| MajikKeyError::crypto("Failed to recover public key"))?;
    ethereum_address_from_public_key(vk.to_sec1_point(false).as_bytes())
}
