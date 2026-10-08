//! Port of `core/keys/keypair-handle.ts` — the object returned by `MajikKey::get_keypair(id)`.
//!
//! In TS this reads LIVE through accessor closures so a handle obtained before
//! `lock()` can never expose stale material. In Rust the borrow checker gives
//! the same guarantee at compile time: the handle borrows the `MajikKey`, so
//! `lock()` (which needs `&mut`) cannot be called while a handle is alive.
//! `.private()` hands back a zeroizing copy.

use serde::Serialize;

use crate::core::error::MajikKeyResult;
use crate::core::keys::key_id::{KeyFamily, KeyId};
use crate::core::keys::registry::algorithm;
use crate::core::keys::types::{KeyKind, KeyPurpose, KeyStatus};
use crate::core::types::SecretBytes;
use crate::core::utils::array_to_base64;
use crate::majik_key::MajikKey;

pub struct MajikKeypair<'a> {
    pub id: KeyId,
    key: &'a MajikKey,
}

impl<'a> MajikKeypair<'a> {
    pub(crate) fn new(id: KeyId, key: &'a MajikKey) -> Self {
        Self { id, key }
    }

    /// Namespaced algorithm id, e.g. `pq:ml-dsa-87`.
    pub fn algorithm(&self) -> KeyId {
        self.id
    }
    pub fn family(&self) -> KeyFamily {
        algorithm(self.id).family
    }
    pub fn purpose(&self) -> KeyPurpose {
        algorithm(self.id).purpose
    }
    pub fn status(&self) -> KeyStatus {
        algorithm(self.id).status
    }
    pub fn is_unlocked(&self) -> bool {
        self.key.is_unlocked()
    }
    /// Public key bytes. Available while locked (except derived views like `web3:sol`).
    pub fn public(&self) -> MajikKeyResult<Vec<u8>> {
        self.key.get_public_key(self.id)
    }
    pub fn public_base64(&self) -> MajikKeyResult<String> {
        Ok(array_to_base64(&self.public()?))
    }
    /// Secret key bytes. Errors if the account is locked. ⚠️ Live key material (zeroized on drop).
    pub fn private(&self) -> MajikKeyResult<SecretBytes> {
        self.key.get_private_key(self.id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub id: KeyId,
    pub family: KeyFamily,
    pub purpose: KeyPurpose,
    pub kind: KeyKind,
    pub status: KeyStatus,
    /// `None` for derived views while locked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_base64: Option<String>,
}
