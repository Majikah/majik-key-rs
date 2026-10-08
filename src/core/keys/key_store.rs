//! Port of `core/keys/key-store.ts` — the single in-memory + at-rest container
//! for every key on a MajikKey account.
//!
//! Responsibilities
//!  - one slot per [`KeyId`]: public key, encrypted secret (`IV ‖ AES-GCM`), and
//!    — only while unlocked — the raw secret (`Zeroizing`, wiped on drop/lock)
//!  - atomic unlock / lock / re-encrypt (no half-states)
//!  - (de)serialize to the new `keys` entries AND to the legacy flat JSON fields
//!  - round-trip entries from NEWER library versions untouched (opaque
//!    pass-through) so a downgrade-then-save never drops keys
//!
//! It never runs a KDF itself: callers hand in already-derived AES keys
//! ([`VaultKeys`]), so the "one Argon2id run per operation" guarantee stays in
//! `MajikKey`.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::core::crypto::crypto_provider::{aes_gcm_decrypt, aes_gcm_encrypt, generate_random_bytes, IV_LENGTH};
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::keys::key_id::KeyId;
use crate::core::keys::key_impls::DerivedKeypair;
use crate::core::keys::registry::{algorithm, known_key_ids};
use crate::core::keys::types::{KeyDerivation, KeyEntryJson};
use crate::core::types::{MajikKeyJson, SecretBytes};
use crate::core::utils::{array_to_base64, base64_to_uint8array, now_iso8601};

pub struct KeySlot {
    pub id: KeyId,
    pub public_key: Vec<u8>,
    /// `IV(12) ‖ AES-256-GCM ciphertext`. Absent for public-only entries.
    pub encrypted_secret_key: Option<Vec<u8>>,
    /// Raw secret. Present ONLY while the store is unlocked.
    pub secret_key: Option<SecretBytes>,
    pub derivation: KeyDerivation,
    pub created_at: Option<String>,
}

/// Supplies the AES key for each slot. Legacy (KDF v1) accounts keep their
/// X25519 blob under PBKDF2 while every other blob is Argon2id, so two keys may
/// be in play. (TS: the `KeyResolver` callback.)
pub struct VaultKeys<'a> {
    x25519: &'a [u8; 32],
    rest: Option<&'a [u8; 32]>,
}

impl<'a> VaultKeys<'a> {
    /// One key for everything (Argon2id accounts).
    pub fn uniform(key: &'a [u8; 32]) -> Self {
        Self { x25519: key, rest: Some(key) }
    }
    /// Legacy accounts: `x25519` for `classic:x25519`, `rest` (if any non-X25519 blob exists) for the others.
    pub fn split(x25519: &'a [u8; 32], rest: Option<&'a [u8; 32]>) -> Self {
        Self { x25519, rest }
    }
    pub fn key_for(&self, id: KeyId) -> MajikKeyResult<&'a [u8; 32]> {
        if id == KeyId::X25519 {
            Ok(self.x25519)
        } else {
            self.rest
                .ok_or_else(|| MajikKeyError::msg(format!("No vault key available for \"{id}\"")))
        }
    }
}

/// The flat, pre-registry JSON fields (a subset of `MajikKeyJson`).
#[derive(Debug, Clone, Default)]
pub struct LegacyKeyJson {
    pub public_key: String,
    pub encrypted_private_key: Option<String>,
    pub ml_kem_public_key: Option<String>,
    pub encrypted_ml_kem_secret_key: Option<String>,
    pub ed_public_key: Option<String>,
    pub encrypted_ed_secret_key: Option<String>,
    pub ml_dsa_public_key: Option<String>,
    pub encrypted_ml_dsa_secret_key: Option<String>,
    pub btc_public_key: Option<String>,
    pub encrypted_btc_secret_key: Option<String>,
}

impl LegacyKeyJson {
    pub fn from_majik_json(j: &MajikKeyJson) -> Self {
        Self {
            public_key: j.public_key.clone(),
            encrypted_private_key: j.encrypted_private_key.clone(),
            ml_kem_public_key: j.ml_kem_public_key.clone(),
            encrypted_ml_kem_secret_key: j.encrypted_ml_kem_secret_key.clone(),
            ed_public_key: j.ed_public_key.clone(),
            encrypted_ed_secret_key: j.encrypted_ed_secret_key.clone(),
            ml_dsa_public_key: j.ml_dsa_public_key.clone(),
            encrypted_ml_dsa_secret_key: j.encrypted_ml_dsa_secret_key.clone(),
            btc_public_key: j.btc_public_key.clone(),
            encrypted_btc_secret_key: j.encrypted_btc_secret_key.clone(),
        }
    }

    /// `(public, encrypted)` for one of the five pre-registry keys.
    fn pair(&self, id: KeyId) -> (Option<&String>, Option<&String>) {
        match id {
            KeyId::X25519 => ((!self.public_key.is_empty()).then_some(&self.public_key), self.encrypted_private_key.as_ref()),
            KeyId::MlKem768 => (self.ml_kem_public_key.as_ref(), self.encrypted_ml_kem_secret_key.as_ref()),
            KeyId::Ed25519 => (self.ed_public_key.as_ref(), self.encrypted_ed_secret_key.as_ref()),
            KeyId::MlDsa87 => (self.ml_dsa_public_key.as_ref(), self.encrypted_ml_dsa_secret_key.as_ref()),
            KeyId::Btc => (self.btc_public_key.as_ref(), self.encrypted_btc_secret_key.as_ref()),
            _ => (None, None),
        }
    }

    fn set(&mut self, id: KeyId, public: String, encrypted: Option<String>) {
        match id {
            KeyId::X25519 => { self.public_key = public; self.encrypted_private_key = encrypted; }
            KeyId::MlKem768 => { self.ml_kem_public_key = Some(public); self.encrypted_ml_kem_secret_key = encrypted; }
            KeyId::Ed25519 => { self.ed_public_key = Some(public); self.encrypted_ed_secret_key = encrypted; }
            KeyId::MlDsa87 => { self.ml_dsa_public_key = Some(public); self.encrypted_ml_dsa_secret_key = encrypted; }
            KeyId::Btc => { self.btc_public_key = Some(public); self.encrypted_btc_secret_key = encrypted; }
            _ => {}
        }
    }
}

/// Canonical order of the five pre-registry keys (matches TS `LEGACY_FIELDS`).
const LEGACY_IDS: [KeyId; 5] = [KeyId::X25519, KeyId::MlKem768, KeyId::Ed25519, KeyId::MlDsa87, KeyId::Btc];

#[derive(Default)]
pub struct KeyStore {
    slots: BTreeMap<KeyId, KeySlot>,
    /// Entries whose id this library version doesn't know. Preserved verbatim.
    opaque: Vec<KeyEntryJson>,
    unlocked: bool,
}

impl KeyStore {
    // ── crypto primitives (same on-disk format as every blob since v1) ───────

    /// `IV(12) ‖ AES-256-GCM(plaintext)` with a fresh random IV.
    pub fn seal(aes_key: &[u8; 32], plaintext: &[u8]) -> MajikKeyResult<Vec<u8>> {
        let iv = generate_random_bytes(IV_LENGTH);
        let ct = aes_gcm_encrypt(aes_key, &iv, plaintext)?;
        let mut out = iv;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(aes_key: &[u8; 32], blob: &[u8], label: &str) -> MajikKeyResult<SecretBytes> {
        if blob.len() <= IV_LENGTH {
            return Err(MajikKeyError::DecryptionFailed(label.to_string()));
        }
        let (iv, ct) = blob.split_at(IV_LENGTH);
        aes_gcm_decrypt(aes_key, iv, ct).ok_or_else(|| MajikKeyError::DecryptionFailed(label.to_string()))
    }

    // ── construction ─────────────────────────────────────────────────────────

    /// Fresh derivation (create / import_from_mnemonic_backup): seals every secret, returns UNLOCKED.
    pub fn from_derived(
        derived: &BTreeMap<KeyId, DerivedKeypair>,
        aes_key: &[u8; 32],
    ) -> MajikKeyResult<Self> {
        let mut store = KeyStore::default();
        for (&id, kp) in derived {
            store.slots.insert(
                id,
                KeySlot {
                    id,
                    public_key: kp.public_key.clone(),
                    secret_key: Some(Zeroizing::new(kp.secret_key.to_vec())),
                    encrypted_secret_key: Some(Self::seal(aes_key, &kp.secret_key)?),
                    derivation: algorithm(id).derivation.clone(),
                    created_at: Some(now_iso8601()),
                },
            );
        }
        store.unlocked = true;
        Ok(store)
    }

    /// From the new `keys` JSON field. Unknown ids are preserved opaquely.
    pub fn from_entries(entries: &[KeyEntryJson]) -> MajikKeyResult<Self> {
        let mut store = KeyStore::default();
        let mut seen = std::collections::HashSet::new();
        for e in entries {
            if e.id.is_empty() || e.public_key.is_empty() {
                return Err(MajikKeyError::msg("Invalid key entry in `keys`"));
            }
            if !seen.insert(e.id.clone()) {
                return Err(MajikKeyError::msg(format!("Duplicate key entry \"{}\"", e.id)));
            }
            let Some(id) = KeyId::parse(&e.id) else {
                store.opaque.push(e.clone()); // from a newer version: keep, don't interpret
                continue;
            };
            store.slots.insert(
                id,
                KeySlot {
                    id,
                    public_key: base64_to_uint8array(&e.public_key)?,
                    encrypted_secret_key: e.encrypted_secret_key.as_deref().map(base64_to_uint8array).transpose()?,
                    secret_key: None,
                    derivation: e.derivation.clone(),
                    created_at: e.created_at.clone(),
                },
            );
        }
        Ok(store)
    }

    /// Tier-1 migration: wrap the flat pre-registry fields. No secrets, no KDF needed.
    pub fn from_legacy_json(j: &LegacyKeyJson) -> MajikKeyResult<Self> {
        let mut store = KeyStore::default();
        for id in LEGACY_IDS {
            let (public, encrypted) = j.pair(id);
            let Some(public) = public else { continue };
            store.slots.insert(
                id,
                KeySlot {
                    id,
                    public_key: base64_to_uint8array(public)?,
                    encrypted_secret_key: encrypted.map(|e| base64_to_uint8array(e)).transpose()?,
                    secret_key: None,
                    derivation: algorithm(id).derivation.clone(),
                    created_at: None,
                },
            );
        }
        if !store.slots.contains_key(&KeyId::X25519) {
            return Err(MajikKeyError::msg("Legacy key JSON is missing the X25519 public key"));
        }
        Ok(store)
    }

    // ── queries ──────────────────────────────────────────────────────────────

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }
    pub fn has(&self, id: KeyId) -> bool {
        self.slots.contains_key(&id)
    }
    pub fn has_all(&self, ids: &[KeyId]) -> bool {
        ids.iter().all(|i| self.has(*i))
    }
    pub fn missing(&self, ids: &[KeyId]) -> Vec<KeyId> {
        ids.iter().copied().filter(|i| !self.has(*i)).collect()
    }
    /// Stored ids in canonical registry order.
    pub fn ids(&self) -> Vec<KeyId> {
        known_key_ids(None).into_iter().filter(|id| self.slots.contains_key(id)).collect()
    }
    pub fn has_opaque_secrets(&self) -> bool {
        self.opaque.iter().any(|e| e.encrypted_secret_key.is_some())
    }
    pub fn slot(&self, id: KeyId) -> Option<&KeySlot> {
        self.slots.get(&id)
    }

    pub fn get_public_key(&self, id: KeyId) -> MajikKeyResult<&[u8]> {
        self.slots
            .get(&id)
            .map(|s| s.public_key.as_slice())
            .ok_or_else(|| MajikKeyError::KeyNotFound(id.to_string()))
    }

    pub fn get_secret_key(&self, id: KeyId) -> MajikKeyResult<&[u8]> {
        let s = self.slots.get(&id).ok_or_else(|| MajikKeyError::KeyNotFound(id.to_string()))?;
        match (&s.secret_key, self.unlocked) {
            (Some(sk), true) => Ok(sk.as_slice()),
            _ => Err(MajikKeyError::Locked),
        }
    }

    /// Non-failing: the raw secret if the store is unlocked and the slot has one.
    pub fn peek_secret_key(&self, id: KeyId) -> Option<&[u8]> {
        if !self.unlocked {
            return None;
        }
        self.slots.get(&id)?.secret_key.as_deref().map(|v| v.as_slice())
    }

    /// Install raw secrets onto existing slots and mark the store unlocked
    /// (`from_dangerous_json`). Every id must already have a slot.
    pub fn attach_secrets(&mut self, secrets: BTreeMap<KeyId, SecretBytes>) -> MajikKeyResult<()> {
        for id in secrets.keys() {
            if !self.slots.contains_key(id) {
                return Err(MajikKeyError::msg(format!("Secret supplied for unknown key \"{id}\"")));
            }
        }
        for (id, secret) in secrets {
            self.slots.get_mut(&id).expect("checked above").secret_key = Some(secret);
        }
        self.unlocked = true;
        Ok(())
    }

    /// Raw secrets of every slot (only while unlocked). Used by `to_dangerous_json`.
    pub fn export_secrets(&self) -> MajikKeyResult<Vec<(KeyId, &[u8])>> {
        if !self.unlocked {
            return Err(MajikKeyError::Locked);
        }
        Ok(self
            .ids()
            .into_iter()
            .filter_map(|id| self.slots.get(&id)?.secret_key.as_ref().map(|s| (id, s.as_slice())))
            .collect())
    }

    // ── lock / unlock (atomic) ───────────────────────────────────────────────

    /// Decrypt every secret into temporaries; commit only if ALL succeed.
    /// (A failure drops — and thereby zeroizes — everything staged so far.)
    pub fn unlock(&mut self, keys: &VaultKeys<'_>) -> MajikKeyResult<()> {
        let mut staged: Vec<(KeyId, SecretBytes)> = Vec::new();
        for slot in self.slots.values() {
            let Some(blob) = &slot.encrypted_secret_key else { continue };
            let plain = Self::open(keys.key_for(slot.id)?, blob, &format!("{} secret key", slot.id))?;
            staged.push((slot.id, plain));
        }
        for (id, secret) in staged {
            self.slots.get_mut(&id).expect("slot exists").secret_key = Some(secret);
        }
        self.unlocked = true;
        Ok(())
    }

    pub fn lock(&mut self) {
        for s in self.slots.values_mut() {
            s.secret_key = None; // Zeroizing wipes on drop
        }
        self.unlocked = false;
    }

    // ── passphrase change / KDF migration (decrypt all → seal all → commit) ──

    /// Returns freshly sealed blobs under `new_key`. Mutates nothing.
    pub fn prepare_reseal(
        &self,
        old: &VaultKeys<'_>,
        new_key: &[u8; 32],
    ) -> MajikKeyResult<BTreeMap<KeyId, Vec<u8>>> {
        if self.has_opaque_secrets() {
            return Err(MajikKeyError::msg(
                "This account holds keys from a newer library version. Upgrade the library before changing the passphrase.",
            ));
        }
        let mut out = BTreeMap::new();
        for slot in self.slots.values() {
            let Some(blob) = &slot.encrypted_secret_key else { continue };
            let plain = Self::open(old.key_for(slot.id)?, blob, &format!("{} secret key", slot.id))?;
            out.insert(slot.id, Self::seal(new_key, &plain)?);
        }
        Ok(out)
    }

    pub fn commit_reseal(&mut self, blobs: BTreeMap<KeyId, Vec<u8>>) {
        for (id, blob) in blobs {
            if let Some(s) = self.slots.get_mut(&id) {
                s.encrypted_secret_key = Some(blob);
            }
        }
    }

    /// Add keys after the fact (`add_keys()`). Caller has already sealed `secret_key`.
    pub fn add(&mut self, slot: KeySlot) -> MajikKeyResult<()> {
        if self.slots.contains_key(&slot.id) {
            return Err(MajikKeyError::msg(format!("\"{}\" already exists on this account", slot.id)));
        }
        self.slots.insert(slot.id, slot);
        Ok(())
    }

    // ── serialization ────────────────────────────────────────────────────────

    pub fn to_entries(&self) -> Vec<KeyEntryJson> {
        let mut out: Vec<KeyEntryJson> = self
            .ids()
            .into_iter()
            .map(|id| {
                let s = &self.slots[&id];
                KeyEntryJson {
                    id: id.to_string(),
                    public_key: array_to_base64(&s.public_key),
                    encrypted_secret_key: s.encrypted_secret_key.as_deref().map(array_to_base64),
                    derivation: s.derivation.clone(),
                    created_at: s.created_at.clone(),
                    extra: Default::default(),
                }
            })
            .collect();
        out.extend(self.opaque.iter().cloned());
        out
    }

    /// Flat pre-registry fields — for `to_json(legacy: true)` so older readers keep working.
    pub fn to_legacy_json(&self) -> LegacyKeyJson {
        let mut out = LegacyKeyJson::default();
        for id in LEGACY_IDS {
            if let Some(s) = self.slots.get(&id) {
                out.set(id, array_to_base64(&s.public_key), s.encrypted_secret_key.as_deref().map(array_to_base64));
            }
        }
        out
    }
}
