//! Port of `core/database/system/identity.ts` — `MajikMessageIdentity`, an
//! immutable identity container with an integrity hash.
//!
//! The TS file imports `MajikUser` (`@thezelijah/majik-user`) and
//! `SerializedMajikContact` / `MajikContact` (`@majikah/majik-contact`). Neither
//! has a Rust crate yet, so minimal data-only stand-ins live here. Swap them for
//! the real types once those crates exist; the hashing logic doesn't change.

use serde::{Deserialize, Serialize};

use crate::core::crypto::crypto_provider::sha256;
use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::utils::now_iso8601;

/// Stand-in for `MajikUser` — only what identity creation reads.
#[derive(Debug, Clone)]
pub struct MajikUserRef {
    pub id: String,
    pub display_name: String,
}

impl MajikUserRef {
    /// Mirrors `MajikUser.validate()`: returns the list of problems (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.id.trim().is_empty() {
            errors.push("id is required".to_string());
        }
        if self.display_name.trim().is_empty() {
            errors.push("displayName is required".to_string());
        }
        errors
    }
}

/// Stand-in for `MajikContactData` — what `MajikKey::to_contact()` produces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikContactData {
    pub id: String,
    /// X25519 public key, base64.
    pub public_key_base64: String,
    pub fingerprint: String,
    pub label: String,
    /// ML-KEM-768 public key, base64.
    pub ml_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed_public_key_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_public_key_base64: Option<String>,
}

/// Stand-in for `SerializedMajikContact`.
pub type SerializedMajikContact = MajikContactData;

#[derive(Debug, Clone, Default)]
pub struct IdentityOptions {
    pub label: Option<String>,
    pub restricted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MajikMessageIdentityJson {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub ml_key: String,
    pub phash: String,
    pub label: String,
    pub timestamp: String,
    pub restricted: bool,
}

#[derive(Debug, Clone)]
pub struct MajikMessageIdentity {
    id: String,
    user_id: String,
    public_key: String,
    ml_key: String,
    phash: String,
    label: String,
    timestamp: String,
    restricted: bool,
}

fn phash(user_id: &str, public_key: &str, id: &str, ml_key: &str) -> String {
    sha256(&format!("{user_id}:{public_key}:{id}:{ml_key}"))
}

impl MajikMessageIdentity {
    fn new(p: MajikMessageIdentityJson) -> MajikKeyResult<Self> {
        for (v, f) in [
            (&p.id, "id"),
            (&p.user_id, "user_id"),
            (&p.public_key, "public_key"),
            (&p.ml_key, "ml_key"),
            (&p.phash, "phash"),
            (&p.label, "label"),
        ] {
            if v.trim().is_empty() {
                return Err(MajikKeyError::msg(format!(
                    "{f} must be a non-empty string"
                )));
            }
        }
        p.timestamp
            .parse::<jiff::Timestamp>()
            .map_err(|_| MajikKeyError::msg("timestamp must be a valid ISO timestamp"))?;
        let me = Self {
            id: p.id,
            user_id: p.user_id,
            public_key: p.public_key,
            ml_key: p.ml_key,
            phash: p.phash,
            label: p.label,
            timestamp: p.timestamp,
            restricted: p.restricted,
        };
        if !me.validate_integrity() {
            return Err(MajikKeyError::msg("Identity integrity validation failed"));
        }
        Ok(me)
    }

    /// Create a new immutable identity from a user + serialized contact.
    pub fn create(
        user: &MajikUserRef,
        account: &SerializedMajikContact,
        options: Option<IdentityOptions>,
    ) -> MajikKeyResult<Self> {
        let errors = user.validate();
        if !errors.is_empty() {
            return Err(MajikKeyError::msg(format!(
                "Invalid MajikUser: {}",
                errors.join(", ")
            )));
        }
        let opts = options.unwrap_or_default();
        let label = opts
            .label
            .filter(|l| !l.is_empty())
            .or_else(|| Some(account.label.clone()).filter(|l| !l.is_empty()))
            .unwrap_or_else(|| user.display_name.clone());

        Self::new(MajikMessageIdentityJson {
            id: account.id.clone(),
            user_id: user.id.clone(),
            public_key: account.public_key_base64.clone(),
            ml_key: account.ml_key.clone(),
            phash: phash(
                &user.id,
                &account.public_key_base64,
                &account.id,
                &account.ml_key,
            ),
            label,
            timestamp: now_iso8601(),
            restricted: opts.restricted,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
    pub fn phash(&self) -> &str {
        &self.phash
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }
    pub fn restricted(&self) -> bool {
        self.restricted
    }
    pub fn is_restricted(&self) -> bool {
        self.restricted
    }

    /// The only mutable field.
    pub fn set_label(&mut self, label: &str) -> MajikKeyResult<()> {
        if label.trim().is_empty() {
            return Err(MajikKeyError::msg("label must be a non-empty string"));
        }
        self.label = label.to_string();
        Ok(())
    }

    /// Detects tampering of id / public_key / ml_key.
    pub fn validate_integrity(&self) -> bool {
        phash(&self.user_id, &self.public_key, &self.id, &self.ml_key) == self.phash
    }

    pub fn matches(&self, user_id: &str, public_key: &str) -> MajikKeyResult<bool> {
        if user_id.trim().is_empty() || public_key.trim().is_empty() {
            return Err(MajikKeyError::msg(
                "userId and publicKey must be non-empty strings",
            ));
        }
        Ok(phash(user_id, public_key, &self.id, &self.ml_key) == self.phash)
    }

    pub fn to_json(&self) -> MajikMessageIdentityJson {
        MajikMessageIdentityJson {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            public_key: self.public_key.clone(),
            ml_key: self.ml_key.clone(),
            phash: self.phash.clone(),
            label: self.label.clone(),
            timestamp: self.timestamp.clone(),
            restricted: self.restricted,
        }
    }

    pub fn from_json(json: &MajikMessageIdentityJson) -> MajikKeyResult<Self> {
        Self::new(json.clone())
    }

    pub fn from_json_str(json: &str) -> MajikKeyResult<Self> {
        Self::from_json(&serde_json::from_str(json)?)
    }
}
