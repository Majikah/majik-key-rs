//! database/system/identity.rs
//!
//! Rust port of the TS lib's `core/database/system/identity.ts`
//! (`MajikMessageIdentity`) — an immutable identity container with
//! integrity verification via a SHA-256 hash over
//! `user_id:public_key:id:ml_key`.
//!
//! ⚠️ DEPENDENCY NOTE — read before wiring this up:
//! The TS version is built directly against `MajikUser` (from
//! `@thezelijah/majik-user`) and `SerializedMajikContact` (from
//! `@majikah/majik-contact`). Neither of those has a Rust port yet — your
//! own `majik_key.rs` already says as much:
//!
//!   to_majik_message_identity() -> "requires database::system::identity, not yet ported"
//!   to_contact()                -> "requires the majik-contact module, not yet ported"
//!
//! Rather than invent a `majik-user`/`majik-contact` crate dependency that
//! doesn't exist, this port is written against two minimal local shapes
//! that carry exactly the fields the TS version actually reads:
//!   - `MajikUserSource` (a trait) — `id()`, `display_name()`, `validate()`.
//!     Implement it for your real `MajikUser` type once that's ported;
//!     until then you can implement it directly on whatever user struct
//!     you already have server-side.
//!   - `SerializedContactRef` (a plain struct) — the four fields read off
//!     `SerializedMajikContact` in the TS constructor (`id`,
//!     `publicKeyBase64`, `mlKey`, `meta.label`).
//!
//! The integrity-hash construction, immutability, and public API surface
//! are otherwise a faithful 1:1 port — swap the two shapes above for the
//! real ported types later with no change to the hashing logic itself.
//!
//! Crate dependencies this file assumes are in Cargo.toml:
//!   sha2   = "0.10"
//!   base64 = "0.22"
//!   serde  = { version = "1", features = ["derive"] }

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{MajikKeyError, MajikKeyResult};

// ─── Minimal user/contact shapes (see module doc comment above) ───────────

/// Minimal surface `MajikMessageIdentity::create` needs from a "user".
/// Implement this for your real `MajikUser` type once it's ported to Rust.
pub trait MajikUserSource {
    fn id(&self) -> &str;
    fn display_name(&self) -> &str;
    /// Mirrors `user.validate()` in TS — `Err` carries the validation
    /// error messages, matching `userValidResult.errors`.
    fn validate(&self) -> Result<(), Vec<String>>;
}

/// Minimal surface read off `SerializedMajikContact` in the TS
/// constructor. Fill this in from your real serialized contact type once
/// `majik-contact` is ported — field names match 1:1.
#[derive(Debug, Clone)]
pub struct SerializedContactRef {
    pub id: String,
    pub public_key_base64: String,
    pub ml_key: String,
    pub meta_label: Option<String>,
}

// ─── JSON shape ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn sha256_b64(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    B64.encode(digest)
}

fn assert_non_empty(value: &str, field: &str) -> MajikKeyResult<()> {
    if value.trim().is_empty() {
        return Err(MajikKeyError::Other(format!(
            "{field} must be a non-empty string"
        )));
    }
    Ok(())
}

/// Options accepted by `MajikMessageIdentity::create`.
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub label: Option<String>,
    pub restricted: Option<bool>,
}

/// MajikMessageIdentity
/// ---
/// Immutable identity container with integrity verification. Rust port of
/// the TS lib's `core/database/system/identity.ts`.
///
/// "Immutable" here matches the TS class exactly: every field is read-only
/// except `label`, which has a dedicated mutator (`set_label`) — same
/// asymmetry the TS class has via its lone `set label(...)` accessor.
#[derive(Debug, Clone)]
pub struct MajikMessageIdentity {
    id: String,
    user_id: String,
    public_key: String,
    ml_key: String,
    phash: String,
    label: String,
    timestamp: String, // ISO 8601
    restricted: bool,
}

impl MajikMessageIdentity {
    /// Private-equivalent constructor — mirrors the TS class's `private
    /// constructor`, reached only via `create()` / `from_json()`.
    fn new(
        id: String,
        user_id: String,
        public_key: String,
        ml_key: String,
        phash: String,
        label: String,
        timestamp: String,
        restricted: bool,
    ) -> MajikKeyResult<Self> {
        assert_non_empty(&id, "id")?;
        assert_non_empty(&user_id, "user_id")?;
        assert_non_empty(&public_key, "public_key")?;
        assert_non_empty(&ml_key, "ml_key")?;
        assert_non_empty(&phash, "phash")?;
        assert_non_empty(&label, "label")?;
        // ISO-8601 timestamp validity check (mirrors `assertISODate`).
        if timestamp.parse::<jiff::Timestamp>().is_err() {
            return Err(MajikKeyError::Other(format!(
                "timestamp must be a valid ISO timestamp, got {timestamp}"
            )));
        }

        let identity = Self {
            id,
            user_id,
            public_key,
            ml_key,
            phash,
            label,
            timestamp,
            restricted,
        };

        if !identity.validate_integrity() {
            return Err(MajikKeyError::Other(
                "Identity integrity validation failed".into(),
            ));
        }

        Ok(identity)
    }

    // ─────────────────────────────
    // Static factory
    // ─────────────────────────────

    /// Create a new immutable identity from a user + serialized contact.
    /// Mirrors `MajikMessageIdentity.create(user, account, options)` in TS.
    pub fn create<U: MajikUserSource>(
        user: &U,
        account: &SerializedContactRef,
        options: Option<CreateOptions>,
    ) -> MajikKeyResult<Self> {
        user.validate().map_err(|errors| {
            MajikKeyError::Other(format!("Invalid MajikUser: {}", errors.join(", ")))
        })?;

        let options = options.unwrap_or_default();
        let label = options
            .label
            .or_else(|| account.meta_label.clone())
            .unwrap_or_else(|| user.display_name().to_string());
        assert_non_empty(&label, "label")?;

        let timestamp = jiff::Timestamp::now().to_string();
        let public_key = account.public_key_base64.clone();
        let phash = sha256_b64(&format!(
            "{}:{}:{}:{}",
            user.id(),
            public_key,
            account.id,
            account.ml_key
        ));

        Self::new(
            account.id.clone(),
            user.id().to_string(),
            public_key,
            account.ml_key.clone(),
            phash,
            label,
            timestamp,
            options.restricted.unwrap_or(false),
        )
    }

    // ─────────────────────────────
    // Getters (safe, read-only)
    // ─────────────────────────────

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

    // ─────────────────────────────
    // Mutators (restricted)
    // ─────────────────────────────

    /// Only mutable field — mirrors the TS class's `set label(...)`.
    pub fn set_label(&mut self, label: &str) -> MajikKeyResult<()> {
        assert_non_empty(label, "label")?;
        self.label = label.to_string();
        Ok(())
    }

    // ─────────────────────────────
    // Identity checks
    // ─────────────────────────────

    /// Returns true if identity is restricted.
    pub fn is_restricted(&self) -> bool {
        self.restricted
    }

    /// Verify identity integrity. Detects tampering of id/public_key.
    pub fn validate_integrity(&self) -> bool {
        let expected = sha256_b64(&format!(
            "{}:{}:{}:{}",
            self.user_id, self.public_key, self.id, self.ml_key
        ));
        expected == self.phash
    }

    /// Explicit verification helper.
    pub fn matches(&self, user_id: &str, public_key: &str) -> MajikKeyResult<bool> {
        assert_non_empty(user_id, "user_id")?;
        assert_non_empty(public_key, "public_key")?;
        let hash = sha256_b64(&format!(
            "{}:{}:{}:{}",
            user_id, public_key, self.id, self.ml_key
        ));
        Ok(hash == self.phash)
    }

    // ─────────────────────────────
    // Serialization
    // ─────────────────────────────

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
        let identity = Self::new(
            json.id.clone(),
            json.user_id.clone(),
            json.public_key.clone(),
            json.ml_key.clone(),
            json.phash.clone(),
            json.label.clone(),
            json.timestamp.clone(),
            json.restricted,
        )?;

        if !identity.validate_integrity() {
            return Err(MajikKeyError::Other("Invalid phash in JSON".into()));
        }
        Ok(identity)
    }

    pub fn from_json_str(json: &str) -> MajikKeyResult<Self> {
        let parsed: MajikMessageIdentityJson =
            serde_json::from_str(json).map_err(MajikKeyError::from)?;
        Self::from_json(&parsed)
    }
}
