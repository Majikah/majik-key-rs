use bip39::Mnemonic;

use crate::crypto::MnemonicLanguage;
use crate::error::{MajikKeyError, MajikKeyResult};
use crate::types::MajikKeyJson;

/// Mirrors `MajikKeyValidator` from core/validator.ts.
///
/// Note on the TS→Rust translation: every `typeof x !== "string"` check in
/// the original is structurally impossible in Rust — a `&str` parameter is
/// always a string, full stop. So those checks simply don't need a Rust
/// equivalent; only the "is it empty/whitespace-only" half of each
/// validator carries over.
pub struct MajikKeyValidator;

impl MajikKeyValidator {
    pub fn validate_mnemonic(mnemonic: &str) -> MajikKeyResult<()> {
        if mnemonic.trim().is_empty() {
            return Err(MajikKeyError::InvalidMnemonic);
        }
        Ok(())
    }
    pub fn validate_mnemonic_language(
        mnemonic: &str,
        language: MnemonicLanguage,
    ) -> MajikKeyResult<()> {
        if mnemonic.trim().is_empty() {
            return Err(MajikKeyError::InvalidMnemonic);
        }

        Mnemonic::parse_in(language.to_bip39()?, mnemonic)
            .map(|_| ())
            .map_err(|e| MajikKeyError::InvalidMnemonicLanguage(e.to_string()))
    }

    /// `field_name` defaults to `"Passphrase"` in the TS lib
    /// (`fieldName = "Passphrase"`); callers here pass it explicitly since
    /// Rust doesn't have default parameter values.
    pub fn validate_passphrase(passphrase: &str, field_name: &str) -> MajikKeyResult<()> {
        if passphrase.trim().is_empty() {
            return Err(MajikKeyError::InvalidPassphrase(format!(
                "{field_name} cannot be empty or whitespace"
            )));
        }
        Ok(())
    }

    /// `None` is always valid (mirrors `label !== undefined` in the TS
    /// guard) — this exists mainly for call-site symmetry with the other
    /// validators, since there's nothing left to check once the type
    /// system already guarantees `Option<&str>` is either absent or a
    /// real string.
    pub fn validate_label(_label: Option<&str>) -> MajikKeyResult<()> {
        Ok(())
    }

    pub fn validate_id(id: &str) -> MajikKeyResult<()> {
        if id.trim().is_empty() {
            return Err(MajikKeyError::InvalidId(
                "ID cannot be empty or whitespace".into(),
            ));
        }
        Ok(())
    }

    /// Validates a deserialized `MajikKeyJson` has non-empty required
    /// fields. Note this runs *after* serde deserialization already
    /// succeeded — missing fields or wrong JSON types are caught earlier,
    /// by `serde_json::from_str` itself, and surface as
    /// `MajikKeyError::Json` rather than reaching this function at all.
    /// This function's remaining job is exactly the gap serde leaves open:
    /// a field that's present and correctly typed, but an empty string
    /// (which TS's `!obj.id` catches and bare deserialization wouldn't).
    pub fn validate_json(parsed: &MajikKeyJson) -> MajikKeyResult<()> {
        if parsed.id.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        if parsed.public_key.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        if parsed.fingerprint.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        if parsed.encrypted_private_key.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        if parsed.salt.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        if parsed.backup.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        if parsed.timestamp.trim().is_empty() {
            return Err(MajikKeyError::InvalidJson);
        }
        Ok(())
    }
}
