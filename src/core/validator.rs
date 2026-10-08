//! Port of `core/validator.ts`.

use serde_json::Value;

use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::types::MajikKeyJson;

pub struct MajikKeyValidator;

impl MajikKeyValidator {
    pub fn validate_mnemonic(mnemonic: &str) -> MajikKeyResult<()> {
        if mnemonic.is_empty() {
            return Err(MajikKeyError::msg("Mnemonic must be a non-empty string"));
        }
        if mnemonic.trim().is_empty() {
            return Err(MajikKeyError::msg("Mnemonic cannot be empty or whitespace"));
        }
        Ok(())
    }

    pub fn validate_passphrase(passphrase: &str, field_name: &str) -> MajikKeyResult<()> {
        if passphrase.is_empty() {
            return Err(MajikKeyError::msg(format!(
                "{field_name} must be a non-empty string"
            )));
        }
        if passphrase.trim().is_empty() {
            return Err(MajikKeyError::msg(format!(
                "{field_name} cannot be empty or whitespace"
            )));
        }
        Ok(())
    }

    /// Labels are `Option<&str>` in Rust, so the TS type check is enforced by the compiler.
    pub fn validate_label(_label: Option<&str>) -> MajikKeyResult<()> {
        Ok(())
    }

    pub fn validate_id(id: &str) -> MajikKeyResult<()> {
        if id.is_empty() {
            return Err(MajikKeyError::msg("ID must be a non-empty string"));
        }
        if id.trim().is_empty() {
            return Err(MajikKeyError::msg("ID cannot be empty or whitespace"));
        }
        Ok(())
    }

    /// Validate a legacy (flat) `MajikKeyJson` — same required fields and messages as TS.
    pub fn validate_json(json: &MajikKeyJson) -> MajikKeyResult<()> {
        let req = |v: &str, f: &str| -> MajikKeyResult<()> {
            if v.is_empty() {
                Err(MajikKeyError::msg(format!(
                    "Invalid JSON: missing or invalid '{f}' field"
                )))
            } else {
                Ok(())
            }
        };
        req(&json.id, "id")?;
        req(&json.public_key, "publicKey")?;
        req(&json.fingerprint, "fingerprint")?;
        req(
            json.encrypted_private_key.as_deref().unwrap_or(""),
            "encryptedPrivateKey",
        )?;
        req(&json.salt, "salt")?;
        req(&json.backup, "backup")?;
        req(&json.timestamp, "timestamp")?;
        Ok(())
    }

    /// Validate an untyped JSON value (field presence/types), then deserialize it.
    pub fn validate_json_value(value: &Value) -> MajikKeyResult<MajikKeyJson> {
        let obj = value
            .as_object()
            .ok_or_else(|| MajikKeyError::msg("Invalid JSON: must be an object"))?;
        for f in ["id", "fingerprint", "salt", "backup", "timestamp"] {
            if obj
                .get(f)
                .and_then(Value::as_str)
                .is_none_or(|s| s.is_empty())
            {
                return Err(MajikKeyError::msg(format!(
                    "Invalid JSON: missing or invalid '{f}' field"
                )));
            }
        }
        if let Some(l) = obj.get("label") {
            if !l.is_string() {
                return Err(MajikKeyError::msg(
                    "Invalid JSON: 'label' must be a string if provided",
                ));
            }
        }
        Ok(serde_json::from_value(value.clone())?)
    }

    pub fn assert(condition: bool, message: &str) -> MajikKeyResult<()> {
        if condition {
            Ok(())
        } else {
            Err(MajikKeyError::msg(message))
        }
    }

    pub fn assert_string(value: &str, field: &str) -> MajikKeyResult<()> {
        Self::assert(
            !value.trim().is_empty(),
            &format!("{field} must be a non-empty string"),
        )
    }
}
