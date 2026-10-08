//! Port of `core/backup/validator.ts` — the single source of truth for
//! "is this a structurally valid MnemonicJson". Called by `create`, `from_json`,
//! `from_png` (post-decode) and `from_zip`; never reimplemented at an entry point.

use serde_json::Value;

use crate::core::backup::error::{BackupResult, MajikKeyBackupError as E};
use crate::core::types::MnemonicJson;

pub fn validate_mnemonic_json_shape(input: &Value) -> BackupResult<MnemonicJson> {
    let invalid = |r: &str| E::InvalidBackupJson(r.to_string());
    let obj = input.as_object().ok_or_else(|| invalid("payload is not an object"))?;

    match obj.get("id").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => {}
        _ => return Err(invalid("missing or empty `id`")),
    }
    let seed = match obj.get("seed").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => return Err(invalid("missing or empty `seed`")),
    };
    if !seed.iter().all(|w| w.as_str().is_some_and(|s| !s.trim().is_empty())) {
        return Err(invalid("`seed` must be an array of non-empty words"));
    }
    if obj.get("phrase").is_some_and(|v| !v.is_string() && !v.is_null()) {
        return Err(invalid("`phrase` must be a string when present"));
    }
    if obj.get("language").is_some_and(|v| !v.is_string() && !v.is_null()) {
        return Err(invalid("`language` must be a string when present"));
    }
    if obj.get("version").is_some_and(|v| !v.is_number() && !v.is_null()) {
        return Err(invalid("`version` must be a number when present"));
    }
    serde_json::from_value(input.clone()).map_err(|e| E::InvalidBackupJson(e.to_string()))
}
