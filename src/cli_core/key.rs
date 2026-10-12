//! Loading, unlocking, saving and describing Majik Keys for the CLI. Mirrors `key.ts`.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use super::errors::{CliError, CliOutcome};
use super::io::{
    read_json, resolve_cli_path, resolve_output_path, short_fingerprint, slugify, write_json_secure,
};
use super::prompt::{get_passphrase, is_interactive, PassphraseSource, ENV_PASSPHRASE};
use crate::{
    known_key_ids, KeyId, MajikKey, MajikKeyDangerousJson, MajikKeyJson, MajikKeyToJsonOptions,
    MnemonicLanguage,
};

pub struct LoadedKey {
    pub key: MajikKey,
    /// Absolute path the key was read from.
    pub path: PathBuf,
    /// The file held RAW private keys (dangerous JSON), so the key is already unlocked.
    pub dangerous: bool,
}

/// Load a Majik Key JSON file — regular (passphrase-encrypted) or dangerous.
/// The returned key is NOT unlocked unless the file was dangerous JSON.
pub fn load_key_file(path: &str) -> CliOutcome<LoadedKey> {
    let resolved = resolve_cli_path(path);
    let extension = resolved
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase)
        .unwrap_or_default();

    if extension == "png" || extension == "zip" {
        return Err(CliError::usage(format!(
            "\"{path}\" looks like a mnemonic backup, not a key file. \
             Restore it into a key file with `majik-key import`."
        )));
    }

    let json = read_json(&resolved)?;
    let dangerous = json.get("privateKeyBase64").is_some_and(Value::is_string);

    let load = || -> Result<MajikKey, String> {
        if dangerous {
            let parsed: MajikKeyDangerousJson =
                serde_json::from_value(json.clone()).map_err(|e| e.to_string())?;
            MajikKey::from_dangerous_json(&parsed).map_err(|e| e.to_string())
        } else {
            let parsed: MajikKeyJson =
                serde_json::from_value(json.clone()).map_err(|e| e.to_string())?;
            MajikKey::from_json(&parsed).map_err(|e| e.to_string())
        }
    };

    let key = load().map_err(|e| {
        CliError::new(format!(
            "Failed to load Majik Key \"{}\": {e}",
            resolved.display()
        ))
    })?;

    Ok(LoadedKey {
        key,
        path: resolved,
        dangerous,
    })
}

/// Unlock a key. Interactive sessions get three tries at the passphrase; env/stdin sources
/// get exactly one (retrying a fixed value is pointless).
pub fn unlock_key(key: &mut MajikKey, source: PassphraseSource) -> CliOutcome<()> {
    if key.is_unlocked() {
        return Ok(());
    }

    let can_retry = is_interactive()
        && !source.stdin
        && std::env::var(ENV_PASSPHRASE).map_or(true, |v| v.is_empty());
    let attempts = if can_retry { 3 } else { 1 };

    for attempt in 1..=attempts {
        let passphrase = get_passphrase(source, "Passphrase: ")?;

        if key.unlock(&passphrase).is_ok() {
            return Ok(());
        }
        if attempt < attempts {
            eprintln!("Incorrect passphrase. Try again.");
        }
    }

    Err(CliError::new(
        "Incorrect passphrase, or the key file is corrupted.",
    ))
}

pub fn lock_key(key: &mut MajikKey) {
    if key.is_unlocked() {
        key.lock();
    }
}

// ─── Serialization ──────────────────────────────────────────────────────────

pub fn to_value<T: Serialize>(value: &T) -> CliOutcome<Value> {
    Ok(serde_json::to_value(value)?)
}

pub fn serialize_key(key: &MajikKey, dangerous: bool, registry_only: bool) -> CliOutcome<Value> {
    if dangerous {
        to_value(&key.to_dangerous_json()?)
    } else {
        to_value(&key.to_json_with(&MajikKeyToJsonOptions {
            legacy: !registry_only,
        }))
    }
}

pub fn default_key_file_name(key: &MajikKey, dangerous: bool) -> String {
    let fingerprint = short_fingerprint(key.fingerprint(), 8);
    let label = if key.label().is_empty() {
        String::new()
    } else {
        slugify(key.label(), 40)
    };
    let stem = if label.is_empty() {
        fingerprint
    } else {
        format!("{label}-{fingerprint}")
    };

    format!(
        "majik-key-{stem}{}.json",
        if dangerous { ".dangerous" } else { "" }
    )
}

pub fn save_key(
    key: &MajikKey,
    dangerous: bool,
    registry_only: bool,
    output: Option<&str>,
    overwrite: bool,
) -> CliOutcome<PathBuf> {
    let path = resolve_output_path(output, &default_key_file_name(key, dangerous), ".json");
    let value = serialize_key(key, dangerous, registry_only)?;
    write_json_secure(&path, &value, overwrite)?;
    Ok(path)
}

// ─── Key id / language parsing ──────────────────────────────────────────────

pub fn parse_language(language: &str) -> CliOutcome<MnemonicLanguage> {
    language.parse::<MnemonicLanguage>().map_err(|_| {
        let all = MnemonicLanguage::ALL.map(|l| l.as_str()).join(", ");
        CliError::usage(format!(
            "Unsupported language \"{language}\". Choose one of: {all}."
        ))
    })
}

/// Accepts full ids (`web3:btc`) or the part after the colon (`btc`). Library-level checks
/// (reserved / unsupported / unimplemented) still apply when the ids reach `create()` /
/// `add_keys()`.
pub fn parse_key_ids(items: &[String]) -> CliOutcome<Vec<KeyId>> {
    let known = known_key_ids(None);
    let mut result: Vec<KeyId> = Vec::new();

    for raw in items {
        let wanted = raw.trim().to_lowercase();
        if wanted.is_empty() {
            continue;
        }

        let found = known
            .iter()
            .find(|id| id.as_str() == wanted)
            .or_else(|| {
                known
                    .iter()
                    .find(|id| id.as_str().split(':').nth(1) == Some(wanted.as_str()))
            })
            .copied();

        let Some(id) = found else {
            return Err(CliError::usage(format!(
                "Unknown key \"{raw}\". Run `majik-key keys --supported` to see what can be enabled."
            )));
        };

        if !result.contains(&id) {
            result.push(id);
        }
    }

    Ok(result)
}

// ─── Description ────────────────────────────────────────────────────────────

pub fn enum_str<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub fn describe_key(key: &MajikKey) -> Vec<(&'static str, Value)> {
    let meta = key.metadata();
    let mut fields: Vec<(&'static str, Value)> = Vec::new();

    if !key.label().is_empty() {
        fields.push(("label", key.label().into()));
    }
    if key.id() != key.fingerprint() {
        fields.push(("id", key.id().into()));
    }
    fields.push(("fingerprint", key.fingerprint().into()));
    fields.push(("createdAt", meta.timestamp.into()));
    fields.push((
        "kdf",
        if key.is_argon2id() {
            "argon2id".into()
        } else {
            "pbkdf2 (legacy — run `migrate`)".into()
        },
    ));
    fields.push(("mnemonicLanguage", key.mnemonic_language().as_str().into()));
    fields.push(("coreComplete", key.is_core_complete().into()));

    if !key.is_core_complete() {
        let missing: Vec<Value> = key
            .missing_keys(None)
            .iter()
            .map(|id| id.as_str().into())
            .collect();
        fields.push(("missingCoreKeys", Value::Array(missing)));
    }

    let keys: Vec<Value> = key
        .available_keys(None)
        .iter()
        .map(|id| id.as_str().into())
        .collect();
    fields.push(("keys", Value::Array(keys)));

    fields
}

/// Convenience used by `short_fingerprint` callers outside this module.
pub fn fingerprint_stem(key: &MajikKey) -> String {
    short_fingerprint(key.fingerprint(), 8)
}
