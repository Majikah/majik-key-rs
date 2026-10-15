//! One function per CLI command. Each takes parsed args, performs the work against
//! `MajikKey`, and returns a [`CliResult`] (or a [`CliError`]). Mirrors `operations.ts`.

use std::path::{Path, PathBuf};

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::errors::{CliError, CliOutcome};
use super::io::{
    read_bytes, read_text, resolve_cli_path, resolve_output_path, short_fingerprint, slugify,
    write_json_secure, write_secure_file,
};
use super::key::{
    default_key_file_name, describe_key, enum_str, load_key_file, lock_key, parse_key_ids,
    parse_language, save_key, serialize_key, to_value, unlock_key, LoadedKey,
};
use super::output::{print_mnemonic, CliResult};
use super::prompt::{
    assert_mnemonic_shape, get_new_passphrase, get_passphrase, is_interactive, normalize_mnemonic,
    prompt_mnemonic, read_hidden, PassphraseSource, ENV_NEW_PASSPHRASE, ENV_PASSPHRASE,
};
use super::types::*;
use crate::{
    algorithm, derive_keys, fingerprint_from_public_raw, generate_random_bytes, looks_like_png,
    looks_like_zip, mnemonic_to_seed, BackupSeed, CreateBackupParams, KeyId, MajikKey,
    MajikKeyBackup, MajikKeyCreateOptions, MnemonicLanguage, ToZipOptions,
};

// ─── Shared helpers ─────────────────────────────────────────────────────────

fn assert_dangerous_flag(format: &SaveFormatArgs) -> CliOutcome<()> {
    if format.dangerous && !format.i_understand_the_risk {
        return Err(CliError::usage(
            "--dangerous writes your PRIVATE KEYS UNENCRYPTED. \
             Add --i-understand-the-risk to confirm you want that.",
        ));
    }
    Ok(())
}

/// Typed confirmation before raw private keys are written anywhere.
/// Non-interactive callers must say `--yes` explicitly.
fn confirm_dangerous(fingerprint: &str, yes: bool) -> CliOutcome<()> {
    if yes {
        return Ok(());
    }

    if !is_interactive() {
        return Err(CliError::usage(
            "Dangerous export needs confirmation. Run it in an interactive terminal, \
             or add --yes for non-interactive use.",
        ));
    }

    let chars: Vec<char> = fingerprint.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(8)..].iter().collect();

    eprintln!(
        "\nThis will output PRIVATE KEY material in PLAINTEXT. Anyone with it controls this key.\n\
         Key fingerprint: {fingerprint}"
    );

    let typed = read_hidden(&format!(
        "Type the last 8 characters of the fingerprint ({tail}) to confirm: "
    ))?;

    if typed.trim() != tail {
        return Err(CliError::new(
            "Confirmation did not match — nothing was written.",
        ));
    }
    Ok(())
}

/// Mnemonic from a file (plain text or MnemonicJSON), env var, or hidden prompt.
fn read_mnemonic_input(
    mnemonic_file: Option<&str>,
) -> CliOutcome<(Zeroizing<String>, Option<String>)> {
    let Some(file) = mnemonic_file else {
        return Ok((prompt_mnemonic("Recovery phrase: ")?, None));
    };

    let text = Zeroizing::new(read_text(&resolve_cli_path(file))?);
    let trimmed = text.trim();

    if trimmed.starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            if let Some(seed) = parsed.get("seed").and_then(Value::as_array) {
                let words: Vec<&str> = seed.iter().filter_map(Value::as_str).collect();
                let mnemonic = Zeroizing::new(normalize_mnemonic(&words.join(" ")));
                assert_mnemonic_shape(&mnemonic)?;
                let language = parsed
                    .get("language")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                return Ok((mnemonic, language));
            }
        }
    }

    let mnemonic = Zeroizing::new(normalize_mnemonic(trimmed));
    assert_mnemonic_shape(&mnemonic)?;
    Ok((mnemonic, None))
}

/// Uniform random integer in `0..n` (rejection sampling — no modulo bias).
fn random_below(n: usize) -> usize {
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let bytes = generate_random_bytes(4);
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if value < zone {
            return (value % n) as usize;
        }
    }
}

/// Pick `count` distinct random indices out of `length`, sorted.
fn pick_positions(length: usize, count: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..length).collect();
    for i in (1..indices.len()).rev() {
        indices.swap(i, random_below(i + 1));
    }
    let mut picked: Vec<usize> = indices.into_iter().take(count.min(length)).collect();
    picked.sort_unstable();
    picked
}

fn nfkd_lower(value: &str) -> String {
    value.trim().to_lowercase().nfkd().collect()
}

fn confirm_written_down(words: &[&str]) -> CliOutcome<()> {
    eprintln!("Confirm you wrote it down — type the requested words.");

    for position in pick_positions(words.len(), 3) {
        let typed = read_hidden(&format!("Word #{}: ", position + 1))?;

        if nfkd_lower(&typed) != nfkd_lower(words[position]) {
            return Err(CliError::new(format!(
                "That doesn't match word #{}. Nothing was saved — run the command again \
                 once you've written the phrase down.",
                position + 1
            )));
        }
    }
    Ok(())
}

/// Does `mnemonic` derive the account `key`? Cheap: no KDF, no passphrase.
fn mnemonic_belongs_to(key: &MajikKey, mnemonic: &str) -> CliOutcome<bool> {
    let seed = mnemonic_to_seed(mnemonic, key.mnemonic_language())?;
    let probe = derive_keys(&seed[..], &[KeyId::X25519])?;
    let derived = probe
        .get(&KeyId::X25519)
        .ok_or_else(|| CliError::new("X25519 key was not derived"))?;
    Ok(fingerprint_from_public_raw(&derived.public_key) == key.fingerprint())
}

fn save_back(loaded: &LoadedKey, key: &MajikKey, write: &WriteArgs) -> CliOutcome<PathBuf> {
    let file_name = loaded
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("majik-key.json")
        .to_string();

    let target = match &write.output {
        Some(output) => resolve_output_path(Some(output), &file_name, ".json"),
        None => loaded.path.clone(),
    };

    // Editing a file in place is the whole point of the command — no --overwrite needed.
    let overwrite = write.overwrite || target == loaded.path;

    let value = serialize_key(key, loaded.dangerous, false)?;
    write_json_secure(&target, &value, overwrite)?;
    Ok(target)
}

fn require_encrypted_key(loaded: &LoadedKey, what: &str) -> CliOutcome<()> {
    if loaded.dangerous {
        let name = loaded
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("this file");
        return Err(CliError::usage(format!(
            "{what} needs a regular (passphrase-encrypted) key file, but \"{name}\" \
             holds raw private keys."
        )));
    }
    Ok(())
}

fn path_str(path: &Path) -> String {
    path.display().to_string()
}

fn strings<I: IntoIterator<Item = S>, S: AsRef<str>>(items: I) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|s| Value::String(s.as_ref().to_string()))
            .collect(),
    )
}

fn key_id_strings(ids: &[KeyId]) -> Value {
    strings(ids.iter().map(|id| id.as_str()))
}

// ─── Creating keys ──────────────────────────────────────────────────────────

/// Shared tail of generate / create / import: build, confirm, save.
fn build_and_save_key(
    command: &'static str,
    mnemonic: &str,
    passphrase: &str,
    language: MnemonicLanguage,
    args: &NewKeyArgs,
) -> CliOutcome<CliResult> {
    let key_ids = parse_key_ids(&args.keys)?;

    let mut key = MajikKey::create(
        mnemonic,
        passphrase,
        args.label.as_deref(),
        &MajikKeyCreateOptions {
            mnemonic_language: Some(language),
            keys: key_ids,
            derive_bitcoin: false,
        },
    )?;

    let result = (|| -> CliOutcome<CliResult> {
        let dangerous = args.format.dangerous;

        if dangerous {
            confirm_dangerous(key.fingerprint(), args.format.yes)?;
        }

        let key_file = save_key(
            &key,
            dangerous,
            args.format.registry_only,
            args.write.output.as_deref(),
            args.write.overwrite,
        )?;

        let mut mnemonic_file: Option<PathBuf> = None;

        if let Some(requested) = &args.mnemonic_out {
            let default_name =
                default_key_file_name(&key, false).replace(".json", ".mnemonic.json");

            let target = match requested {
                Some(path) => path.clone(),
                None => {
                    let parent = key_file.parent().map(path_str).unwrap_or_default();
                    format!("{parent}{}", std::path::MAIN_SEPARATOR)
                }
            };

            let path = resolve_output_path(Some(&target), &default_name, ".json");
            let json = to_value(&key.to_mnemonic_json(mnemonic, None)?)?;
            write_json_secure(&path, &json, args.write.overwrite)?;
            mnemonic_file = Some(path);
        }

        Ok(CliResult::ok(
            command,
            if dangerous {
                "Majik Key saved as DANGEROUS plaintext JSON."
            } else {
                "Majik Key saved."
            },
        )
        .with("keyFile", path_str(&key_file))
        .with(
            "format",
            if dangerous {
                "DANGEROUS — raw private keys, unencrypted"
            } else {
                "passphrase-encrypted JSON"
            },
        )
        .with_opt(
            "label",
            Some(key.label().to_string()).filter(|l| !l.is_empty()),
        )
        .with("fingerprint", key.fingerprint())
        .with("keys", key_id_strings(&key.available_keys(None)))
        .with_opt("mnemonicFile", mnemonic_file.as_deref().map(path_str))
        .with_opt(
            "warning",
            mnemonic_file
                .as_ref()
                .map(|_| "The mnemonic file is PLAINTEXT. Move it somewhere safe and offline."),
        ))
    })();

    lock_key(&mut key);
    result
}

pub fn run_generate(args: &GenerateArgs) -> CliOutcome<CliResult> {
    let size: u32 = args
        .size
        .parse()
        .map_err(|_| CliError::usage("--size must be 12 or 24."))?;
    if size != 12 && size != 24 {
        return Err(CliError::usage("--size must be 12 or 24."));
    }

    let language = parse_language(&args.language)?;
    assert_dangerous_flag(&args.new_key.format)?;
    parse_key_ids(&args.new_key.keys)?; // fail on bad ids before prompting

    let passphrase = get_new_passphrase(
        PassphraseSource::from_flag(args.new_key.passphrase.passphrase_stdin),
        "Set a passphrase: ",
    )?;

    let mnemonic = Zeroizing::new(MajikKey::generate_mnemonic(
        if size == 24 { 256 } else { 128 },
        language,
    )?);
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    print_mnemonic(&words);

    if is_interactive() && !args.skip_confirm {
        confirm_written_down(&words)?;
    }

    build_and_save_key("generate", &mnemonic, &passphrase, language, &args.new_key)
}

pub fn run_create(args: &CreateArgs) -> CliOutcome<CliResult> {
    assert_dangerous_flag(&args.new_key.format)?;
    parse_key_ids(&args.new_key.keys)?;

    let (mnemonic, file_language) = read_mnemonic_input(args.mnemonic_file.as_deref())?;

    let language = match (&args.language, &file_language) {
        (Some(l), _) | (None, Some(l)) => parse_language(l)?,
        (None, None) => MnemonicLanguage::En,
    };

    let passphrase = get_new_passphrase(
        PassphraseSource::from_flag(args.new_key.passphrase.passphrase_stdin),
        "Set a passphrase: ",
    )?;

    build_and_save_key("create", &mnemonic, &passphrase, language, &args.new_key)
}

pub fn run_import(args: &ImportArgs) -> CliOutcome<CliResult> {
    assert_dangerous_flag(&args.new_key.format)?;
    parse_key_ids(&args.new_key.keys)?;

    let path = resolve_cli_path(&args.backup);
    let bytes = read_bytes(&path)?;

    let backup = if looks_like_png(&bytes) {
        return Err(CliError::new(
            "PNG backups can't be read by the Rust CLI yet (the MajikByte PNG codec has no \
             Rust port). Use a .json or .zip backup, or restore this one with the \
             TypeScript CLI.",
        ));
    } else if looks_like_zip(&bytes) {
        MajikKeyBackup::from_zip(&bytes, None)
    } else {
        let text = String::from_utf8(bytes)
            .map_err(|_| CliError::new("Backup is neither a ZIP nor UTF-8 JSON."))?;
        MajikKeyBackup::from_json_str(&text)
    }
    .map_err(|e| CliError::new(format!("Could not read backup \"{}\": {e}", path.display())))?;

    let language = match (&args.language, backup.language()) {
        (Some(l), _) => parse_language(l)?,
        (None, Some(l)) => l,
        (None, None) => MnemonicLanguage::En,
    };

    let passphrase = get_new_passphrase(
        PassphraseSource::from_flag(args.new_key.passphrase.passphrase_stdin),
        "Set a passphrase: ",
    )?;

    let phrase = Zeroizing::new(backup.seed_phrase());
    build_and_save_key("import", &phrase, &passphrase, language, &args.new_key)
}

// ─── Inspecting keys ────────────────────────────────────────────────────────

pub fn run_info(args: &InfoArgs) -> CliOutcome<CliResult> {
    let loaded = load_key_file(&args.key)?;
    let key = &loaded.key;

    let mut result = CliResult::ok(
        "info",
        if key.label().is_empty() {
            "Majik Key".to_string()
        } else {
            format!("Majik Key \"{}\"", key.label())
        },
    )
    .with("file", path_str(&loaded.path));

    for (name, value) in describe_key(key) {
        result = result.with(name, value);
    }

    Ok(result.with("containsRawPrivateKeys", loaded.dangerous.then_some(true)))
}

pub fn run_keys(args: &KeysArgs, json: bool) -> CliOutcome<CliResult> {
    if args.supported {
        let rows: Vec<Value> = MajikKey::supported_keys()
            .into_iter()
            .map(|id| {
                let def = algorithm(id);
                serde_json::json!({
                    "id": id.as_str(),
                    "family": def.family.as_str(),
                    "purpose": enum_str(&def.purpose),
                    "kind": enum_str(&def.kind),
                    "status": enum_str(&def.status),
                    "standard": def.standard,
                })
            })
            .collect();

        return Ok(CliResult::ok(
            "keys",
            format!("{} key algorithms can be enabled.", rows.len()),
        )
        .with("keys", Value::Array(rows)));
    }

    let Some(input) = &args.key else {
        return Err(CliError::usage("Provide a key file, or use --supported."));
    };

    let loaded = load_key_file(input)?;
    let show_full = args.full || json;

    let rows: Vec<Value> = loaded
        .key
        .list_keys()
        .into_iter()
        .map(|info| {
            let public_key = info.public_key_base64.map(|pk| {
                if !show_full && pk.chars().count() > 24 {
                    format!(
                        "{}… ({} chars)",
                        pk.chars().take(20).collect::<String>(),
                        pk.chars().count()
                    )
                } else {
                    pk
                }
            });

            serde_json::json!({
                "id": info.id.as_str(),
                "purpose": enum_str(&info.purpose),
                "kind": enum_str(&info.kind),
                "status": enum_str(&info.status),
                "publicKey": public_key,
            })
        })
        .collect();

    Ok(
        CliResult::ok("keys", format!("{} key(s) on this account.", rows.len()))
            .with("keys", Value::Array(rows)),
    )
}

pub fn run_verify(args: &VerifyArgs) -> CliOutcome<CliResult> {
    let loaded = load_key_file(&args.key)?;
    require_encrypted_key(&loaded, "Passphrase verification")?;

    let passphrase = get_passphrase(
        PassphraseSource::from_flag(args.passphrase.passphrase_stdin),
        "Passphrase: ",
    )?;
    let valid = loaded.key.verify(&passphrase);

    let result = if valid {
        CliResult::ok("verify", "Passphrase is correct.")
    } else {
        CliResult::failed("verify", "Incorrect passphrase.")
    };

    Ok(result
        .with("valid", valid)
        .with("fingerprint", loaded.key.fingerprint()))
}

// ─── Editing keys ───────────────────────────────────────────────────────────

pub fn run_label(args: &LabelArgs) -> CliOutcome<CliResult> {
    let mut loaded = load_key_file(&args.key)?;

    let Some(new_label) = &args.label else {
        let current = loaded.key.label().to_string();
        return Ok(CliResult::ok(
            "label",
            if current.is_empty() {
                "This key has no label.".to_string()
            } else {
                format!("Label: {current}")
            },
        )
        .with_opt("label", Some(current).filter(|l| !l.is_empty())));
    };

    let previous = loaded.key.label().to_string();
    loaded.key.update_label(new_label)?;

    let file = save_back(&loaded, &loaded.key, &args.write)?;

    Ok(CliResult::ok("label", "Label updated.")
        .with_opt("previousLabel", Some(previous).filter(|l| !l.is_empty()))
        .with_opt(
            "label",
            Some(loaded.key.label().to_string()).filter(|l| !l.is_empty()),
        )
        .with("file", path_str(&file)))
}

pub fn run_passphrase(args: &PassphraseArgs) -> CliOutcome<CliResult> {
    let mut loaded = load_key_file(&args.key)?;
    require_encrypted_key(&loaded, "Changing the passphrase")?;

    let current = get_passphrase(
        PassphraseSource::env(ENV_PASSPHRASE),
        "Current passphrase: ",
    )?;

    if !loaded.key.verify(&current) {
        return Err(CliError::new("Incorrect passphrase."));
    }
    loaded.key.unlock(&current)?;

    let outcome = (|| -> CliOutcome<PathBuf> {
        let next = get_new_passphrase(
            PassphraseSource::env(ENV_NEW_PASSPHRASE),
            "New passphrase: ",
        )?;

        if *next == *current {
            return Err(CliError::usage(
                "The new passphrase is the same as the current one.",
            ));
        }

        loaded.key.update_passphrase(&current, &next)?;
        save_back(&loaded, &loaded.key, &args.write)
    })();

    lock_key(&mut loaded.key);
    let file = outcome?;

    Ok(CliResult::ok(
        "passphrase",
        "Passphrase updated. Keys were re-encrypted under a fresh salt.",
    )
    .with("fingerprint", loaded.key.fingerprint())
    .with("file", path_str(&file)))
}

pub fn run_migrate(args: &MigrateArgs) -> CliOutcome<CliResult> {
    let mut loaded = load_key_file(&args.key)?;
    require_encrypted_key(&loaded, "Migration")?;

    if loaded.key.is_argon2id() {
        return Ok(
            CliResult::ok("migrate", "Already on Argon2id — nothing to do.")
                .with("kdf", "argon2id"),
        );
    }

    let passphrase = get_passphrase(
        PassphraseSource::from_flag(args.passphrase.passphrase_stdin),
        "Passphrase: ",
    )?;

    if !loaded.key.verify(&passphrase) {
        return Err(CliError::new("Incorrect passphrase."));
    }

    loaded.key.migrate(&passphrase)?;
    let file = save_back(&loaded, &loaded.key, &args.write)?;

    Ok(
        CliResult::ok("migrate", "Migrated from PBKDF2 to Argon2id.")
            .with("kdf", "argon2id")
            .with("file", path_str(&file)),
    )
}

pub fn run_add_keys(args: &AddKeysArgs) -> CliOutcome<CliResult> {
    let ids = parse_key_ids(&args.keys)?;
    if ids.is_empty() {
        return Err(CliError::usage(
            "Provide at least one key with --keys, e.g. --keys btc,eth.",
        ));
    }

    let mut loaded = load_key_file(&args.key)?;
    require_encrypted_key(&loaded, "Adding keys")?;

    let passphrase = get_passphrase(PassphraseSource::env(ENV_PASSPHRASE), "Passphrase: ")?;

    if !loaded.key.verify(&passphrase) {
        return Err(CliError::new("Incorrect passphrase."));
    }

    // New keys are derived from the seed, which is never stored.
    let (mnemonic, _) = read_mnemonic_input(args.mnemonic_file.as_deref())?;

    let migrated = !loaded.key.is_argon2id();
    if migrated {
        loaded.key.migrate(&passphrase)?;
    }

    let added = loaded.key.add_keys(&ids, &mnemonic, &passphrase)?;
    lock_key(&mut loaded.key);

    if added.is_empty() && !migrated {
        return Ok(CliResult::ok(
            "add-keys",
            "Nothing to add — those keys are already on this account.",
        )
        .with("keys", key_id_strings(&loaded.key.available_keys(None))));
    }

    let file = save_back(&loaded, &loaded.key, &args.write)?;

    Ok(CliResult::ok(
        "add-keys",
        if added.is_empty() {
            "Migrated to Argon2id; no new keys were needed.".to_string()
        } else {
            format!("Added {} key(s).", added.len())
        },
    )
    .with("added", key_id_strings(&added))
    .with("migratedToArgon2id", migrated.then_some(true))
    .with("file", path_str(&file)))
}

// ─── Serialization ──────────────────────────────────────────────────────────

pub fn run_export(args: &ExportArgs, json: bool) -> CliOutcome<CliResult> {
    if json && args.stdout {
        return Err(CliError::usage("--json cannot be combined with --stdout."));
    }
    if args.contact && args.format.dangerous {
        return Err(CliError::usage(
            "--contact is public data; it cannot be combined with --dangerous.",
        ));
    }
    assert_dangerous_flag(&args.format)?;

    let mut loaded = load_key_file(&args.key)?;

    let outcome = (|| -> CliOutcome<CliResult> {
        let key = &mut loaded.key;
        let (value, default_name, kind): (Value, String, &str) = if args.contact {
            (
                to_value(&key.to_contact(None)?.to_json())?,
                format!(
                    "majik-contact-{}.json",
                    short_fingerprint(key.fingerprint(), 8)
                ),
                "public contact JSON",
            )
        } else {
            if args.format.dangerous {
                unlock_key(
                    key,
                    PassphraseSource::from_flag(args.passphrase.passphrase_stdin),
                )?;
                confirm_dangerous(key.fingerprint(), args.format.yes)?;
            }
            (
                serialize_key(key, args.format.dangerous, args.format.registry_only)?,
                default_key_file_name(key, args.format.dangerous),
                if args.format.dangerous {
                    "DANGEROUS — raw private keys, unencrypted"
                } else {
                    "passphrase-encrypted JSON"
                },
            )
        };

        let mut text = serde_json::to_string_pretty(&value)?;
        text.push('\n');

        if args.stdout {
            use std::io::Write;
            std::io::stdout().write_all(text.as_bytes())?;
            return Ok(CliResult::ok("export", "Exported to stdout.")
                .with("format", kind)
                .with("fingerprint", key.fingerprint()));
        }

        let file = resolve_output_path(args.write.output.as_deref(), &default_name, ".json");
        write_secure_file(&file, text.as_bytes(), args.write.overwrite)?;

        Ok(CliResult::ok("export", "Exported.")
            .with("format", kind)
            .with("file", path_str(&file))
            .with("fingerprint", key.fingerprint()))
    })();

    lock_key(&mut loaded.key);
    outcome
}

pub fn run_backup(args: &BackupArgs) -> CliOutcome<CliResult> {
    let loaded = load_key_file(&args.key)?;
    let key = &loaded.key;

    let (mnemonic, _) = read_mnemonic_input(args.mnemonic_file.as_deref())?;

    if !mnemonic_belongs_to(key, &mnemonic)? {
        return Err(CliError::new(
            "That recovery phrase does not belong to this key.",
        ));
    }

    let backup = MajikKeyBackup::create(CreateBackupParams {
        seed: BackupSeed::Phrase(mnemonic.to_string()),
        id: key.backup().to_string(),
        language: key.mnemonic_language(),
        phrase: None,
    })?;

    let data: Vec<u8> = match args.format.as_str() {
        "json" => {
            let mut text = serde_json::to_string_pretty(&backup.to_json())?;
            text.push('\n');
            text.into_bytes()
        }
        "zip" => backup.to_zip(None, &ToZipOptions::default())?,
        other => {
            return Err(CliError::usage(format!(
                "Unsupported backup format \"{other}\" (use json or zip)."
            )))
        }
    };

    let stem = ["majik-key"]
        .into_iter()
        .map(str::to_string)
        .chain(
            Some(key.label())
                .filter(|l| !l.is_empty())
                .map(|l| slugify(l, 40)),
        )
        .chain(Some(short_fingerprint(key.fingerprint(), 8)))
        .chain(Some("backup".to_string()))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    let ext = format!(".{}", args.format);
    let file = resolve_output_path(args.write.output.as_deref(), &format!("{stem}{ext}"), &ext);
    write_secure_file(&file, &data, args.write.overwrite)?;

    Ok(CliResult::ok(
        "backup",
        format!("Mnemonic backup written as {}.", args.format.to_uppercase()),
    )
    .with("file", path_str(&file))
    .with("fingerprint", key.fingerprint())
    .with(
        "warning",
        "This backup contains your recovery phrase. Store it offline and keep it private.",
    ))
}
