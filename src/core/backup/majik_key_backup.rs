//! Port of `core/backup/majik-key-backup.ts`.
//!
//! A validated Majik Key backup payload, and the single place that knows how to
//! read/write it as JSON, a MajikByte PNG, or a `.zip` archive containing both
//! plus a README. Every construction path funnels through the same shape
//! validator, so there is exactly one definition of "valid backup".

use std::io::{Cursor, Read, Write};

use serde_json::Value;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::core::backup::error::{BackupResult, MajikKeyBackupError as E};
use crate::core::backup::types::{BackupSeed, CreateBackupParams, ToZipOptions, BACKUP_FORMAT_VERSION};
use crate::core::backup::utils::{build_readme_text, looks_like_png, to_safe_file_name, PngCodec};
use crate::core::backup::validator::validate_mnemonic_json_shape;
use crate::core::crypto::wordlist::MnemonicLanguage;
use crate::core::types::MnemonicJson;
use crate::core::utils::{base64_to_utf8, format_iso8601, utf8_to_base64};

const BACKUP_JSON_FILENAME: &str = "backup.json";
const BACKUP_PNG_FILENAME: &str = "backup.png";
const README_FILENAME: &str = "IMPORTANT README.txt";

#[derive(Debug, Clone)]
pub struct MajikKeyBackup {
    data: MnemonicJson,
}

impl MajikKeyBackup {
    // ── Static constructors ──

    /// Builds a fresh backup from a newly generated seed. Pure — no I/O.
    pub fn create(params: CreateBackupParams) -> BackupResult<Self> {
        let seed = match params.seed {
            BackupSeed::Words(w) => w,
            BackupSeed::Phrase(p) => p.split_whitespace().map(str::to_string).collect(),
        };
        let json = MnemonicJson {
            id: params.id,
            seed,
            language: Some(params.language),
            phrase: params.phrase,
            version: Some(BACKUP_FORMAT_VERSION),
        };
        validate_mnemonic_json_shape(&serde_json::to_value(&json).expect("serializable"))?;
        Ok(Self { data: json })
    }

    /// Validates and wraps an already-parsed JSON payload.
    pub fn from_json(input: &Value) -> BackupResult<Self> {
        Ok(Self { data: validate_mnemonic_json_shape(input)? })
    }

    pub fn from_json_str(input: &str) -> BackupResult<Self> {
        let v: Value = serde_json::from_str(input).map_err(|e| E::InvalidBackupJson(e.to_string()))?;
        Self::from_json(&v)
    }

    /// Decodes a MajikByte PNG backup and validates the embedded payload.
    pub fn from_png(png: &[u8], codec: &dyn PngCodec) -> BackupResult<Self> {
        if !codec.is_valid_png(png) {
            return Err(E::InvalidBackupPng("not a recognized MajikByte PNG".into()));
        }
        let decoded: Value = codec
            .decode(png)
            .and_then(|b64| {
                let text = base64_to_utf8(&b64).map_err(|e| E::InvalidBackupPng(e.to_string()))?;
                serde_json::from_str(&text).map_err(|e| E::InvalidBackupPng(e.to_string()))
            })
            .map_err(|e| E::InvalidBackupPng(format!("could not decode embedded payload ({e})")))?;
        Ok(Self { data: validate_mnemonic_json_shape(&decoded)? })
    }

    /// Parses a `.zip` backup archive. Classification is by magic bytes, not
    /// filename, so a renamed or oddly-cased file is still found.
    ///
    /// PNG wins when both a valid PNG and a valid JSON backup are present. If both
    /// are present but describe different accounts that's surfaced as
    /// [`E::BackupIntegrityMismatch`], not silently resolved. `codec` is only
    /// needed to read PNG entries; without one they are skipped (JSON still works).
    pub fn from_zip(bytes: &[u8], codec: Option<&dyn PngCodec>) -> BackupResult<Self> {
        let mut archive = ZipArchive::new(Cursor::new(bytes))
            .map_err(|e| E::InvalidBackupZip(format!("could not open archive ({e})")))?;

        let mut png_result: Option<MajikKeyBackup> = None;
        let mut png_error: Option<String> = None;
        let mut json_result: Option<MajikKeyBackup> = None;

        for i in 0..archive.len() {
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if entry.is_dir() {
                continue;
            }
            let mut data = Vec::new();
            if entry.read_to_end(&mut data).is_err() {
                continue;
            }

            if png_result.is_none() && looks_like_png(&data) {
                let r = match codec {
                    Some(c) => Self::from_png(&data, c),
                    None => Err(E::MissingOptionalDependency {
                        pkg: "a PngCodec (MajikByte)".into(),
                        feature: "read PNG backups".into(),
                    }),
                };
                match r {
                    Ok(b) => png_result = Some(b),
                    Err(e) => png_error = png_error.or(Some(e.to_string())),
                }
                continue;
            }

            if json_result.is_none() {
                // Not every non-PNG entry is the backup JSON (e.g. the README) — skip silently.
                if let Ok(text) = std::str::from_utf8(&data) {
                    if let Ok(b) = Self::from_json_str(text) {
                        json_result = Some(b);
                    }
                }
            }
        }

        if let (Some(p), Some(j)) = (&png_result, &json_result) {
            if p.id() != j.id() || p.seed() != j.seed() {
                return Err(E::BackupIntegrityMismatch(
                    "the PNG and JSON backups inside this archive do not describe the same account".into(),
                ));
            }
        }
        if let Some(p) = png_result {
            return Ok(p);
        }
        if let Some(j) = json_result {
            return Ok(j);
        }
        Err(E::InvalidBackupZip(match png_error {
            Some(e) => format!("a PNG-shaped file was found but is invalid ({e})"),
            None => "no valid backup.png or backup.json found inside the archive".into(),
        }))
    }

    // ── Instance accessors ──

    pub fn to_json(&self) -> MnemonicJson {
        self.data.clone()
    }
    pub fn id(&self) -> &str {
        &self.data.id
    }
    pub fn seed(&self) -> Vec<String> {
        self.data.seed.clone()
    }
    pub fn seed_phrase(&self) -> String {
        self.data.seed.join(" ")
    }
    pub fn language(&self) -> Option<MnemonicLanguage> {
        self.data.language
    }
    pub fn format_version(&self) -> Option<u32> {
        self.data.version
    }

    // ── Instance serializers ──

    pub fn to_png(&self, codec: &dyn PngCodec) -> BackupResult<Vec<u8>> {
        codec.encode(&utf8_to_base64(&self.json_string()))
    }

    /// Zip with `backup.json` + README, plus `backup.png` when a `codec` is supplied.
    pub fn to_zip(&self, codec: Option<&dyn PngCodec>, _opts: &ToZipOptions) -> BackupResult<Vec<u8>> {
        let zerr = |e: &dyn std::fmt::Display| E::InvalidBackupZip(e.to_string());
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .compression_level(Some(9));
            zip.start_file(BACKUP_JSON_FILENAME, opts).map_err(|e| zerr(&e))?;
            zip.write_all(self.json_string().as_bytes()).map_err(|e| zerr(&e))?;
            if let Some(c) = codec {
                let png = self.to_png(c)?;
                zip.start_file(BACKUP_PNG_FILENAME, opts).map_err(|e| zerr(&e))?;
                zip.write_all(&png).map_err(|e| zerr(&e))?;
            }
            zip.start_file(README_FILENAME, opts).map_err(|e| zerr(&e))?;
            zip.write_all(build_readme_text(jiff::Timestamp::now()).as_bytes()).map_err(|e| zerr(&e))?;
            zip.finish().map_err(|e| zerr(&e))?;
        }
        Ok(buf.into_inner())
    }

    /// Convenience for a native `save()` dialog default path.
    pub fn suggested_file_name(&self, label: Option<&str>) -> String {
        to_safe_file_name(&format!(
            "{} - {} - SEED KEY - {}",
            label.unwrap_or("Majik Key"),
            self.data.id,
            format_iso8601(jiff::Timestamp::now())
        ))
    }

    fn json_string(&self) -> String {
        serde_json::to_string(&self.data).expect("MnemonicJson serializes")
    }
}
