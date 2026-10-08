//! Port of `core/backup/utils.ts`.
//!
//! The lazy `import("jszip")` / `import("@majikah/majik-bytes")` loaders disappear:
//! `zip` is a normal dependency, and the MajikByte PNG container — which has no Rust
//! implementation yet — is abstracted behind [`PngCodec`] so you can plug one in.

use crate::core::backup::error::BackupResult;
use crate::core::utils::format_iso8601;

/// The MajikByte PNG container (`@majikah/majik-bytes`). The payload is the
/// base64 string of the backup JSON — exactly what TS passes to `MajikBytes.create()`.
pub trait PngCodec {
    /// `true` if `png` is a recognized MajikByte PNG.
    fn is_valid_png(&self, png: &[u8]) -> bool;
    /// Embed `base64_payload` in a PNG.
    fn encode(&self, base64_payload: &str) -> BackupResult<Vec<u8>>;
    /// Extract the base64 payload from a PNG.
    fn decode(&self, png: &[u8]) -> BackupResult<String>;
}

// ── Binary sniffing — classify by magic bytes, never by file extension ──

const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

pub fn looks_like_png(bytes: &[u8]) -> bool {
    bytes.len() >= PNG_MAGIC.len() && bytes[..PNG_MAGIC.len()] == PNG_MAGIC
}

/// Zip local-file-header signature (`"PK\x03\x04"`); also covers empty/spanned variants starting `"PK"`.
pub fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.len() > 2 && bytes[0] == 0x50 && bytes[1] == 0x4b
}

/// Strip characters that are illegal in file names on common platforms.
pub fn to_safe_file_name(value: &str) -> String {
    let replaced: String = value
        .chars()
        .map(|c| {
            if "<>:\"/\\|?*".contains(c) || (c as u32) < 0x20 {
                '-'
            } else {
                c
            }
        })
        .collect();
    let collapsed = replaced.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .trim_end_matches(|c| c == '.' || c == ' ')
        .to_string()
}

/// Static body of the backup README — update copy here, every zip picks it up.
pub const README_TEXT: &str = "Majik Key Backup\r\n\r\nIMPORTANT: Keep this file secure and private at all times. If lost or compromised, your account access may be permanently at risk.\r\n\r\nOverview\r\nThis backup ZIP file contains your raw JSON data and a Backup PNG. These files are essential for recovering your account.\r\n\r\nUsage Instructions\r\n- Storage: You may delete the JSON file and keep only the PNG file if preferred.\r\n- Customization: You can rename the PNG file for added discretion.\r\n- Recovery: This PNG allows you to securely re-import your account without exposing raw JSON data.\r\n\r\nCritical Handling Requirements\r\nTo prevent data corruption and ensure the backup remains functional, please follow these rules:\r\n\r\n- No Modifications: Do not edit, crop, or apply filters to the PNG image.\r\n- No Processing: Avoid running the image through compression tools or \"optimization\" software.\r\n- Storage Only: Store the image as is. Do not upload it to social media, messaging apps, or cloud platforms that automatically compress or manipulate images, as this will destroy the embedded data.\r\n\r\nIMPORTANT: Keep this file secure and private at all times. If lost or compromised, your account access may be permanently at risk.";

/// `README_TEXT` plus a creation timestamp line — the only per-backup variable part.
pub fn build_readme_text(created_at: jiff::Timestamp) -> String {
    format!(
        "{README_TEXT}\n\nBackup created on: {}\n",
        format_iso8601(created_at)
    )
}
