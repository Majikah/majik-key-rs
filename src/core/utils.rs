//! Utilities — port of `core/utils.ts`.
//!
//! The WebCrypto/`CryptoKey | { raw }` helpers (`keyToBase64`, `base64ToKey`)
//! have no Rust equivalent: every key here is plain bytes.

use base64::{
    alphabet,
    engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig},
    Engine as _,
};

use crate::core::error::MajikKeyResult;
use crate::core::types::MnemonicJson;

/// Standard-alphabet base64 that *writes* padded output and *reads* padded or
/// unpadded input — the same leniency as JS `atob()`.
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub fn array_to_base64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn array_buffer_to_base64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn base64_to_uint8array(base64: &str) -> MajikKeyResult<Vec<u8>> {
    Ok(B64.decode(base64.trim())?)
}

pub fn base64_to_array_buffer(base64: &str) -> MajikKeyResult<Vec<u8>> {
    base64_to_uint8array(base64)
}

pub fn base64_to_utf8(base64: &str) -> MajikKeyResult<String> {
    String::from_utf8(base64_to_uint8array(base64)?)
        .map_err(|_| crate::core::error::MajikKeyError::msg("Base64 payload is not valid UTF-8"))
}

pub fn utf8_to_base64(s: &str) -> String {
    B64.encode(s.as_bytes())
}

pub fn concat_uint8_arrays(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// Space-separated seed phrase → words, lower-cased, whitespace-trimmed.
pub fn seed_string_to_array(seed: &str) -> Vec<String> {
    seed.split_whitespace().map(|w| w.to_lowercase()).collect()
}

/// Words → single space-separated string.
pub fn seed_array_to_string(seed: &[String]) -> String {
    seed.join(" ")
}

/// Converts a seed phrase string into [`MnemonicJson`].
pub fn seed_to_json(seed: &str, id: &str, phrase: Option<&str>) -> MnemonicJson {
    MnemonicJson {
        seed: seed_string_to_array(seed),
        id: id.to_string(),
        phrase: phrase.map(str::to_string),
        language: None,
        version: None,
    }
}

/// [`MnemonicJson`] → single space-separated string.
pub fn json_to_seed(json: &MnemonicJson) -> String {
    seed_array_to_string(&json.seed)
}

/// `new Date().toISOString()` — UTC, millisecond precision, `Z` suffix.
pub fn now_iso8601() -> String {
    format_iso8601(jiff::Timestamp::now())
}

pub fn format_iso8601(ts: jiff::Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
