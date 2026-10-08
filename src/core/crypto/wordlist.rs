//! Port of `core/crypto/wordlist.ts`.
//!
//! The TS lib lazy-imports `@scure/bip39` wordlists per language; here the
//! `bip39` crate bundles them behind cargo features (all enabled in Cargo.toml).

use serde::{Deserialize, Serialize};

use crate::core::error::{MajikKeyError, MajikKeyResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum MnemonicLanguage {
    #[default]
    #[serde(rename = "en")]
    En,
    #[serde(rename = "fr")]
    Fr,
    #[serde(rename = "es")]
    Es,
    #[serde(rename = "it")]
    It,
    #[serde(rename = "ja")]
    Ja,
    #[serde(rename = "ko")]
    Ko,
    #[serde(rename = "czech")]
    Czech,
    #[serde(rename = "pt")]
    Pt,
    #[serde(rename = "zh-cn")]
    ZhCn,
    #[serde(rename = "zh-tw")]
    ZhTw,
}

impl MnemonicLanguage {
    pub const ALL: [MnemonicLanguage; 10] = [
        Self::En,
        Self::Fr,
        Self::Es,
        Self::It,
        Self::Ja,
        Self::Ko,
        Self::Czech,
        Self::Pt,
        Self::ZhCn,
        Self::ZhTw,
    ];

    /// The string used in JSON (`"en"`, `"zh-cn"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Fr => "fr",
            Self::Es => "es",
            Self::It => "it",
            Self::Ja => "ja",
            Self::Ko => "ko",
            Self::Czech => "czech",
            Self::Pt => "pt",
            Self::ZhCn => "zh-cn",
            Self::ZhTw => "zh-tw",
        }
    }

    pub fn to_bip39(self) -> bip39::Language {
        match self {
            Self::En => bip39::Language::English,
            Self::Fr => bip39::Language::French,
            Self::Es => bip39::Language::Spanish,
            Self::It => bip39::Language::Italian,
            Self::Ja => bip39::Language::Japanese,
            Self::Ko => bip39::Language::Korean,
            Self::Czech => bip39::Language::Czech,
            Self::Pt => bip39::Language::Portuguese,
            Self::ZhCn => bip39::Language::SimplifiedChinese,
            Self::ZhTw => bip39::Language::TraditionalChinese,
        }
    }

    /// The 2048-word list (TS: `WORDLISTS[lang]()`).
    pub fn wordlist(self) -> &'static [&'static str; 2048] {
        self.to_bip39().word_list()
    }

    /// Separator `@scure/bip39` uses when *generating* a phrase: an ideographic
    /// space for Japanese, an ASCII space for everything else.
    pub(crate) fn word_separator(self) -> &'static str {
        if self == Self::Ja {
            "\u{3000}"
        } else {
            " "
        }
    }
}

impl std::str::FromStr for MnemonicLanguage {
    type Err = MajikKeyError;
    fn from_str(s: &str) -> MajikKeyResult<Self> {
        Self::ALL
            .into_iter()
            .find(|l| l.as_str() == s)
            .ok_or_else(|| MajikKeyError::msg(format!("Unsupported language: {s}")))
    }
}
