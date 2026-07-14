use crate::error::MajikKeyResult;
use bip39::Language;

/// Mirrors `MnemonicLanguage` from wordlist.ts. Unlike the TS version,
/// there's no lazy `import()` per language here — `bip39`'s wordlists are
/// compiled in as static tables, so there's no async loader step at all;
/// this becomes a simple, synchronous enum-to-`bip39::Language` mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MnemonicLanguage {
    #[default]
    En,
    Fr,
    Es,
    It,
    Ja,
    Ko,
    Czech,
    Pt,
    #[serde(rename = "zh-cn")]
    ZhCn,
    #[serde(rename = "zh-tw")]
    ZhTw,
}

impl MnemonicLanguage {
    pub fn to_bip39(self) -> MajikKeyResult<Language> {
        Ok(match self {
            MnemonicLanguage::En => Language::English,
            MnemonicLanguage::Fr => Language::French,
            MnemonicLanguage::Es => Language::Spanish,
            MnemonicLanguage::It => Language::Italian,
            MnemonicLanguage::Ja => Language::Japanese,
            MnemonicLanguage::Ko => Language::Korean,
            MnemonicLanguage::Czech => Language::Czech,
            MnemonicLanguage::Pt => Language::Portuguese,
            MnemonicLanguage::ZhCn => Language::SimplifiedChinese,
            MnemonicLanguage::ZhTw => Language::TraditionalChinese,
        })
    }
}
