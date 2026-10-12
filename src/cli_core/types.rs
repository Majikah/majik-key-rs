//! CLI intent types — the clap argument structs. `cli.rs` parses argv into these and the
//! operation layer turns them into `MajikKey` calls. Mirrors `types.ts`.

use clap::builder::PossibleValuesParser;
use clap::Args;

use crate::MnemonicLanguage;

/// Allowed `--language` values, straight from the library's own list.
pub fn language_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(MnemonicLanguage::ALL.map(|l| l.as_str()))
}

/// Where a secret (passphrase) may come from besides the interactive prompt.
#[derive(Args, Debug, Clone, Default)]
pub struct PassphraseSourceArgs {
    /// Read the passphrase from the first line of stdin.
    #[arg(long)]
    pub passphrase_stdin: bool,
}

/// Shared by every command that writes a file.
#[derive(Args, Debug, Clone, Default)]
pub struct WriteArgs {
    /// Output file, or directory. Defaults to the current directory (or the key file itself
    /// for commands that edit a key).
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<String>,

    /// Replace the output file if it already exists.
    #[arg(long)]
    pub overwrite: bool,
}

/// Shared by commands that can emit a Majik Key JSON file.
#[derive(Args, Debug, Clone, Default)]
pub struct SaveFormatArgs {
    /// Save RAW, UNENCRYPTED private keys instead of passphrase-encrypted JSON.
    #[arg(long)]
    pub dangerous: bool,

    /// Required with --dangerous. Acknowledges that the file grants full control of the key.
    #[arg(long)]
    pub i_understand_the_risk: bool,

    /// Skip the typed confirmation for --dangerous (needed when non-interactive).
    #[arg(long)]
    pub yes: bool,

    /// Omit the legacy pre-registry fields from the JSON (not readable by older library versions).
    #[arg(long)]
    pub registry_only: bool,
}

/// Shared by generate / create / import.
#[derive(Args, Debug, Clone, Default)]
pub struct NewKeyArgs {
    #[command(flatten)]
    pub passphrase: PassphraseSourceArgs,

    #[command(flatten)]
    pub write: WriteArgs,

    #[command(flatten)]
    pub format: SaveFormatArgs,

    /// Human-readable name for the key.
    #[arg(short, long)]
    pub label: Option<String>,

    /// Extra keypairs on top of the core four, comma-separated. Short names work:
    /// btc,eth,sol,ml-kem-1024.
    #[arg(short = 'k', long, value_delimiter = ',', action = clap::ArgAction::Append, value_name = "IDS")]
    pub keys: Vec<String>,

    /// Also save the recovery phrase as PLAINTEXT JSON (default: next to the key file).
    #[arg(long, num_args = 0..=1, value_name = "PATH")]
    pub mnemonic_out: Option<Option<String>>,
}

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    #[command(flatten)]
    pub new_key: NewKeyArgs,

    /// Recovery phrase length in words.
    #[arg(short, long, value_parser = ["12", "24"], default_value = "24", value_name = "WORDS")]
    pub size: String,

    /// BIP-39 wordlist language.
    #[arg(long, value_parser = language_parser(), default_value = "en", value_name = "CODE")]
    pub language: String,

    /// Don't ask you to type back words from the phrase.
    #[arg(long)]
    pub skip_confirm: bool,
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    #[command(flatten)]
    pub new_key: NewKeyArgs,

    /// BIP-39 wordlist language.
    #[arg(long, value_parser = language_parser(), value_name = "CODE")]
    pub language: Option<String>,

    /// Read the phrase from a text file or MnemonicJSON file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub mnemonic_file: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ImportArgs {
    /// Mnemonic backup: .json or .zip.
    pub backup: String,

    #[command(flatten)]
    pub new_key: NewKeyArgs,

    /// Override the wordlist language stored in the backup.
    #[arg(long, value_parser = language_parser(), value_name = "CODE")]
    pub language: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct InfoArgs {
    /// Key file (normal or dangerous JSON).
    pub key: String,
}

#[derive(Args, Debug, Clone)]
pub struct KeysArgs {
    /// Key file. Not needed with --supported.
    pub key: Option<String>,

    /// List every algorithm this version can enable.
    #[arg(long)]
    pub supported: bool,

    /// Print full public keys instead of shortened ones.
    #[arg(long)]
    pub full: bool,
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    pub key: String,

    #[command(flatten)]
    pub passphrase: PassphraseSourceArgs,
}

#[derive(Args, Debug, Clone)]
pub struct LabelArgs {
    pub key: String,

    /// New label. Omit to just show the current one.
    pub label: Option<String>,

    #[command(flatten)]
    pub write: WriteArgs,
}

#[derive(Args, Debug, Clone)]
pub struct PassphraseArgs {
    pub key: String,

    #[command(flatten)]
    pub write: WriteArgs,
}

#[derive(Args, Debug, Clone)]
pub struct MigrateArgs {
    pub key: String,

    #[command(flatten)]
    pub write: WriteArgs,

    #[command(flatten)]
    pub passphrase: PassphraseSourceArgs,
}

#[derive(Args, Debug, Clone)]
pub struct AddKeysArgs {
    pub key: String,

    /// Extra keypairs to add, comma-separated. Short names work: btc,eth,sol,ml-kem-1024.
    #[arg(short = 'k', long, required = true, value_delimiter = ',', action = clap::ArgAction::Append, value_name = "IDS")]
    pub keys: Vec<String>,

    /// Read the phrase from a text file or MnemonicJSON file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub mnemonic_file: Option<String>,

    #[command(flatten)]
    pub write: WriteArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ExportArgs {
    pub key: String,

    /// Export the PUBLIC contact JSON (safe to share) instead of the key file.
    #[arg(long)]
    pub contact: bool,

    /// Print to stdout instead of writing a file.
    #[arg(long)]
    pub stdout: bool,

    #[command(flatten)]
    pub write: WriteArgs,

    #[command(flatten)]
    pub passphrase: PassphraseSourceArgs,

    #[command(flatten)]
    pub format: SaveFormatArgs,
}

#[derive(Args, Debug, Clone)]
pub struct BackupArgs {
    pub key: String,

    /// Backup file format. (PNG needs a MajikByte codec, which has no Rust port yet.)
    #[arg(short, long, value_parser = ["json", "zip"], default_value = "json")]
    pub format: String,

    /// Read the phrase from a text file or MnemonicJSON file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub mnemonic_file: Option<String>,

    #[command(flatten)]
    pub write: WriteArgs,
}
