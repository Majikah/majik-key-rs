//! Majik Key CLI — create, inspect, edit, export and back up Majik Keys.
//!
//! ```text
//! cargo install majik-key --features cli
//! majik-key --help
//! majik-key generate
//! ```
//!
//! This file is the Rust counterpart of the TypeScript package's `src/cli.ts`: it owns the
//! command tree and the "run one command, print the result, set the exit code" wrapper.
//! Everything else lives in [`crate::cli_core`]. Also usable as a library entry point:
//! [`run`] takes explicit arguments so tests can drive the real parser without a process.

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::cli_core::operations;
use crate::cli_core::output::{print_failure, print_json_result, print_result, CliResult, Stream};
use crate::cli_core::types::*;
use crate::cli_core::CliOutcome;

const AFTER_HELP: &str = "\
Quick start:
  majik-key generate                      new 24-word key, saved to the current directory
  majik-key generate --size 12            12-word recovery phrase instead
  majik-key info ./majik-key-*.json       inspect a key file (no passphrase needed)

Passphrases are never taken as arguments (they would end up in shell history).
They come from, in order: --passphrase-stdin, an environment variable, or a
hidden prompt:
  MAJIK_KEY_PASSPHRASE       passphrase for the key (new or existing)
  MAJIK_KEY_NEW_PASSPHRASE   new passphrase for `passphrase`
  MAJIK_KEY_MNEMONIC         recovery phrase for `create`, `add-keys`, `backup`

Exit codes: 0 ok · 1 operation failed · 2 usage error · 130 cancelled.";

#[derive(Parser, Debug)]
#[command(
    name = "majik-key",
    version,
    about = "Majik Key CLI — create, inspect, edit, export and back up post-quantum-ready Majik Keys.",
    after_help = AFTER_HELP,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a brand-new recovery phrase and key, then save the key file.
    #[command(
        visible_alias = "new",
        after_help = "\
The recovery phrase is shown ONCE on stderr. On a terminal you must type back
three random words to prove you wrote it down. The key file is saved as
majik-key-<label>-<fingerprint>.json in the current directory unless -o is given.

Examples:
  majik-key generate
  majik-key generate --size 12 --label alice
  majik-key generate -o ~/keys/ --keys btc,eth
  majik-key generate --dangerous --i-understand-the-risk"
    )]
    Generate(GenerateArgs),

    /// Create a key from a recovery phrase you already have.
    Create(CreateArgs),

    /// Restore a key from a mnemonic backup (.json or .zip) under a new passphrase.
    Import(ImportArgs),

    /// Show a key's non-secret details. No passphrase needed.
    Info(InfoArgs),

    /// List the keypairs on an account, or every algorithm that can be enabled.
    Keys(KeysArgs),

    /// Check a passphrase against a key file. Exit code 1 if wrong.
    Verify(VerifyArgs),

    /// Show or change a key's label. Edits the file in place unless -o is given.
    Label(LabelArgs),

    /// Change a key's passphrase. Re-encrypts every key; edits the file in place unless -o is given.
    #[command(
        after_help = "Non-interactive: set MAJIK_KEY_PASSPHRASE (current) and MAJIK_KEY_NEW_PASSPHRASE (new)."
    )]
    Passphrase(PassphraseArgs),

    /// Upgrade a legacy PBKDF2 key to Argon2id without changing its passphrase.
    Migrate(MigrateArgs),

    /// Add keypairs the account doesn't have yet. Needs the key's passphrase AND its recovery phrase.
    AddKeys(AddKeysArgs),

    /// Serialize a key: normal JSON, DANGEROUS plaintext JSON, or its public contact JSON.
    #[command(after_help = "\
Examples:
  majik-key export key.json --registry-only -o ./clean/
  majik-key export key.json --contact
  majik-key export key.json --dangerous --i-understand-the-risk
  majik-key export key.json --dangerous --i-understand-the-risk --yes --stdout | your-secrets-tool")]
    Export(ExportArgs),

    /// Write a recovery-phrase backup (json or zip) for a key. Needs the recovery phrase.
    Backup(BackupArgs),
}

/// Run one command: print its result, translate errors into exit codes.
/// `data_on_stdout` routes the human summary to stderr so exported data (or any other
/// payload written to stdout) stays clean.
fn exec(
    json: bool,
    data_on_stdout: bool,
    work: impl FnOnce() -> CliOutcome<CliResult>,
) -> ExitCode {
    match work() {
        Ok(result) => {
            if json {
                print_json_result(&result);
            } else {
                let stream = if data_on_stdout {
                    Stream::Stderr
                } else {
                    Stream::Stdout
                };
                print_result(&result, stream);
            }
            ExitCode::from(if result.ok { 0 } else { 1 })
        }
        Err(error) => {
            print_failure(&error.message, json);
            ExitCode::from(error.exit_code)
        }
    }
}

/// Parse `args` (including argv[0]) and run the matching command.
///
/// Clap usage errors (unknown option, invalid choice, missing argument) print their message
/// and exit `2`; `--help` / `--version` exit `0`.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };

    let json = cli.json;

    match &cli.command {
        Commands::Generate(a) => exec(json, false, || operations::run_generate(a)),
        Commands::Create(a) => exec(json, false, || operations::run_create(a)),
        Commands::Import(a) => exec(json, false, || operations::run_import(a)),
        Commands::Info(a) => exec(json, false, || operations::run_info(a)),
        Commands::Keys(a) => exec(json, false, || operations::run_keys(a, json)),
        Commands::Verify(a) => exec(json, false, || operations::run_verify(a)),
        Commands::Label(a) => exec(json, false, || operations::run_label(a)),
        Commands::Passphrase(a) => exec(json, false, || operations::run_passphrase(a)),
        Commands::Migrate(a) => exec(json, false, || operations::run_migrate(a)),
        Commands::AddKeys(a) => exec(json, false, || operations::run_add_keys(a)),
        Commands::Export(a) => exec(json, a.stdout, || operations::run_export(a, json)),
        Commands::Backup(a) => exec(json, false, || operations::run_backup(a)),
    }
}

/// Entry point used by `src/bin/majik-key.rs`.
pub fn main() -> ExitCode {
    run(std::env::args_os())
}
