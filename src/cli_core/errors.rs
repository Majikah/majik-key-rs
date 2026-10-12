//! Error type for the CLI. Operations return `Err(CliError)`; the command wrapper in
//! `cli.rs` is the only place that turns one into output + an exit code.
//!
//! Exit codes:
//!   0   success
//!   1   operation failed (wrong passphrase, bad file, ...)
//!   2   usage error (bad flag combination, invalid value) — also what clap uses
//!   130 cancelled by the user (Ctrl-C at a prompt)

use std::fmt;

use crate::{MajikKeyBackupError, MajikKeyError};

pub type CliOutcome<T> = Result<T, CliError>;

#[derive(Debug)]
pub struct CliError {
    pub message: String,
    pub exit_code: u8,
}

impl CliError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    pub fn cancelled() -> Self {
        Self {
            message: "Operation cancelled.".into(),
            exit_code: 130,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<MajikKeyError> for CliError {
    fn from(e: MajikKeyError) -> Self {
        Self::new(e.to_string())
    }
}

impl From<MajikKeyBackupError> for CliError {
    fn from(e: MajikKeyBackupError) -> Self {
        Self::new(e.to_string())
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::new(e.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(format!("JSON error: {e}"))
    }
}
