//! cli_core — everything behind the `majik-key` command-line interface.
//!
//! Mirrors the TypeScript package's `src/cli-core/` folder one-to-one:
//!
//! | TypeScript          | Rust            |
//! |---------------------|-----------------|
//! | `errors.ts`         | [`errors`]      |
//! | `types.ts`          | [`types`]       |
//! | `io.ts`             | [`io`]          |
//! | `prompt.ts`         | [`prompt`]      |
//! | `key.ts`            | [`key`]         |
//! | `output.ts`         | [`output`]      |
//! | `operations.ts`     | [`operations`]  |
//!
//! Only compiled with the `cli` cargo feature.

pub mod errors;
pub mod io;
pub mod key;
pub mod operations;
pub mod output;
pub mod prompt;
pub mod types;

pub use errors::{CliError, CliOutcome};
pub use output::CliResult;
