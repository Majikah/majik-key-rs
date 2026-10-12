//! Interactive input for secrets. All prompts are written to STDERR so stdout stays clean
//! for `--json` and `--stdout` consumers.
//!
//! Passphrases are never accepted as command-line arguments (they would land in shell
//! history and the process list). Sources, in order:
//!
//!   1. `--passphrase-stdin`        first line of stdin
//!   2. `MAJIK_KEY_PASSPHRASE`      (`MAJIK_KEY_NEW_PASSPHRASE` for `passphrase`)
//!   3. hidden interactive prompt

use std::io::{IsTerminal, Write};

use zeroize::Zeroizing;

use super::errors::{CliError, CliOutcome};
use super::io::read_stdin_line;

pub const ENV_PASSPHRASE: &str = "MAJIK_KEY_PASSPHRASE";
pub const ENV_NEW_PASSPHRASE: &str = "MAJIK_KEY_NEW_PASSPHRASE";
pub const ENV_MNEMONIC: &str = "MAJIK_KEY_MNEMONIC";

pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// Read one line from the terminal without echoing it.
pub fn read_hidden(message: &str) -> CliOutcome<Zeroizing<String>> {
    if !is_interactive() {
        return Err(CliError::new(format!(
            "An interactive terminal is required for this prompt. \
             Use {ENV_PASSPHRASE} or --passphrase-stdin for non-interactive use."
        )));
    }

    let result = read_hidden_tty(message);
    // The user's Enter isn't echoed, so move to a fresh line ourselves.
    eprintln!();
    result
}

/// Unix: put the terminal into no-echo, non-canonical, signal-free mode BEFORE the prompt is
/// shown (so type-ahead is never echoed), read byte by byte, and restore the original modes
/// on every exit path. Ctrl-C arrives as a plain byte and becomes a clean "cancelled" error
/// instead of killing the process with the terminal still in no-echo mode.
#[cfg(unix)]
fn read_hidden_tty(message: &str) -> CliOutcome<Zeroizing<String>> {
    use std::io::Read;

    const FD: libc::c_int = 0; // stdin — is_interactive() already proved it is a terminal

    struct Restore(libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restoring the termios we captured from this same fd.
            unsafe { libc::tcsetattr(FD, libc::TCSADRAIN, &self.0) };
        }
    }

    // SAFETY: termios is plain-old-data; tcgetattr fully initialises it on success.
    let original = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(FD, &mut t) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        t
    };

    let mut raw = original;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;

    // SAFETY: `raw` is a valid termios derived from the one the OS gave us.
    if unsafe { libc::tcsetattr(FD, libc::TCSADRAIN, &raw) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _restore = Restore(original);

    eprint!("{message}");
    let _ = std::io::stderr().flush();

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut bytes: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        if input.read(&mut byte)? == 0 {
            break; // EOF
        }

        match byte[0] {
            b'\r' | b'\n' | 0x04 => break,
            0x03 => return Err(CliError::cancelled()),
            0x08 | 0x7f => {
                // Backspace: drop one whole UTF-8 character.
                while let Some(last) = bytes.pop() {
                    if last & 0xC0 != 0x80 {
                        break;
                    }
                }
            }
            0x1b => {
                // Swallow an escape sequence (arrow keys etc.): ESC [ ... <final byte>.
                if input.read(&mut byte)? == 1 && byte[0] == b'[' {
                    while input.read(&mut byte)? == 1 && !(0x40..=0x7e).contains(&byte[0]) {}
                }
            }
            b if b < 0x20 => {}
            b => bytes.push(b),
        }
    }

    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| CliError::new("Input was not valid UTF-8."))
}

/// Non-Unix fallback (untested in CI here): rpassword handles the console modes.
#[cfg(not(unix))]
fn read_hidden_tty(message: &str) -> CliOutcome<Zeroizing<String>> {
    eprint!("{message}");
    let _ = std::io::stderr().flush();

    match rpassword::read_password() {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(CliError::cancelled()),
        Err(e) => Err(e.into()),
    }
}

/// Read one visible line (confirmations, yes/no).
pub fn read_line(message: &str) -> CliOutcome<String> {
    if !is_interactive() {
        return Err(CliError::new(
            "An interactive terminal is required for this prompt.",
        ));
    }

    eprint!("{message}");
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn env_value(name: &str) -> Option<Zeroizing<String>> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map(Zeroizing::new)
}

#[derive(Clone, Copy)]
pub struct PassphraseSource {
    /// Honour `--passphrase-stdin`.
    pub stdin: bool,
    /// Environment variable to consult before prompting.
    pub env_var: &'static str,
}

impl PassphraseSource {
    pub fn env(env_var: &'static str) -> Self {
        Self {
            stdin: false,
            env_var,
        }
    }

    pub fn from_flag(stdin: bool) -> Self {
        Self {
            stdin,
            env_var: ENV_PASSPHRASE,
        }
    }
}

fn from_non_interactive_source(source: PassphraseSource) -> CliOutcome<Option<Zeroizing<String>>> {
    if source.stdin {
        let line = read_stdin_line()?;
        if line.is_empty() {
            return Err(CliError::usage(
                "--passphrase-stdin was given but stdin was empty.",
            ));
        }
        return Ok(Some(Zeroizing::new(line)));
    }
    Ok(env_value(source.env_var))
}

fn no_source_error(source: PassphraseSource) -> CliError {
    CliError::new(format!(
        "A passphrase is required, but stdin is not an interactive terminal. \
         Set {} or pass --passphrase-stdin.",
        source.env_var
    ))
}

/// Ask for an existing passphrase (single entry).
pub fn get_passphrase(source: PassphraseSource, message: &str) -> CliOutcome<Zeroizing<String>> {
    if let Some(fixed) = from_non_interactive_source(source)? {
        return Ok(fixed);
    }
    if !is_interactive() {
        return Err(no_source_error(source));
    }
    read_hidden(message)
}

/// Ask for a NEW passphrase, entered twice, with a weak-passphrase warning.
pub fn get_new_passphrase(
    source: PassphraseSource,
    message: &str,
) -> CliOutcome<Zeroizing<String>> {
    if let Some(fixed) = from_non_interactive_source(source)? {
        return Ok(fixed);
    }
    if !is_interactive() {
        return Err(no_source_error(source));
    }

    for _ in 0..3 {
        let first = read_hidden(message)?;

        if first.trim().is_empty() {
            eprintln!("Passphrase cannot be empty.");
            continue;
        }

        let second = read_hidden("Confirm passphrase: ")?;

        if *first != *second {
            eprintln!("Passphrases didn't match. Try again.");
            continue;
        }

        if first.chars().count() < 8 {
            eprintln!("Warning: that passphrase is short. Longer is much safer.");
        }

        return Ok(first);
    }

    Err(CliError::new("Too many failed attempts."))
}

/// Normalise a typed/pasted mnemonic: lowercase, single spaces.
pub fn normalize_mnemonic(raw: &str) -> String {
    raw.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn assert_mnemonic_shape(mnemonic: &str) -> CliOutcome<()> {
    let count = if mnemonic.is_empty() {
        0
    } else {
        mnemonic.split(' ').count()
    };

    if matches!(count, 12 | 15 | 18 | 21 | 24) {
        Ok(())
    } else {
        Err(CliError::new(format!(
            "Expected a 12, 15, 18, 21 or 24 word recovery phrase, got {count} word(s)."
        )))
    }
}

/// Mnemonic from the env var, otherwise a hidden prompt (never argv).
pub fn prompt_mnemonic(message: &str) -> CliOutcome<Zeroizing<String>> {
    let raw = match env_value(ENV_MNEMONIC) {
        Some(v) => v,
        None => read_hidden(message)?,
    };

    let mnemonic = Zeroizing::new(normalize_mnemonic(&raw));
    assert_mnemonic_shape(&mnemonic)?;
    Ok(mnemonic)
}
