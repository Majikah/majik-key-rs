//! Filesystem + stdin helpers.
//!
//! Every file this CLI writes can contain key material, so writes are created with
//! owner-only permissions (0600 on Unix) and never replace an existing file unless the
//! caller explicitly opts in.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use super::errors::{CliError, CliOutcome};

pub fn resolve_cli_path(path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

pub fn read_bytes(path: &Path) -> CliOutcome<Vec<u8>> {
    fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CliError::new(format!(
                "Cannot read \"{}\": file not found",
                path.display()
            ))
        } else {
            CliError::new(format!("Cannot read \"{}\": {e}", path.display()))
        }
    })
}

pub fn read_text(path: &Path) -> CliOutcome<String> {
    let bytes = read_bytes(path)?;
    String::from_utf8(bytes)
        .map_err(|_| CliError::new(format!("\"{}\" is not valid UTF-8 text", path.display())))
}

pub fn read_json(path: &Path) -> CliOutcome<serde_json::Value> {
    let text = read_text(path)?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::new(format!("Invalid JSON in \"{}\": {e}", path.display())))
}

/// Write a file with owner-only permissions.
///
/// * `overwrite == false` uses exclusive creation, so an existing file is never touched
///   (and there is no check-then-write race).
/// * `overwrite == true` writes a sibling temp file and renames it into place, so a crash
///   mid-write cannot leave a truncated key file behind.
pub fn write_secure_file(path: &Path, data: &[u8], overwrite: bool) -> CliOutcome<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    if !overwrite {
        let mut file = match secure_options().create_new(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(CliError::new(format!(
                    "Output already exists: \"{}\". Use --overwrite to replace it.",
                    path.display()
                )))
            }
            Err(e) => return Err(e.into()),
        };
        file.write_all(data)?;
        file.flush()?;
        return Ok(());
    }

    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(".{}.tmp", std::process::id()));
    let temp = PathBuf::from(temp);

    let result = (|| -> CliOutcome<()> {
        let mut file = secure_options().create(true).truncate(true).open(&temp)?;
        file.write_all(data)?;
        file.flush()?;
        drop(file);
        fs::rename(&temp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn secure_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

pub fn write_json_secure(
    path: &Path,
    value: &serde_json::Value,
    overwrite: bool,
) -> CliOutcome<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    write_secure_file(path, text.as_bytes(), overwrite)
}

/// Turn `--output` into a concrete file path.
///
/// - not provided                    → `<cwd>/<default_name>`
/// - existing directory, or ends "/" → `<that dir>/<default_name>`
/// - anything else                   → treated as a file path
///   (`default_ext` appended if it has no extension)
pub fn resolve_output_path(output: Option<&str>, default_name: &str, default_ext: &str) -> PathBuf {
    let Some(output) = output else {
        return resolve_cli_path(default_name);
    };

    let resolved = resolve_cli_path(output);
    let ends_with_separator = output.ends_with('/') || output.ends_with(std::path::MAIN_SEPARATOR);

    if ends_with_separator || resolved.is_dir() {
        return resolved.join(default_name);
    }

    if resolved.extension().is_none() {
        let mut with_ext = resolved.into_os_string();
        with_ext.push(default_ext);
        return PathBuf::from(with_ext);
    }

    resolved
}

/// Filesystem-safe fragment: letters, digits, dash, underscore.
pub fn slugify(value: &str, max: usize) -> String {
    let mut out = String::new();
    let mut last_dash = true;

    for c in value.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }

    out.trim_matches('-').chars().take(max).collect()
}

/// Short filename-safe piece of a base64 fingerprint.
pub fn short_fingerprint(fingerprint: &str, length: usize) -> String {
    fingerprint
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(length)
        .collect()
}

/// First line of stdin, without the line terminator. Used by `--passphrase-stdin`.
pub fn read_stdin_line() -> CliOutcome<String> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}
