//! Human-readable and machine-readable result presentation.
//! Results go to stdout by default; `--stdout` exports route them to stderr so the exported
//! data is the only thing on stdout.

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::Value;

/// A command result. Fields keep insertion order (human output and `--json` both read well).
#[derive(Debug, Clone)]
pub struct CliResult {
    pub ok: bool,
    pub command: &'static str,
    pub message: String,
    pub fields: Vec<(&'static str, Value)>,
}

impl CliResult {
    pub fn ok(command: &'static str, message: impl Into<String>) -> Self {
        Self {
            ok: true,
            command,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    pub fn failed(command: &'static str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            command,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    /// Add a field. `None`/`null` values are dropped so they never clutter output.
    pub fn with(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        let value = value.into();
        if !value.is_null() {
            self.fields.push((key, value));
        }
        self
    }

    pub fn with_opt<T: Into<Value>>(self, key: &'static str, value: Option<T>) -> Self {
        match value {
            Some(v) => self.with(key, v),
            None => self,
        }
    }
}

impl Serialize for CliResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3 + self.fields.len()))?;
        map.serialize_entry("ok", &self.ok)?;
        map.serialize_entry("command", self.command)?;
        map.serialize_entry("message", &self.message)?;
        for (key, value) in &self.fields {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Broken pipes (`majik-key keys | head`) must not panic, so write errors are ignored.
fn write(stream: Stream, line: &str) {
    use std::io::Write;
    let _ = match stream {
        Stream::Stdout => writeln!(std::io::stdout(), "{line}"),
        Stream::Stderr => writeln!(std::io::stderr(), "{line}"),
    };
}

/// `mnemonicLanguage` → `Mnemonic Language`.
fn human_label(key: &str) -> String {
    let mut out = String::new();
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else {
            if c.is_uppercase() {
                out.push(' ');
            }
            out.push(c);
        }
    }
    out
}

fn as_key_rows(value: &Value) -> Option<Vec<&serde_json::Map<String, Value>>> {
    let array = value.as_array()?;
    if array.is_empty() {
        return None;
    }
    array
        .iter()
        .map(|item| {
            item.as_object()
                .filter(|o| o.get("id").is_some_and(Value::is_string))
        })
        .collect()
}

fn print_key_table(stream: Stream, rows: &[&serde_json::Map<String, Value>]) {
    let all: [(&str, &str); 6] = [
        ("ID", "id"),
        ("Purpose", "purpose"),
        ("Kind", "kind"),
        ("Status", "status"),
        ("Standard", "standard"),
        ("Public key", "publicKey"),
    ];

    let cell = |row: &serde_json::Map<String, Value>, key: &str| -> String {
        row.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    let columns: Vec<&(&str, &str)> = all
        .iter()
        .filter(|(_, key)| rows.iter().any(|row| !cell(row, key).is_empty()))
        .collect();

    let widths: Vec<usize> = columns
        .iter()
        .map(|(title, key)| {
            rows.iter()
                .map(|row| cell(row, key).chars().count())
                .max()
                .unwrap_or(0)
                .max(title.chars().count())
        })
        .collect();

    let line = |cells: Vec<String>| {
        let joined = cells
            .iter()
            .zip(&widths)
            .map(|(text, width)| format!("{text:<width$}", width = *width))
            .collect::<Vec<_>>()
            .join("  ");
        format!("  {}", joined.trim_end())
    };

    write(
        stream,
        &line(columns.iter().map(|(t, _)| t.to_string()).collect()),
    );
    write(
        stream,
        &line(widths.iter().map(|w| "─".repeat(*w)).collect()),
    );

    for row in rows {
        write(
            stream,
            &line(columns.iter().map(|(_, k)| cell(row, k)).collect()),
        );
    }
}

fn print_field(stream: Stream, label: &str, value: &Value) {
    let prefix = format!("{:<20} ", human_label(label));

    match value {
        Value::Null => {}
        Value::String(s) if s.is_empty() => {}
        Value::Array(items) if items.is_empty() => {}
        Value::Array(items) if items.iter().all(Value::is_string) => {
            let joined = items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            write(stream, &format!("{prefix}{joined}"));
        }
        Value::Array(_) => {
            if let Some(rows) = as_key_rows(value) {
                write(stream, &human_label(label));
                print_key_table(stream, &rows);
            } else {
                write(stream, &format!("{prefix}{value}"));
            }
        }
        Value::String(s) => write(stream, &format!("{prefix}{s}")),
        Value::Object(_) => write(stream, &format!("{prefix}{value}")),
        other => write(stream, &format!("{prefix}{other}")),
    }
}

pub fn print_result(result: &CliResult, stream: Stream) {
    if !result.ok {
        eprintln!("✘ {}", result.message);
        return;
    }

    write(stream, &format!("→ {}", result.message));
    for (key, value) in &result.fields {
        print_field(stream, key, value);
    }
}

pub fn print_json_result(result: &CliResult) {
    write(
        Stream::Stdout,
        &serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into()),
    );
}

pub fn print_failure(message: &str, json: bool) {
    if json {
        print_json_result(&CliResult::failed("error", message));
    } else {
        eprintln!("✘ {message}");
    }
}

/// Print a boxed warning to stderr.
pub fn print_warning(lines: &[&str]) {
    let width = (lines.iter().map(|l| l.chars().count()).max().unwrap_or(0) + 4).min(78);
    let bar = "═".repeat(width);

    eprintln!("\n{bar}");
    for line in lines {
        eprintln!("  {line}");
    }
    eprintln!("{bar}\n");
}

pub fn print_mnemonic(words: &[&str]) {
    let columns = if words.len() > 12 { 3 } else { 2 };
    let rows = words.len().div_ceil(columns);

    print_warning(&[
        "WRITE THIS RECOVERY PHRASE DOWN. It is shown ONCE.",
        "It is the only way to recover this key if the file or passphrase is lost.",
        "Anyone who has it controls this key. Never store it online.",
    ]);

    for row in 0..rows {
        let mut line = String::from("  ");
        for col in 0..columns {
            let index = row + col * rows;
            if let Some(word) = words.get(index) {
                line.push_str(&format!("{:<24}", format!("{:>2}. {word}", index + 1)));
            }
        }
        eprintln!("{}", line.trim_end());
    }
    eprintln!();
}
