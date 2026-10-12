//! Integration tests for the `majik-key` binary. Run with:
//!
//!     cargo test --features cli --test cli
//!
//! They drive the real executable (not the library), so they cover argument parsing,
//! exit codes, file naming/permissions and the non-interactive secret sources. The
//! interactive prompts need a pseudo-terminal and are checked separately.

#![cfg(feature = "cli")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

const PASS: &str = "correct horse battery staple";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "majik-key-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Sandbox(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn str(&self, name: &str) -> String {
        self.path(name).display().to_string()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cmd(args: &[&str], envs: &[(&str, &str)]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_majik-key"));
    c.args(args)
        .env_remove("MAJIK_KEY_PASSPHRASE")
        .env_remove("MAJIK_KEY_NEW_PASSPHRASE")
        .env_remove("MAJIK_KEY_MNEMONIC")
        .envs(envs.iter().copied())
        .stdin(Stdio::null());
    c
}

fn run(args: &[&str], envs: &[(&str, &str)]) -> Output {
    cmd(args, envs).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// Generate a 12-word key into the sandbox; returns (key file, mnemonic file).
fn generate(sb: &Sandbox, name: &str) -> (PathBuf, PathBuf) {
    let key = sb.path(&format!("{name}.json"));
    let mnemonic = sb.path(&format!("{name}.mnemonic.json"));
    let o = run(
        &[
            "generate",
            "--size",
            "12",
            "-o",
            &key.display().to_string(),
            "--mnemonic-out",
            &mnemonic.display().to_string(),
        ],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    (key, mnemonic)
}

#[test]
fn generate_defaults_to_24_words_and_saves_to_the_output_directory() {
    let sb = Sandbox::new();
    let dir = format!("{}/", sb.0.display());
    let o = run(
        &[
            "generate",
            "-o",
            &dir,
            "--label",
            "alice",
            "--mnemonic-out",
            "--json",
        ],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    );
    assert_eq!(code(&o), 0, "{}", err(&o));

    let result: Value = serde_json::from_str(&out(&o)).unwrap();
    let key_file = PathBuf::from(result["keyFile"].as_str().unwrap());
    let mnemonic_file = PathBuf::from(result["mnemonicFile"].as_str().unwrap());
    assert!(key_file.starts_with(&sb.0));

    assert_eq!(
        read_json(&mnemonic_file)["seed"].as_array().unwrap().len(),
        24
    );

    let key = read_json(&key_file);
    assert_eq!(key["label"], "alice");
    assert!(key.get("privateKeyBase64").is_none());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key files must be owner-only");
    }
}

#[test]
fn generate_defaults_to_the_current_directory() {
    let sb = Sandbox::new();
    let o = cmd(
        &["generate", "--size", "12"],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    )
    .current_dir(&sb.0)
    .output()
    .unwrap();
    assert_eq!(code(&o), 0, "{}", err(&o));

    let files: Vec<_> = fs::read_dir(&sb.0).unwrap().flatten().collect();
    assert_eq!(files.len(), 1);
    assert!(files[0]
        .file_name()
        .to_string_lossy()
        .starts_with("majik-key-"));
}

#[test]
fn generate_12_words_and_rejects_other_sizes() {
    let sb = Sandbox::new();
    let (_, mnemonic) = generate(&sb, "k");
    assert_eq!(read_json(&mnemonic)["seed"].as_array().unwrap().len(), 12);

    assert_eq!(code(&run(&["generate", "--size", "18"], &[])), 2);
}

#[test]
fn passphrase_never_comes_from_argv_and_missing_one_fails_cleanly() {
    let sb = Sandbox::new();
    let o = run(&["generate", "--size", "12", "-o", &sb.str("k.json")], &[]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("MAJIK_KEY_PASSPHRASE"));
    assert!(!sb.path("k.json").exists());
}

#[test]
fn passphrase_stdin_works() {
    let sb = Sandbox::new();
    let mut child = cmd(
        &[
            "generate",
            "--size",
            "12",
            "-o",
            &sb.str("k.json"),
            "--passphrase-stdin",
        ],
        &[],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASS}\n").as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());

    let o = run(
        &["verify", &sb.str("k.json")],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    );
    assert_eq!(code(&o), 0);
}

#[test]
fn refuses_to_overwrite_without_the_flag() {
    let sb = Sandbox::new();
    let file = sb.str("k.json");
    let args = ["generate", "--size", "12", "-o", file.as_str(), "--json"];
    assert_eq!(code(&run(&args, &[("MAJIK_KEY_PASSPHRASE", PASS)])), 0);

    let o = run(&args, &[("MAJIK_KEY_PASSPHRASE", PASS)]);
    assert_eq!(code(&o), 1);
    assert!(out(&o).contains("--overwrite"));
}

#[test]
fn info_keys_and_verify() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let k = key.display().to_string();

    let o = run(&["info", &k, "--json"], &[]);
    assert_eq!(code(&o), 0);
    let info: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(info["coreComplete"], true);
    assert_eq!(info["kdf"], "argon2id");

    let o = run(&["keys", &k, "--json"], &[]);
    let keys: Value = serde_json::from_str(&out(&o)).unwrap();
    let ids: Vec<&str> = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"pq:ml-dsa-87") && ids.contains(&"classic:ed25519"));

    assert_eq!(
        code(&run(&["verify", &k], &[("MAJIK_KEY_PASSPHRASE", PASS)])),
        0
    );
    assert_eq!(
        code(&run(
            &["verify", &k],
            &[("MAJIK_KEY_PASSPHRASE", "nope nope")]
        )),
        1
    );
}

#[test]
fn keys_supported_lists_algorithms_without_a_file() {
    let o = run(&["keys", "--supported", "--json"], &[]);
    assert_eq!(code(&o), 0);
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert!(v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["id"] == "web3:btc"));
    assert_eq!(code(&run(&["keys"], &[])), 2);
}

#[test]
fn label_edits_in_place() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let k = key.display().to_string();

    assert_eq!(code(&run(&["label", &k, "renamed"], &[])), 0);
    assert_eq!(read_json(&key)["label"], "renamed");
    assert!(out(&run(&["label", &k], &[])).contains("renamed"));
}

#[test]
fn passphrase_command_changes_the_passphrase() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let k = key.display().to_string();

    let o = run(
        &["passphrase", &k],
        &[
            ("MAJIK_KEY_PASSPHRASE", PASS),
            ("MAJIK_KEY_NEW_PASSPHRASE", "a brand new passphrase"),
        ],
    );
    assert_eq!(code(&o), 0, "{}", err(&o));

    assert_eq!(
        code(&run(&["verify", &k], &[("MAJIK_KEY_PASSPHRASE", PASS)])),
        1
    );
    assert_eq!(
        code(&run(
            &["verify", &k],
            &[("MAJIK_KEY_PASSPHRASE", "a brand new passphrase")]
        )),
        0
    );

    // Re-using the same passphrase is rejected.
    let o = run(
        &["passphrase", &k],
        &[
            ("MAJIK_KEY_PASSPHRASE", "a brand new passphrase"),
            ("MAJIK_KEY_NEW_PASSPHRASE", "a brand new passphrase"),
        ],
    );
    assert_eq!(code(&o), 2);
}

#[test]
fn dangerous_export_is_gated_and_contains_raw_keys() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let k = key.display().to_string();
    let dest = sb.str("d.json");
    let pass = [("MAJIK_KEY_PASSPHRASE", PASS)];

    // missing acknowledgement
    assert_eq!(
        code(&run(&["export", &k, "--dangerous", "-o", &dest], &pass)),
        2
    );
    // acknowledged, but non-interactive without --yes
    assert_eq!(
        code(&run(
            &[
                "export",
                &k,
                "--dangerous",
                "--i-understand-the-risk",
                "-o",
                &dest
            ],
            &pass
        )),
        2
    );
    assert!(!sb.path("d.json").exists());

    let o = run(
        &[
            "export",
            &k,
            "--dangerous",
            "--i-understand-the-risk",
            "--yes",
            "-o",
            &dest,
        ],
        &pass,
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let dangerous = read_json(&sb.path("d.json"));
    assert!(dangerous["privateKeyBase64"].is_string());
    assert!(dangerous["secretKeys"]["pq:ml-dsa-87"].is_string());

    // dangerous files can be inspected, but can't be used where a passphrase is needed
    assert_eq!(code(&run(&["info", &dest], &[])), 0);
    assert_eq!(code(&run(&["verify", &dest], &pass)), 2);
}

#[test]
fn export_stdout_keeps_stdout_clean_and_conflicts_with_json() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let k = key.display().to_string();

    let o = run(
        &[
            "export",
            &k,
            "--dangerous",
            "--i-understand-the-risk",
            "--yes",
            "--stdout",
        ],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    );
    assert_eq!(code(&o), 0);
    let v: Value = serde_json::from_str(&out(&o)).expect("stdout must be pure JSON");
    assert!(v["privateKeyBase64"].is_string());
    assert!(err(&o).contains("Exported to stdout"));

    assert_eq!(code(&run(&["export", &k, "--stdout", "--json"], &[])), 2);
}

#[test]
fn export_registry_only_drops_legacy_fields() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let k = key.display().to_string();

    assert_eq!(
        code(&run(
            &["export", &k, "--registry-only", "-o", &sb.str("r.json")],
            &[]
        )),
        0
    );
    let exported = read_json(&sb.path("r.json"));
    assert!(exported.get("keys").is_some());
    assert!(exported.get("encryptedMlKemSecretKey").is_none());
}

#[test]
fn create_restores_the_same_account_and_add_keys_checks_the_phrase() {
    let sb = Sandbox::new();
    let (key, mnemonic) = generate(&sb, "a");
    let m = mnemonic.display().to_string();

    let restored = sb.str("b.json");
    let o = run(
        &["create", "--mnemonic-file", &m, "-o", &restored],
        &[("MAJIK_KEY_PASSPHRASE", "other pass 123")],
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(
        read_json(&key)["fingerprint"],
        read_json(&sb.path("b.json"))["fingerprint"]
    );

    let pass = [("MAJIK_KEY_PASSPHRASE", "other pass 123")];
    let o = run(
        &[
            "add-keys",
            &restored,
            "-k",
            "btc,eth",
            "--mnemonic-file",
            &m,
        ],
        &pass,
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let o = run(&["keys", &restored, "--json"], &[]);
    assert!(out(&o).contains("web3:btc") && out(&o).contains("web3:eth"));

    // idempotent
    assert!(out(&run(
        &["add-keys", &restored, "-k", "btc", "--mnemonic-file", &m],
        &pass
    ))
    .contains("Nothing to add"));

    // a phrase from a different account is rejected and nothing is written
    let bad = sb.path("bad.txt");
    fs::write(&bad, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let o = run(
        &[
            "add-keys",
            &restored,
            "-k",
            "ml-kem-1024",
            "--mnemonic-file",
            &bad.display().to_string(),
        ],
        &pass,
    );
    assert_eq!(code(&o), 1);
    assert!(!fs::read_dir(&sb.0)
        .unwrap()
        .flatten()
        .any(|f| f.file_name().to_string_lossy().ends_with(".tmp")));

    // add-keys requires --keys
    assert_eq!(code(&run(&["add-keys", &restored], &pass)), 2);
}

#[test]
fn backup_uses_a_short_default_name_and_import_restores_json_and_zip() {
    let sb = Sandbox::new();
    let (key, mnemonic) = generate(&sb, "k");
    let k = key.display().to_string();
    let m = mnemonic.display().to_string();
    let dir = format!("{}/", sb.path("bk").display());

    for format in ["json", "zip"] {
        let o = run(
            &[
                "backup",
                &k,
                "-f",
                format,
                "--mnemonic-file",
                &m,
                "-o",
                &dir,
                "--json",
            ],
            &[],
        );
        assert_eq!(code(&o), 0, "{}", err(&o));
        let result: Value = serde_json::from_str(&out(&o)).unwrap();
        let file = PathBuf::from(result["file"].as_str().unwrap());
        assert!(file.file_name().unwrap().to_string_lossy().len() < 80);
        assert!(file
            .to_string_lossy()
            .ends_with(&format!("-backup.{format}")));

        let restored = sb.str(&format!("restored-{format}.json"));
        let o = run(
            &["import", &file.display().to_string(), "-o", &restored],
            &[("MAJIK_KEY_PASSPHRASE", "imported pass 1")],
        );
        assert_eq!(code(&o), 0, "{}", err(&o));
        assert_eq!(
            read_json(&key)["fingerprint"],
            read_json(&sb.path(&format!("restored-{format}.json")))["fingerprint"]
        );
    }

    // wrong phrase
    let bad = sb.path("bad.txt");
    fs::write(&bad, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let o = run(
        &[
            "backup",
            &k,
            "--mnemonic-file",
            &bad.display().to_string(),
            "-o",
            &sb.str("x"),
        ],
        &[],
    );
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("does not belong"));
}

#[test]
fn png_backups_are_rejected_with_a_clear_message() {
    let sb = Sandbox::new();
    fs::write(sb.path("fake.png"), b"\x89PNG\r\n\x1a\nxxxx").unwrap();
    let o = run(
        &["import", &sb.str("fake.png")],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    );
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("PNG"));
}

#[test]
fn migrate_is_a_noop_on_argon2id_keys() {
    let sb = Sandbox::new();
    let (key, _) = generate(&sb, "k");
    let o = run(
        &["migrate", &key.display().to_string()],
        &[("MAJIK_KEY_PASSPHRASE", PASS)],
    );
    assert_eq!(code(&o), 0);
    assert!(out(&o).contains("Already on Argon2id"));
}

#[test]
fn unknown_command_and_no_args_are_usage_errors() {
    assert_eq!(code(&run(&["bogus"], &[])), 2);
    assert_eq!(code(&run(&[], &[])), 2);
    assert_eq!(code(&run(&["--help"], &[])), 0);
    assert_eq!(code(&run(&["--version"], &[])), 0);
}
