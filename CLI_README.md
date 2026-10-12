# Majik Key CLI (Rust)

`majik-key` is the command-line interface for **Majik Key**, the post-quantum-ready seed-phrase account library for the Majikah ecosystem. It lets you create, inspect, edit, export, back up, and restore Majik Keys from a terminal, with no code required.

One recovery phrase (a BIP-39 mnemonic) deterministically produces a whole set of keypairs:

- **X25519** and **ML-KEM-768 (FIPS-203)** for encryption / key agreement
- **Ed25519** and **ML-DSA-87 (FIPS-204)** for signing
- Optional extras on top: more ML-KEM / ML-DSA sizes, SLH-DSA (FIPS-205), **Bitcoin**, **Ethereum**, and **Solana**
- Every secret key is encrypted at rest with your passphrase (**Argon2id** + AES-256-GCM)

The CLI covers the full key lifecycle:

- Generate a brand-new key with a recovery phrase in one command
- Rebuild a key from a phrase you already have, or from a `.json` / `.zip` backup
- Inspect a key and list its keypairs without needing the passphrase
- Edit a key's label, change its passphrase, upgrade legacy keys, add new keypairs
- Export as normal JSON, **dangerous** (raw, unencrypted) JSON, or public contact JSON
- Write recovery-phrase backups as JSON or ZIP
- Machine-readable JSON output and non-interactive use for scripts and CI

This is the **Rust** edition. It ships inside the `majik-key` crate behind the `cli` cargo feature, and it has the **same commands, flags, file formats, and exit codes** as the TypeScript CLI (`npx @majikah/majik-key`). Files are interchangeable between the two: a key created by either can be opened by the other (see [Compatibility with the TypeScript CLI](#compatibility-with-the-typescript-cli)).

The crate is:

```text
majik-key
```

The executable names it builds are:

```text
majik-key
mjkkey
```

Both names run the same CLI.

---

## Table of Contents

- [Majik Key CLI](#majik-key-cli)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
    - [Install](#install)
    - [Run without installing](#run-without-installing)
    - [Your first key in 30 seconds](#your-first-key-in-30-seconds)
- [Feature Overview](#feature-overview)
- [Compatibility with the TypeScript CLI](#compatibility-with-the-typescript-cli)
- [Differences from the TypeScript CLI](#differences-from-the-typescript-cli)
- [Available Commands](#available-commands)
- [Core Concepts](#core-concepts)
  - [The key file vs. the recovery phrase](#the-key-file-vs-the-recovery-phrase)
  - [File formats this CLI reads and writes](#file-formats-this-cli-reads-and-writes)
  - [Which keypairs a key contains](#which-keypairs-a-key-contains)
  - [Choosing extra keypairs with `--keys`](#choosing-extra-keypairs-with---keys)
- [Secrets: Passphrases and Recovery Phrases](#secrets-passphrases-and-recovery-phrases)
  - [Passphrase resolution](#passphrase-resolution)
  - [Which command needs which secret](#which-command-needs-which-secret)
  - [Recovery phrase input](#recovery-phrase-input)
  - [Interactive use](#interactive-use)
  - [Non-interactive use](#non-interactive-use)
- [Where Files Are Saved](#where-files-are-saved)
  - [The `--output` rules](#the---output-rules)
  - [Default file names](#default-file-names)
  - [Overwriting and permissions](#overwriting-and-permissions)
- [`generate`](#generate)
- [`create`](#create)
- [`import`](#import)
- [`info`](#info)
- [`keys`](#keys)
- [`verify`](#verify)
- [`label`](#label)
- [`passphrase`](#passphrase)
- [`migrate`](#migrate)
- [`add-keys`](#add-keys)
- [`export`](#export)
- [`backup`](#backup)
- [Dangerous JSON](#dangerous-json)
- [Invalid and Rejected Combinations](#invalid-and-rejected-combinations)
- [Exit Codes](#exit-codes)
- [JSON Output](#json-output)
- [Common End-to-End Recipes](#common-end-to-end-recipes)
- [Installing and Running](#installing-and-running)
- [Using the CLI from Rust Code](#using-the-cli-from-rust-code)
- [Complete Command Cheat Sheet](#complete-command-cheat-sheet)
- [Troubleshooting](#troubleshooting)
- [Operational Notes](#operational-notes)
- [Summary](#summary)

---

## Quick Start

### Install

The CLI is optional, so library users never compile it. Enable the `cli` feature:

```bash
cargo install majik-key --features cli
```

From a checkout of the repository:

```bash
cargo install --path . --features cli
```

Then use:

```bash
majik-key --help
majik-key --version
```

### Run without installing

From a checkout:

```bash
cargo run --features cli --bin majik-key -- --help
cargo run --features cli --bin majik-key -- generate
cargo run --features cli --bin mjkkey -- --help
```

(The `--` separates cargo's own flags from the CLI's.) For everyday use, build an optimized binary; Argon2id is much faster in release mode:

```bash
cargo build --release --features cli
./target/release/majik-key generate
```

### Your first key in 30 seconds

```bash
majik-key generate
```

What happens:

1. You are asked to **set a passphrase** (typed twice, hidden, never stored in shell history).
2. A **24-word recovery phrase** is shown once. Write it down.
3. You are asked to **type back 3 random words** to prove you wrote it down.
4. The encrypted key file is saved **in the folder you ran the command from**, for example:

```text
→ Majik Key saved.
Key File             /home/you/project/majik-key-AbC123xy.json
Format               passphrase-encrypted JSON
Fingerprint          AbC123xy...
Keys                 classic:x25519, classic:ed25519, pq:ml-kem-768, pq:ml-dsa-87, web3:sol
```

Want a shorter phrase? Use `--size 12`:

```bash
majik-key generate --size 12
```

---

# Feature Overview

| Feature                       | CLI support | Purpose                                                                        |
| ----------------------------- | ----------- | ------------------------------------------------------------------------------ |
| Generate a new key            | Yes         | New recovery phrase + key in one step (12 or 24 words).                        |
| Create from an existing phrase| Yes         | Rebuild a key from a phrase you typed or stored in a file.                     |
| Restore from a backup         | Yes         | Import a `.json` or `.zip` recovery-phrase backup.                             |
| Inspect without a passphrase  | Yes         | `info` and `keys` read only public, non-secret data.                           |
| Verify a passphrase           | Yes         | Check a passphrase against a key file (exit code `1` if wrong).                |
| Edit label                    | Yes         | Show or change the human-readable key name.                                    |
| Change passphrase             | Yes         | Re-encrypt every secret key under a new passphrase and fresh salt.             |
| Upgrade legacy keys           | Yes         | Move old PBKDF2 keys to Argon2id (`migrate`).                                  |
| Add keypairs later            | Yes         | Add Bitcoin, Ethereum, and more to an existing key (`add-keys`).               |
| Export normal JSON            | Yes         | Passphrase-encrypted key file; safe at rest.                                   |
| Export dangerous JSON         | Yes         | Raw, unencrypted private keys, behind explicit safety gates.                   |
| Export public contact JSON    | Yes         | Shareable public identity, no secrets.                                         |
| Recovery-phrase backups       | Yes         | Write JSON or ZIP backups (`backup`). PNG is not available in the Rust edition yet. |
| Pipe to other tools           | Yes         | `export --stdout` prints data to stdout for secrets managers.                  |
| JSON output                   | Yes         | `--json` on every command for scripts and CI.                                  |
| Passphrase from stdin or env  | Yes         | `--passphrase-stdin` and `MAJIK_KEY_PASSPHRASE` for non-interactive runs.      |
| Passphrase as an argument     | **No**      | Deliberately unsupported: it would end up in shell history.                    |
| 10 mnemonic languages         | Yes         | `en`, `fr`, `es`, `it`, `ja`, `ko`, `pt`, `czech`, `zh-cn`, `zh-tw`.          |

---

# Compatibility with the TypeScript CLI

Both CLIs sit on libraries that produce **byte-identical** results, and this is tested:

| Check                                                                  | Result                                   |
| ---------------------------------------------------------------------- | ---------------------------------------- |
| A key created by the Rust CLI, opened by the TypeScript CLI            | Works (`verify`, `info`, `keys`, …)      |
| A key created by the TypeScript CLI, opened by the Rust CLI            | Works                                    |
| `export --dangerous` of the same key from both CLIs                    | **Identical** secret keys                |
| The same recovery phrase + `create` in both                            | Same fingerprint, same public keys       |
| A key edited by one CLI (`add-keys`) then opened by the other          | Works                                    |
| ZIP backup made by one CLI, restored by the other                      | Same account                             |

So you can generate a key with `npx @majikah/majik-key` on one machine and manage it with this CLI on another.

---

# Differences from the TypeScript CLI

| Area                    | TypeScript CLI                                   | Rust CLI                                                                                   |
| ----------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Install / run           | `npx @majikah/majik-key`                         | `cargo install majik-key --features cli`                                                   |
| PNG backups             | `backup -f png`, `import x.png` (optional pkgs)  | **Not yet.** The MajikByte PNG container has no Rust port. `backup` offers `json` and `zip`; `import` reads `.json` and `.zip`. |
| ZIP contents            | PNG + JSON + README                              | JSON + README. TypeScript-made ZIPs still import fine (the JSON entry is used).            |
| Falcon keys             | `falcon-512`, `falcon-1024` (experimental)       | Not implemented in the Rust library yet. `keys --supported` lists 23 algorithms, not 25.   |
| `export --contact` JSON | TypeScript contact format                        | The Rust crate's own `MajikContactData` shape. **Not interchangeable** with the TypeScript contact file. |
| `--json` position       | After the command                                | Anywhere (`majik-key --json info k.json` and `majik-key info k.json --json` both work).    |
| Usage errors            | Exit `2`                                         | Exit `2` (same)                                                                            |
| Windows                 | Works                                            | Builds with a different prompt backend; **not yet tested on Windows**.                     |

Everything else (every command, flag, default file name, exit code, and safety gate described below) is the same.

---

# Available Commands

| Command                       | Main purpose                                     | Needs a passphrase? | Needs the recovery phrase? | Typical output                          |
| ----------------------------- | ------------------------------------------------ | :-----------------: | :------------------------: | --------------------------------------- |
| `majik-key --help`            | Show CLI help                                    |         No          |             No             | Help text                               |
| `majik-key --version`         | Show installed CLI version                       |         No          |             No             | Version string                          |
| `majik-key generate`          | Create a brand-new key (alias: `new`)            |   Yes (new, twice)  |     Generated for you      | Key file (+ optional phrase file)       |
| `majik-key create`            | Create a key from a phrase you already have      |   Yes (new, twice)  |            Yes             | Key file                                |
| `majik-key import <backup>`   | Restore a key from a `.json`/`.zip` backup       |   Yes (new, twice)  |      Read from backup      | Key file                                |
| `majik-key info <key>`        | Show non-secret key details                      |         No          |             No             | Key summary                             |
| `majik-key keys [key]`        | List a key's keypairs, or all supported algorithms |       No          |             No             | Table of keypairs                       |
| `majik-key verify <key>`      | Check a passphrase                               |    Yes (existing)   |             No             | Pass/fail + exit code                   |
| `majik-key label <key> [label]` | Show or change the label                       |         No          |             No             | Updated key file                        |
| `majik-key passphrase <key>`  | Change the passphrase                            |  Yes (old and new)  |             No             | Updated key file                        |
| `majik-key migrate <key>`     | Upgrade legacy PBKDF2 to Argon2id                |    Yes (existing)   |             No             | Updated key file                        |
| `majik-key add-keys <key>`    | Add keypairs the key doesn't have yet            |    Yes (existing)   |            Yes             | Updated key file                        |
| `majik-key export <key>`      | Serialize: normal, dangerous, or contact JSON    |  Only for `--dangerous` on an encrypted file | No   | JSON file or stdout                     |
| `majik-key backup <key>`      | Write a recovery-phrase backup                   |         No          |            Yes             | `.json` / `.zip` backup                 |

---

# Core Concepts

## The key file vs. the recovery phrase

A Majik Key has two separate things you must protect, and they do different jobs.

| Thing                  | What it is                                                         | Protects against                           | If you lose it                                                                  |
| ---------------------- | ------------------------------------------------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------- |
| **Key file** (`.json`) | Your keypairs, each secret key encrypted with your passphrase.     | Daily use: signing, decrypting, exporting. | Rebuild it from the recovery phrase with `create` or `import`.                  |
| **Recovery phrase**    | 12 or 24 words that deterministically regenerate every keypair.    | Losing the key file or forgetting the passphrase. | The key file still works, but you can never recover from a lost file, and `add-keys`/`backup` stop working. |
| **Passphrase**         | Encrypts the secret keys inside the key file.                      | Someone stealing the key file.             | The key file becomes unusable. Recreate it from the recovery phrase.            |

> **Rule of thumb:** the **recovery phrase** is the master secret. Anyone who has it controls every key, forever. The **key file** is only safe to leave lying around because it is encrypted. Write the phrase on paper; keep it offline.

## File formats this CLI reads and writes

| Format                        | Contains                                                | Safe at rest? | Written by                                         | Read by                                                            |
| ----------------------------- | ------------------------------------------------------- | :-----------: | -------------------------------------------------- | ------------------------------------------------------------------ |
| **Normal key JSON** (default) | Public keys + passphrase-encrypted secret keys          |      Yes      | `generate`, `create`, `import`, `export`, edits    | All key commands                                                   |
| **Registry-only JSON**        | Same, without legacy pre-registry fields                |      Yes      | `--registry-only`                                  | All key commands (older library versions can't read it)            |
| **Dangerous JSON**            | **Raw, unencrypted** private keys                       |    **NO**     | `--dangerous`                                      | `info`, `keys`, `label`, `export` (see [Dangerous JSON](#dangerous-json)) |
| **Contact JSON**              | Public keys only (Rust shape; differs from the TypeScript contact format) |  Yes (public) | `export --contact`                                 | Rust `MajikContactData` consumers                                  |
| **Mnemonic JSON**             | The recovery phrase in **plaintext**                    |    **NO**     | `--mnemonic-out`, `backup -f json`                 | `create --mnemonic-file`, `import`, `add-keys`, `backup`           |
| **Backup ZIP**                | JSON + a README (TypeScript-made ZIPs may also hold a PNG) |    **NO**     | `backup -f zip`                                    | `import`                                                           |

> "Safe at rest" means safe to store on disk without extra protection, apart from normal file hygiene. Everything marked **NO** gives full control of your key to anyone who can read it.

## Which keypairs a key contains

Every new key always contains the **core four**:

| Keypair             | Used for                                |
| ------------------- | --------------------------------------- |
| `classic:x25519`    | Classical key agreement; the key's fingerprint/identity |
| `classic:ed25519`   | Classical signatures                    |
| `pq:ml-kem-768`     | Post-quantum encryption (FIPS-203)      |
| `pq:ml-dsa-87`      | Post-quantum signatures (FIPS-204)      |

`web3:sol` (Solana) is a **derived view** of the Ed25519 key, so every key can produce a Solana address without storing anything extra.

Everything else is **opt-in**: you choose extras when you create the key (`--keys`) or add them later (`add-keys`).

## Choosing extra keypairs with `--keys`

`--keys` (short: `-k`) takes a comma-separated list, and can be repeated. You can use the full id (`web3:btc`) or just the part after the colon (`btc`).

| Short name              | Full id                    | Kind                              |
| ----------------------- | -------------------------- | --------------------------------- |
| `btc`                   | `web3:btc`                 | Bitcoin (BIP-32 / BIP-84)         |
| `eth`                   | `web3:eth`                 | Ethereum (BIP-44)                 |
| `sol`                   | `web3:sol`                 | Solana (derived; already included)|
| `ml-kem-512`            | `pq:ml-kem-512`            | Post-quantum KEM                  |
| `ml-kem-1024`           | `pq:ml-kem-1024`           | Post-quantum KEM                  |
| `ml-dsa-44`, `ml-dsa-65`| `pq:ml-dsa-44`, `pq:ml-dsa-65` | Post-quantum signatures       |
| `slh-dsa-sha2-128s` … `slh-dsa-shake-256f` | `pq:slh-dsa-…`  | Hash-based signatures (FIPS-205), 12 variants |

See the live list for your installed version at any time:

```bash
majik-key keys --supported
```

Examples:

```bash
majik-key generate --keys btc,eth
majik-key generate -k btc -k eth          # same thing
majik-key generate --keys web3:btc,pq:ml-dsa-65
```

Algorithms that are defined but not usable yet (HQC, FN-DSA, LMS, and Falcon in the Rust edition) are rejected with a clear error.

---

# Secrets: Passphrases and Recovery Phrases

**The CLI never accepts a passphrase or recovery phrase as a command-line argument.** Anything you type after a command is saved in your shell history and visible to other processes. Secrets come from safer places instead.

## Passphrase resolution

The CLI looks for a passphrase in this order:

1. `--passphrase-stdin` (first line of standard input), on commands that offer it
2. The `MAJIK_KEY_PASSPHRASE` environment variable
3. A **hidden interactive prompt**

The `passphrase` command also uses `MAJIK_KEY_NEW_PASSPHRASE` for the new passphrase.

## Which command needs which secret

| Command                              | Passphrase                                   | `--passphrase-stdin` | Recovery phrase                          |
| ------------------------------------ | -------------------------------------------- | :------------------: | ---------------------------------------- |
| `generate`                           | **New**; typed twice when prompting          |         Yes          | Generated and shown to you               |
| `create`                             | **New**; typed twice when prompting          |         Yes          | Prompt, `MAJIK_KEY_MNEMONIC`, or `--mnemonic-file` |
| `import`                             | **New**; typed twice when prompting          |         Yes          | Read from the backup file                |
| `verify`                             | Existing                                     |         Yes          | No                                       |
| `migrate`                            | Existing                                     |         Yes          | No                                       |
| `export --dangerous`                 | Existing (not needed if the input is already a dangerous file) |  Yes  | No                                  |
| `passphrase`                         | Current (`MAJIK_KEY_PASSPHRASE` / prompt) **and** new (`MAJIK_KEY_NEW_PASSPHRASE` / prompt) |  No  | No      |
| `add-keys`                           | Existing (`MAJIK_KEY_PASSPHRASE` / prompt)   |          No          | Prompt, `MAJIK_KEY_MNEMONIC`, or `--mnemonic-file` |
| `backup`                             | **Not needed**                               |          —           | Prompt, `MAJIK_KEY_MNEMONIC`, or `--mnemonic-file` |
| `info`, `keys`, `label`, `export` (normal/contact) | **Not needed**                 |          —           | No                                       |

## Recovery phrase input

Where a command needs your phrase (`create`, `add-keys`, `backup`), it is read from:

1. `--mnemonic-file <path>`, if given
2. The `MAJIK_KEY_MNEMONIC` environment variable
3. A **hidden interactive prompt**

A `--mnemonic-file` may be either:

- A **plain text** file with the words separated by spaces or newlines, or
- A **Mnemonic JSON** file (what `--mnemonic-out` and `backup -f json` write):

```json
{
  "id": "…",
  "seed": ["word1", "word2", "…"],
  "language": "en",
  "version": 1
}
```

Phrases are normalized (lower-cased, extra whitespace collapsed) and must be **12, 15, 18, 21, or 24 words**.

## Interactive use

```bash
majik-key generate
```

You will see prompts like:

```text
Set a passphrase:
Confirm passphrase:
```

Typing is hidden. Backspace works, Ctrl-C cancels (exit code `130`). A passphrase can't be empty, and a warning appears if it is shorter than 8 characters.

## Non-interactive use

PowerShell:

```powershell
$env:MAJIK_KEY_PASSPHRASE="your-passphrase"
```

Bash/Zsh:

```bash
export MAJIK_KEY_PASSPHRASE="your-passphrase"
```

Then:

```bash
majik-key verify ./majik-key-AbC123xy.json
```

Or pipe it in from a secrets tool so it never touches shell history:

```bash
your-secrets-tool get majik-passphrase | majik-key verify ./key.json --passphrase-stdin
```

> **Security note:** environment variables can be exposed by process inspection, CI configuration, logs, or debugging tools. Use your CI platform's secret mechanism for production automation. Avoid typing `echo "secret" | majik-key …` directly: the `echo` line is itself saved in your shell history.

---

# Where Files Are Saved

## The `--output` rules

Every command that writes a file accepts `-o, --output <path>`. The rules are the same everywhere:

| You pass                                         | Result                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------- |
| Nothing                                          | Saved in the **current directory** (where you ran the command) with a default name. |
| An existing folder, or a path ending in `/`      | Saved inside that folder with the default name. Missing folders are created. |
| A path with an extension (`./alice.json`)        | Used exactly as the file path.                                      |
| A path with no extension (`./alice`)             | Treated as a file name; the right extension is added (`.json`, or `.zip` for `backup -f zip`). |

Commands that **edit** an existing key (`label`, `passphrase`, `migrate`, `add-keys`) default to **editing the file in place** instead of the current directory. Pass `-o` to write a copy elsewhere and leave the original untouched.

## Default file names

| File                          | Default name                                      | Example                                      |
| ----------------------------- | ------------------------------------------------- | -------------------------------------------- |
| Key file                      | `majik-key-<label>-<fingerprint8>.json`           | `majik-key-alice-AbC123xy.json`              |
| Key file (no label)           | `majik-key-<fingerprint8>.json`                   | `majik-key-AbC123xy.json`                    |
| Dangerous key file            | `majik-key-<label>-<fingerprint8>.dangerous.json` | `majik-key-alice-AbC123xy.dangerous.json`    |
| Recovery phrase file          | `majik-key-<label>-<fingerprint8>.mnemonic.json`  | `majik-key-alice-AbC123xy.mnemonic.json`     |
| Public contact                | `majik-contact-<fingerprint8>.json`               | `majik-contact-AbC123xy.json`                |
| Backup                        | `majik-key-<label>-<fingerprint8>-backup.<ext>`   | `majik-key-alice-AbC123xy-backup.zip`        |

The label is made filename-safe (letters, digits, `-`, `_`).

## Overwriting and permissions

- The CLI **never replaces an existing file** unless you add `--overwrite`. (Editing a key **in place** is the one exception: that is the whole point of those commands.)
- Every file it writes is created **owner-read/write only** (`0600`) on systems that support permissions, because any of them can hold key material.
- Writes that replace a file go through a temporary file and a rename, so a crash can't leave a half-written key behind.

---

# `generate`

Create a brand-new recovery phrase **and** a key from it, then save the key file. This is the quickest way to get started.

```bash
majik-key generate [options]
```

Alias: `majik-key new`

What it does, in order:

1. Validates your flags (before asking for anything).
2. Asks for a **new passphrase** (hidden, typed twice).
3. Generates a **12- or 24-word recovery phrase** and shows it **once**, on stderr.
4. On a terminal, asks you to **type back 3 random words** to prove you wrote it down. A wrong word aborts and **nothing is saved**.
5. Creates the key (Argon2id takes about a second) and saves the file.

## `generate` options

| Option                    | Argument      | Description                                                                                      |
| ------------------------- | ------------- | ------------------------------------------------------------------------------------------------ |
| `-s, --size <words>`      | `12` or `24`  | Recovery phrase length. Default: `24`.                                                           |
| `-l, --label <label>`     | Text          | Human-readable name for the key (also used in the file name).                                    |
| `-k, --keys <ids>`        | CSV           | Extra keypairs on top of the core four. See [`--keys`](#choosing-extra-keypairs-with---keys).    |
| `--language <code>`       | Code          | Wordlist language: `en` (default), `fr`, `es`, `it`, `ja`, `ko`, `pt`, `czech`, `zh-cn`, `zh-tw`.|
| `-o, --output <path>`     | File or dir   | Where to save. Default: current directory. See [the rules](#the---output-rules).                 |
| `--overwrite`             | None          | Replace the output file if it exists.                                                            |
| `--mnemonic-out [path]`   | Optional path | Also save the recovery phrase as **plaintext** Mnemonic JSON. Default: next to the key file.     |
| `--skip-confirm`          | None          | Don't ask you to type back words. (Non-interactive runs never ask.)                              |
| `--passphrase-stdin`      | None          | Read the new passphrase from stdin instead of prompting.                                         |
| `--dangerous`             | None          | Save **raw, unencrypted** private keys instead of encrypted JSON. See [Dangerous JSON](#dangerous-json). |
| `--i-understand-the-risk` | None          | Required with `--dangerous`.                                                                     |
| `--yes`                   | None          | Skip the typed confirmation for `--dangerous` (required when non-interactive).                   |
| `--registry-only`         | None          | Omit legacy fields from the JSON (older library versions can't read it).                         |
| `--json`                  | None          | Machine-readable output.                                                                         |

## `generate` examples and combinations

| Goal                                  | Example                                                              | What it does                                                                              |
| ------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Simplest                              | `majik-key generate`                                                 | 24-word phrase, prompts for passphrase, saves in the current directory.                   |
| 12-word phrase                        | `majik-key generate --size 12`                                       | Shorter phrase, same security model.                                                      |
| 24-word phrase (explicit)             | `majik-key generate --size 24`                                       | Same as the default.                                                                      |
| With a label                          | `majik-key generate --label alice`                                   | File becomes `majik-key-alice-<fp8>.json`.                                                |
| Save to a folder                      | `majik-key generate -o ~/keys/`                                      | Saves inside `~/keys/` (created if missing) with the default name.                        |
| Save to an exact file                 | `majik-key generate -o ./alice.json`                                 | Uses exactly that path.                                                                   |
| Extension added for you               | `majik-key generate -o ./alice`                                      | Saves `./alice.json`.                                                                     |
| Replace an existing file              | `majik-key generate -o ./alice.json --overwrite`                     | Replaces the file instead of refusing.                                                    |
| Add wallets at creation               | `majik-key generate --keys btc,eth`                                  | Core four + Bitcoin + Ethereum (Solana is always derivable).                              |
| Repeated `-k`                         | `majik-key generate -k btc -k eth`                                   | Same as `--keys btc,eth`.                                                                 |
| More post-quantum keys                | `majik-key generate --keys ml-kem-1024,ml-dsa-65`                    | Adds a bigger KEM and a mid-size signature key.                                           |
| Another language                      | `majik-key generate --language es`                                   | Spanish BIP-39 wordlist.                                                                  |
| Also save the phrase to a file        | `majik-key generate --mnemonic-out`                                  | Writes `…mnemonic.json` next to the key. **Plaintext: guard it.**                         |
| Phrase to a chosen path               | `majik-key generate --mnemonic-out ./phrase.json`                    | Writes the phrase file exactly there.                                                     |
| Skip the write-it-down quiz           | `majik-key generate --skip-confirm`                                  | Shows the phrase but doesn't ask you to type words back.                                  |
| Dangerous JSON                        | `majik-key generate --dangerous --i-understand-the-risk`             | Writes **only** the raw-keys file (`….dangerous.json`) after a typed fingerprint check.   |
| Dangerous, scripted                   | `majik-key generate --dangerous --i-understand-the-risk --yes`       | Same, without the typed check (non-interactive).                                          |
| Registry-only JSON                    | `majik-key generate --registry-only`                                 | Omits legacy fields.                                                                      |
| Passphrase from a pipe                | `your-secrets-tool get pw \| majik-key generate --passphrase-stdin`  | No prompt; passphrase never touches history.                                              |
| Fully non-interactive                 | `MAJIK_KEY_PASSPHRASE=… majik-key generate --size 12 --mnemonic-out` | No prompts. The phrase goes to stderr and the `--mnemonic-out` file.                      |
| JSON result                           | `majik-key generate --json`                                          | Prints a JSON object describing what was saved.                                           |
| Everything at once                    | `majik-key generate -s 12 -l ops -k btc,eth -o ~/keys/ --mnemonic-out --overwrite` | Combines all of the above.                                          |

> **Important in scripts:** a non-interactive run can't ask you to confirm the phrase. The phrase is still printed to stderr, but if you don't capture it (or use `--mnemonic-out`), **you will have no copy**. Without the phrase you can't recover from a lost file or use `add-keys`/`backup`.

> **Flag order tip:** `--mnemonic-out` takes an *optional* path. When something other than a path follows it, put it last or give it a path, so it doesn't swallow the next word.

Typical JSON result (`--json`):

```json
{
  "ok": true,
  "command": "generate",
  "message": "Majik Key saved.",
  "keyFile": "/home/you/project/majik-key-alice-AbC123xy.json",
  "format": "passphrase-encrypted JSON",
  "label": "alice",
  "fingerprint": "AbC123xy…=",
  "keys": ["classic:x25519", "classic:ed25519", "pq:ml-kem-768", "pq:ml-dsa-87", "web3:sol"]
}
```

`mnemonicFile` and `warning` appear only when `--mnemonic-out` was used. The phrase itself is never in the JSON.

---

# `create`

Create a key from a recovery phrase you **already have** (typed, piped via env, or read from a file). Use it to rebuild a lost key file, or to bring an existing phrase into the CLI.

```bash
majik-key create [options]
```

It takes the same options as [`generate`](#generate-options) **except** `--size` and `--skip-confirm`, plus:

| Option                    | Argument | Description                                                                          |
| ------------------------- | -------- | ------------------------------------------------------------------------------------ |
| `--mnemonic-file <path>`  | Path     | Read the phrase from a plain-text file or a Mnemonic JSON file instead of prompting. |
| `--language <code>`       | Code     | Wordlist language. If omitted: the file's language, else `en`.                       |

The phrase is read from `--mnemonic-file`, then `MAJIK_KEY_MNEMONIC`, then a hidden prompt (see [Recovery phrase input](#recovery-phrase-input)). The same phrase + a new passphrase always produces the **same account** (same fingerprint, same public keys).

| Goal                                | Example                                                                          | What it does                                                             |
| ----------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Type the phrase at a prompt         | `majik-key create`                                                               | Hidden prompt for the phrase, then a new passphrase.                     |
| From a Mnemonic JSON file           | `majik-key create --mnemonic-file ./phrase.json`                                 | Uses the phrase and the language stored in the file.                     |
| From a plain text file              | `majik-key create --mnemonic-file ./phrase.txt`                                  | Words separated by spaces or newlines.                                   |
| From the environment                | `MAJIK_KEY_MNEMONIC="word1 word2 …" majik-key create`                            | No phrase prompt. (Beware shell history; prefer a file.)                 |
| Non-English phrase                  | `majik-key create --language fr`                                                 | Validates against the French wordlist.                                   |
| With label, wallets, location       | `majik-key create --mnemonic-file ./phrase.json -l alice -k btc,eth -o ~/keys/`  | Rebuilds a key and enables Bitcoin and Ethereum.                         |
| Save a dangerous copy               | `majik-key create --mnemonic-file ./phrase.json --dangerous --i-understand-the-risk` | Raw-keys file after a typed fingerprint check.                       |
| Fully non-interactive               | `MAJIK_KEY_PASSPHRASE=… majik-key create --mnemonic-file ./phrase.json --json`   | No prompts.                                                              |

> **Recovering a lost key?** Use the same phrase and **the same `--keys`** you used originally to get the same set of keypairs. The core four are always included; extras can be added later with [`add-keys`](#add-keys).

---

# `import`

Restore a key from a **recovery-phrase backup** file (the kind `backup` writes). The phrase and its language are read from the backup; you choose a **new** passphrase.

```bash
majik-key import <backup> [options]
```

Accepted backups (detected by their contents, not their file extension):

| Backup       | Notes                                                                                           |
| ------------ | ----------------------------------------------------------------------------------------------- |
| `.json`      | Mnemonic JSON.                                                                                  |
| `.zip`       | Reads the JSON entry. Works with ZIPs made by either CLI (a PNG entry, if present, is ignored). |
| `.png`       | **Not supported in the Rust edition yet**: you get a clear error. Restore it with the TypeScript CLI, or use the `.json`/`.zip` backup. |

Options are the same as [`create`](#create) minus `--mnemonic-file`. `--language` overrides the language stored in the backup.

| Goal                        | Example                                                                | What it does                                                      |
| --------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Restore a JSON backup       | `majik-key import ./backup.json`                                       | Prompts for a new passphrase, saves in the current directory.     |
| Restore a ZIP backup        | `majik-key import ./backup.zip -o ~/keys/`                             | Saves into `~/keys/`.                                             |
| Restore with wallets        | `majik-key import ./backup.json -k btc,eth`                            | Rebuilds the key and enables Bitcoin/Ethereum.                    |
| Override the language       | `majik-key import ./backup.json --language en`                         | Ignores the language stored in the file.                          |
| Non-interactive             | `MAJIK_KEY_PASSPHRASE=… majik-key import ./backup.zip --json`          | No prompts.                                                       |
| Also keep a phrase copy     | `majik-key import ./backup.json -o ./k.json --mnemonic-out ./phrase.json` | Writes the phrase file too (plaintext).                        |

> Put `--mnemonic-out` **after** the backup path, or give it an explicit path, so the backup path isn't mistaken for its value.

---

# `info`

Show a key's **non-secret** details. No passphrase needed.

```bash
majik-key info <key> [--json]
```

```text
→ Majik Key "alice"
File                 /home/you/project/majik-key-alice-AbC123xy.json
Label                alice
Fingerprint          AbC123xy…=
Created At           2026-10-12T04:08:36.920Z
Kdf                  argon2id
Mnemonic Language    en
Core Complete        true
Keys                 classic:x25519, classic:ed25519, pq:ml-kem-768, pq:ml-dsa-87, web3:btc, web3:eth, web3:sol
```

| Field                     | Meaning                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------- |
| Fingerprint               | The account's identity (hash of its X25519 public key).                                       |
| Kdf                       | `argon2id`, or `pbkdf2 (legacy — run migrate)` for old keys.                                  |
| Mnemonic Language         | Wordlist the recovery phrase uses.                                                            |
| Core Complete             | `true` when all of the core four keypairs are present. Otherwise `Missing Core Keys` is shown. |
| Keys                      | Every keypair on the account.                                                                 |
| Contains Raw Private Keys | Shown (`true`) only when the file is a **dangerous** JSON file.                               |

| Example                              | What it does                                      |
| ------------------------------------ | ------------------------------------------------- |
| `majik-key info key.json`            | Human-readable summary.                           |
| `majik-key info key.json --json`     | The same fields as JSON.                          |
| `majik-key info key.dangerous.json`  | Works on dangerous files too, and flags them.     |

---

# `keys`

List the keypairs on an account, or every algorithm that can be enabled.

```bash
majik-key keys [key] [options]
```

| Option        | Description                                                         |
| ------------- | ------------------------------------------------------------------- |
| `--supported` | List every algorithm this version can enable (no key file needed).  |
| `--full`      | Print full public keys instead of shortened ones.                   |
| `--json`      | Machine-readable output (always includes full public keys).         |

| Goal                              | Example                                | What it does                                                                   |
| --------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------ |
| Keys on an account                | `majik-key keys key.json`              | Table of id, purpose, kind, status, shortened public key.                      |
| Full public keys                  | `majik-key keys key.json --full`       | Complete base64 public keys (ML-DSA-87 keys are thousands of characters).      |
| As JSON                           | `majik-key keys key.json --json`       | Full public keys in JSON.                                                      |
| What can I enable?                | `majik-key keys --supported`           | Table of every algorithm with its standard (FIPS-203, FIPS-204, …).            |
| Supported, as JSON                | `majik-key keys --supported --json`    | Same, machine-readable.                                                        |

How to read the table: **kind** is `stored` (encrypted inside the file) or `derived` (computed on demand, like Solana). **status** is `stable` or `experimental`. Solana shows no public key because it is derived from the Ed25519 key only once unlocked.

Running `keys` with neither a file nor `--supported` is a usage error (exit `2`).

---

# `verify`

Check a passphrase against a key file, without changing anything.

```bash
majik-key verify <key> [--passphrase-stdin] [--json]
```

| Example                                                         | What it does                                             |
| --------------------------------------------------------------- | -------------------------------------------------------- |
| `majik-key verify key.json`                                     | Hidden passphrase prompt.                                |
| `MAJIK_KEY_PASSPHRASE=… majik-key verify key.json`              | Non-interactive.                                         |
| `your-secrets-tool get pw \| majik-key verify key.json --passphrase-stdin` | Passphrase from a pipe.                       |
| `majik-key verify key.json --json`                              | Result as JSON (`"valid": true/false`).                  |

Exit code `0` = correct, `1` = wrong. That makes it ideal for scripts:

```bash
if majik-key verify key.json --passphrase-stdin < pw.txt >/dev/null 2>&1; then echo ok; fi
```

`verify` needs a regular (encrypted) key file; a **dangerous** file has no passphrase to check and is rejected with exit `2`.

---

# `label`

Show or change a key's label. The key file is **edited in place** unless you pass `-o`. No passphrase needed.

```bash
majik-key label <key> [label] [options]
```

| Option                | Description                                                             |
| --------------------- | ----------------------------------------------------------------------- |
| `-o, --output <path>` | Write the updated key here instead of editing the original.             |
| `--overwrite`         | Allow `-o` to replace an existing file.                                 |
| `--json`              | Machine-readable output.                                                |

| Goal                         | Example                                              | What it does                                             |
| ---------------------------- | ---------------------------------------------------- | -------------------------------------------------------- |
| Show the label               | `majik-key label key.json`                           | Prints it; changes nothing.                              |
| Change the label             | `majik-key label key.json "Alice Prime"`             | Rewrites `key.json` with the new label.                  |
| Keep the original            | `majik-key label key.json "Alice" -o ./copy.json`    | Writes a copy; the original is untouched.                |
| Overwrite that copy          | `majik-key label key.json "Alice" -o ./copy.json --overwrite` | Replaces `copy.json` if it exists.              |
| Edit a dangerous file        | `majik-key label key.dangerous.json "Alice"`         | Works, and the file stays dangerous JSON.                |

Changing the label doesn't change the file name or the fingerprint.

---

# `passphrase`

Change a key's passphrase. Every secret key is **re-encrypted** under the new passphrase with a fresh salt, and an old PBKDF2 key is upgraded to Argon2id as part of it. The recovery phrase is **not** affected. The file is edited in place unless you pass `-o`.

```bash
majik-key passphrase <key> [options]
```

Options: `-o, --output <path>`, `--overwrite`, `--json`.

This command doesn't offer `--passphrase-stdin`, because it needs two secrets. The sources are:

| Secret            | Environment variable           | Otherwise        |
| ----------------- | ------------------------------ | ---------------- |
| Current passphrase| `MAJIK_KEY_PASSPHRASE`         | Hidden prompt    |
| New passphrase    | `MAJIK_KEY_NEW_PASSPHRASE`     | Hidden prompt, typed twice |

| Goal                     | Example                                                                                                  |
| ------------------------ | -------------------------------------------------------------------------------------------------------- |
| Interactive              | `majik-key passphrase key.json`                                                                          |
| Write to a new file      | `majik-key passphrase key.json -o ./rotated.json`                                                        |
| Non-interactive          | `MAJIK_KEY_PASSPHRASE=old MAJIK_KEY_NEW_PASSPHRASE=new majik-key passphrase key.json`                    |

Rules: the current passphrase must be correct, and the new one must be **different** from the current one (usage error, exit `2`). Dangerous files can't be used here.

---

# `migrate`

Upgrade a **legacy PBKDF2** key to **Argon2id** without changing its passphrase. Only older keys need this; `info` shows `Kdf: pbkdf2 (legacy — run migrate)` for them.

```bash
majik-key migrate <key> [options]
```

Options: `-o, --output <path>`, `--overwrite`, `--passphrase-stdin`, `--json`.

| Example                                              | What it does                                                         |
| ---------------------------------------------------- | -------------------------------------------------------------------- |
| `majik-key migrate old-key.json`                     | Prompts for the passphrase and upgrades the file in place.           |
| `majik-key migrate old-key.json -o ./upgraded.json`  | Writes the upgraded key to a new file.                               |
| `majik-key migrate key.json`                         | On a key that's already Argon2id: does nothing and says so (exit `0`). |

---

# `add-keys`

Add keypairs the account doesn't have yet, such as Bitcoin, Ethereum, or other post-quantum algorithms.

```bash
majik-key add-keys <key> --keys <ids> [options]
```

New keys are derived from the recovery phrase, which is **never stored**, so this command needs **both** secrets:

| Needs                          | Source                                                                   |
| ------------------------------ | ------------------------------------------------------------------------ |
| The key's passphrase           | `MAJIK_KEY_PASSPHRASE` or a hidden prompt                                |
| The key's recovery phrase      | `--mnemonic-file`, `MAJIK_KEY_MNEMONIC`, or a hidden prompt              |

Safety checks run **before** anything changes: the passphrase must be correct and the phrase must belong to this exact account. A legacy key is upgraded to Argon2id automatically as part of the operation.

| Option                   | Description                                                                      |
| ------------------------ | -------------------------------------------------------------------------------- |
| `-k, --keys <ids>`       | **Required.** Keypairs to add, comma-separated. Short names work.                |
| `--mnemonic-file <path>` | Read the phrase from a file instead of prompting.                                |
| `-o, --output <path>`    | Write the updated key elsewhere instead of editing in place.                     |
| `--overwrite`            | Allow `-o` to replace an existing file.                                          |
| `--json`                 | Machine-readable output.                                                         |

| Goal                              | Example                                                                  | What it does                                                           |
| --------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| Add Bitcoin and Ethereum          | `majik-key add-keys key.json --keys btc,eth`                             | Prompts for passphrase and phrase, edits the file in place.            |
| From a phrase file                | `majik-key add-keys key.json -k btc --mnemonic-file ./phrase.json`       | No phrase prompt.                                                      |
| Keep the original                 | `majik-key add-keys key.json -k eth -o ./with-eth.json`                  | Original untouched.                                                    |
| Add a bigger post-quantum KEM     | `majik-key add-keys key.json -k ml-kem-1024`                             | Adds ML-KEM-1024 alongside ML-KEM-768.                                 |
| Non-interactive                   | `MAJIK_KEY_PASSPHRASE=… MAJIK_KEY_MNEMONIC="…" majik-key add-keys key.json -k btc --json` | No prompts.                                           |
| Already present                   | `majik-key add-keys key.json -k btc` (again)                             | "Nothing to add" (exit `0`); the file isn't rewritten.                 |
| Wrong phrase                      | `majik-key add-keys key.json -k btc --mnemonic-file ./other.txt`         | Fails (exit `1`): the phrase doesn't belong to this account.           |
| Solana only                       | `majik-key add-keys key.json -k sol`                                     | Nothing to add. Solana is always derivable from the Ed25519 key.       |

Leaving out `--keys` is a usage error (exit `2`).

---

# `export`

Serialize a key to a file or to stdout. Three flavors:

| Flavor                    | Flags                  | Contains                                   | Passphrase needed?                           |
| ------------------------- | ---------------------- | ------------------------------------------ | -------------------------------------------- |
| **Normal JSON** (default) | none                   | Public keys + encrypted secrets            | No                                           |
| **Public contact JSON**   | `--contact`            | Public keys only                           | No                                           |
| **Dangerous JSON**        | `--dangerous …`        | **Raw, unencrypted** private keys          | Yes, unless the input is already a dangerous file |

```bash
majik-key export <key> [options]
```

## `export` options

| Option                    | Description                                                                                         |
| ------------------------- | --------------------------------------------------------------------------------------------------- |
| `-o, --output <path>`     | File or directory. Default: current directory with the [default name](#default-file-names).         |
| `--overwrite`             | Replace the output if it exists.                                                                    |
| `--contact`               | Export the **public** contact JSON (safe to share).                                                 |
| `--stdout`                | Print the exported data to **stdout** instead of a file. The summary goes to stderr.                |
| `--dangerous`             | Export raw private keys. Needs `--i-understand-the-risk`.                                           |
| `--i-understand-the-risk` | Required with `--dangerous`.                                                                        |
| `--yes`                   | Skip the typed fingerprint confirmation (required when non-interactive).                            |
| `--registry-only`         | Omit legacy fields (normal JSON only).                                                              |
| `--passphrase-stdin`      | Read the passphrase (for `--dangerous`) from stdin.                                                 |
| `--json`                  | Machine-readable summary. Can't be combined with `--stdout`.                                        |

## `export` examples and combinations

| Goal                                   | Example                                                                           | What it does                                                                            |
| -------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Re-save normal JSON                    | `majik-key export key.json -o ./copy.json`                                        | Writes an encrypted copy. No passphrase.                                                |
| Upgrade a legacy file's shape          | `majik-key export old.json -o ./new.json`                                         | Re-serializes with the multi-key registry.                                              |
| Registry-only                          | `majik-key export key.json --registry-only -o ./clean/`                           | Drops legacy fields. **Older library versions can't read the result.**                  |
| Into a folder                          | `majik-key export key.json -o ./out/`                                             | Saved as `./out/majik-key-<…>.json`.                                                    |
| Replace an existing file               | `majik-key export key.json -o ./copy.json --overwrite`                            | Overwrites `copy.json`.                                                                 |
| Public contact                         | `majik-key export key.json --contact`                                             | Writes `majik-contact-<fp8>.json`. Safe to share.                                       |
| Contact to a path                      | `majik-key export key.json --contact -o ./alice-contact.json`                     | Exact path.                                                                             |
| Contact to stdout                      | `majik-key export key.json --contact --stdout`                                    | Pipe it anywhere.                                                                       |
| Dangerous (interactive)                | `majik-key export key.json --dangerous --i-understand-the-risk`                   | Passphrase prompt, then a typed fingerprint check, then the file is written.            |
| Dangerous (scripted)                   | `MAJIK_KEY_PASSPHRASE=… majik-key export key.json --dangerous --i-understand-the-risk --yes -o ./d.json` | No prompts.                                              |
| Dangerous to stdout                    | `… majik-key export key.json --dangerous --i-understand-the-risk --yes --stdout \| your-secrets-tool` | Nothing is written to disk.                                    |
| Dangerous, passphrase from a pipe      | `pw-tool \| majik-key export key.json --dangerous --i-understand-the-risk --yes --passphrase-stdin --stdout` | Passphrase via stdin.                                   |
| Summary as JSON                        | `majik-key export key.json --json`                                                | JSON describing what was written.                                                       |
| Re-export a dangerous file as normal   | `majik-key export key.dangerous.json -o ./encrypted.json`                         | Re-serializes it as the passphrase-encrypted shape.                                     |

> **Convert a dangerous file to a normal one?** The encrypted fields in a dangerous file are the same encrypted blobs, so the re-export keeps the key's original passphrase. To change it, run `passphrase` afterward.

Rejected combinations are listed in [Invalid and Rejected Combinations](#invalid-and-rejected-combinations).

---

# `backup`

Write a **recovery-phrase backup** you can store offline and later restore with [`import`](#import). The command needs the recovery phrase (not the passphrase) and **verifies it belongs to the key** before writing anything.

```bash
majik-key backup <key> [options]
```

| Option                    | Argument               | Description                                                              |
| ------------------------- | ---------------------- | ------------------------------------------------------------------------ |
| `-f, --format <format>`   | `json`, `zip`          | Backup format. Default: `json`. (PNG isn't available in the Rust edition yet.) |
| `--mnemonic-file <path>`  | Path                   | Read the phrase from a file instead of prompting.                        |
| `-o, --output <path>`     | File or directory      | Where to save. Default: current directory.                               |
| `--overwrite`             | None                   | Replace an existing file.                                                |
| `--json`                  | None                   | Machine-readable output.                                                 |

| Format | What it is                                                         | Needs          |
| ------ | ------------------------------------------------------------------ | -------------- |
| `json` | Mnemonic JSON file.                                                | Nothing extra. |
| `zip`  | A ZIP holding the JSON and a README.                               | Nothing extra. |

| Goal                              | Example                                                                         | What it does                                                          |
| --------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| JSON backup                       | `majik-key backup key.json`                                                     | Prompts for the phrase; writes `majik-key-<label>-<fp8>-backup.json`. |
| ZIP backup                        | `majik-key backup key.json -f zip -o ~/safe/`                                   | Writes into `~/safe/`.                                                |
| Exact file name                   | `majik-key backup key.json -f zip -o ./vault`                                   | Extension added for you: `./vault.zip`.                               |
| Phrase from a file                | `majik-key backup key.json --mnemonic-file ./phrase.json`                       | No phrase prompt.                                                     |
| Non-interactive                   | `MAJIK_KEY_MNEMONIC="…" majik-key backup key.json -f zip --json`                | No prompts.                                                           |
| Replace an existing backup        | `majik-key backup key.json -o ./backup.json --overwrite`                        | Overwrites.                                                           |
| Wrong phrase                      | `majik-key backup key.json --mnemonic-file ./other.txt`                         | Fails (exit `1`): "does not belong to this key". Nothing is written.  |

> **A backup contains your recovery phrase in a readable form.** Treat it exactly like the phrase itself: offline, private, never in a repository or cloud sync.

---

# Dangerous JSON

"Dangerous JSON" is a key file with the **raw, unencrypted** private keys. It exists for real needs: injecting a key into a server's secrets store, interoperating with tools that can't handle passphrase-encrypted keys, migrating between systems. It is dangerous because **anyone who can read the file controls your key**.

The CLI puts several gates in front of it:

| Gate                                         | What it does                                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `--dangerous` + `--i-understand-the-risk`    | Both flags are required. `--dangerous` alone is refused (exit `2`).                              |
| Typed confirmation                           | On a terminal you must type the **last 8 characters of the key's fingerprint**.                  |
| `--yes`                                      | Replaces the typed confirmation. **Required when not on a terminal.**                            |
| Distinct file name                           | Files end in `.dangerous.json` so they're easy to spot.                                          |
| Owner-only permissions                       | Created `0600`.                                                                                  |
| Never silent                                 | The result always says `DANGEROUS — raw private keys, unencrypted`.                              |

Where dangerous files can and can't be used:

| Command                                    | On a dangerous file |
| ------------------------------------------ | :-----------------: |
| `info`, `keys`, `label`, `export`          | Works               |
| `verify`, `passphrase`, `migrate`, `add-keys` | Rejected (exit `2`): they need an encrypted file |
| `backup`                                   | Works (needs the phrase) |

`generate --dangerous` writes **only** the dangerous file (no encrypted copy). If you want both, run `generate` normally, then `export --dangerous`.

---

# Invalid and Rejected Combinations

The CLI intentionally rejects the following. Usage errors exit with code `2` and write nothing.

| Combination                                                          | Result          | Why                                                                              |
| -------------------------------------------------------------------- | --------------- | -------------------------------------------------------------------------------- |
| `--dangerous` without `--i-understand-the-risk`                      | Usage error     | Raw private keys need explicit acknowledgement.                                  |
| `--dangerous --i-understand-the-risk` without a terminal or `--yes`  | Usage error     | A script can't answer the typed confirmation, so it must opt out explicitly.     |
| `export --contact --dangerous`                                       | Usage error     | A contact is public data; there's nothing "dangerous" to export.                 |
| `export --stdout --json`                                             | Usage error     | Both want stdout. Use one.                                                       |
| `generate --size 18` (anything but 12 or 24)                         | Usage error     | Only 12- and 24-word phrases can be generated.                                   |
| `--language <unknown>`                                               | Usage error     | Must be one of the 10 supported codes.                                           |
| `--keys <unknown>`                                                   | Usage error     | Run `keys --supported` for valid names.                                          |
| `--keys` with reserved/unsupported algorithms (HQC, FN-DSA, LMS)     | Operation error | Defined, but can't be enabled yet.                                               |
| `add-keys` without `--keys`                                          | Usage error     | Nothing to add.                                                                  |
| `keys` with no file and no `--supported`                             | Usage error     | Nothing to list.                                                                 |
| `verify`/`passphrase`/`migrate`/`add-keys` on a dangerous file       | Usage error     | They need a passphrase-encrypted file.                                           |
| `passphrase` with the same new and current passphrase                | Usage error     | Nothing would change.                                                            |
| A `.png`/`.zip` file given where a key file is expected              | Usage error     | That's a backup; use `import`.                                                   |
| `import` of a `.png` backup                                          | Operation error | The Rust edition has no PNG codec yet.                                           |
| Writing to a path that already exists, without `--overwrite`         | Operation error | The CLI never replaces files silently. (In-place edits are exempt.)              |
| `--passphrase-stdin` with an empty stdin                             | Usage error     | No passphrase was provided.                                                      |
| Wrong passphrase or wrong recovery phrase                            | Operation error | Nothing is written.                                                                |
| Recovery phrase that isn't 12/15/18/21/24 words                      | Operation error | Not a valid BIP-39 length.                                                       |

---

# Exit Codes

The CLI uses exit codes suitable for scripting and CI.

| Exit code | Meaning                                                                                              |
| --------: | ---------------------------------------------------------------------------------------------------- |
|       `0` | Success. Also `--help` and `--version`.                                                              |
|       `1` | The operation failed: wrong passphrase, unreadable file, existing output without `--overwrite`, bad phrase, … |
|       `2` | Usage error: unknown command/option, invalid value, incompatible flags, missing required option.     |
|     `130` | Cancelled by you (Ctrl-C at a prompt).                                                               |

`verify` is the one command where "failure" is a normal answer: exit `1` simply means the passphrase is wrong.

**Streams:** results go to **stdout**. Prompts, the recovery phrase, and warnings go to **stderr**. With `export --stdout`, the *data* owns stdout and the human summary moves to stderr, so a pipe receives only the data.

---

# JSON Output

Add `--json` to any command for machine-readable output:

```bash
majik-key info key.json --json
majik-key keys key.json --json
majik-key verify key.json --json
majik-key generate --json
```

Every result has `ok`, `command`, and `message`, plus command-specific fields:

```json
{
  "ok": true,
  "command": "verify",
  "message": "Passphrase is correct.",
  "valid": true,
  "fingerprint": "AbC123xy…="
}
```

Errors in JSON mode are printed to **stdout** in the same envelope, with a non-zero exit code:

```json
{
  "ok": false,
  "command": "error",
  "message": "--json cannot be combined with --stdout."
}
```

Typical automation pattern:

```bash
result=$(majik-key verify release-key.json --passphrase-stdin --json < pw.txt)
echo "$result" | jq -r '.valid'
```

```powershell
majik-key verify key.json --json
if ($LASTEXITCODE -ne 0) {
    throw "Majik Key verification failed"
}
```

---

# Common End-to-End Recipes

## 1. Create your first key

```bash
majik-key generate --label me
```

Write the phrase down, answer the 3-word quiz, and you have `majik-key-me-<fp8>.json`.

---

## 2. A 12-word key with wallets, saved somewhere specific

```bash
majik-key generate --size 12 --label ops --keys btc,eth -o ~/keys/
```

---

## 3. Back up and restore on another machine

On the original machine:

```bash
majik-key backup ./majik-key-me-AbC123xy.json -f zip -o ~/safe/
```

On the new machine (choose any new passphrase):

```bash
majik-key import ~/safe/majik-key-me-AbC123xy-backup.zip -o ./restored.json
```

Confirm it is the same account:

```bash
majik-key info ./restored.json     # same Fingerprint as the original
```

---

## 4. Rotate a passphrase

```bash
majik-key passphrase ./key.json
majik-key verify ./key.json        # now accepts only the new passphrase
```

---

## 5. Upgrade an old key

```bash
majik-key info old-key.json        # Kdf: pbkdf2 (legacy — run migrate)
majik-key migrate old-key.json
majik-key info old-key.json        # Kdf: argon2id
```

---

## 6. Add Bitcoin and Ethereum to an existing key

```bash
majik-key add-keys ./key.json --keys btc,eth
```

You'll be asked for the passphrase and the recovery phrase.

---

## 7. Share your public identity

```bash
majik-key export ./key.json --contact -o ./my-contact.json
```

Safe to send to anyone: it contains no secrets.

---

## 8. Inject a key into a server's secrets tool

```bash
MAJIK_KEY_PASSPHRASE="$KEY_PASSPHRASE" \
  majik-key export ./key.json --dangerous --i-understand-the-risk --yes --stdout \
  | your-secrets-tool put majik-key-raw -
```

Nothing is written to disk; the raw keys exist only in the pipe.

---

## 9. Generate a key in CI

```bash
export MAJIK_KEY_PASSPHRASE="$MAJIK_KEY_SECRET"
majik-key generate --size 24 --label release \
  --mnemonic-out ./secure/release.mnemonic.json \
  -o ./secure/ --json
```

Store `release.mnemonic.json` in your secrets vault immediately, then delete it from the runner.

---

## 10. Recover from a lost key file

You still have the recovery phrase:

```bash
majik-key create --label me -o ./recovered.json
# (type the phrase at the hidden prompt, then choose a new passphrase)
majik-key info ./recovered.json
```

Add the same `--keys` you used originally if you had extras.

---

# Installing and Running

| You want to…                          | Do this                                                                 |
| ------------------------------------- | ----------------------------------------------------------------------- |
| Install the command                   | `cargo install majik-key --features cli`                                |
| Install from a local checkout         | `cargo install --path . --features cli`                                 |
| Run from a checkout without installing| `cargo run --features cli --bin majik-key -- <command> [options]`       |
| Build an optimized binary             | `cargo build --release --features cli` → `./target/release/majik-key` or `./target/release/mjkkey` |
| Run the CLI's own tests               | `cargo test --features cli --test cli`                                  |
| Update                                | Re-run `cargo install majik-key --features cli --force`                 |

Why a feature? The crate is primarily a library. Keeping the CLI behind `--features cli` means projects that depend on `majik-key` (for example, a Tauri app) never compile the command-line parser. Add it to a project **without** the CLI as usual:

```toml
[dependencies]
majik-key = "1"
```

> Prompts work normally under `cargo run`. Release builds are noticeably faster at the Argon2id step; debug builds of the CLI itself are fine, because dependencies are optimized even in debug.

---

# Using the CLI from Rust Code

Everything lives in the library (behind the `cli` feature), so tools and tests can drive the real command parser without spawning a process:

```toml
[dependencies]
majik-key = { version = "1", features = ["cli"] }
```

```rust
use std::process::ExitCode;

// Includes argv[0]. Returns the exit code the binary would have returned.
let code: ExitCode = majik_key::cli::run([
    "majik-key", "generate", "--size", "12", "-o", "./keys/", "--json",
]);
```

Module layout (mirrors the TypeScript package's `cli.ts` + `cli-core/`):

| Rust                         | TypeScript            | Purpose                                              |
| ---------------------------- | --------------------- | ---------------------------------------------------- |
| `src/cli.rs`                 | `src/cli.ts`          | Command tree, "run one command" wrapper, `run()`     |
| `src/cli_core/errors.rs`     | `errors.ts`           | `CliError` with exit codes                           |
| `src/cli_core/types.rs`      | `types.ts`            | Argument structs (clap)                              |
| `src/cli_core/io.rs`         | `io.ts`               | Safe file writes, `--output` rules                   |
| `src/cli_core/prompt.rs`     | `prompt.ts`           | Hidden prompts, passphrase/phrase sources            |
| `src/cli_core/key.rs`        | `key.ts`              | Load/unlock/save keys, key-id parsing                |
| `src/cli_core/output.rs`     | `output.ts`           | Human and JSON output                                |
| `src/cli_core/operations.rs` | `operations.ts`       | One function per command                             |
| `src/bin/majik-key.rs`       | `bin` entry           | Thin `main()`                                        |

For **cryptographic operations in your own code** (encrypting, signing, deriving), use the library API (`majik_key::MajikKey`) directly; the CLI is for key management.

---

# Complete Command Cheat Sheet

| Goal                                 | Command                                                                   |
| ------------------------------------ | ------------------------------------------------------------------------- |
| Show help                            | `majik-key --help`                                                        |
| Show version                         | `majik-key --version`                                                     |
| New key (24 words)                   | `majik-key generate`                                                      |
| New key (12 words)                   | `majik-key generate --size 12`                                            |
| New key with label                   | `majik-key generate --label NAME`                                         |
| New key with wallets                 | `majik-key generate --keys btc,eth`                                       |
| New key to a folder                  | `majik-key generate -o DIR/`                                              |
| New key + phrase file                | `majik-key generate --mnemonic-out`                                       |
| New dangerous key                    | `majik-key generate --dangerous --i-understand-the-risk`                  |
| Key from an existing phrase          | `majik-key create`                                                        |
| Key from a phrase file               | `majik-key create --mnemonic-file PHRASE.json`                            |
| Restore from a backup                | `majik-key import BACKUP.{json,zip}`                                  |
| Inspect a key                        | `majik-key info KEY.json`                                                 |
| List a key's keypairs                | `majik-key keys KEY.json`                                                 |
| List supported algorithms            | `majik-key keys --supported`                                              |
| Check a passphrase                   | `majik-key verify KEY.json`                                               |
| Show label                           | `majik-key label KEY.json`                                                |
| Change label                         | `majik-key label KEY.json "New"`                                          |
| Change passphrase                    | `majik-key passphrase KEY.json`                                           |
| Upgrade legacy KDF                   | `majik-key migrate KEY.json`                                              |
| Add keypairs                         | `majik-key add-keys KEY.json --keys btc,eth`                              |
| Export normal JSON                   | `majik-key export KEY.json -o OUT.json`                                   |
| Export public contact                | `majik-key export KEY.json --contact`                                     |
| Export dangerous JSON                | `majik-key export KEY.json --dangerous --i-understand-the-risk`           |
| Export to stdout                     | `majik-key export KEY.json --contact --stdout`                            |
| Backup (JSON)                        | `majik-key backup KEY.json`                                               |
| Backup (ZIP)                         | `majik-key backup KEY.json -f zip`                                        |
| JSON output                          | Add `--json`                                                              |
| Passphrase from stdin                | Add `--passphrase-stdin`                                                  |
| Non-interactive passphrase           | Set `MAJIK_KEY_PASSPHRASE`                                                |
| Non-interactive new passphrase       | Set `MAJIK_KEY_NEW_PASSPHRASE` (for `passphrase`)                         |
| Non-interactive recovery phrase      | Set `MAJIK_KEY_MNEMONIC` or use `--mnemonic-file`                         |

---

# Troubleshooting

| You see                                                              | What it means / what to do                                                                                          |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `Incorrect passphrase, or the key file is corrupted.`                | Wrong passphrase. Check for typos and keyboard layout. If the file was edited by hand, restore it from a backup.    |
| `Output already exists: "…". Use --overwrite to replace it.`         | The CLI never replaces files silently. Pick another `-o`, or add `--overwrite` if you mean it.                      |
| `A passphrase is required, but stdin is not an interactive terminal.`| Running in a script/CI. Set `MAJIK_KEY_PASSPHRASE` or add `--passphrase-stdin`.                                     |
| `That recovery phrase does not belong to this key.`                  | The phrase is for a different account (or has a typo). Nothing was written.                                         |
| `Expected a 12, 15, 18, 21 or 24 word recovery phrase, got N`        | A word is missing or extra. Phrases are space-separated; check the file for stray characters.                       |
| `Dangerous export needs confirmation…`                               | Not on a terminal. Add `--yes` (and `--i-understand-the-risk`).                                                     |
| `"…" looks like a mnemonic backup, not a key file.`                  | You passed a `.png`/`.zip` where a key file belongs. Use `majik-key import`.                                        |
| `PNG backups can't be read by the Rust CLI yet…`                     | The Rust edition has no PNG codec. Use a `.json`/`.zip` backup, or restore the PNG with the TypeScript CLI.         |
| Generation is slow                                                   | Argon2id is deliberately expensive (about a second on modern hardware). Use a `--release` build if you're running from source. |
| `--mnemonic-out` swallowed my next argument                          | It takes an *optional* path. Put it last, or give it an explicit path.                                              |
| The passphrase prompt shows nothing as I type                        | That is intended: input is hidden. Press Enter when done.                                                           |
| PowerShell: environment variable isn't picked up                     | Use `$env:MAJIK_KEY_PASSPHRASE="…"` (Bash's `VAR=… command` prefix isn't PowerShell syntax).                        |
| `error: unexpected argument … found` / `error: the following required arguments were not provided` | A usage error from the argument parser (exit `2`). Run `majik-key <command> --help`.   |

---

# Operational Notes

### Protect the recovery phrase above everything

It regenerates every key, forever, and can't be changed. Write it on paper; keep copies offline in separate places. Never photograph it, email it, or store it in cloud notes. Use `--mnemonic-out` and `backup` only to move it into a vault you trust.

### Keep the key file and the passphrase apart

The key file is encrypted, so it's reasonable to back it up widely. Never store the passphrase next to it.

### Prefer prompts or `--passphrase-stdin` over environment variables

Environment variables can leak through process listings, crash dumps, and CI logs. A prompt or a pipe from a secrets tool leaves no trace.

### Use `--overwrite` deliberately

It permits replacing an existing output. Without it, the CLI refuses, which protects you from clobbering a key you still need.

### Dangerous JSON is a loaded tool

Delete dangerous files as soon as they've done their job, don't commit them, and prefer `--stdout` into a secrets tool over writing them to disk.

### Verify a backup before you trust it

After creating a backup, restore it somewhere harmless and compare fingerprints:

```bash
majik-key import ./backup.json -o /tmp/check.json
majik-key info /tmp/check.json      # fingerprint must match the original
```

### Pin versions in automation

```bash
cargo install majik-key --features cli --version <version> --locked
```

### Files are written owner-only

Key files, phrase files, and backups are created `0600` on systems that support permissions. Keep them that way.

---

# Summary

The most common commands are:

```bash
# New key (24 words), saved in the current directory
majik-key generate

# New key, 12 words, labelled, with wallets
majik-key generate --size 12 --label alice --keys btc,eth

# Inspect without a passphrase
majik-key info key.json
majik-key keys key.json

# Check / change the passphrase
majik-key verify key.json
majik-key passphrase key.json

# Add wallets later
majik-key add-keys key.json --keys btc,eth

# Share your public identity
majik-key export key.json --contact

# Back up and restore the recovery phrase
majik-key backup key.json -f zip
majik-key import backup.zip

# Raw keys (only when you must)
majik-key export key.json --dangerous --i-understand-the-risk

# Machine-readable output
majik-key info key.json --json
```

**Generate. Protect. Recover. Trust the Chain. Just like Majik.**
