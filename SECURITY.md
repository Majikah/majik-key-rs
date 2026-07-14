# Security Policy

Majik Key handles private key material for the Majikah ecosystem. We take reports of security issues seriously and appreciate the work of anyone who takes the time to responsibly disclose one.

This document covers how to report a vulnerability, what's in and out of scope, and an honest summary of the library's current security architecture and known limitations.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately by emailing:

**business@majikah.solutions**

Please include, as applicable:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a minimal proof-of-concept
- The affected version(s) or commit hash
- Whether you believe the issue is in Majik Key itself, or in one of its dependencies

We will acknowledge receipt of your report as soon as we're able, and aim to keep you updated as we investigate. Response and remediation times depend on severity and complexity, so we can't commit to a fixed SLA here — if you need a specific timeline commitment for coordinated disclosure, say so in your initial report and we'll do our best to accommodate it.

We ask that you give us a reasonable opportunity to investigate and address a report before any public disclosure. We don't currently operate a paid bug bounty program.

---

## Supported Versions

Majik Key is under active development. Until a formal LTS/support policy is published, please assume that **only the latest published version on npm** receives security fixes, and update accordingly. If you're running an older version and are unsure whether a known issue affects you, ask via the contact above.

---

## Scope

**In scope:**
- The `@majikah/majik-key` package itself: key derivation, encryption/decryption logic, KDF implementation, serialization formats, and the public API surface.
- Misuse-resistant design issues — e.g. an API that makes it easy to accidentally leak key material.

**Out of scope (but still worth reporting responsibly if found):**
- Vulnerabilities in upstream dependencies (`@scure/bip39`, `@noble/*`, `@stablelib/*`, `hash-wasm`, `ed2curve`, etc.) — please also report these upstream.
- Vulnerabilities in the optional Web3 peer dependencies (`@scure/btc-signer`, `@solana/kit`).
- Issues that require an already-compromised runtime (e.g. a malicious browser extension with full page access, or a rooted/jailbroken device with a compromised OS) to exploit. We're still interested in hearing about these, but they're a different risk class than a flaw in this library's own logic.
- Social engineering, or vulnerabilities in downstream applications that misuse the API in ways the documentation explicitly warns against (see "Known Limitations" below).

---

## Security Architecture Summary

For full detail, see the [README](./README.md). Short version, for anyone triaging a report:

- **Encryption at rest, not hashing.** Private keys (X25519, ML-KEM-768, Ed25519, ML-DSA-87, and the default Bitcoin key) are never stored in plaintext. Each is encrypted with **AES-256-GCM**, using a key derived from the account passphrase via **Argon2id** (64 MB memory / 3 iterations / 4 parallel lanes).
- **Argon2id implementation.** WASM-accelerated (`hash-wasm`) when available in the runtime, with an automatic fallback to a pure-JS implementation (`@noble/hashes`) if WASM is unavailable or fails at runtime. Output is bit-identical between the two, so this fallback never silently weakens the derived key.
- **Legacy KDF (v1).** Older accounts encrypted with PBKDF2-SHA256 can still be unlocked for backward compatibility. New accounts, and any account whose passphrase is changed, are always encrypted under Argon2id (v2). If you're auditing an account, check `kdfVersion`/`isArgon2id` before assuming the stronger KDF is in use.
- **Post-quantum posture.** ML-KEM-768 (FIPS-203) and ML-DSA-87 (FIPS-204) are included alongside their classical counterparts (X25519, Ed25519) on every new account. This is a defense-in-depth posture against future quantum attacks on the classical primitives, not a claim that the classical primitives are currently broken.
- **No network calls during key generation or derivation.** Everything is computed locally, verifiable directly in source.
- **One Ed25519 keypair, two roles.** The account's X25519 identity/encryption key is derived by converting the same Ed25519 keypair used for message signing (via `ed2curve`), not generated independently. This is an intentional design choice, not a bug — but it means the two roles are not cryptographically independent of each other, only domain-separated by the conversion.

---

## Known Limitations & Honest Caveats

We'd rather you read this here than discover it the hard way:

- **JavaScript cannot guarantee memory is wiped.** `lock()` drops references to decrypted key material so it becomes eligible for garbage collection, but this library cannot force immediate, guaranteed erasure of that memory (no `mlock`-equivalent, no guaranteed zeroing). Treat `lock()` as "best-effort minimization of exposure window," not as a hard security boundary against, e.g., a memory-dumping attacker who is already running arbitrary code in the same process.
- **`toMnemonicJSON()` is a plaintext export, not a safe-storage format.** Unlike `toJSON()`/`toString()` (which never contain raw key material), `toMnemonicJSON()` embeds the raw mnemonic words — and, if supplied, the passphrase — in plaintext. It exists as a transport convenience, not an at-rest format. Storing its output unencrypted is equivalent to storing the mnemonic itself unencrypted.
- **`toDangerousJSON()` / `fromDangerousJSON()` skip encryption entirely by design.** No KDF, no AES-GCM — instant reconstruction of a fully unlocked key from raw bytes. This exists for one narrow, intentional use case: injecting a pre-unlocked signing key into a trusted server process from a secrets manager at boot. It is not intended for anything that touches a client, a database, a log, or the network. Misuse of this API is a design trade-off we've made deliberately, not a bug — but we're glad to hear feedback on it.
- **Web3 (Bitcoin/Solana) support is explicitly experimental.** The `web3` namespace, its Bitcoin/Solana derivation paths, and related methods are marked `@experimental` throughout the codebase and may change without a major version bump. Bitcoin key derivation happens by default on every new account (BIP-32/84, domain-separated path); Solana key material is derived on demand from the Ed25519 signing key. If you're relying on either for production custody of real funds, review the derivation paths and threat model carefully — this code has had less scrutiny than the core identity/signing/encryption paths.
- **This library has not undergone a public, independent third-party security audit as of this writing.** If that changes, this section will be updated with a link to the report. Until then, treat the cryptographic design as reviewed by the maintainers and the open-source community, not as formally audited.
- **Passphrase strength is the caller's responsibility.** Argon2id makes brute-forcing a weak passphrase slower, not impossible. This library validates passphrase presence/format but cannot enforce entropy — choose (or require your users to choose) a strong, unique passphrase.
- **A lost mnemonic is unrecoverable, by design.** There is no backdoor, master key, or recovery mechanism. This is the intended security model for a self-custodial identity library, but it means user error (losing the mnemonic) has the same practical outcome as a successful attack (permanent loss of access).

---

## Coordinated Disclosure

We follow standard coordinated disclosure practice: we ask for the opportunity to investigate and ship a fix before any details are made public, and we're happy to credit reporters (by name, handle, or anonymously — your choice) in release notes once a fix ships, unless you'd prefer not to be mentioned at all.

Thank you for helping keep Majik Key and the Majikah ecosystem safe.

---

**Contact:** [business@majikah.solutions](mailto:business@majikah.solutions)