//! Port of `core/keys/registry.ts` — the table of every algorithm the registry knows.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde_json::Map;

use crate::core::error::{MajikKeyError, MajikKeyResult};
use crate::core::keys::key_id::{key_family_of, KeyFamily, KeyId, CORE_KEYS};
use crate::core::keys::types::{
    KeyAlgorithmDefinition, KeyDerivation, KeyKind, KeyPurpose, KeyStatus,
};

fn hkdf(id: KeyId) -> KeyDerivation {
    KeyDerivation {
        scheme: "hkdf-sha512-v1".into(),
        version: 1,
        info: Some(format!("majik/v1/{}", id.as_str())),
        path: None,
        note: None,
        extra: Map::new(),
    }
}

fn legacy(note: Option<&str>) -> KeyDerivation {
    KeyDerivation {
        scheme: "legacy-v1".into(),
        version: 1,
        info: None,
        path: None,
        note: note.map(str::to_string),
        extra: Map::new(),
    }
}

fn bip32(path: &str, note: &str) -> KeyDerivation {
    KeyDerivation {
        scheme: "bip32".into(),
        version: 1,
        info: None,
        path: Some(path.into()),
        note: Some(note.into()),
        extra: Map::new(),
    }
}

#[derive(Default)]
struct Opts {
    kind: Option<KeyKind>,
    status: Option<KeyStatus>,
    implemented: bool,
    derived_from: Option<KeyId>,
    note: Option<&'static str>,
}

fn def(
    id: KeyId,
    purpose: KeyPurpose,
    standard: &str,
    derivation: KeyDerivation,
    o: Opts,
) -> KeyAlgorithmDefinition {
    KeyAlgorithmDefinition {
        id,
        family: key_family_of(id),
        purpose,
        kind: o.kind.unwrap_or(KeyKind::Stored),
        status: o.status.unwrap_or(KeyStatus::Stable),
        implemented: o.implemented,
        standard: standard.into(),
        derivation,
        derived_from: o.derived_from,
        note: o.note.map(str::to_string),
    }
}

fn implemented() -> Opts {
    Opts {
        implemented: true,
        ..Opts::default()
    }
}

fn slh(id: KeyId, variant: &str) -> KeyAlgorithmDefinition {
    def(
        id,
        KeyPurpose::Signature,
        &format!("FIPS 205 ({variant})"),
        hkdf(id),
        implemented(),
    )
}

pub static KEY_ALGORITHMS: LazyLock<BTreeMap<KeyId, KeyAlgorithmDefinition>> = LazyLock::new(
    || {
        use KeyId::*;
        use KeyPurpose::*;
        let reserved = |note: &'static str| Opts {
            status: Some(KeyStatus::Reserved),
            note: Some(note),
            ..Opts::default()
        };

        let defs = vec![
        // ── classic ── (legacy recipes are frozen)
        def(X25519, KeyAgreement, "RFC 7748",
            KeyDerivation { scheme: "ed2curve".into(), version: 1, info: None, path: None,
                note: Some("ed2curve(classic:ed25519); account id/fingerprint anchor".into()), extra: Map::new() },
            implemented()),
        def(Ed25519, Signature, "RFC 8032", legacy(Some("BIP-39 seed[0..32]")), implemented()),

        // ── pq KEM ──
        def(MlKem512, Kem, "FIPS 203", hkdf(MlKem512), implemented()),
        def(MlKem768, Kem, "FIPS 203", legacy(Some("full 64-byte BIP-39 seed")), implemented()),
        def(MlKem1024, Kem, "FIPS 203", hkdf(MlKem1024), implemented()),
        def(Hqc128, Kem, "NIST HQC (draft)", hkdf(Hqc128),
            reserved("NIST backup KEM; standard not final and no vetted implementation in the current dependency set.")),
        def(Hqc192, Kem, "NIST HQC (draft)", hkdf(Hqc192), reserved("See pq:hqc-128.")),
        def(Hqc256, Kem, "NIST HQC (draft)", hkdf(Hqc256), reserved("See pq:hqc-128.")),

        // ── pq signatures ──
        def(MlDsa44, Signature, "FIPS 204", hkdf(MlDsa44), implemented()),
        def(MlDsa65, Signature, "FIPS 204", hkdf(MlDsa65), implemented()),
        def(MlDsa87, Signature, "FIPS 204", legacy(Some("sha256(seed64 || \"MajikSignatureSeedDSA\")")), implemented()),

        slh(SlhDsaSha2_128s, "SHA2-128s"), slh(SlhDsaSha2_128f, "SHA2-128f"),
        slh(SlhDsaSha2_192s, "SHA2-192s"), slh(SlhDsaSha2_192f, "SHA2-192f"),
        slh(SlhDsaSha2_256s, "SHA2-256s"), slh(SlhDsaSha2_256f, "SHA2-256f"),
        slh(SlhDsaShake128s, "SHAKE-128s"), slh(SlhDsaShake128f, "SHAKE-128f"),
        slh(SlhDsaShake192s, "SHAKE-192s"), slh(SlhDsaShake192f, "SHAKE-192f"),
        slh(SlhDsaShake256s, "SHAKE-256s"), slh(SlhDsaShake256f, "SHAKE-256f"),

        // Falcon: derivable in the TS lib only (see key_impls.rs). `implemented: false` here
        // means "this crate cannot derive it"; stored Falcon entries still round-trip.
        def(Falcon512, Signature, "Falcon (NIST PQC Round 3)", hkdf(Falcon512),
            Opts { status: Some(KeyStatus::Experimental), implemented: false,
                note: Some("Round 3 Falcon, NOT FIPS 206. Derivable in the TS library only: no pure-Rust crate reproduces \
                    @noble/post-quantum's Round-3 keygen byte-for-byte. Keys created by TS still load/unlock/re-encrypt here."),
                ..Opts::default() }),
        def(Falcon1024, Signature, "Falcon (NIST PQC Round 3)", hkdf(Falcon1024),
            Opts { status: Some(KeyStatus::Experimental), implemented: false, note: Some("See pq:falcon-512."), ..Opts::default() }),
        def(FnDsa512, Signature, "FIPS 206 (draft)", hkdf(FnDsa512),
            reserved("Reserved until FIPS 206 is final and an implementation tracks it.")),
        def(FnDsa1024, Signature, "FIPS 206 (draft)", hkdf(FnDsa1024), reserved("See pq:fn-dsa-512.")),

        def(Lms, Signature, "NIST SP 800-208 / RFC 8554", hkdf(Lms),
            Opts { status: Some(KeyStatus::Unsupported), note: Some(
                "Stateful: every signature consumes a one-time key index. Mnemonic recovery, backups and multi-device use \
                 all reset that state and make one-time-key reuse (total forgery) likely. Not offered as a stored signing key."),
                ..Opts::default() }),

        // ── web3 ──
        def(Btc, Wallet, "BIP-32 / BIP-84", bip32("m/84'/1971'/0'/0/0", "Majik domain-separated path (legacy default)"), implemented()),
        def(Eth, Wallet, "BIP-32 / BIP-44 (SLIP-44 coin 60)", bip32("m/44'/60'/0'/0/0", "Standard path: MetaMask-compatible"), implemented()),
        def(Sol, Wallet, "Ed25519 (Solana)",
            KeyDerivation { scheme: "derived-view".into(), version: 1, info: None, path: None,
                note: Some("sha256(edSeed || \"MajikKeySolanaSeed\")".into()), extra: Map::new() },
            Opts { kind: Some(KeyKind::Derived), derived_from: Some(Ed25519), implemented: true, ..Opts::default() }),
    ];
        defs.into_iter().map(|d| (d.id, d)).collect()
    },
);

/// The registry entry for `id`.
pub fn algorithm(id: KeyId) -> &'static KeyAlgorithmDefinition {
    KEY_ALGORITHMS
        .get(&id)
        .expect("every KeyId has a registry entry")
}

/// Look up by wire string; `None` for ids this version doesn't know.
pub fn get_algorithm(id: &str) -> Option<&'static KeyAlgorithmDefinition> {
    KeyId::parse(id).map(algorithm)
}

/// Everything the registry knows, in canonical order (includes reserved/unsupported).
pub fn known_key_ids(family: Option<KeyFamily>) -> Vec<KeyId> {
    KeyId::ALL
        .iter()
        .copied()
        .filter(|id| family.is_none_or(|f| key_family_of(*id) == f))
        .collect()
}

/// Ids that can actually be enabled today.
pub fn enableable_key_ids() -> Vec<KeyId> {
    KeyId::ALL
        .iter()
        .copied()
        .filter(|id| {
            let d = algorithm(*id);
            d.implemented && matches!(d.status, KeyStatus::Stable | KeyStatus::Experimental)
        })
        .collect()
}

/// Validate a caller's requested keys and return the STORED key ids to create:
/// `CORE_KEYS ∪ requested`, de-duplicated, canonical order. Derived views
/// (e.g. `web3:sol`) are accepted as no-ops because they require a stored key
/// that is already in the core set.
pub fn resolve_requested_keys(requested: &[KeyId]) -> MajikKeyResult<Vec<KeyId>> {
    let mut stored: std::collections::BTreeSet<KeyId> = CORE_KEYS.into_iter().collect();
    for &id in requested {
        let d = algorithm(id);
        match d.status {
            KeyStatus::Unsupported => {
                return Err(MajikKeyError::msg(format!(
                    "\"{id}\" is not supported: {}",
                    d.note.as_deref().unwrap_or("")
                )))
            }
            KeyStatus::Reserved => {
                return Err(MajikKeyError::msg(format!(
                    "\"{id}\" is reserved and cannot be enabled yet: {}",
                    d.note.as_deref().unwrap_or("")
                )))
            }
            _ => {}
        }
        if !d.implemented {
            return Err(MajikKeyError::msg(format!(
                "\"{id}\" is defined but not implemented in this version"
            )));
        }
        if d.kind == KeyKind::Derived {
            if let Some(src) = d.derived_from {
                stored.insert(src);
            }
            continue;
        }
        stored.insert(id);
    }
    Ok(stored.into_iter().collect()) // BTreeSet<KeyId> iterates in canonical order
}

/// Same as [`resolve_requested_keys`] but for wire strings (rejects unknown ids).
pub fn resolve_requested_key_strs(requested: &[&str]) -> MajikKeyResult<Vec<KeyId>> {
    let ids = requested
        .iter()
        .map(|s| s.parse::<KeyId>())
        .collect::<MajikKeyResult<Vec<_>>>()?;
    resolve_requested_keys(&ids)
}
