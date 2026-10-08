//! Rust integration coverage corresponding to the TypeScript `majik-key.test.ts` suite.
//!
//! These tests exercise the public account API; frozen derivation and lower-level
//! KeyStore behavior are covered by `ts_key_impls.rs` and `ts_key_store.rs`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use majik_key::*;
use serde_json::Value;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE: &str = "TestPassphrase123!";
const NEW_PASSPHRASE: &str = "NewSecurePassphrase456!";

fn create(keys: &[KeyId]) -> MajikKey {
    MajikKey::create(
        MNEMONIC,
        PASSPHRASE,
        Some("Rust test account"),
        &MajikKeyCreateOptions {
            keys: keys.to_vec(),
            ..Default::default()
        },
    )
    .unwrap()
}

fn secret_snapshot(key: &MajikKey) -> Vec<(KeyId, Vec<u8>)> {
    key.available_keys(None)
        .into_iter()
        .filter(|id| algorithm(*id).kind == KeyKind::Stored)
        .map(|id| (id, key.get_private_key(id).unwrap().to_vec()))
        .collect()
}

#[test]
fn creation_registry_accessors_and_metadata_match_the_account() {
    let key = create(&[]);
    assert_eq!(key.id(), key.fingerprint());
    assert!(key.is_unlocked() && key.is_argon2id() && key.is_core_complete());
    assert!(key.is_fully_upgraded());
    assert_eq!(
        key.available_keys(None),
        [CORE_KEYS.as_slice(), &[KeyId::Sol]].concat()
    );
    assert!(!key.has_ethereum() && !key.has_key(KeyId::Btc));
    assert!(key.missing_keys(None).is_empty());
    assert!(key.has_keys(&[KeyId::X25519, KeyId::Ed25519, KeyId::Sol]));
    assert_eq!(key.get_public_key(KeyId::X25519).unwrap().len(), 32);
    assert_eq!(key.get_private_key(KeyId::Ed25519).unwrap().len(), 64);

    let extra = create(&[KeyId::Btc, KeyId::Eth, KeyId::MlKem1024, KeyId::MlDsa65]);
    assert!(extra.has_keys(&[KeyId::Btc, KeyId::Eth, KeyId::MlKem1024, KeyId::MlDsa65,]));
    assert_eq!(extra.get_public_key(KeyId::MlKem1024).unwrap().len(), 1568);
    assert_eq!(extra.get_private_key(KeyId::MlDsa65).unwrap().len(), 4032);
    assert_eq!(extra.get_ethereum_address().unwrap().len(), 42);

    let metadata = extra.metadata();
    assert_eq!(metadata.id, extra.id());
    assert_eq!(metadata.fingerprint, extra.fingerprint());
    assert_eq!(metadata.label, "Rust test account");
    assert_eq!(metadata.web3.has_bitcoin, Some(true));
    assert_eq!(metadata.web3.has_ethereum, Some(true));
    assert_eq!(metadata.web3.has_solana, Some(true));
    assert_eq!(metadata.keys.unwrap(), extra.available_keys(None));

    let listed = extra.list_keys();
    assert_eq!(listed.len(), extra.available_keys(None).len());
    for info in listed {
        assert_eq!(info.family, algorithm(info.id).family);
        assert_eq!(info.kind, algorithm(info.id).kind);
        assert!(info.public_key_base64.is_some());
    }
    assert!(MajikKey::supported_keys().contains(&KeyId::Eth));
    assert!(!MajikKey::supported_keys().contains(&KeyId::Hqc128));
}

#[test]
fn lock_unlock_and_verify_are_atomic() {
    let mut key = create(&[KeyId::Eth, KeyId::Btc]);
    let before = secret_snapshot(&key);
    key.lock();
    key.lock();
    assert!(key.is_locked());
    assert!(key.get_public_key(KeyId::Eth).is_ok());
    assert!(key.get_private_key(KeyId::Eth).is_err());
    assert!(key.get_public_key(KeyId::Sol).is_err());
    assert!(key.web3().is_none());

    assert!(key.verify(PASSPHRASE));
    assert!(!key.verify("wrong passphrase"));
    assert!(key.is_locked());
    assert!(key.unlock("wrong passphrase").is_err());
    assert!(key.is_locked());

    key.unlock(PASSPHRASE).unwrap();
    assert_eq!(secret_snapshot(&key), before);
    assert!(key.unlock(PASSPHRASE).is_err());

    let mut auto = create(&[]);
    let result = auto
        .with_auto_lock(|account| account.get_solana_address(None).unwrap())
        .unwrap();
    assert!(!result.is_empty());
    assert!(auto.is_locked());
    auto.unlock(PASSPHRASE).unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = auto.with_auto_lock(|_| panic!("operation failed"));
    }));
    assert!(panicked.is_err());
    assert!(auto.is_locked());
}

#[test]
fn safe_json_roundtrips_registry_and_migrates_legacy_shape() {
    let key = create(&[KeyId::Eth, KeyId::MlKem1024]);
    let original_secrets = secret_snapshot(&key);
    let json = key.to_json();
    let encoded = serde_json::to_string(&json).unwrap();
    for (_, secret) in &original_secrets {
        assert!(!encoded.contains(&B64.encode(secret)));
    }
    assert!(!encoded.contains("secretKeys") && !encoded.contains("privateKeyBase64"));

    let mut restored = MajikKey::from_json_str(&encoded).unwrap();
    assert!(restored.is_locked());
    assert_eq!(restored.available_keys(None), key.available_keys(None));
    restored.unlock(PASSPHRASE).unwrap();
    assert_eq!(secret_snapshot(&restored), original_secrets);

    let lean = key.to_json_with(&MajikKeyToJsonOptions { legacy: false });
    let lean_value = serde_json::to_value(&lean).unwrap();
    assert!(lean_value.get("encryptedMlKemSecretKey").is_none());
    assert!(lean_value.get("keys").is_some());
    assert!(MajikKey::from_json_str(&lean_value.to_string()).is_ok());

    let mut legacy = json;
    legacy.keys = None;
    legacy.keys_version = None;
    let migrated = MajikKey::from_json(&legacy).unwrap();
    assert_eq!(
        migrated.available_keys(None),
        vec![
            KeyId::X25519,
            KeyId::Ed25519,
            KeyId::MlKem768,
            KeyId::MlDsa87,
            KeyId::Sol,
        ]
    );
    assert!(migrated.is_core_complete());

    let mut invalid: Value = serde_json::from_str(&encoded).unwrap();
    invalid["publicKey"] = "AAAA".into();
    assert!(MajikKey::from_json_str(&invalid.to_string()).is_err());
    invalid["publicKey"] = json_public_key(&key);
    invalid["keysVersion"] = 99.into();
    assert!(MajikKey::from_json_str(&invalid.to_string()).is_err());
}

fn json_public_key(key: &MajikKey) -> Value {
    Value::String(B64.encode(key.get_public_key(KeyId::X25519).unwrap()))
}

#[test]
fn dangerous_json_roundtrips_every_secret_and_rejects_locked_export() {
    let key = create(&[KeyId::Btc, KeyId::Eth, KeyId::MlKem1024]);
    let before = secret_snapshot(&key);
    let exported = key.to_dangerous_json().unwrap();
    assert_eq!(exported.secret_keys.as_ref().unwrap().len(), before.len());

    let restored = MajikKey::from_dangerous_json(&exported).unwrap();
    assert!(restored.is_unlocked());
    assert_eq!(secret_snapshot(&restored), before);
    assert_eq!(
        restored.get_ethereum_address().unwrap(),
        key.get_ethereum_address().unwrap()
    );

    let locked = MajikKey::from_json(&key.to_json()).unwrap();
    assert!(locked.to_dangerous_json().is_err());

    let mut incomplete = exported;
    incomplete.private_key_base64.clear();
    assert!(MajikKey::from_dangerous_json(&incomplete).is_err());
}

#[test]
fn mnemonic_json_and_backup_restore_identity_and_language() {
    let japanese = MajikKey::generate_mnemonic(128, MnemonicLanguage::Ja).unwrap();
    let japanese_key = MajikKey::create(
        &japanese,
        PASSPHRASE,
        Some("Japanese phrase"),
        &MajikKeyCreateOptions {
            mnemonic_language: Some(MnemonicLanguage::Ja),
            ..Default::default()
        },
    )
    .unwrap();
    let japanese_export = japanese_key.to_mnemonic_json(&japanese, None).unwrap();
    assert_eq!(japanese_export.language, Some(MnemonicLanguage::Ja));
    let japanese_restored =
        MajikKey::from_mnemonic_json(&japanese_export, NEW_PASSPHRASE, None, &Default::default())
            .unwrap();
    assert_eq!(japanese_restored.mnemonic_language(), MnemonicLanguage::Ja);
    assert_eq!(japanese_restored.id(), japanese_key.id());

    let english = create(&[]);
    let exported = english
        .to_mnemonic_json(MNEMONIC, Some(PASSPHRASE))
        .unwrap();
    assert_eq!(exported.seed.len(), 12);
    assert_eq!(exported.id, english.backup());
    assert_eq!(exported.phrase.as_deref(), Some(PASSPHRASE));
    let recovered =
        MajikKey::from_mnemonic_json(&exported, NEW_PASSPHRASE, None, &Default::default()).unwrap();
    assert_eq!(recovered.fingerprint(), english.fingerprint());
    assert!(recovered.verify(NEW_PASSPHRASE));

    let backup = english.export_mnemonic_backup(MNEMONIC).unwrap();
    let restored = MajikKey::import_from_mnemonic_backup(
        &backup,
        MNEMONIC,
        NEW_PASSPHRASE,
        Some("Recovered"),
        &MajikKeyCreateOptions {
            keys: vec![KeyId::Eth],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(restored.fingerprint(), english.fingerprint());
    assert!(restored.has_ethereum() && restored.is_unlocked());
    assert!(MajikKey::import_from_mnemonic_backup(
        &backup,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        NEW_PASSPHRASE,
        None,
        &Default::default(),
    )
    .is_err());
}

#[test]
fn passphrase_rotation_and_add_keys_preserve_state_on_failure() {
    let mut key = create(&[]);
    let before = secret_snapshot(&key);
    let json_before = serde_json::to_value(key.to_json()).unwrap();
    assert!(key
        .update_passphrase("wrong current", NEW_PASSPHRASE)
        .is_err());
    assert_eq!(serde_json::to_value(key.to_json()).unwrap(), json_before);

    key.update_passphrase(PASSPHRASE, NEW_PASSPHRASE).unwrap();
    assert!(!key.verify(PASSPHRASE) && key.verify(NEW_PASSPHRASE));
    assert_eq!(secret_snapshot(&key), before);

    assert!(key.add_keys(&[KeyId::Eth], MNEMONIC, PASSPHRASE).is_err());
    assert!(key
        .add_keys(
            &[KeyId::Eth],
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            NEW_PASSPHRASE
        )
        .is_err());
    assert!(!key.has_ethereum());
    assert_eq!(
        key.add_keys(
            &[KeyId::Eth, KeyId::Eth, KeyId::Sol],
            MNEMONIC,
            NEW_PASSPHRASE
        )
        .unwrap(),
        vec![KeyId::Eth]
    );
    assert!(key.get_private_key(KeyId::Eth).is_ok());

    key.lock();
    assert_eq!(
        key.add_keys(&[KeyId::MlDsa44], MNEMONIC, NEW_PASSPHRASE)
            .unwrap(),
        vec![KeyId::MlDsa44]
    );
    assert!(key.is_locked() && key.get_private_key(KeyId::MlDsa44).is_err());
    key.unlock(NEW_PASSPHRASE).unwrap();
    assert_eq!(key.get_private_key(KeyId::MlDsa44).unwrap().len(), 2560);
}
