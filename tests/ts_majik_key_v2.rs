//! Rust counterparts to TypeScript `majik-key-v2.test.ts`.
//! Focuses on registry-era accounts, legacy KDF migration, and TS JSON compatibility.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use majik_key::*;
use serde_json::Value;
use std::sync::OnceLock;

fn vectors() -> &'static Value {
    static VECTORS: OnceLock<Value> = OnceLock::new();
    VECTORS.get_or_init(|| serde_json::from_str(include_str!("vectors/ts-vectors.json")).unwrap())
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap()
}

#[test]
fn legacy_pbkdf2_account_unlocks_migrates_and_accepts_additions() {
    let fixture = &vectors()["legacyAccount"];
    let mut key = MajikKey::from_json_str(&fixture["json"].to_string()).unwrap();
    assert_eq!(key.kdf_version(), KdfVersion::Pbkdf2);
    assert!(key.unlock(string(&fixture["passphrase"])).is_ok());

    for (id, secret) in fixture["secrets"].as_object().unwrap() {
        let expected = B64.decode(string(secret)).unwrap();
        assert_eq!(
            &key.get_private_key(id.parse().unwrap()).unwrap()[..],
            &expected[..],
            "{id}"
        );
    }

    let mnemonic = string(&vectors()["account"]["mnemonic"]);
    assert!(key
        .add_keys(&[KeyId::Eth], mnemonic, string(&fixture["passphrase"]))
        .is_err());
    key.migrate(string(&fixture["passphrase"])).unwrap();
    assert!(key.is_argon2id());
    assert_eq!(
        key.add_keys(
            &[KeyId::MlKem512, KeyId::Eth],
            mnemonic,
            string(&fixture["passphrase"])
        )
        .unwrap(),
        vec![KeyId::MlKem512, KeyId::Eth]
    );

    let reloaded =
        MajikKey::from_json_str(&serde_json::to_string(&key.to_json()).unwrap()).unwrap();
    let mut reloaded = reloaded;
    reloaded.unlock(string(&fixture["passphrase"])).unwrap();
    assert_eq!(
        &reloaded.get_private_key(KeyId::MlKem512).unwrap()[..],
        &B64.decode(string(
            &vectors()["mnemonics"][0]["keys"]["pq:ml-kem-512"]["sec"]
        ))
        .unwrap()[..]
    );
}

#[test]
fn ts_registry_account_roundtrips_and_passphrase_rotation_preserves_secrets() {
    let account = &vectors()["account"];
    let mut key = MajikKey::from_json_str(&account["json"].to_string()).unwrap();
    let original: Vec<(String, Vec<u8>)> = account["secrets"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, secret)| (id.clone(), B64.decode(string(secret)).unwrap()))
        .collect();

    key.unlock(string(&account["passphrase"])).unwrap();
    key.update_passphrase(string(&account["passphrase"]), "new passphrase 123!")
        .unwrap();
    assert!(!key.verify(string(&account["passphrase"])));
    assert!(key.verify("new passphrase 123!"));

    let mut restored = MajikKey::from_json(&key.to_json()).unwrap();
    restored.unlock("new passphrase 123!").unwrap();
    for (id, expected) in &original {
        assert_eq!(
            &restored.get_private_key(id.parse().unwrap()).unwrap()[..],
            &expected[..],
            "{id}"
        );
    }

    let mut tampered = account["json"].clone();
    let duplicate = tampered["keys"][0].clone();
    tampered["keys"].as_array_mut().unwrap().push(duplicate);
    assert!(MajikKey::from_json_str(&tampered.to_string()).is_err());

    let mut future_schema = account["json"].clone();
    future_schema["keysVersion"] = 99.into();
    assert!(MajikKey::from_json_str(&future_schema.to_string()).is_err());
}

#[test]
fn registry_only_and_legacy_json_are_both_readable() {
    let account = &vectors()["account"];
    let mut registry_only = MajikKey::from_json_str(&account["json"].to_string()).unwrap();
    registry_only
        .unlock(string(&account["passphrase"]))
        .unwrap();
    let slim =
        serde_json::to_value(registry_only.to_json_with(&MajikKeyToJsonOptions { legacy: false }))
            .unwrap();
    assert!(slim.get("keys").is_some());
    assert!(slim.get("encryptedMlKemSecretKey").is_none());
    assert!(MajikKey::from_json_str(&slim.to_string()).is_ok());

    let mut legacy = account["json"].clone();
    legacy.as_object_mut().unwrap().remove("keys");
    legacy.as_object_mut().unwrap().remove("keysVersion");
    let migrated = MajikKey::from_json_str(&legacy.to_string()).unwrap();
    assert!(migrated.is_core_complete());
    assert!(!migrated.has_key(KeyId::Eth));
    assert!(migrated.has_key(KeyId::Btc));
}

#[test]
fn unknown_future_keys_survive_parse_serialize_but_block_rotation() {
    let account = &vectors()["account"];
    let mut json = account["json"].clone();
    let future = serde_json::json!({
        "id": "pq:future-kem-9000",
        "publicKey": "AAAA",
        "encryptedSecretKey": "BBBB",
        "derivation": {"scheme": "future", "version": 9},
        "custom": true
    });
    json["keys"].as_array_mut().unwrap().push(future.clone());

    let mut key = MajikKey::from_json_str(&json.to_string()).unwrap();
    let serialized = serde_json::to_value(key.to_json()).unwrap();
    assert_eq!(
        serialized["keys"].as_array().unwrap().last().unwrap(),
        &future
    );
    assert!(!key.has_key(KeyId::Falcon512));
    key.unlock(string(&account["passphrase"])).unwrap();
    assert!(key
        .update_passphrase(string(&account["passphrase"]), "new passphrase")
        .is_err());

    json["keysVersion"] = 99.into();
    assert!(MajikKey::from_json_str(&json.to_string()).is_err());
}
