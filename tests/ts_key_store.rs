//! Rust counterparts to TypeScript `key-store.test.ts`.

use majik_key::*;
use serde_json::json;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const IDS: [KeyId; 5] = [
    KeyId::X25519,
    KeyId::Ed25519,
    KeyId::MlKem768,
    KeyId::MlDsa87,
    KeyId::Btc,
];

fn fresh(aes_key: &[u8; 32]) -> KeyStore {
    let seed = mnemonic_to_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        MnemonicLanguage::En,
    )
    .unwrap();
    let derived = derive_keys(&seed[..], &IDS).unwrap();
    KeyStore::from_derived(&derived, aes_key).unwrap()
}

#[test]
fn entries_roundtrip_locked_then_unlocks_every_secret() {
    let aes_key = [7u8; 32];
    let original = fresh(&aes_key);
    assert!(original.is_unlocked());

    let mut restored = KeyStore::from_entries(&original.to_entries()).unwrap();
    assert!(!restored.is_unlocked());
    assert!(restored.get_secret_key(KeyId::Ed25519).is_err());
    restored.unlock(&VaultKeys::uniform(&aes_key)).unwrap();
    assert!(restored.is_unlocked());

    for id in IDS {
        assert_eq!(
            restored.get_public_key(id).unwrap(),
            original.get_public_key(id).unwrap()
        );
        assert_eq!(
            restored.get_secret_key(id).unwrap(),
            original.get_secret_key(id).unwrap()
        );
    }
    assert_eq!(restored.ids(), IDS);
}

#[test]
fn failed_unlock_is_atomic_and_lock_discards_secret_access() {
    let good_key = [3u8; 32];
    let bad_key = [9u8; 32];
    let mut store = KeyStore::from_entries(&fresh(&good_key).to_entries()).unwrap();

    assert!(store.unlock(&VaultKeys::uniform(&bad_key)).is_err());
    assert!(!store.is_unlocked());
    for id in IDS {
        assert!(store.get_secret_key(id).is_err());
    }

    store.unlock(&VaultKeys::uniform(&good_key)).unwrap();
    store.lock();
    assert!(!store.is_unlocked());
    for id in IDS {
        assert!(store.get_secret_key(id).is_err());
        assert!(store.get_public_key(id).is_ok());
    }
}

#[test]
fn reseal_prepares_without_mutation_and_commits_new_blobs() {
    let old_key = [1u8; 32];
    let new_key = [2u8; 32];
    let mut store = fresh(&old_key);
    let entries_before = store.to_entries();
    let prepared = store
        .prepare_reseal(&VaultKeys::uniform(&old_key), &new_key)
        .unwrap();
    assert_eq!(store.to_entries(), entries_before);

    store.commit_reseal(prepared);
    store.lock();
    assert!(store.unlock(&VaultKeys::uniform(&old_key)).is_err());
    assert!(!store.is_unlocked());
    store.unlock(&VaultKeys::uniform(&new_key)).unwrap();
    assert_eq!(store.get_secret_key(KeyId::Ed25519).unwrap().len(), 64);
}

#[test]
fn legacy_fields_roundtrip_and_incomplete_accounts_are_supported() {
    let key = [4u8; 32];
    let source = fresh(&key);
    let legacy = source.to_legacy_json();
    let mut restored = KeyStore::from_legacy_json(&legacy).unwrap();
    assert_eq!(restored.ids(), IDS);
    assert_eq!(restored.to_legacy_json().public_key, legacy.public_key);

    let minimal = LegacyKeyJson {
        public_key: legacy.public_key.clone(),
        encrypted_private_key: legacy.encrypted_private_key.clone(),
        ..Default::default()
    };
    let minimal_store = KeyStore::from_legacy_json(&minimal).unwrap();
    assert_eq!(minimal_store.ids(), vec![KeyId::X25519]);
    assert!(KeyStore::from_legacy_json(&LegacyKeyJson::default()).is_err());

    restored.unlock(&VaultKeys::uniform(&key)).unwrap();
    assert_eq!(
        restored.get_secret_key(KeyId::X25519).unwrap(),
        source.get_secret_key(KeyId::X25519).unwrap()
    );
}

#[test]
fn unknown_entries_are_preserved_but_prevent_resealing() {
    let aes_key = [8u8; 32];
    let mut entries = fresh(&aes_key).to_entries();
    let future: KeyEntryJson = serde_json::from_value(json!({
        "id": "pq:future-kem-9000",
        "publicKey": "AAAA",
        "encryptedSecretKey": "BBBB",
        "derivation": {"scheme": "future", "version": 9},
        "newEntryField": {"preserve": true}
    }))
    .unwrap();
    entries.push(future.clone());

    let mut store = KeyStore::from_entries(&entries).unwrap();
    assert_eq!(store.to_entries().last().unwrap(), &future);
    assert!(store.has_opaque_secrets());
    assert!(store
        .prepare_reseal(&VaultKeys::uniform(&aes_key), &[5; 32])
        .is_err());
    store.unlock(&VaultKeys::uniform(&aes_key)).unwrap();
    assert!(store.is_unlocked());
}

#[test]
fn duplicate_malformed_and_unknown_secret_ids_are_rejected() {
    let mut entries = fresh(&[6u8; 32]).to_entries();
    entries.push(entries[0].clone());
    assert!(KeyStore::from_entries(&entries).is_err());

    let malformed = KeyEntryJson {
        id: String::new(),
        public_key: String::new(),
        encrypted_secret_key: None,
        derivation: algorithm(KeyId::X25519).derivation.clone(),
        created_at: None,
        extra: Default::default(),
    };
    assert!(KeyStore::from_entries(&[malformed]).is_err());

    let mut store = fresh(&[7u8; 32]);
    let unknown_secret = BTreeMap::from([(KeyId::Eth, Zeroizing::new(vec![1]))]);
    assert!(store.attach_secrets(unknown_secret).is_err());
}
