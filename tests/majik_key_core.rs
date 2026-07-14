// Core integration tests mirroring the TS `majik-key` core suite.

use majik_key::crypto::wordlist::MnemonicLanguage;
use majik_key::majik_key::{MajikKey, MajikKeyCreateOptions};
use zeroize::Zeroizing;

// ── CREATION TESTS ────────────────────────────────────────────────────────

#[test]
fn create_and_basic_metadata() {
    let mnemonic =
        MajikKey::generate_mnemonic(128, MnemonicLanguage::En).expect("generate mnemonic");
    let passphrase = "TestPassphrase123!".to_string();
    let label = Some("Rust Test Key");

    let key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase),
        label,
        MajikKeyCreateOptions::default(),
    )
    .expect("create majik key");

    assert!(!key.id().is_empty());
    assert!(!key.fingerprint().is_empty());
    assert_eq!(key.label(), "Rust Test Key");
    assert!(key.is_unlocked());
    assert!(key.is_argon2id());

    // Assert keys exist[cite: 3]
    assert!(!key.ml_kem_public_key().is_empty());
    assert!(key.ed_public_key().is_some());
}

#[test]
fn create_fails_invalid_mnemonic() {
    // Checksum failure: The canonical 12x "abandon" vector ends in "about",
    // so using "abandon" for the final word deliberately breaks the checksum[cite: 1].
    let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon".to_string();

    let res = MajikKey::create(
        Zeroizing::new(invalid_mnemonic),
        Zeroizing::new("Passphrase123!".to_string()),
        Some("Label"),
        MajikKeyCreateOptions::default(),
    );

    assert!(res.is_err(), "Should fail with invalid BIP39 checksum");
}

// ── CAPABILITY FLAGS & METADATA ───────────────────────────────────────────

#[test]
fn capability_flags_and_metadata() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new("Pass123!".to_string()),
        Some("Flags Key"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    // has_signing_keys should be true once Ed25519 and ML-DSA exist[cite: 1, 3]
    assert!(key.has_signing_keys());
    assert!(key.ed_public_key().is_some());
    assert!(key.ml_dsa_public_key().is_some());

    // Bitcoin should be created by default via MajikKeyCreateOptions[cite: 3]
    assert!(key.has_bitcoin());
    let metadata = key.metadata();
    assert_eq!(metadata.web3.has_bitcoin, Some(true));

    // Metadata matches getters[cite: 1, 3]
    assert_eq!(metadata.id, key.id());
    assert_eq!(metadata.is_locked, key.is_locked());
    assert_eq!(metadata.has_ml_kem, key.has_ml_kem());

    // Verify metadata survives locking[cite: 1]
    key.lock();
    let locked_meta = key.metadata();
    assert!(locked_meta.is_locked);
    assert_eq!(locked_meta.web3.has_bitcoin, Some(true));
}

// ── MULTI-LANGUAGE MNEMONIC TESTS ─────────────────────────────────────────

#[test]
fn multi_language_generation_and_derivation() {
    // Generate Japanese mnemonic and execute a full derive/lock/unlock cycle[cite: 1]
    let language = MnemonicLanguage::Ja;
    let mnemonic = MajikKey::generate_mnemonic(128, language).expect("generate ja mnemonic");
    let passphrase = "GlobalPassphrase123!".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("JA Key"),
        MajikKeyCreateOptions {
            mnemonic_language: language,
            derive_bitcoin: true,
        },
    )
    .expect("create key from ja mnemonic");

    assert!(key.is_fully_upgraded());
    assert!(key.has_ml_kem());

    // Roundtrip cycle[cite: 1]
    key.lock();
    key.unlock(Zeroizing::new(passphrase))
        .expect("unlock ja key");
    assert!(key.is_unlocked());
    assert!(key.get_private_key().is_ok());
}

#[test]
fn multi_language_rejects_wrong_wordlist() {
    let japanese_mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::Ja).unwrap();

    // Try to parse Japanese mnemonic as English[cite: 1]
    let res = MajikKey::create(
        Zeroizing::new(japanese_mnemonic),
        Zeroizing::new("Passphrase".to_string()),
        None,
        MajikKeyCreateOptions {
            mnemonic_language: MnemonicLanguage::En,
            derive_bitcoin: false,
        },
    );

    assert!(
        res.is_err(),
        "Japanese mnemonic should fail English validation"
    );
}

// ── LOCK & UNLOCK TESTS ───────────────────────────────────────────────────

#[test]
fn lock_unlock_roundtrip() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "LockPassphrase!".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("Lock Test"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    key.lock();
    assert!(key.is_locked());
    assert!(!key.is_unlocked());
    assert!(key.get_private_key().is_err()); // Private credentials stripped[cite: 1]

    key.unlock(Zeroizing::new(passphrase)).expect("unlock");
    assert!(key.is_unlocked());
    assert!(key.get_private_key().is_ok());
}

#[test]
fn lock_unlock_errors() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "CorrectPassphrase!".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        None,
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    // Already unlocked error[cite: 1, 3]
    assert!(key.unlock(Zeroizing::new(passphrase.clone())).is_err());

    key.lock();

    // Incorrect passphrase error[cite: 1]
    let wrong_pass = "wrong-passphrase".to_string();
    assert!(key.unlock(Zeroizing::new(wrong_pass)).is_err());
}

// ── SERIALIZATION TESTS ───────────────────────────────────────────────────

#[test]
fn json_roundtrip_and_unlock() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "JsonPass123".to_string();

    let key = MajikKey::create(
        Zeroizing::new(mnemonic.clone()),
        Zeroizing::new(passphrase.clone()),
        Some("JSON Test"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    let json = key.to_json();
    let mut reconstructed = MajikKey::from_json(&json).expect("from_json");

    // Reconstructed keys start locked[cite: 1, 3]
    assert!(reconstructed.is_locked());
    assert_eq!(reconstructed.id(), key.id());

    // Proves salt/ciphertext survive serialization[cite: 1]
    reconstructed
        .unlock(Zeroizing::new(passphrase))
        .expect("unlock reconstructed");
    assert!(reconstructed.is_unlocked());
    assert!(reconstructed.get_private_key().is_ok());
}

// ── DANGEROUS JSON EXPORT / IMPORT ────────────────────────────────────────

#[test]
fn dangerous_json_fails_when_locked() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new("DangerPass!".to_string()),
        None,
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    key.lock();

    // Should throw if the key is locked[cite: 1, 3]
    assert!(key.to_dangerous_json().is_err());
}

#[test]
fn dangerous_json_roundtrip() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "DangerPass!".to_string();

    let key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("Danger Test"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    let ml_kem_before = key.get_ml_kem_secret_key().unwrap();

    let dangerous = key.to_dangerous_json().expect("to_dangerous_json");
    assert!(!dangerous.private_key_base64.is_empty());

    let reconstructed = MajikKey::from_dangerous_json(&dangerous).expect("from_dangerous_json");

    // Instantly unlocked and share key material[cite: 1, 3]
    assert!(reconstructed.is_unlocked());
    assert_eq!(reconstructed.id(), key.id());

    let ml_kem_after = reconstructed.get_ml_kem_secret_key().unwrap();
    assert_eq!(*ml_kem_before, *ml_kem_after);
}

// ── MNEMONICJSON EXPORT / IMPORT ──────────────────────────────────────────

#[test]
fn mnemonic_json_export_import() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "MnemonicJsonPass".to_string();
    let new_passphrase = "NewPassphrase123".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic.clone()),
        Zeroizing::new(passphrase.clone()),
        Some("MnemonicJSON Key"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    // Export[cite: 1, 3]
    let json_with_phrase = key.to_mnemonic_json(&mnemonic, Some(&passphrase)).unwrap();
    assert!(!json_with_phrase.seed.is_empty());
    assert_eq!(
        json_with_phrase.phrase.as_deref(),
        Some(passphrase.as_str())
    );

    let json_no_phrase = key.to_mnemonic_json(&mnemonic, None).unwrap();
    assert!(json_no_phrase.phrase.is_none());

    // Should throw if key is locked[cite: 1, 3]
    key.lock();
    assert!(key.to_mnemonic_json(&mnemonic, Some(&passphrase)).is_err());

    // Import[cite: 1, 3]
    let reconstructed = MajikKey::from_mnemonic_json(
        &json_with_phrase,
        Zeroizing::new(new_passphrase.clone()),
        Some("Reconstructed"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    assert_eq!(reconstructed.id(), key.id());
    assert_eq!(reconstructed.fingerprint(), key.fingerprint());
    assert!(reconstructed.is_unlocked());
    assert!(reconstructed.is_fully_upgraded());

    // Verify passphrase rotated upon recreation[cite: 1]
    assert!(reconstructed.verify(&new_passphrase));
    assert!(!reconstructed.verify(&passphrase));
}

// ── STATE UPDATES ─────────────────────────────────────────────────────────

#[test]
fn update_label() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new("Pass".to_string()),
        Some("Old Label"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    key.update_label("New Updated Label").unwrap();
    assert_eq!(key.label(), "New Updated Label"); //[cite: 1, 3]
}

#[test]
fn update_passphrase_rotates_blobs() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "OldPass123".to_string();
    let new_pass = "NewPass456".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("Rotate Test"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    let before = key.to_dangerous_json().expect("to_dangerous_json");
    let salt_before = key.to_json().salt;

    key.update_passphrase(&passphrase, &new_pass)
        .expect("update_passphrase");

    assert_ne!(key.to_json().salt, salt_before);
    assert!(!key.verify(&passphrase));
    assert!(key.verify(&new_pass));

    let after = key.to_dangerous_json().expect("to_dangerous_json after");
    assert_eq!(before.private_key_base64, after.private_key_base64);
    assert_eq!(
        before.ml_kem_secret_key_base64,
        after.ml_kem_secret_key_base64
    );
    assert_eq!(before.ed_secret_key_base64, after.ed_secret_key_base64);
    assert_eq!(
        before.ml_dsa_secret_key_base64,
        after.ml_dsa_secret_key_base64
    );

    // Check round trip of lock/unlock with new passphrase[cite: 1]
    key.lock();
    key.unlock(Zeroizing::new(new_pass)).unwrap();
    assert!(key.is_unlocked());
}

// ── BACKUP & RECOVERY TESTS ───────────────────────────────────────────────

#[test]
fn backup_and_restoration() {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let passphrase = "BackupPassphrase".to_string();
    let new_passphrase = "RecoveryPassphrase".to_string();

    let key = MajikKey::create(
        Zeroizing::new(mnemonic.clone()),
        Zeroizing::new(passphrase.clone()),
        Some("Original Key"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    // Export backup[cite: 1, 3]
    let backup_string = key
        .export_mnemonic_backup(Zeroizing::new(mnemonic.clone()))
        .unwrap();
    assert!(!backup_string.is_empty());

    // Import from backup[cite: 1, 3]
    let imported_key = MajikKey::import_from_mnemonic_backup(
        &backup_string,
        Zeroizing::new(mnemonic.clone()),
        Zeroizing::new(new_passphrase.clone()),
        Some("Recovered Key"),
        MajikKeyCreateOptions::default(),
    )
    .unwrap();

    assert_eq!(imported_key.id(), key.id());
    assert!(imported_key.is_fully_upgraded());
    assert!(imported_key.is_unlocked());

    // Import rejection with wrong mnemonic[cite: 1, 3]
    let wrong_mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::En).unwrap();
    let err = MajikKey::import_from_mnemonic_backup(
        &backup_string,
        Zeroizing::new(wrong_mnemonic),
        Zeroizing::new(new_passphrase.clone()),
        Some("Should Fail"),
        MajikKeyCreateOptions::default(),
    );
    assert!(err.is_err());
}
