// Core integration tests mirroring the TS `majik-key` core suite.
// Marked `#[ignore]` because these exercise real crypto and can be
// slow; run explicitly with `cargo test -- --ignored`.

use majik_key::majik_key::{MajikKey, MajikKeyCreateOptions};
use zeroize::Zeroizing;


#[test]
#[ignore]
fn create_and_basic_metadata() {
    let mnemonic =
        MajikKey::generate_mnemonic(128, majik_key::crypto::wordlist::MnemonicLanguage::En)
            .expect("generate mnemonic");
    let passphrase = "TestPassphrase123!".to_string();
    let label = Some("Rust Test Key");

    let key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase),
        label,
        MajikKeyCreateOptions::default(),
    )
    .expect("create majik key");

    // Basic assertions that mirror the TS expectations
    assert!(!key.id().is_empty());
    assert!(!key.fingerprint().is_empty());
    assert_eq!(key.label(), "Rust Test Key");
    assert!(key.is_unlocked());
    // KDF version for freshly-created keys should be Argon2id
    assert!(key.is_argon2id());
}

#[test]
#[ignore]
fn lock_unlock_roundtrip() {
    let mnemonic =
        MajikKey::generate_mnemonic(128, majik_key::crypto::wordlist::MnemonicLanguage::En)
            .expect("generate mnemonic");
    let passphrase = "LockPassphrase!".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("Lock Test"),
        MajikKeyCreateOptions::default(),
    )
    .expect("create majik key");

    key.lock();
    assert!(key.is_locked());

    key.unlock(Zeroizing::new(passphrase)).expect("unlock");
    assert!(key.is_unlocked());
}

#[test]
#[ignore]
fn json_roundtrip_and_unlock() {
    let mnemonic =
        MajikKey::generate_mnemonic(128, majik_key::crypto::wordlist::MnemonicLanguage::En)
            .expect("generate mnemonic");
    let passphrase = "JsonPass123".to_string();

    let key = MajikKey::create(
        Zeroizing::new(mnemonic.clone()),
        Zeroizing::new(passphrase.clone()),
        Some("JSON Test"),
        MajikKeyCreateOptions::default(),
    )
    .expect("create majik key");

    let json = key.to_json();
    // Reconstruct from JSON (starts locked)
    let mut reconstructed = MajikKey::from_json(&json).expect("from_json");
    assert!(reconstructed.is_locked());

    // Unlock reconstructed using same passphrase
    reconstructed
        .unlock(Zeroizing::new(passphrase))
        .expect("unlock reconstructed");
    assert!(reconstructed.is_unlocked());
}

#[test]
#[ignore]
fn dangerous_json_roundtrip() {
    let mnemonic =
        MajikKey::generate_mnemonic(128, majik_key::crypto::wordlist::MnemonicLanguage::En)
            .expect("generate mnemonic");
    let passphrase = "DangerPass!".to_string();

    let key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("Danger Test"),
        MajikKeyCreateOptions::default(),
    )
    .expect("create majik key");

    // Dangerous JSON requires unlocked key
    let dangerous = key.to_dangerous_json().expect("to_dangerous_json");
    let reconstructed = MajikKey::from_dangerous_json(&dangerous).expect("from_dangerous_json");

    // Reconstructed from dangerous JSON should be unlocked and share id/fingerprint
    assert!(reconstructed.is_unlocked());
    assert_eq!(reconstructed.id(), key.id());
    assert_eq!(reconstructed.fingerprint(), key.fingerprint());
}

#[test]
#[ignore]
fn update_passphrase_rotates_blobs() {
    let mnemonic =
        MajikKey::generate_mnemonic(128, majik_key::crypto::wordlist::MnemonicLanguage::En)
            .expect("generate mnemonic");
    let passphrase = "OldPass123".to_string();
    let new_pass = "NewPass456".to_string();

    let mut key = MajikKey::create(
        Zeroizing::new(mnemonic),
        Zeroizing::new(passphrase.clone()),
        Some("Rotate Test"),
        MajikKeyCreateOptions::default(),
    )
    .expect("create majik key");

    // Keep copies of secrets via dangerous JSON for equality checks
    let before = key.to_dangerous_json().expect("to_dangerous_json");

    key.update_passphrase(&passphrase, &new_pass)
        .expect("update_passphrase");

    // After rotation, old passphrase should fail verify
    assert!(!key.verify(&passphrase));
    assert!(key.verify(&new_pass));

    // And the in-memory secrets should remain equal to prior raw values
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
}
