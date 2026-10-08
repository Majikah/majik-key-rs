//! Rust counterparts to TypeScript `majik-key-pq.test.ts`.

#![allow(deprecated)]

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use fips204::traits::{SerDes, Signer, Verifier};
use majik_key::*;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate as _, Encapsulate as _, EncapsulationKey, TryKeyInit as _};
use ml_kem::{DecapsulationKey, ExpandedKeyEncoding as _, MlKem1024};
use serde_json::Value;
use std::sync::OnceLock;

const PASS: &str = "Vector-Test-Passphrase-123!";

fn vectors() -> &'static Value {
    static VECTORS: OnceLock<Value> = OnceLock::new();
    VECTORS.get_or_init(|| serde_json::from_str(include_str!("vectors/ts-vectors.json")).unwrap())
}

fn string(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn decode(value: &Value) -> Vec<u8> {
    B64.decode(string(value)).unwrap()
}

#[test]
fn registry_pq_derivation_matches_ts_vectors_and_roundtrips() {
    let mnemonic = &vectors()["mnemonics"][0];
    let ids = [
        KeyId::MlKem512,
        KeyId::MlKem768,
        KeyId::MlKem1024,
        KeyId::MlDsa44,
        KeyId::MlDsa65,
        KeyId::MlDsa87,
        KeyId::SlhDsaShake128f,
    ];
    let key = MajikKey::create(
        string(&mnemonic["phrase"]),
        PASS,
        Some("PQ vector account"),
        &MajikKeyCreateOptions {
            keys: ids.to_vec(),
            ..Default::default()
        },
    )
    .unwrap();

    for id in ids {
        let expected = &mnemonic["keys"][id.as_str()];
        assert_eq!(
            key.get_public_key(id).unwrap(),
            decode(&expected["pub"]),
            "{id}"
        );
        assert_eq!(
            &key.get_private_key(id).unwrap()[..],
            &decode(&expected["sec"])[..],
            "{id}"
        );
    }
    assert_eq!(key.get_public_key(KeyId::MlKem1024).unwrap().len(), 1568);
    assert_eq!(key.get_private_key(KeyId::MlKem1024).unwrap().len(), 3168);
    assert_eq!(algorithm(KeyId::SlhDsaShake128f).status, KeyStatus::Stable);

    let mut restored = MajikKey::from_json(&key.to_json()).unwrap();
    restored.unlock(PASS).unwrap();
    for id in ids {
        assert_eq!(
            restored.get_public_key(id).unwrap(),
            key.get_public_key(id).unwrap()
        );
        assert_eq!(
            restored.get_private_key(id).unwrap(),
            key.get_private_key(id).unwrap()
        );
    }
}

#[test]
#[allow(deprecated)]
fn ml_kem_1024_encapsulation_uses_stored_expanded_secret() {
    let seed = hex::decode(string(&vectors()["mnemonics"][0]["seedHex"])).unwrap();
    let pair = derive_key(KeyId::MlKem1024, &seed).unwrap();
    let encapsulation_key =
        EncapsulationKey::<MlKem1024>::new_from_slice(&pair.public_key).unwrap();
    let (ciphertext, shared_secret) = encapsulation_key.encapsulate();

    let expanded: Array<u8, _> = Array::try_from(pair.secret_key.as_slice()).unwrap();
    let decapsulation_key = DecapsulationKey::<MlKem1024>::from_expanded_bytes(&expanded).unwrap();
    let recovered = decapsulation_key.decapsulate(&ciphertext);
    assert_eq!(shared_secret.as_slice(), recovered.as_slice());
}

#[test]
fn ml_dsa_65_signs_and_verifies_with_derived_ts_compatible_keys() {
    let seed = hex::decode(string(&vectors()["mnemonics"][0]["seedHex"])).unwrap();
    let pair = derive_key(KeyId::MlDsa65, &seed).unwrap();
    let public_bytes = pair.public_key.try_into().unwrap();
    let secret_bytes = pair.secret_key.to_vec().try_into().unwrap();
    let public = fips204::ml_dsa_65::PublicKey::try_from_bytes(public_bytes).unwrap();
    let secret = fips204::ml_dsa_65::PrivateKey::try_from_bytes(secret_bytes).unwrap();
    let message = b"post-quantum account signature";
    let signature = secret.try_sign(message, &[]).unwrap();

    assert!(public.verify(message, &signature, &[]));
    assert!(!public.verify(b"tampered message", &signature, &[]));
}

#[test]
fn rust_declares_falcon_known_but_not_derivable() {
    for id in [KeyId::Falcon512, KeyId::Falcon1024] {
        assert!(!algorithm(id).implemented);
        assert!(!enableable_key_ids().contains(&id));
        assert!(resolve_requested_keys(&[id]).is_err());
    }
}
