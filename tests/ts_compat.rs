//! Cross-implementation tests. Every expected value in `tests/vectors/ts-vectors.json` was
//! produced by running the ACTUAL TypeScript sources (see `tests/vectors/generator/`), so a
//! pass here means byte-for-byte compatibility with `@majikah/majik-key`.

use std::sync::OnceLock;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use majik_key::*;
use serde_json::Value;
use zeroize::Zeroizing;

fn v() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(include_str!("vectors/ts-vectors.json")).unwrap())
}
fn b64(s: &Value) -> Vec<u8> {
    B64.decode(s.as_str().unwrap()).unwrap()
}
fn s(x: &Value) -> &str {
    x.as_str().unwrap()
}
fn lang(x: &Value) -> MnemonicLanguage {
    s(x).parse().unwrap()
}
const FALCON: [&str; 2] = ["pq:falcon-512", "pq:falcon-1024"];

#[test]
fn bip39_seed_and_validation_all_ten_languages() {
    let mut seen = std::collections::HashSet::new();
    for m in v()["mnemonics"].as_array().unwrap() {
        let l = lang(&m["language"]);
        seen.insert(l);
        validate_mnemonic_in(s(&m["phrase"]), l)
            .unwrap_or_else(|_| panic!("{} invalid", s(&m["name"])));
        let seed = mnemonic_to_seed(s(&m["phrase"]), l).unwrap();
        assert_eq!(
            hex::encode(&seed[..]),
            s(&m["seedHex"]),
            "seed mismatch for {}",
            s(&m["name"])
        );
    }
    assert_eq!(seen.len(), 10, "all ten languages covered");
    // wrong language must be rejected
    let en = &v()["mnemonics"][0];
    assert!(validate_mnemonic_in(s(&en["phrase"]), MnemonicLanguage::Fr).is_err());
}

#[test]
fn every_key_matches_ts_byte_for_byte() {
    let mut checked = 0;
    for m in v()["mnemonics"].as_array().unwrap() {
        let seed = hex::decode(s(&m["seedHex"])).unwrap();
        for (id, kp) in m["keys"].as_object().unwrap() {
            let kid: KeyId = id.parse().unwrap();
            if FALCON.contains(&id.as_str()) {
                assert!(
                    derive_key(kid, &seed).is_err(),
                    "falcon must refuse to derive"
                );
                continue;
            }
            let d = derive_key(kid, &seed).unwrap();
            assert_eq!(
                d.public_key,
                b64(&kp["pub"]),
                "{} pub ({})",
                id,
                s(&m["name"])
            );
            assert_eq!(
                &d.secret_key[..],
                &b64(&kp["sec"])[..],
                "{} sec ({})",
                id,
                s(&m["name"])
            );
            checked += 1;
        }
        let x = derive_key(KeyId::X25519, &seed).unwrap();
        assert_eq!(
            fingerprint_from_public_raw(&x.public_key),
            s(&m["fingerprint"])
        );
    }
    assert!(checked > 80, "checked {checked}");
}

#[test]
fn falcon_is_declared_unimplemented_but_known() {
    for id in [KeyId::Falcon512, KeyId::Falcon1024] {
        assert!(!algorithm(id).implemented);
        assert!(!enableable_key_ids().contains(&id));
        assert!(resolve_requested_keys(&[id]).is_err());
    }
}

#[test]
fn registry_order_and_ids_match_ts() {
    let ts_ids: Vec<&str> = v()["ids"].as_array().unwrap().iter().map(s).collect();
    let rs: Vec<String> = enableable_key_ids()
        .iter()
        .filter(|i| algorithm(**i).kind == KeyKind::Stored)
        .map(|i| i.to_string())
        .collect();
    // TS also lists the two Falcon ids as enableable; Rust deliberately doesn't.
    let ts_wo_falcon: Vec<&str> = ts_ids
        .iter()
        .copied()
        .filter(|i| !FALCON.contains(i))
        .collect();
    assert_eq!(rs, ts_wo_falcon);
    assert_eq!(KeyId::ALL.len(), 31);
    for id in KeyId::ALL {
        assert_eq!(KeyId::parse(id.as_str()), Some(*id));
    }
}

#[test]
fn hkdf_vectors() {
    let seed = hex::decode(s(&v()["mnemonics"][0]["seedHex"])).unwrap();
    for h in v()["hkdf"].as_array().unwrap() {
        let id: KeyId = s(&h["id"]).parse().unwrap();
        let out = derive_seed_hkdf(&seed, id, h["len"].as_u64().unwrap() as usize).unwrap();
        assert_eq!(hex::encode(&out[..]), s(&h["out"]), "{}", s(&h["id"]));
    }
}

#[test]
fn kdf_vectors() {
    let k = &v()["kdf"];
    let salt = b64(&k["saltB64"]);
    assert_eq!(
        &derive_key_from_passphrase_argon2(s(&k["passphrase"]), &salt).unwrap()[..],
        &b64(&k["argonPassphraseKey"])[..]
    );
    assert_eq!(
        &derive_key_from_passphrase(s(&k["passphrase"]), &salt)[..],
        &b64(&k["pbkdf2Key"])[..]
    );
    let mn = s(&v()["mnemonics"][0]["phrase"]);
    assert_eq!(
        &derive_key_from_mnemonic_argon2(mn, MAJIK_MNEMONIC_SALT.as_bytes()).unwrap()[..],
        &b64(&k["argonMnemonicKey"])[..]
    );
}

#[test]
fn imports_every_ts_backup_generation() {
    let mn = s(&v()["mnemonics"][0]["phrase"]);
    let fp = s(&v()["backups"]["fingerprint"]);
    for name in ["v2Argon", "v1Argon", "v1ArgonExplicit", "pbkdf2"] {
        let backup = s(&v()["backups"][name]);
        let k = MajikKey::import_from_mnemonic_backup(
            backup,
            mn,
            "pw-123",
            Some("imp"),
            &Default::default(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(k.fingerprint(), fp, "{name}");
        assert!(k.is_unlocked() && k.is_core_complete());
        assert_eq!(k.backup(), backup);
    }
    // wrong mnemonic is rejected before the expensive derivation
    let wrong = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    assert!(MajikKey::import_from_mnemonic_backup(
        s(&v()["backups"]["v2Argon"]),
        wrong,
        "pw-123",
        None,
        &Default::default()
    )
    .is_err());
}

#[test]
fn loads_ts_registry_account_and_roundtrips_json_exactly() {
    let acct = &v()["account"];
    let mut k = MajikKey::from_json_str(&acct["json"].to_string()).unwrap();
    assert!(k.is_locked() && k.is_argon2id());
    assert!(!k.verify("wrong passphrase") && k.verify(s(&acct["passphrase"])));
    assert!(
        k.unlock("wrong passphrase").is_err() && k.is_locked(),
        "failed unlock leaves account locked"
    );
    k.unlock(s(&acct["passphrase"])).unwrap();

    // every secret the TS side sealed decrypts to exactly the same bytes
    for (id, sec) in acct["secrets"].as_object().unwrap() {
        let got = k.get_private_key(id.parse().unwrap()).unwrap();
        assert_eq!(&got[..], &b64(sec)[..], "{id}");
    }
    // serialization is lossless against TS output (compared as JSON values)
    assert_eq!(
        serde_json::to_value(k.to_json()).unwrap(),
        acct["json"],
        "to_json != TS toJSON"
    );
    // registry-only output drops the flat fields
    let slim =
        serde_json::to_value(k.to_json_with(&MajikKeyToJsonOptions { legacy: false })).unwrap();
    assert!(slim.get("encryptedMlKemSecretKey").is_none() && slim.get("keys").is_some());
    assert!(MajikKey::from_json_str(&slim.to_string()).is_ok());
}

#[test]
fn passphrase_change_and_add_keys_on_ts_account() {
    let acct = &v()["account"];
    let mut k = MajikKey::from_json_str(&acct["json"].to_string()).unwrap();
    let old = s(&acct["passphrase"]);
    k.unlock(old).unwrap();
    k.update_passphrase(old, "brand new passphrase").unwrap();
    k.lock();
    assert!(!k.verify(old) && k.verify("brand new passphrase"));

    // reload from JSON, unlock with the new passphrase, secrets unchanged
    let mut k2 = MajikKey::from_json(&k.to_json()).unwrap();
    k2.unlock("brand new passphrase").unwrap();
    for (id, sec) in acct["secrets"].as_object().unwrap() {
        assert_eq!(
            &k2.get_private_key(id.parse().unwrap()).unwrap()[..],
            &b64(sec)[..],
            "{id}"
        );
    }

    // add_keys: wrong mnemonic refused, right one adds and matches the TS derivation
    let wrong = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    assert!(k2
        .add_keys(&[KeyId::MlKem512], wrong, "brand new passphrase")
        .is_err());
    assert!(k2
        .add_keys(
            &[KeyId::MlKem512],
            s(&acct["mnemonic"]),
            "not the passphrase"
        )
        .is_err());
    let added = k2
        .add_keys(
            &[KeyId::MlKem512, KeyId::Eth],
            s(&acct["mnemonic"]),
            "brand new passphrase",
        )
        .unwrap();
    assert_eq!(added, vec![KeyId::MlKem512], "Eth was already present");
    let ts = &v()["mnemonics"][0]["keys"]["pq:ml-kem-512"];
    assert_eq!(
        &k2.get_private_key(KeyId::MlKem512).unwrap()[..],
        &b64(&ts["sec"])[..]
    );
    // and the new key survives a lock/unlock cycle under the new passphrase
    k2.lock();
    k2.unlock("brand new passphrase").unwrap();
    assert!(k2.get_private_key(KeyId::MlKem512).is_ok());
}

#[test]
fn loads_legacy_flat_account_with_mixed_kdf_and_migrates() {
    let acct = &v()["legacyAccount"];
    let mut k = MajikKey::from_json_str(&acct["json"].to_string()).unwrap();
    assert_eq!(k.kdf_version(), KdfVersion::Pbkdf2);
    assert!(!k.is_fully_upgraded() || k.is_argon2id());
    k.unlock(s(&acct["passphrase"])).unwrap();
    for (id, sec) in acct["secrets"].as_object().unwrap() {
        assert_eq!(
            &k.get_private_key(id.parse().unwrap()).unwrap()[..],
            &b64(sec)[..],
            "{id}"
        );
    }
    assert!(
        k.add_keys(
            &[KeyId::Eth],
            s(&v()["account"]["mnemonic"]),
            s(&acct["passphrase"])
        )
        .is_err(),
        "legacy KDF must migrate first"
    );
    k.lock();
    k.migrate(s(&acct["passphrase"])).unwrap();
    assert!(k.is_argon2id());
    let mut again = MajikKey::from_json(&k.to_json()).unwrap();
    again.unlock(s(&acct["passphrase"])).unwrap();
    for (id, sec) in acct["secrets"].as_object().unwrap() {
        assert_eq!(
            &again.get_private_key(id.parse().unwrap()).unwrap()[..],
            &b64(sec)[..],
            "{id}"
        );
    }
}

#[test]
fn web3_vectors() {
    let w = &v()["web3"];
    let seed = hex::decode(s(&v()["mnemonics"][0]["seedHex"])).unwrap();

    // Bitcoin: standard + domain paths, WIF, bech32
    let std = derive_bitcoin_keypair_from_seed(
        &seed,
        Some(&BitcoinDerivationOptions {
            standard: true,
            path: None,
        }),
    )
    .unwrap();
    assert_eq!(&std.public_key[..], &b64(&w["btcStd"]["pub"])[..]);
    assert_eq!(&std.private_key[..], &b64(&w["btcStd"]["sec"])[..]);
    assert_eq!(to_wif(&std, None), s(&w["btcStd"]["wif"]));
    assert_eq!(to_wif(&std, Some(false)), s(&w["btcStd"]["wifU"]));
    assert_eq!(
        to_bitcoin_address(&std).unwrap(),
        s(&w["btcStd"]["address"])
    );
    assert_eq!(
        bitcoin_public_key_from_private_key(&std.private_key).unwrap(),
        std.public_key
    );

    let dom = derive_bitcoin_keypair_from_seed(&seed, None).unwrap();
    assert_eq!(&dom.public_key[..], &b64(&w["btcDom"]["pub"])[..]);
    assert_eq!(to_wif(&dom, None), s(&w["btcDom"]["wif"]));
    assert_eq!(
        to_bitcoin_address(&dom).unwrap(),
        s(&w["btcDom"]["address"])
    );
    let msg = hex::decode(s(&w["btcSchnorr"]["msgHex"])).unwrap();
    assert_eq!(
        sign_with_bitcoin_material(&dom, &msg, BitcoinSignatureScheme::Ecdsa).unwrap(),
        b64(&w["btcEcdsa"]),
        "ECDSA must be RFC6979-identical"
    );
    let aux: [u8; 32] = hex::decode(s(&w["btcSchnorr"]["auxHex"]))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        sign_schnorr_with_aux(&dom, &msg, &aux).unwrap(),
        b64(&w["btcSchnorr"]["sig"]),
        "BIP-340 with fixed aux"
    );
    assert_eq!(
        sign_with_bitcoin_material(&dom, &msg, BitcoinSignatureScheme::Schnorr)
            .unwrap()
            .len(),
        64
    );

    // Ethereum
    let derived = derive_key(KeyId::Eth, &seed).unwrap();
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&derived.secret_key);
    let eth = EthereumKeypairMaterial {
        private_key: sk,
        public_key: derived.public_key.clone(),
    };
    assert_eq!(
        ethereum_address_from_public_key(&eth.public_key).unwrap(),
        s(&w["eth"]["address"])
    );
    let h = hex::decode(s(&w["ethSigHash"]["msgHex"])).unwrap();
    let sig = sign_ethereum_hash(&eth, &h).unwrap();
    for f in ["r", "s", "serialized"] {
        assert_eq!(
            serde_json::to_value(&sig).unwrap()[f],
            w["ethSigHash"][f],
            "{f}"
        );
    }
    assert_eq!(sig.v as u64, w["ethSigHash"]["v"].as_u64().unwrap());
    assert_eq!(
        recover_ethereum_address(&h, &sig).unwrap(),
        s(&w["eth"]["address"])
    );
    let msig = sign_ethereum_message(&eth, s(&w["ethSigMsg"]["message"]).as_bytes()).unwrap();
    assert_eq!(msig.serialized, s(&w["ethSigMsg"]["serialized"]));

    // Solana
    let ed = derive_key(KeyId::Ed25519, &seed).unwrap();
    let sol = derive_solana_keypair_from_ed_secret_key(&ed.secret_key).unwrap();
    assert_eq!(&sol.public_key[..], &b64(&w["sol"]["pub"])[..]);
    assert_eq!(&sol.secret_key[..], &b64(&w["sol"]["sec"])[..]);
    assert_eq!(
        solana_address_from_public_key(&sol.public_key),
        s(&w["sol"]["address"])
    );
    assert_eq!(
        sign_with_solana_material(&sol, s(&w["solSig"]["message"]).as_bytes()),
        b64(&w["solSig"]["sig"])
    );
}

#[test]
fn rust_created_account_end_to_end() {
    let m = &v()["mnemonics"][0];
    let mut k = MajikKey::create(
        s(&m["phrase"]),
        "hunter2 hunter2",
        Some("rs"),
        &MajikKeyCreateOptions {
            keys: vec![KeyId::Btc, KeyId::Sol, KeyId::Eth],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(k.id(), s(&m["fingerprint"]));
    assert_eq!(
        k.available_keys(None),
        vec![
            KeyId::X25519,
            KeyId::Ed25519,
            KeyId::MlKem768,
            KeyId::MlDsa87,
            KeyId::Btc,
            KeyId::Eth,
            KeyId::Sol
        ]
    );
    for (id, kp) in m["keys"].as_object().unwrap() {
        if let Ok(kid) = id.parse::<KeyId>() {
            if k.store_has(kid) {
                assert_eq!(
                    &k.get_private_key(kid).unwrap()[..],
                    &b64(&kp["sec"])[..],
                    "{id}"
                );
            }
        }
    }
    // keypair handle + derived Solana view
    let h = k.get_keypair(KeyId::Sol).unwrap();
    assert_eq!(h.public().unwrap(), b64(&v()["web3"]["sol"]["pub"]));
    assert_eq!(
        k.get_solana_address(None).unwrap(),
        s(&v()["web3"]["sol"]["address"])
    );
    assert_eq!(
        k.get_ethereum_address().unwrap(),
        s(&v()["web3"]["eth"]["address"])
    );
    let w3 = k.web3().unwrap();
    assert!(w3.bitcoin.is_some() && w3.ethereum.is_some());
    assert_eq!(
        w3.ethereum.as_ref().unwrap().address(),
        s(&v()["web3"]["eth"]["address"])
    );
    assert_eq!(
        w3.bitcoin.as_ref().unwrap().get_bitcoin_address().unwrap(),
        s(&v()["web3"]["btcDom"]["address"])
    );

    // dangerous JSON round trip
    let d = k.to_dangerous_json().unwrap();
    let k2 = MajikKey::from_dangerous_json(&d).unwrap();
    assert!(k2.is_unlocked());
    assert_eq!(
        &k2.get_private_key(KeyId::MlDsa87).unwrap()[..],
        &k.get_private_key(KeyId::MlDsa87).unwrap()[..]
    );

    // backup export → import
    let exported = k.export_mnemonic_backup(s(&m["phrase"])).unwrap();
    let k3 = MajikKey::import_from_mnemonic_backup(
        &exported,
        s(&m["phrase"]),
        "other pw",
        None,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(k3.fingerprint(), k.fingerprint());

    // with_auto_lock locks afterwards, even when the closure panics
    let pk = k
        .with_auto_lock(|k| k.get_public_key(KeyId::Ed25519).unwrap())
        .unwrap();
    assert_eq!(pk, b64(&m["keys"]["classic:ed25519"]["pub"]));
    assert!(k.is_locked());
    k.unlock("hunter2 hunter2").unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = k.with_auto_lock(|_| panic!("boom"));
    }));
    assert!(r.is_err() && k.is_locked());
    assert!(k.get_private_key(KeyId::X25519).is_err());

    // mnemonic JSON round trip keeps the language
    k.unlock("hunter2 hunter2").unwrap();
    let mj = k.to_mnemonic_json(s(&m["phrase"]), None).unwrap();
    let k4 = MajikKey::from_mnemonic_json(&mj, "pw pw pw", None, &Default::default()).unwrap();
    assert_eq!(k4.id(), k.id());
}

#[test]
fn japanese_and_generation() {
    let ja = v()["mnemonics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| s(&m["name"]) == "ja12")
        .unwrap();
    let k = MajikKey::create(
        s(&ja["phrase"]),
        "pw pw pw",
        None,
        &MajikKeyCreateOptions {
            mnemonic_language: Some(MnemonicLanguage::Ja),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(k.id(), s(&ja["fingerprint"]));
    for l in MnemonicLanguage::ALL {
        for strength in [128, 256] {
            let g = MajikKey::generate_mnemonic(strength, l).unwrap();
            validate_mnemonic_in(&g, l).unwrap();
        }
    }
    assert!(MajikKey::generate_mnemonic(200, MnemonicLanguage::En).is_err());
}

#[test]
fn unknown_future_key_entries_round_trip_untouched() {
    let acct = &v()["account"];
    let mut j = acct["json"].clone();
    let future = serde_json::json!({
        "id": "pq:hqc-999", "publicKey": "AAAA", "encryptedSecretKey": "BBBB",
        "derivation": {"scheme": "hkdf-sha512-v2", "version": 2, "extraField": 7},
        "somethingNew": true
    });
    j["keys"].as_array_mut().unwrap().push(future.clone());
    let k = MajikKey::from_json_str(&j.to_string()).unwrap();
    let out = serde_json::to_value(k.to_json()).unwrap();
    assert_eq!(out["keys"].as_array().unwrap().last().unwrap(), &future);
    // but we refuse to re-encrypt an account holding secrets we can't interpret
    let mut k = k;
    k.unlock(s(&acct["passphrase"])).unwrap();
    assert!(k
        .update_passphrase(s(&acct["passphrase"]), "new pass")
        .is_err());
    // and reject JSON from a newer schema
    j["keysVersion"] = 99.into();
    assert!(MajikKey::from_json_str(&j.to_string()).is_err());
}

#[test]
fn tampered_json_is_rejected() {
    let mut j = v()["account"]["json"].clone();
    j["publicKey"] = B64.encode([1u8; 32]).into();
    assert!(MajikKey::from_json_str(&j.to_string()).is_err());
}

// ── backup module ──

struct MockPng;
impl PngCodec for MockPng {
    fn is_valid_png(&self, png: &[u8]) -> bool {
        looks_like_png(png)
    }
    fn encode(&self, p: &str) -> BackupResult<Vec<u8>> {
        let mut v = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
        v.extend(p.as_bytes());
        Ok(v)
    }
    fn decode(&self, png: &[u8]) -> BackupResult<String> {
        Ok(String::from_utf8(png[8..].to_vec()).unwrap())
    }
}

#[test]
fn backup_zip_json_png() {
    let b = MajikKeyBackup::create(CreateBackupParams {
        seed: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        id: "acct-1".into(), language: MnemonicLanguage::En, phrase: Some("pw".into()),
    }).unwrap();
    assert_eq!(b.format_version(), Some(BACKUP_FORMAT_VERSION));
    assert_eq!(b.seed().len(), 12);

    // JSON only
    let zip = b.to_zip(None, &Default::default()).unwrap();
    assert!(looks_like_zip(&zip));
    assert_eq!(
        MajikKeyBackup::from_zip(&zip, None).unwrap().seed_phrase(),
        b.seed_phrase()
    );
    // PNG + JSON
    let zip = b.to_zip(Some(&MockPng), &Default::default()).unwrap();
    let r = MajikKeyBackup::from_zip(&zip, Some(&MockPng)).unwrap();
    assert_eq!((r.id(), r.seed()), (b.id(), b.seed()));
    // PNG-only read without a codec falls back to the JSON entry
    assert!(MajikKeyBackup::from_zip(&zip, None).is_ok());

    // validator
    assert!(MajikKeyBackup::from_json_str(r#"{"id":"x","seed":[]}"#).is_err());
    assert!(MajikKeyBackup::from_json_str(r#"{"id":"","seed":["a"]}"#).is_err());
    assert!(MajikKeyBackup::from_json_str(r#"{"id":"x","seed":["a"],"version":"1"}"#).is_err());
    assert!(MajikKeyBackup::from_zip(b"not a zip", None).is_err());
    assert_eq!(to_safe_file_name("a<b>:c/d. "), "a-b--c-d");
}

#[test]
fn message_identity_integrity() {
    let m = &v()["mnemonics"][0];
    let k = MajikKey::create(s(&m["phrase"]), "pw pw pw", Some("Me"), &Default::default()).unwrap();
    let user = MajikUserRef {
        id: "u1".into(),
        display_name: "User".into(),
    };
    let id = k.to_majik_message_identity(&user, None).unwrap();
    assert!(id.validate_integrity() && id.matches("u1", k.public_key_base64()).unwrap());
    assert_eq!(id.label(), "Me");
    let mut j = id.to_json();
    assert!(MajikMessageIdentity::from_json(&j).is_ok());
    j.public_key = "tampered".into();
    assert!(MajikMessageIdentity::from_json(&j).is_err());
}

#[test]
fn ml_kem_roundtrip_with_ts_secret_key() {
    let kp = &v()["mnemonics"][0]["keys"]["pq:ml-kem-768"];
    let (ss, ct) = ml_kem_encapsulate(&b64(&kp["pub"])).unwrap();
    // decapsulate using the 2400-byte secret key exactly as TS stored it
    let back = ml_kem_decapsulate(&ct, &b64(&kp["sec"])).unwrap();
    assert_eq!(&ss[..], &back[..]);
    let seed = hex::decode(s(&v()["mnemonics"][0]["seedHex"])).unwrap();
    assert_eq!(
        derive_ml_kem_keypair_from_seed(&seed).unwrap().public_key,
        b64(&kp["pub"])
    );
    assert!(derive_ml_kem_keypair_from_seed(&seed[..32]).is_err());
}

#[test]
fn x25519_agreement() {
    let a = generate_ed25519_keypair().unwrap();
    let b = generate_ed25519_keypair().unwrap();
    assert_eq!(
        &x25519_shared_secret(&a.x_secret, &b.x_public).unwrap()[..],
        &x25519_shared_secret(&b.x_secret, &a.x_public).unwrap()[..]
    );
    assert!(
        x25519_shared_secret(&a.x_secret, &[0u8; 32]).is_err(),
        "small-order point rejected"
    );
}
