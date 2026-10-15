//! `MajikKey::to_contact` / message-identity integration with the `majik-contact` crate.
//! Port of the TS test "toContact / toKeyIdentity / toSerializedIdentity expose the right public data".

use majik_key::core::utils::array_to_base64;
use majik_key::{
    KeyId, MajikContact, MajikContactMeta, MajikKey, MajikMessageIdentity, MajikUserRef,
};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn key() -> MajikKey {
    MajikKey::create(PHRASE, "pw pw pw", Some("Me"), &Default::default()).unwrap()
}

#[test]
fn to_contact_exposes_the_right_public_data() {
    let k = key();
    let c = k.to_contact(None).unwrap();
    assert_eq!(c.id(), k.id());
    assert_eq!(c.fingerprint(), k.fingerprint());
    assert_eq!(c.public_key().raw, k.get_public_key(KeyId::X25519).unwrap());
    assert_eq!(c.address(), k.public_key_base64());
    assert_eq!(
        c.ml_key(),
        array_to_base64(&k.get_public_key(KeyId::MlKem768).unwrap())
    );
    assert_eq!(
        c.ed_public_key_base64(),
        array_to_base64(&k.get_public_key(KeyId::Ed25519).unwrap())
    );
    assert_eq!(
        c.ml_dsa_public_key_base64(),
        array_to_base64(&k.get_public_key(KeyId::MlDsa87).unwrap())
    );
    assert_eq!(c.meta.label.as_deref(), Some("Me"));
    assert!(!c.is_majikah_identity_checked());
}

#[test]
fn initial_meta_overrides_the_key_label_and_keeps_other_fields() {
    let k = key();
    let c = k
        .to_contact(Some(MajikContactMeta {
            label: Some("ignored-default".into()),
            notes: Some("n".into()),
            ..Default::default()
        }))
        .unwrap();
    assert_eq!(c.meta.label.as_deref(), Some("ignored-default"));
    assert_eq!(c.meta.notes.as_deref(), Some("n"));

    // meta without a label falls back to the key's label
    let c = k
        .to_contact(Some(MajikContactMeta {
            notes: Some("n".into()),
            ..Default::default()
        }))
        .unwrap();
    assert_eq!(c.meta.label.as_deref(), Some("Me"));
}

#[test]
fn contact_json_is_the_public_serialized_contact_and_round_trips() {
    let k = key();
    let json = serde_json::to_value(k.to_contact(None).unwrap().to_json()).unwrap();
    assert_eq!(json["id"], k.id());
    assert_eq!(json["publicKeyBase64"], k.public_key_base64());
    assert_eq!(json["meta"]["label"], "Me");
    assert!(json.get("mlKey").is_some() && json.get("edPublicKeyBase64").is_some());
    // public data only
    let text = json.to_string();
    assert!(!text.contains("secret") && !text.contains("private") && !text.contains("encrypted"));

    let back = MajikContact::from_json(serde_json::from_value(json).unwrap()).unwrap();
    assert_eq!(back.id(), k.id());
    assert_eq!(
        back.public_key().raw,
        k.get_public_key(KeyId::X25519).unwrap()
    );
}

#[test]
fn message_identity_is_built_from_the_contact() {
    let k = key();
    let user = MajikUserRef {
        id: "u1".into(),
        display_name: "User".into(),
    };

    let id = k.to_majik_message_identity(&user, None).unwrap();
    assert_eq!(id.id(), k.id());
    assert_eq!(id.public_key(), k.public_key_base64());
    assert_eq!(id.label(), "Me"); // contact meta label, not the user's display name
    assert!(id.validate_integrity() && id.matches("u1", k.public_key_base64()).unwrap());

    let opts = majik_key::IdentityOptions {
        label: Some("Custom".into()),
        restricted: true,
    };
    let id = k.to_majik_message_identity(&user, Some(opts)).unwrap();
    assert_eq!(id.label(), "Custom");
    assert!(id.is_restricted());

    // the identity JSON is wire-compatible with majik-contact's MajikMessageIdentityJSON
    let contact = MajikContact::from_identity_json(
        &serde_json::from_value(serde_json::to_value(id.to_json()).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(contact.id(), k.id());
    assert_eq!(contact.address(), k.public_key_base64());
    assert!(contact.is_majikah_registered() && contact.is_blocked());
    assert!(MajikMessageIdentity::from_json(&id.to_json()).is_ok());
}
