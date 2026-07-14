//! Cross-compatibility fixture and test.
//! Run with `cargo test cross_compat_dump -- --nocapture` to view the Base64 output.
//! The `cross_compat_assertions` test guarantees strict parity with the TS repo.

use majik_key::crypto::encryption_engine::derive_identity_from_mnemonic;
use majik_key::crypto::wordlist::MnemonicLanguage;
use base64::prelude::*; // Make sure `base64` is in your Cargo.toml

/// # ⚠️ SECURITY WARNING: FOR TESTING ONLY
///
/// This mnemonic is publicly known and completely insecure. It must **never** be
/// used in production environments, mainnet deployments, or with any real funds.
///
/// ### Danger
/// If you find this mnemonic being used in production code, immediate action is
/// required to rotate keys and secure any affected assets. You have been warned:
/// this is strictly for local development and integration testing.
#[deprecated(
    since = "0.1.0", 
    note = "CRITICAL SECURITY RISK: Do not use this testing mnemonic in production."
)]
const FIXED_TEST_MNEMONIC: &str =
    "wing ride lawsuit satisfy buddy depart budget sight shaft else margin wait";

#[test]
#[ignore]
fn cross_compat_dump() {
    let identity = derive_identity_from_mnemonic(FIXED_TEST_MNEMONIC, MnemonicLanguage::En)
        .expect("derivation should succeed for a valid test mnemonic");

    println!("=== Rust derivation output (Base64) ===");
    println!("x25519_public:     {}", BASE64_STANDARD.encode(identity.public_key));
    println!("x25519_private:    {}", BASE64_STANDARD.encode(identity.private_key));
    println!("fingerprint:       {}", BASE64_STANDARD.encode(identity.fingerprint));
    println!("ml_kem_public:     {}", BASE64_STANDARD.encode(&identity.ml_kem_public_key));
    println!("ed25519_public:    {}", BASE64_STANDARD.encode(identity.ed_public_key));
    println!("ml_dsa_public:     {}", BASE64_STANDARD.encode(&identity.ml_dsa_public_key));
    println!("=======================================");
}

#[test]
#[ignore]
fn cross_compat_assertions() {
    let identity = derive_identity_from_mnemonic(FIXED_TEST_MNEMONIC, MnemonicLanguage::En)
        .expect("derivation should succeed for a valid test mnemonic");

    // Assertions mapping exactly to the TypeScript test assertions
    assert_eq!(
        BASE64_STANDARD.encode(identity.public_key),
        "7jO1AiB7Cko496HX0sH1zccjJ0KkVOdE1jeA+pC9BSY="
    );

    assert_eq!(
        BASE64_STANDARD.encode(identity.private_key),
        "uDzKSMaJ7l2nWPRwTv05cwj7b1ASkq3zPC/fdKEtyl4="
    );

    assert_eq!(
        BASE64_STANDARD.encode(identity.fingerprint),
        "fCabZ+T3Ecc8eDUFr2eSBPprhVbbHfEC1wGHphiQB2I="
    );

    assert_eq!(
        BASE64_STANDARD.encode(identity.ed_public_key),
        "no9pSEbuVXlhIQBdnRaTQ7t7u80DpIY56TslHen34NE="
    );

    assert_eq!(
        BASE64_STANDARD.encode(&identity.ml_kem_public_key),
        "SAeNyEBuBIKOHOF045tUAOBoLXZs2jSHWSwrMNqJhrFCqMmwY0AVrlDGpFBnwEN7hzWLYtgdSnVPvzy3rdt4+qihrJpkWWhSeSSRRkXAbAIt/8ANJtQoH5xg1lgfRzHEK+VK2No67XvEYTOyeJp8Z+ubqPKeInGhpiCK9tcS22hrMhdT4TIAWNW2tJxbFmgcOSEHy/QxFPdAobCB/GXA7FYkOmc2SdEZ2XES6jIcVJgyFRO5hHYT4ASk45dXCna6xQeA+zyZSDhluQMrUrWwXeINluiFc4FQjQkdE7ka1LNAINwiOGPIM5aBDlK/+OddpYgiGxuv39vISrNz2ZxoKHlJ4gwXnnzApggGSGOYz9CSbvGmqIpKsaw81wuHTcCpAJt6zJt+G/qJ2DNvOjxiuxdu3hCnHBDDz1dVp6gXS0GsUbE+KlwtYmCPEyFKU/N26zkaNdmgeLIj2fBxpridXdOTFpGPfOAW4GtfiGtvehRMg9tsCXXImVAlkGBjv1OS2kAwYHooI6GGOktaMDdnWbMgL1oBnvumRCeOM1dAa3oHEwykzTduDBvI6mtPP6VAGHuFdjKSTLtP8eN1lPm1HEJRpfqJG0trAZSHM0J+gBJfxUh3pZa1qVRDu1ZwGkEN2evI5ElQ1WjIq9rGe9Mn71KXKkPO7QykWAacFui5+pk1zxy5EmCjGbgABvU3A5sV1LNVAtUScyVQ1ZhMnaPKh3dsEtGe/uzEnJcQVsLJqIweFMh6d/OOBboT7NFitkJzeQfAsAhSpqQn15MaiIieh0uyOPcMTXYiTlKz+7tg7EVrJdM1YzUcW3CWvLhrbVYTgLBdxpmANjwh//GoTYQQm5Of6pZBeOov3lGRmYinEQIUnrwq+uNlnco/GZjGyUyeScKCGdZsBsxqk/krEzocc8PC+1FrAJY+YZCcAIVTSwoGjTtVEMgiyQN3kWCSeaLLiji+sfkKdua13VmpltsbODZkTggNKfRlpqMmkmGk4DBbm5tvWhOxH+sf7oQH7EFpU7A3nZIhfeislHB0MlWla/cwf1YM4zqUZbmwN7leY+U8kdV5KWQnDYtwl9Z4vPykE7I3sbMHrFNpOOofoih3WiOMwWhmtRlhOFY/c3WN8/Bep6ERh3OEB4O6LSwGENCtSyM/YGhhemwj6iYVnQCIMvAHuLtrZfSW6AhzyVRQ8MNj4sBCrIOFY/gJtfFs1TQIFMgBmNK/9IF5v3p2dwiyJTzPCpRW5fYEQPsp8yEcG9J5Z8m1NwgFCiulHCgOG2Z9AF0dlsED6LxyWbVZ4yBhDxalO2SHiAZ5JlNWYqZTjzUNdwpvYEUpsZs866Z/FBKCb0orORexqHikcKZ5NOVRgyCcm8zItnUj0XMXlZolwXq5djpcU2ZBbRqtrKWOPsUhKmTEyrYr+DtrxYXI0zV4/sZXcaDPg1hzZRkYzSXP17mWHmA8hIYrcoNxCtez95Gg2qAGblCJUdOL3uawe9iaugkfMTJ7t3QONfHGqeYMHlIpzPURdKaQzGikZaK81RoucKx3KceoQtksC+I4ecOnXABs44e9zxaFp1J1tWpAVBc="
    );

    assert_eq!(
        BASE64_STANDARD.encode(&identity.ml_dsa_public_key),
        "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"
    );
}