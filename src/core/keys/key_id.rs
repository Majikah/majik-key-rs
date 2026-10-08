//! Port of `core/keys/key-id.ts`.
//!
//! Namespaced identifiers for every key algorithm the MajikKey registry knows.
//! Wire format: `"<family>:<name>"`. Adding an algorithm = one line in the
//! `key_ids!` table below + one entry in `registry.rs`. Existence of an id does
//! NOT mean it is usable — see `status` / `implemented` in the registry.
//!
//! Variant order **is** the canonical registry order (`Ord` is derived), so a
//! `BTreeMap<KeyId, _>` always iterates in the same order the TS lib emits.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::error::MajikKeyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyFamily {
    Classic,
    Pq,
    Web3,
}

impl KeyFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyFamily::Classic => "classic",
            KeyFamily::Pq => "pq",
            KeyFamily::Web3 => "web3",
        }
    }
}

macro_rules! key_ids {
    ($( $(#[$m:meta])* $variant:ident => $s:literal ),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum KeyId { $( $(#[$m])* $variant ),* }

        impl KeyId {
            /// Every id, in canonical registry order.
            pub const ALL: &'static [KeyId] = &[ $( KeyId::$variant ),* ];

            /// The namespaced wire string, e.g. `"pq:ml-dsa-87"`.
            pub const fn as_str(&self) -> &'static str {
                match self { $( KeyId::$variant => $s ),* }
            }

            /// `None` for ids this library version does not know.
            pub fn parse(s: &str) -> Option<KeyId> {
                match s { $( $s => Some(KeyId::$variant), )* _ => None }
            }
        }
    };
}

key_ids! {
    // ── classic ──
    X25519 => "classic:x25519",
    Ed25519 => "classic:ed25519",

    // ── pq: KEM (FIPS 203) ──
    MlKem512 => "pq:ml-kem-512",
    MlKem768 => "pq:ml-kem-768",
    MlKem1024 => "pq:ml-kem-1024",

    // ── pq: KEM (HQC — NIST backup KEM, not yet final) ──
    Hqc128 => "pq:hqc-128",
    Hqc192 => "pq:hqc-192",
    Hqc256 => "pq:hqc-256",

    // ── pq: signatures (FIPS 204) ──
    MlDsa44 => "pq:ml-dsa-44",
    MlDsa65 => "pq:ml-dsa-65",
    MlDsa87 => "pq:ml-dsa-87",

    // ── pq: signatures (FIPS 205, stateless hash-based) ──
    SlhDsaSha2_128s => "pq:slh-dsa-sha2-128s",
    SlhDsaSha2_128f => "pq:slh-dsa-sha2-128f",
    SlhDsaSha2_192s => "pq:slh-dsa-sha2-192s",
    SlhDsaSha2_192f => "pq:slh-dsa-sha2-192f",
    SlhDsaSha2_256s => "pq:slh-dsa-sha2-256s",
    SlhDsaSha2_256f => "pq:slh-dsa-sha2-256f",
    SlhDsaShake128s => "pq:slh-dsa-shake-128s",
    SlhDsaShake128f => "pq:slh-dsa-shake-128f",
    SlhDsaShake192s => "pq:slh-dsa-shake-192s",
    SlhDsaShake192f => "pq:slh-dsa-shake-192f",
    SlhDsaShake256s => "pq:slh-dsa-shake-256s",
    SlhDsaShake256f => "pq:slh-dsa-shake-256f",

    // ── pq: Falcon Round 3 ──
    Falcon512 => "pq:falcon-512",
    Falcon1024 => "pq:falcon-1024",

    // ── pq: FN-DSA (FIPS 206) — RESERVED until the standard is final ──
    FnDsa512 => "pq:fn-dsa-512",
    FnDsa1024 => "pq:fn-dsa-1024",

    // ── pq: stateful hash-based (NIST SP 800-208) — NOT SUPPORTED ──
    Lms => "pq:lms",

    // ── web3 ──
    /// Majik domain-separated path `m/84'/1971'/0'/0/0` (legacy default).
    Btc => "web3:btc",
    /// Standard BIP-44 `m/44'/60'/0'/0/0`.
    Eth => "web3:eth",
    /// Derived view over `classic:ed25519`.
    Sol => "web3:sol",
}

/// Keys every account must hold from this version on (backward-compat baseline).
pub const CORE_KEYS: [KeyId; 4] = [KeyId::X25519, KeyId::Ed25519, KeyId::MlKem768, KeyId::MlDsa87];

impl KeyId {
    pub fn family(&self) -> KeyFamily {
        key_family_of(*self)
    }
}

pub fn key_family_of(id: KeyId) -> KeyFamily {
    match id.as_str().split(':').next() {
        Some("classic") => KeyFamily::Classic,
        Some("pq") => KeyFamily::Pq,
        _ => KeyFamily::Web3,
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeyId {
    type Err = MajikKeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyId::parse(s).ok_or_else(|| MajikKeyError::msg(format!("Unknown key algorithm \"{s}\"")))
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        KeyId::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("Unknown key algorithm \"{s}\"")))
    }
}
