import { mnemonicToSeedSync, entropyToMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist as en } from "@scure/bip39/wordlists/english.js";
import { wordlist as ja } from "@scure/bip39/wordlists/japanese.js";
import { wordlist as zh } from "@scure/bip39/wordlists/simplified-chinese.js";
import { wordlist as fr } from "@scure/bip39/wordlists/french.js";
import { wordlist as es } from "@scure/bip39/wordlists/spanish.js";
import { wordlist as it } from "@scure/bip39/wordlists/italian.js";
import { wordlist as ko } from "@scure/bip39/wordlists/korean.js";
import { wordlist as pt } from "@scure/bip39/wordlists/portuguese.js";
import { wordlist as cs } from "@scure/bip39/wordlists/czech.js";
import { wordlist as zht } from "@scure/bip39/wordlists/traditional-chinese.js";
import { HDKey } from "@scure/bip32";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import * as btc from "@scure/btc-signer";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { pbkdf2 } from "node:crypto";
import { createCipheriv } from "node:crypto";
import fs from "node:fs";

import { deriveKeys, KEY_IMPLS } from "../src/core/keys/key-impls.ts";
import { KeyId, CORE_KEYS } from "../src/core/keys/key-id.ts";
import { KEY_ALGORITHMS, enableableKeyIds, resolveRequestedKeys } from "../src/core/keys/registry.ts";
import { KeyStore } from "../src/core/keys/key-store.ts";
import { deriveSeedHkdf } from "../src/core/keys/hkdf-recipe.ts";
import {
  deriveKeyFromPassphraseArgon2, deriveKeyFromMnemonicArgon2, deriveKeyFromPassphrase,
  fingerprintFromPublicRaw, aesGcmEncrypt, generateRandomBytes, IV_LENGTH,
} from "../src/core/crypto/crypto-provider.ts";
import { arrayToBase64 } from "../src/core/utils.ts";
import { deriveSolanaKeypairFromEdSecretKey, solanaAddressFromPublicKey, signWithSolanaMaterial } from "../src/core/web3/solana/solana.ts";
import { toWIF, signWithBitcoinMaterial, deriveBitcoinKeypairFromSeed } from "../src/core/web3/bitcoin/bitcoin.ts";
import { ethereumAddressFromPublicKey, signEthereumMessage, signEthereumHash } from "../src/core/web3/ethereum/ethereum.ts";
import { MAJIK_MNEMONIC_SALT, LEGACY_MAJIK_MNEMONIC_SALT } from "../src/core/crypto/constants.ts";

const b64 = arrayToBase64;
const enc = (s: string) => new TextEncoder().encode(s);
const hex = bytesToHex;

const mnemonics: { name: string; language: string; phrase: string }[] = [
  { name: "en12", language: "en", phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" },
  { name: "en24", language: "en", phrase: Array(23).fill("abandon").join(" ") + " art" },
  { name: "ja12", language: "ja", phrase: entropyToMnemonic(new Uint8Array(16).fill(7), ja) },
  { name: "zh12", language: "zh-cn", phrase: entropyToMnemonic(new Uint8Array(16).fill(9), zh) },
  { name: "fr12", language: "fr", phrase: entropyToMnemonic(new Uint8Array(16).fill(3), fr) },
  { name: "es12", language: "es", phrase: entropyToMnemonic(new Uint8Array(16).fill(11), es) },
  { name: "it12", language: "it", phrase: entropyToMnemonic(new Uint8Array(16).fill(13), it) },
  { name: "ko12", language: "ko", phrase: entropyToMnemonic(new Uint8Array(16).fill(17), ko) },
  { name: "pt12", language: "pt", phrase: entropyToMnemonic(new Uint8Array(16).fill(19), pt) },
  { name: "cs12", language: "czech", phrase: entropyToMnemonic(new Uint8Array(16).fill(23), cs) },
  { name: "zht12", language: "zh-tw", phrase: entropyToMnemonic(new Uint8Array(16).fill(29), zht) },
];

const ids = enableableKeyIds().filter((id) => KEY_ALGORITHMS[id].kind === "stored");
const out: any = { ids, mnemonics: [] };

// ── per-mnemonic key vectors. Heavy ids only for en12 to keep the file small ──
const HEAVY = new Set(ids.filter((i) => i.startsWith("pq:slh") || i.startsWith("pq:falcon")));
for (const m of mnemonics) {
  const seed = new Uint8Array(mnemonicToSeedSync(m.phrase));
  const use = m.name === "en12" ? ids : ids.filter((i) => !HEAVY.has(i));
  const keys: any = {};
  const d = deriveKeys(seed, use);
  for (const [id, kp] of d) keys[id] = { pub: b64(kp.publicKey), sec: b64(kp.secretKey) };
  out.mnemonics.push({ ...m, seedHex: hex(seed), keys, fingerprint: fingerprintFromPublicRaw(d.get(KeyId.X25519)!.publicKey) });
  console.error("derived", m.name, use.length);
}

// ── HKDF vectors ──
const seed0 = new Uint8Array(mnemonicToSeedSync(mnemonics[0].phrase));
out.hkdf = ["pq:ml-kem-512", "pq:ml-dsa-44", "pq:falcon-512", "pq:slh-dsa-sha2-128s"].map((id) => ({
  id, len: 48, out: hex(deriveSeedHkdf(seed0, id as any, 48)),
}));

// ── KDF vectors ──
const salt = new Uint8Array(32).map((_, i) => i + 1);
out.kdf = {
  saltB64: b64(salt),
  passphrase: "correct horse battery staple",
  argonPassphraseKey: b64(await deriveKeyFromPassphraseArgon2("correct horse battery staple", salt)),
  argonMnemonicKey: b64(await deriveKeyFromMnemonicArgon2(mnemonics[0].phrase, enc(MAJIK_MNEMONIC_SALT))),
  pbkdf2Key: b64(deriveKeyFromPassphrase("correct horse battery staple", salt)),
};

// ── Backup blobs (TS recipe: argon2(mnemonic, salt) -> AES-GCM(private x25519)) ──
const d0 = deriveKeys(seed0, [KeyId.X25519]).get(KeyId.X25519)!;
const fp = fingerprintFromPublicRaw(d0.publicKey);
async function mkBackup(saltStr: string, saltVersion?: number, kdf: 1 | 2 = 2) {
  const iv = generateRandomBytes(IV_LENGTH);
  let key: Uint8Array;
  let ct: Uint8Array;
  if (kdf === 2) {
    key = await deriveKeyFromMnemonicArgon2(mnemonics[0].phrase, enc(saltStr));
    ct = aesGcmEncrypt(key, iv, d0.secretKey);
  } else {
    key = await new Promise<Uint8Array>((res, rej) =>
      pbkdf2(enc(mnemonics[0].phrase), enc(saltStr), 200000, 32, "sha256", (e, k) => (e ? rej(e) : res(new Uint8Array(k)))));
    const c = createCipheriv("aes-256-gcm", key, iv);
    const body = Buffer.concat([c.update(d0.secretKey), c.final()]);
    ct = new Uint8Array(Buffer.concat([body, c.getAuthTag()]));
  }
  const obj: any = { id: fp, iv: b64(iv), ciphertext: b64(ct), publicKey: b64(d0.publicKey), fingerprint: fp, backupKdfVersion: kdf };
  if (saltVersion !== undefined) obj.backupSaltVersion = saltVersion;
  return Buffer.from(JSON.stringify(obj)).toString("base64");
}
out.backups = {
  v2Argon: await mkBackup(MAJIK_MNEMONIC_SALT, 2),
  v1Argon: await mkBackup(LEGACY_MAJIK_MNEMONIC_SALT, undefined),
  v1ArgonExplicit: await mkBackup(LEGACY_MAJIK_MNEMONIC_SALT, 1),
  pbkdf2: await mkBackup(LEGACY_MAJIK_MNEMONIC_SALT, undefined, 1),
  fingerprint: fp,
};

// ── Full registry account (mirror of MajikKey._deriveFromMnemonic + toJSON legacy:true) ──
const pass = "correct horse battery staple";
const acctIds = resolveRequestedKeys([KeyId.BTC, KeyId.ETH, KeyId.ML_KEM_1024, KeyId.ML_DSA_65, KeyId.SOL]);
const derived = deriveKeys(seed0, acctIds);
const acctSalt = new Uint8Array(32).map((_, i) => 200 - i);
const aesKey = await deriveKeyFromPassphraseArgon2(pass, acctSalt);
const store = KeyStore.fromDerived(derived, aesKey);
const xpub = d0.publicKey;
out.account = {
  passphrase: pass,
  mnemonic: mnemonics[0].phrase,
  json: {
    id: fp, label: "ts-account", publicKey: b64(xpub), fingerprint: fp, salt: b64(acctSalt),
    backup: out.backups.v2Argon, timestamp: "2026-07-11T00:00:00.000Z", kdfVersion: 2,
    mnemonicLanguage: "en", keysVersion: 1, keys: store.toEntries(), ...store.toLegacyJSON(),
  },
  secrets: Object.fromEntries([...derived].map(([id, kp]) => [id, b64(kp.secretKey)])),
};

// ── Legacy flat account (kdfVersion 1: X25519 blob via PBKDF2, rest via Argon2id) ──
{
  const lsalt = new Uint8Array(32).map((_, i) => 100 + i);
  const pbKey = deriveKeyFromPassphrase(pass, lsalt);
  const argKey = await deriveKeyFromPassphraseArgon2(pass, lsalt);
  const dd = deriveKeys(seed0, [KeyId.X25519, KeyId.ED25519, KeyId.ML_KEM_768, KeyId.ML_DSA_87]);
  const legacy = KeyStore.fromDerived(dd, argKey);
  const flat: any = legacy.toLegacyJSON();
  flat.encryptedPrivateKey = b64(KeyStore.seal(pbKey, dd.get(KeyId.X25519)!.secretKey));
  out.legacyAccount = {
    passphrase: pass,
    json: { id: fp, label: "legacy", publicKey: b64(xpub), fingerprint: fp, salt: b64(lsalt), backup: out.backups.v1Argon,
      timestamp: "2025-01-01T00:00:00.000Z", kdfVersion: 1, ...flat },
    secrets: Object.fromEntries([...dd].map(([id, kp]) => [id, b64(kp.secretKey)])),
  };
}

// ── web3 ──
{
  const stdBtc = deriveBitcoinKeypairFromSeed(seed0, { standard: true });
  const domBtc = deriveBitcoinKeypairFromSeed(seed0);
  const eth = derived.get(KeyId.ETH)!;
  const edSec = derived.get(KeyId.ED25519)!.secretKey;
  const sol = deriveSolanaKeypairFromEdSecretKey(edSec);
  const msg32 = new Uint8Array(32).map((_, i) => i * 7 + 1);
  const aux = new Uint8Array(32).fill(5);
  const p2 = btc.p2wpkh(domBtc.publicKey);
  const p2std = btc.p2wpkh(stdBtc.publicKey);
  const ethSigH = signEthereumHash({ privateKey: eth.secretKey, publicKey: eth.publicKey }, msg32);
  const ethSigM = signEthereumMessage({ privateKey: eth.secretKey, publicKey: eth.publicKey }, "hello majik");
  const schn = schnorr.sign(msg32, domBtc.privateKey, aux);
  out.web3 = {
    btcStd: { pub: b64(stdBtc.publicKey), sec: b64(stdBtc.privateKey), wif: toWIF(stdBtc), wifU: toWIF(stdBtc, { compressed: false }), address: p2std.address },
    btcDom: { pub: b64(domBtc.publicKey), sec: b64(domBtc.privateKey), wif: toWIF(domBtc), address: p2.address },
    eth: { pub: b64(eth.publicKey), sec: b64(eth.secretKey), address: ethereumAddressFromPublicKey(eth.publicKey) },
    ethSigHash: { msgHex: hex(msg32), ...ethSigH },
    ethSigMsg: { message: "hello majik", ...ethSigM },
    sol: { pub: b64(sol.publicKey), sec: b64(sol.secretKey), address: solanaAddressFromPublicKey(sol.publicKey) },
    solSig: { message: "hi", sig: b64(signWithSolanaMaterial(sol, enc("hi"))) },
    btcEcdsa: b64(signWithBitcoinMaterial(domBtc, msg32, "ecdsa")),
    btcSchnorr: { auxHex: hex(aux), msgHex: hex(msg32), sig: b64(schnorr.sign(msg32, domBtc.privateKey, aux)), pubX: b64(schnorr.getPublicKey(domBtc.privateKey)) },
  };
}

fs.writeFileSync("vectors.json", JSON.stringify(out, null, 1));
console.error("wrote vectors.json", fs.statSync("vectors.json").size, "bytes");
