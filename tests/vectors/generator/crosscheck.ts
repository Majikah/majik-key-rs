// Loads a Rust-produced account with the REAL TS KeyStore / crypto provider and checks it.
// Run from the TS repo root:  npx tsx gen/crosscheck.ts /path/to/rust-account.json
import fs from "node:fs";
import { mnemonicToSeedSync } from "@scure/bip39";
import { KeyStore } from "../src/core/keys/key-store.ts";
import { deriveKeys } from "../src/core/keys/key-impls.ts";
import { KeyId } from "../src/core/keys/key-id.ts";
import { deriveKeyFromPassphraseArgon2, deriveKeyFromMnemonicArgon2, aesGcmDecrypt, fingerprintFromPublicRaw } from "../src/core/crypto/crypto-provider.ts";
import { backupSaltFor } from "../src/core/crypto/constants.ts";
import { arrayToBase64, base64ToUint8Array, base64ToUtf8 } from "../src/core/utils.ts";

const doc = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const j = doc.json;
const eq = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
let ok = 0;
const check = (c: boolean, m: string) => { if (!c) { console.error("FAIL:", m); process.exit(1); } ok++; };

// 1) registry `keys` → KeyStore → unlock with passphrase → secrets equal TS derivation
const salt = base64ToUint8Array(j.salt);
const aes = await deriveKeyFromPassphraseArgon2(doc.passphrase, salt);
const store = KeyStore.fromEntries(j.keys);
store.unlock(() => aes);
const seed = new Uint8Array(mnemonicToSeedSync(doc.mnemonic));
const ids = store.ids();
const want = deriveKeys(seed, ids);
for (const id of ids) {
  check(eq(store.getSecretKey(id), want.get(id)!.secretKey), `${id} secret`);
  check(eq(store.getPublicKey(id), want.get(id)!.publicKey), `${id} public`);
}
check(ids.length === 9, `expected 9 keys, got ${ids.length}`);

// 2) flat legacy fields written by Rust are readable by TS fromLegacyJSON
const legacy = KeyStore.fromLegacyJSON(j);
legacy.unlock(() => aes);
for (const id of legacy.ids()) check(eq(legacy.getSecretKey(id), want.get(id)!.secretKey), `legacy ${id}`);
check(legacy.ids().length === 5, "legacy has the 5 pre-registry keys");

// 3) fingerprint / id
check(j.fingerprint === fingerprintFromPublicRaw(want.get(KeyId.X25519)!.publicKey), "fingerprint");

// 4) Rust-written mnemonic backup decrypts with the TS recipe (salt gen 2, Argon2id)
for (const b of [j.backup, doc.exportedBackup]) {
  const blob = JSON.parse(base64ToUtf8(b));
  check(blob.backupKdfVersion === 2 && blob.backupSaltVersion === 2, "backup version fields");
  const key = await deriveKeyFromMnemonicArgon2(doc.mnemonic, new TextEncoder().encode(backupSaltFor(blob.backupSaltVersion)));
  const plain = aesGcmDecrypt(key, base64ToUint8Array(blob.iv), base64ToUint8Array(blob.ciphertext));
  check(!!plain && eq(plain, want.get(KeyId.X25519)!.secretKey), "backup plaintext is the X25519 secret");
}
console.log(`TS accepted the Rust-created account: ${ok} checks passed`);
