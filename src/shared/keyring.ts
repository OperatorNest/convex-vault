import { base64urlEncode, utf8 } from "./base64url.js";
import { vaultError } from "./errors.js";

// readConfig builds a new Keyring per function call, so derivedKeys caches for one call only.
export type Keyring = {
  active: number;
  keys: Map<number, Uint8Array<ArrayBuffer>>;
  derivedKeys: Map<string, Promise<CryptoKey>>;
};
export function masterKey(ring: Keyring, version: number): Uint8Array<ArrayBuffer> {
  const key = ring.keys.get(version);
  if (!key) throw vaultError("VAULT_NOT_CONFIGURED");
  return key;
}
export async function deriveKeyBytes(
  master: Uint8Array,
  purpose: "wrap" | "hash" | "fingerprint",
): Promise<Uint8Array<ArrayBuffer>> {
  const ikm = await crypto.subtle.importKey("raw", master.slice(), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: utf8(`convex-vault/1/${purpose}`),
      },
      ikm,
      256,
    ),
  );
}
export function derivedKey(
  ring: Keyring,
  version: number,
  purpose: "wrap" | "hash",
): Promise<CryptoKey> {
  const master = masterKey(ring, version);
  const name = `${purpose}:${version}`;
  let key = ring.derivedKeys.get(name);
  if (!key) {
    key = deriveKeyBytes(master, purpose).then((bytes) =>
      purpose === "wrap"
        ? crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"])
        : crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    );
    ring.derivedKeys.set(name, key);
  }
  return key;
}
export async function keyringFingerprint(ring: Keyring): Promise<string> {
  const parts = await Promise.all(
    [...ring.keys]
      .toSorted(([a], [b]) => a - b)
      .map(
        async ([version, key]) =>
          `${version}:${base64urlEncode(await deriveKeyBytes(key, "fingerprint"))}`,
      ),
  );
  return base64urlEncode(
    new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(parts.join(",")))),
  );
}
/** Returns a new random 32-byte master key as unpadded base64url, without a version. */
export function generateMasterKey(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
}
