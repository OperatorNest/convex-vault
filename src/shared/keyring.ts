import { base64urlDecode, base64urlEncode, utf8 } from "./base64url.js";
import { vaultError } from "./errors.js";

export type Keyring = { active: number; keys: Map<number, Uint8Array<ArrayBuffer>> };
export function readConfig(env: { VAULT_KEYS?: string }): Keyring {
  const config = env.VAULT_KEYS;
  try {
    if (!config) throw vaultError("VAULT_NOT_CONFIGURED");
    const keys = new Map<number, Uint8Array<ArrayBuffer>>();
    for (const part of config.split(",")) {
      const match = /^([1-9][0-9]*):([A-Za-z0-9_-]+)$/.exec(part);
      if (!match) throw vaultError("VAULT_NOT_CONFIGURED");
      const version = Number(match[1]);
      const encoded = match[2];
      if (!Number.isSafeInteger(version) || keys.has(version) || encoded === undefined) {
        throw vaultError("VAULT_NOT_CONFIGURED");
      }
      const key = base64urlDecode(encoded);
      if (key.length !== 32) throw vaultError("VAULT_NOT_CONFIGURED");
      keys.set(version, key);
    }
    return { active: Math.max(...keys.keys()), keys };
  } catch {
    throw vaultError("VAULT_NOT_CONFIGURED");
  }
}
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
