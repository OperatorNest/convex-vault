import { base64urlDecode, base64urlEncode, utf8 } from "./base64url.js";
import { vaultError } from "./errors.js";
import { deriveKeyBytes, masterKey, type Keyring } from "./keyring.js";

export type Identity = { owner: string; kind: string; entryId: string; valueId: string };
export type Envelope = {
  keyVersion: number;
  ciphertext: string;
  iv: string;
  wrappedKey: string;
  keyIv: string;
};
function aad(identity: Identity, version?: number): Uint8Array<ArrayBuffer> {
  const { owner, kind, entryId, valueId } = identity;
  return utf8(
    JSON.stringify(
      version === undefined
        ? ["convex-vault", 1, "value", owner, kind, entryId, valueId]
        : ["convex-vault", 1, "key", owner, kind, entryId, valueId, version],
    ),
  );
}
async function aes(bytes: Uint8Array, usage: "encrypt" | "decrypt") {
  return crypto.subtle.importKey("raw", bytes.slice(), "AES-GCM", false, [usage]);
}
async function wrap(ring: Keyring, identity: Identity, dataKey: Uint8Array) {
  const keyIv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aes(await deriveKeyBytes(masterKey(ring, ring.active), "wrap"), "encrypt");
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: keyIv, additionalData: aad(identity, ring.active) },
    key,
    dataKey.slice(),
  );
  return {
    keyVersion: ring.active,
    wrappedKey: base64urlEncode(new Uint8Array(wrapped)),
    keyIv: base64urlEncode(keyIv),
  };
}
async function unwrap(ring: Keyring, identity: Identity, envelope: Envelope) {
  const key = await aes(
    await deriveKeyBytes(masterKey(ring, envelope.keyVersion), "wrap"),
    "decrypt",
  );
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64urlDecode(envelope.keyIv),
        additionalData: aad(identity, envelope.keyVersion),
      },
      key,
      base64urlDecode(envelope.wrappedKey),
    ),
  );
}
export async function encryptEnvelope(
  ring: Keyring,
  identity: Identity,
  value: string,
): Promise<Envelope> {
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aes(dataKey, "encrypt");
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(identity) },
    key,
    utf8(value),
  );
  return {
    ...(await wrap(ring, identity, dataKey)),
    ciphertext: base64urlEncode(new Uint8Array(ciphertext)),
    iv: base64urlEncode(iv),
  };
}
export async function decryptEnvelope(
  ring: Keyring,
  identity: Identity,
  envelope: Envelope,
): Promise<string> {
  masterKey(ring, envelope.keyVersion);
  try {
    const key = await aes(await unwrap(ring, identity, envelope), "decrypt");
    const bytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64urlDecode(envelope.iv), additionalData: aad(identity) },
      key,
      base64urlDecode(envelope.ciphertext),
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw vaultError("VAULT_DECRYPT_FAILED");
  }
}
export async function rewrapEnvelope(
  ring: Keyring,
  identity: Identity,
  envelope: Envelope,
): Promise<Envelope> {
  masterKey(ring, envelope.keyVersion);
  try {
    return { ...envelope, ...(await wrap(ring, identity, await unwrap(ring, identity, envelope))) };
  } catch {
    throw vaultError("VAULT_DECRYPT_FAILED");
  }
}
