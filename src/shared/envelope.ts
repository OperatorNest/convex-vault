import { base64urlDecode, base64urlEncode, utf8 } from "./base64url.js";
import { vaultError } from "./errors.js";
import { derivedKey, type Keyring } from "./keyring.js";

export type Identity = { owner: string; kind: string; credentialId: string; valueId: string };
export type Envelope = {
  keyVersion: number;
  ciphertext: string;
  iv: string;
  wrappedKey: string;
  keyIv: string;
};
function aad(identity: Identity, version?: number): Uint8Array<ArrayBuffer> {
  const { owner, kind, credentialId, valueId } = identity;
  return utf8(
    JSON.stringify(
      version === undefined
        ? ["convex-vault", 1, "value", owner, kind, credentialId, valueId]
        : ["convex-vault", 1, "key", owner, kind, credentialId, valueId, version],
    ),
  );
}
async function dataKeyCipher(dataKey: Uint8Array, usage: "encrypt" | "decrypt") {
  return crypto.subtle.importKey("raw", dataKey.slice(), "AES-GCM", false, [usage]);
}
export async function wrapDataKey(
  ring: Keyring,
  identity: Identity,
  dataKey: Uint8Array,
): Promise<Pick<Envelope, "keyVersion" | "wrappedKey" | "keyIv">> {
  const keyIv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivedKey(ring, ring.active, "wrap");
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
export async function unwrapDataKey(
  ring: Keyring,
  identity: Identity,
  envelope: Envelope,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await derivedKey(ring, envelope.keyVersion, "wrap");
  try {
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
  } catch {
    throw vaultError("VAULT_DECRYPT_FAILED");
  }
}
export async function decryptPayload(
  identity: Identity,
  envelope: Envelope,
  dataKey: Uint8Array,
): Promise<string> {
  try {
    const bytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64urlDecode(envelope.iv), additionalData: aad(identity) },
      await dataKeyCipher(dataKey, "decrypt"),
      base64urlDecode(envelope.ciphertext),
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw vaultError("VAULT_DECRYPT_FAILED");
  }
}
export async function encryptEnvelope(
  ring: Keyring,
  identity: Identity,
  value: string,
): Promise<Envelope> {
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(identity) },
    await dataKeyCipher(dataKey, "encrypt"),
    utf8(value),
  );
  return {
    ...(await wrapDataKey(ring, identity, dataKey)),
    ciphertext: base64urlEncode(new Uint8Array(ciphertext)),
    iv: base64urlEncode(iv),
  };
}
export async function decryptEnvelope(
  ring: Keyring,
  identity: Identity,
  envelope: Envelope,
): Promise<string> {
  return decryptPayload(identity, envelope, await unwrapDataKey(ring, identity, envelope));
}
