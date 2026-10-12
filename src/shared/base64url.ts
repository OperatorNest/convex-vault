import { vaultError } from "./errors.js";

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
/** Decodes canonical, unpadded RFC 4648 base64url and rejects every other encoding. */
export function base64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw vaultError("VAULT_INVALID_ARGUMENT");
  }
  try {
    const binary = atob(
      text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4),
    );
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (base64urlEncode(bytes) !== text) throw vaultError("VAULT_INVALID_ARGUMENT");
    return bytes;
  } catch {
    throw vaultError("VAULT_INVALID_ARGUMENT");
  }
}
export const utf8 = (text: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(text);
