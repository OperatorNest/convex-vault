import { base64urlEncode, utf8 } from "./base64url.js";
import { derivedKey, type Keyring } from "./keyring.js";

export async function lookupHash(
  ring: Keyring,
  version: number,
  kind: string,
  lookupOwner: string,
  value: string,
): Promise<string> {
  const key = await derivedKey(ring, version, "hash");
  return base64urlEncode(
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        key,
        utf8(JSON.stringify(["convex-vault", 1, kind, lookupOwner, value])),
      ),
    ),
  );
}
export function generateValue(prefix = "", bytes = 32): string {
  return prefix + base64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}
export function valueHint(value: string, enabled: boolean, prefix = ""): string | undefined {
  const codePoints = Array.from(value);
  return enabled && codePoints.length - prefix.length >= 16
    ? `${prefix}…${codePoints.slice(-4).join("")}`
    : undefined;
}
export function randomId(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}
