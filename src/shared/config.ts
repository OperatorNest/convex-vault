import { base64urlDecode } from "./base64url.js";
import { vaultError } from "./errors.js";
import type { Keyring } from "./keyring.js";

/** Component env values the component reads; each stays an optional string until `readConfig` validates it. */
export type ComponentEnv = {
  readonly VAULT_KEYS?: string;
};

/** Validates every component env value and returns the keyring; throws `VAULT_NOT_CONFIGURED` on a missing or malformed `VAULT_KEYS`. */
export function readConfig(env: ComponentEnv): Keyring {
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
    return { active: Math.max(...keys.keys()), keys, derivedKeys: new Map() };
  } catch {
    throw vaultError("VAULT_NOT_CONFIGURED");
  }
}
