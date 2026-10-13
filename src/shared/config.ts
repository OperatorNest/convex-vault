import { base64urlDecode } from "./base64url.js";
import { vaultError } from "./errors.js";
import type { Keyring } from "./keyring.js";

// repository-config:begin
/** Component env values the component reads; each stays an optional string until `readConfig` validates it. */
export type ComponentEnv = {
  readonly VAULT_KEYS?: string;
};

/** Validates every component env value and returns the keyring; throws `VAULT_NOT_CONFIGURED` on a missing or malformed `VAULT_KEYS`. */
export function readConfig(env: ComponentEnv): Keyring {
  try {
    const config = readSecret(env.VAULT_KEYS);
    if (config === undefined) throw vaultError("VAULT_NOT_CONFIGURED");
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
// repository-config:end

// shared-block:begin
/** Returns `undefined` for an unset value and `value` when it is non-empty, well-formed and equal to its trim; otherwise throws `VAULT_NOT_CONFIGURED`. */
export function readSecret(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (value === "" || !value.isWellFormed() || value.trim() !== value)
    throw vaultError("VAULT_NOT_CONFIGURED");
  return value;
}
// shared-block:end
