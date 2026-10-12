import { ConvexError } from "convex/values";

export const VAULT_ERROR_CODES = [
  "VAULT_NOT_CONFIGURED",
  "VAULT_INVALID_ARGUMENT",
  "VAULT_NOT_FOUND",
  "VAULT_NOT_REVEALABLE",
  "VAULT_NOT_VERIFIABLE",
  "VAULT_DUPLICATE_VALUE",
  "VAULT_DUPLICATE_NAME",
  "VAULT_KIND_CONFLICT",
  "VAULT_INACTIVE",
  "VAULT_DECRYPT_FAILED",
] as const;
export type VaultErrorCode = (typeof VAULT_ERROR_CODES)[number];
export type VaultErrorData = { code: VaultErrorCode; message: string };

const VAULT_ERROR_MESSAGES = {
  VAULT_NOT_CONFIGURED:
    "VAULT_KEYS is missing or malformed, lacks a required key version, or changed during key rotation.",
  VAULT_INVALID_ARGUMENT: "An argument is invalid, missing or out of bounds.",
  VAULT_NOT_FOUND: "The entry, name or required current value does not exist.",
  VAULT_NOT_REVEALABLE: "The entry's kind stores only a hash, so its value cannot be revealed.",
  VAULT_NOT_VERIFIABLE: "The kind stores only ciphertext, so its values cannot be verified.",
  VAULT_DUPLICATE_VALUE: "A stored current or previous value has the same hash.",
  VAULT_DUPLICATE_NAME: "The owner already has an entry of this kind with this name.",
  VAULT_KIND_CONFLICT: "Storage, origin or lookup differs from the kind's recorded policy.",
  VAULT_INACTIVE:
    "The entry is revoked or exhausted, or expired for a reveal or for a replace without new expiry.",
  VAULT_DECRYPT_FAILED: "The payload or wrapped key failed authentication.",
} as const satisfies Record<VaultErrorCode, string>;

export function vaultError(code: VaultErrorCode): ConvexError<VaultErrorData> {
  return new ConvexError({ code, message: VAULT_ERROR_MESSAGES[code] });
}
export function isVaultError(error: unknown): error is ConvexError<VaultErrorData> {
  if (!(error instanceof ConvexError)) return false;
  const data: unknown = error.data;
  return (
    typeof data === "object" &&
    data !== null &&
    "code" in data &&
    "message" in data &&
    typeof data.message === "string" &&
    VAULT_ERROR_CODES.some((code) => code === data.code)
  );
}
