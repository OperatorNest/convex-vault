import { ConvexError } from "convex/values";
import { truncateText } from "./bounds.js";

// repository-codes:begin
/** Lists every code a vault error can carry. */
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

const VAULT_PROVIDER_ERROR_CODES = [] as const satisfies readonly VaultErrorCode[];

const VAULT_ERROR_MESSAGES = {
  VAULT_NOT_CONFIGURED:
    "VAULT_KEYS is missing or malformed, lacks a required key version, or changed during key rotation.",
  VAULT_INVALID_ARGUMENT: "An argument is missing, malformed or out of bounds.",
  VAULT_NOT_FOUND: "The credential, name or required current value does not exist.",
  VAULT_NOT_REVEALABLE:
    "The credential's kind stores only a hash, so its value cannot be revealed.",
  VAULT_NOT_VERIFIABLE: "The kind stores only ciphertext, so its values cannot be verified.",
  VAULT_DUPLICATE_VALUE: "A stored current or previous value has the same hash.",
  VAULT_DUPLICATE_NAME: "The owner already has a credential of this kind with this name.",
  VAULT_KIND_CONFLICT: "Storage, origin or lookup differs from the kind's recorded policy.",
  VAULT_INACTIVE:
    "The credential is revoked or exhausted, or expired for a reveal or for a replace without new expiry.",
  VAULT_DECRYPT_FAILED: "The payload or wrapped key failed authentication.",
} as const satisfies Record<VaultErrorCode, string>;
// repository-codes:end

const ERROR_DATA_KEYS: ReadonlySet<string> = new Set([
  "code",
  "message",
  "retryable",
  "providerStatus",
  "providerCode",
]);

/** One fixed caller-visible failure; `VAULT_ERROR_CODES` lists every code. */
export type VaultErrorCode = (typeof VAULT_ERROR_CODES)[number];

/** Error data: the code, its fixed message and bounded provider failure details. `retryable` is present exactly on provider-originated codes. */
export type VaultErrorData = {
  code: VaultErrorCode;
  message: string;
  /** `true` only when the failure may be transient (a network failure, a timeout, or provider status 408, 429 or 5xx) and repeating the identical call cannot create a second provider effect (the call is a read, carries an idempotency key the component or provider deduplicates, or failed with a 429 or before the request was sent). */
  retryable?: boolean;
  providerStatus?: number;
  providerCode?: string;
};

type ProviderErrorCode = (typeof VAULT_PROVIDER_ERROR_CODES)[number];

type ErrorDetails<Code extends VaultErrorCode> = [Code] extends [
  Exclude<VaultErrorCode, ProviderErrorCode>,
]
  ? [details?: { retryable?: never; providerStatus?: number; providerCode?: string }]
  : [details: { retryable: boolean; providerStatus?: number; providerCode?: string }];

function isProviderErrorCode(code: unknown): code is ProviderErrorCode {
  return VAULT_PROVIDER_ERROR_CODES.some((candidate) => candidate === code);
}

/** Creates the error for `code` with its fixed message. Provider-originated codes require `details.retryable`; other codes forbid it. `providerCode` is truncated to 64 characters. */
export function vaultError<Code extends VaultErrorCode>(
  code: Code,
  ...[details]: ErrorDetails<Code>
): ConvexError<VaultErrorData> {
  return new ConvexError({
    code,
    message: VAULT_ERROR_MESSAGES[code],
    ...(isProviderErrorCode(code) &&
      details?.retryable !== undefined && { retryable: details.retryable }),
    ...(details?.providerStatus !== undefined && { providerStatus: details.providerStatus }),
    ...(details?.providerCode !== undefined && {
      providerCode: truncateText(details.providerCode, 64),
    }),
  });
}

/** Returns true when `error` carries exactly a known code, its fixed message, `retryable` on provider-originated codes only, and well-formed provider details. */
export function isVaultError(error: unknown): error is ConvexError<VaultErrorData> {
  if (!(error instanceof ConvexError)) return false;
  const data: unknown = error.data;
  if (typeof data !== "object" || data === null || !("code" in data) || !("message" in data))
    return false;
  const { code, message } = data;
  return (
    Object.keys(data).every((key) => ERROR_DATA_KEYS.has(key)) &&
    VAULT_ERROR_CODES.some(
      (candidate) => candidate === code && message === VAULT_ERROR_MESSAGES[candidate],
    ) &&
    ("retryable" in data
      ? isProviderErrorCode(code) && typeof data.retryable === "boolean"
      : !isProviderErrorCode(code)) &&
    (!("providerStatus" in data) ||
      (typeof data.providerStatus === "number" &&
        Number.isInteger(data.providerStatus) &&
        data.providerStatus >= 100 &&
        data.providerStatus <= 599)) &&
    (!("providerCode" in data) ||
      (typeof data.providerCode === "string" &&
        data.providerCode.isWellFormed() &&
        data.providerCode.length <= 64))
  );
}
