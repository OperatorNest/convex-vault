import type { PaginationOptions } from "convex/server";
import { jsonToConvex, type Value } from "convex/values";
import { utf8 } from "./base64url.js";
import { vaultError } from "./errors.js";
import type { Metadata } from "./validators.js";

// shared-block:begin
/** Returns the first `max` UTF-16 code units of `value` as well-formed text without ending inside a surrogate pair. */
export function truncateText(value: string, max: number): string {
  const text = value.toWellFormed();
  const end = Math.min(text.length, max);
  const last = text.charCodeAt(end - 1);
  return text.slice(0, last >= 0xd800 && last <= 0xdbff ? end - 1 : end);
}

/** Returns `value` when it is non-empty, well-formed and at most `maxLength` UTF-16 code units; otherwise throws `VAULT_INVALID_ARGUMENT`. */
export function boundedString(value: string, maxLength: number): string {
  if (value.length === 0 || value.length > maxLength || !value.isWellFormed())
    throw vaultError("VAULT_INVALID_ARGUMENT");
  return value;
}

/** Throws `VAULT_INVALID_ARGUMENT` unless `cursor` is well-formed, at most 4096 characters, and a JSON array of at most `indexKeyLength` primitive values whose strings are well-formed. */
export function validateCursor(cursor: string, indexKeyLength: number): void {
  const isBoundedText = cursor.length <= 4096 && cursor.isWellFormed();
  if (!isBoundedText) throw vaultError("VAULT_INVALID_ARGUMENT");
  let values: Value;
  try {
    values = jsonToConvex(JSON.parse(cursor));
  } catch {
    throw vaultError("VAULT_INVALID_ARGUMENT");
  }
  if (
    !Array.isArray(values) ||
    values.length > indexKeyLength ||
    !values.every(
      (value) =>
        value === null ||
        (typeof value === "string" && value.isWellFormed()) ||
        typeof value === "number" ||
        typeof value === "boolean" ||
        typeof value === "bigint" ||
        value instanceof ArrayBuffer,
    )
  )
    throw vaultError("VAULT_INVALID_ARGUMENT");
}

/** Returns page options with `numItems` 1 to 100, `cursor` and `endCursor` validated against `indexKeyLength` (the paginated index's declared fields plus `_creationTime` and `_id`), `maximumRowsRead` `numItems + 1` and `maximumBytesRead` 1048576; caller read budgets are ignored. */
export function boundedPage(options: PaginationOptions, indexKeyLength: number): PaginationOptions {
  if (!Number.isSafeInteger(options.numItems) || options.numItems < 1 || options.numItems > 100)
    throw vaultError("VAULT_INVALID_ARGUMENT");
  for (const cursor of [options.cursor, options.endCursor])
    if (cursor !== null && cursor !== undefined) validateCursor(cursor, indexKeyLength);
  return {
    numItems: options.numItems,
    cursor: options.cursor,
    endCursor: options.endCursor,
    maximumRowsRead: options.numItems + 1,
    maximumBytesRead: 1_048_576,
  };
}
// shared-block:end

export function invalid(condition: boolean): void {
  if (condition) throw vaultError("VAULT_INVALID_ARGUMENT");
}
export function validateValue(value: string, globalSupplied: boolean): void {
  const length = utf8(value).byteLength;
  invalid(length < 1 || length > 16384 || (globalSupplied && value.length < 32));
}
export function validateScopes(scopes: string[]): void {
  invalid(scopes.length > 32);
  for (const scope of scopes) boundedString(scope, 64);
}
export function validateMetadata(metadata: Metadata): void {
  invalid(Object.keys(metadata).length > 32 || utf8(JSON.stringify(metadata)).byteLength > 4096);
  for (const [key, value] of Object.entries(metadata)) {
    invalid(
      !/^[\x20-\x7e]+$/.test(key) ||
        key.startsWith("_") ||
        key.startsWith("$") ||
        (typeof value === "number" && !Number.isFinite(value)),
    );
  }
}
export function validateGenerate(prefix: string, bytes: number): void {
  invalid(
    !/^[A-Za-z0-9_-]{0,32}$/.test(prefix) || !Number.isInteger(bytes) || bytes < 16 || bytes > 64,
  );
}
export function expiry(
  options: { ttlMs?: number; expiresAt?: number },
  now: number,
): number | undefined {
  invalid(options.ttlMs !== undefined && options.expiresAt !== undefined);
  if (options.ttlMs !== undefined) {
    invalid(
      !Number.isSafeInteger(options.ttlMs) ||
        options.ttlMs <= 0 ||
        !Number.isSafeInteger(now + options.ttlMs),
    );
    return now + options.ttlMs;
  }
  if (options.expiresAt !== undefined)
    invalid(!Number.isSafeInteger(options.expiresAt) || options.expiresAt <= now);
  return options.expiresAt;
}
export function validateMaxUses(maxUses: number | undefined): void {
  if (maxUses !== undefined) invalid(!Number.isSafeInteger(maxUses) || maxUses < 1);
}
