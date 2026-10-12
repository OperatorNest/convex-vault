import type { PaginationOptions } from "convex/server";
import { jsonToConvex } from "convex/values";
import { utf8 } from "./base64url.js";
import { vaultError } from "./errors.js";
import type { Metadata } from "./validators.js";

export function invalid(condition: boolean): void {
  if (condition) throw vaultError("VAULT_INVALID_ARGUMENT");
}
// With endCursor, paginate ignores numItems; maximumRowsRead keeps the read bounded.
export function boundedPage(options: PaginationOptions): PaginationOptions {
  invalid(
    !Number.isSafeInteger(options.numItems) || options.numItems < 1 || options.numItems > 100,
  );
  for (const cursor of [options.cursor, options.endCursor]) {
    if (cursor === null || cursor === undefined) continue;
    try {
      invalid(!Array.isArray(jsonToConvex(JSON.parse(cursor))));
    } catch {
      throw vaultError("VAULT_INVALID_ARGUMENT");
    }
  }
  return {
    numItems: options.numItems,
    cursor: options.cursor,
    endCursor: options.endCursor,
    maximumRowsRead: options.numItems + 1,
  };
}
export function boundedString(value: string, max: number): void {
  invalid(value.length === 0 || value.length > max);
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
