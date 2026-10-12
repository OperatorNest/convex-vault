import { convexTest } from "convex-test";
import { expect, vi } from "vitest";
import schema from "./component/schema.js";
import { generateMasterKey } from "./shared/keyring.js";
import { isVaultError, type VaultErrorCode } from "./shared/errors.js";

const modules = import.meta.glob(["./component/**/*.ts", "!./component/**/*.test.ts"]);
export function setupTest() {
  return convexTest(schema, modules);
}
export type TestCtx = ReturnType<typeof setupTest>;
export function configureKeys(version = 1) {
  const key = generateMasterKey();
  vi.stubEnv("VAULT_KEYS", `${version}:${key}`);
  return key;
}
export async function drain(t: TestCtx) {
  await t.finishAllScheduledFunctions(vi.runAllTimers);
}
export function required<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) throw new Error("Expected a test value");
  return value;
}
export async function expectVaultError(promise: Promise<unknown>, code: VaultErrorCode) {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(isVaultError(error)).toBe(true);
  if (isVaultError(error)) expect(error.data.code).toBe(code);
}
