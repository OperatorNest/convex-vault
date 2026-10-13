import { convexTest } from "convex-test";
import { expect, vi } from "vitest";
import schema from "./component/schema.js";
import { generateMasterKey } from "./shared/keyring.js";
import { isVaultError, type VaultErrorCode } from "./shared/errors.js";

// shared-block:begin
type GlobImportMeta = ImportMeta & {
  glob: (patterns: string[]) => Record<string, () => Promise<unknown>>;
};
const modules = (import.meta as GlobImportMeta).glob([
  "./component/**/*.ts",
  "!./component/**/*.test.ts",
]);

export function setupTest() {
  const t = convexTest(schema, modules);
  return t;
}

export type TestCtx = ReturnType<typeof setupTest>;

export async function drain(t: Pick<TestCtx, "finishAllScheduledFunctions">): Promise<void> {
  await t.finishAllScheduledFunctions(vi.runAllTimers);
}

export function required<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`Expected ${what} to exist`);
  return value;
}

export async function expectVaultError(
  promise: Promise<unknown>,
  code: VaultErrorCode,
): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(isVaultError(error), String(error)).toBe(true);
  if (isVaultError(error)) expect(error.data.code).toBe(code);
}
// shared-block:end

export function configureKeys(version = 1) {
  const key = generateMasterKey();
  vi.stubEnv("VAULT_KEYS", `${version}:${key}`);
  return key;
}
