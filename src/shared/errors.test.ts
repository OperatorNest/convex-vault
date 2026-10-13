import { ConvexError } from "convex/values";
import { describe, expect, it } from "vitest";
import { isVaultError, vaultError } from "./errors.js";

describe("vaultError", () => {
  it("keeps provider details and truncates providerCode to 64 characters", () => {
    const error = vaultError("VAULT_NOT_FOUND", {
      providerStatus: 404,
      providerCode: "x".repeat(70),
    });
    expect(error.data).toEqual({
      code: "VAULT_NOT_FOUND",
      message: "The credential, name or required current value does not exist.",
      providerStatus: 404,
      providerCode: "x".repeat(64),
    });
    expect(isVaultError(error)).toBe(true);
  });
});

describe("isVaultError", () => {
  const valid = vaultError("VAULT_INACTIVE").data;
  it.each([
    ["an unknown key", { ...valid, extra: true }],
    ["retryable on a code that is not provider-originated", { ...valid, retryable: false }],
    ["a message that differs from the code's message", { ...valid, message: "other" }],
    ["an unknown code", { ...valid, code: "VAULT_UNKNOWN" }],
    ["a providerStatus below 100", { ...valid, providerStatus: 99 }],
    ["a non-integer providerStatus", { ...valid, providerStatus: 200.5 }],
    ["a providerCode longer than 64 characters", { ...valid, providerCode: "x".repeat(65) }],
    ["a providerCode that is not well-formed", { ...valid, providerCode: "\ud800" }],
    ["data without a message", { code: valid.code }],
  ])("rejects error data with %s", (_, data) => {
    expect(isVaultError(new ConvexError(data))).toBe(false);
  });
  it("rejects values that are not ConvexError instances with object data", () => {
    expect(isVaultError(new Error("VAULT_INACTIVE"))).toBe(false);
    expect(isVaultError(new ConvexError("VAULT_INACTIVE"))).toBe(false);
  });
});
