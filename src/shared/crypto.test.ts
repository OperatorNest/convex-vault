import { afterEach, describe, expect, it, vi } from "vitest";
import { ConvexError } from "convex/values";
import { base64urlEncode, base64urlDecode } from "./base64url.js";
import { readConfig } from "./config.js";
import { deriveKeyBytes, generateMasterKey } from "./keyring.js";
import { encryptEnvelope, decryptEnvelope, unwrapDataKey, wrapDataKey } from "./envelope.js";
import { lookupHash, generateValue, valueHint } from "./value.js";
import { vaultError, isVaultError, VAULT_ERROR_CODES } from "./errors.js";
import { expectVaultError } from "../test-helpers.js";

// Fixed independent vectors produced with Node's OpenSSL HKDF/HMAC/AES-GCM APIs.
const TEST_MASTER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const bound = { owner: "tenant", kind: "apiKey", credentialId: "credential", valueId: "value" };
const vector = {
  keyVersion: 1,
  ciphertext: "SCUt6tdYlJi6WxoJlRSkZArfGb2lx5fpa_pHQkTX7w",
  wrappedKey: "RdPHPrRgP-2cj3RjxPvTOtSFKeBGbSKQSpM-PFuqeKRrtdbXE_Kll6I8rpmxLXwF",
  iv: "CAgICAgICAgICAgI",
  keyIv: "CQkJCQkJCQkJCQkJ",
};
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("credential cryptography", () => {
  it("matches independent HKDF and lookup hash vectors", async () => {
    const master = base64urlDecode(TEST_MASTER);
    expect(hex(await deriveKeyBytes(master, "wrap"))).toBe(
      "1f9ed288177ee5f65e35ab46e7336e94711305a8dc3aa96281a907690362c0d4",
    );
    expect(hex(await deriveKeyBytes(master, "hash"))).toBe(
      "aebd1d58cf7d06e2ea10f0956ba454797b213645c71e4f32597aeee7b12ca759",
    );
    const ring = readConfig({ VAULT_KEYS: `1:${TEST_MASTER}` });
    expect(await lookupHash(ring, 1, "apiKey", "tenant", "test credential")).toBe(
      "SdNROiMrjB-jwHvYDKZzmZQHeLJxdCzCOTnrevjIe-w",
    );
  });
  it("matches independent envelope encryption and decryption vectors", async () => {
    const ring = readConfig({ VAULT_KEYS: `1:${TEST_MASTER}` });
    let call = 7;
    vi.spyOn(crypto, "getRandomValues").mockImplementation((bytes) => {
      if (bytes instanceof Uint8Array) bytes.fill(call++);
      return bytes;
    });
    expect(await encryptEnvelope(ring, bound, "test credential")).toEqual(vector);
    expect(await decryptEnvelope(ring, bound, vector)).toBe("test credential");
  });
  it.each(["owner", "kind", "credentialId", "valueId"] as const)(
    "binds %s in AAD",
    async (field) => {
      await expectVaultError(
        decryptEnvelope(
          readConfig({ VAULT_KEYS: `1:${TEST_MASTER}` }),
          { ...bound, [field]: "other" },
          vector,
        ),
        "VAULT_DECRYPT_FAILED",
      );
    },
  );
  it("binds keyVersion even if both versions share a master key", async () => {
    await expectVaultError(
      decryptEnvelope(readConfig({ VAULT_KEYS: `1:${TEST_MASTER},2:${TEST_MASTER}` }), bound, {
        ...vector,
        keyVersion: 2,
      }),
      "VAULT_DECRYPT_FAILED",
    );
  });
  it.each(["ciphertext", "wrappedKey", "iv", "keyIv"] as const)(
    "rejects one-byte tamper of %s",
    async (field) => {
      const bytes = base64urlDecode(vector[field]);
      bytes[0] = (bytes[0] ?? 0) ^ 1;
      await expectVaultError(
        decryptEnvelope(readConfig({ VAULT_KEYS: `1:${TEST_MASTER}` }), bound, {
          ...vector,
          [field]: base64urlEncode(bytes),
        }),
        "VAULT_DECRYPT_FAILED",
      );
    },
  );
  it("rewraps without changing ciphertext and fails closed on corrupt or missing keys", async () => {
    const ring = readConfig({ VAULT_KEYS: `1:${TEST_MASTER},2:${generateMasterKey()}` });
    const next = {
      ...vector,
      ...(await wrapDataKey(ring, bound, await unwrapDataKey(ring, bound, vector))),
    };
    expect(next.ciphertext).toBe(vector.ciphertext);
    expect(next.iv).toBe(vector.iv);
    expect(next.keyVersion).toBe(2);
    expect(await decryptEnvelope(ring, bound, next)).toBe("test credential");
    await expectVaultError(
      unwrapDataKey(ring, { ...bound, owner: "other" }, vector),
      "VAULT_DECRYPT_FAILED",
    );
    await expectVaultError(
      decryptEnvelope(readConfig({ VAULT_KEYS: `2:${TEST_MASTER}` }), bound, vector),
      "VAULT_NOT_CONFIGURED",
    );
    await expectVaultError(
      unwrapDataKey(readConfig({ VAULT_KEYS: `2:${TEST_MASTER}` }), bound, vector),
      "VAULT_NOT_CONFIGURED",
    );
    await expectVaultError(
      decryptEnvelope(ring, bound, { ...vector, ciphertext: "!" }),
      "VAULT_DECRYPT_FAILED",
    );
  });
});
describe("configuration and presentation", () => {
  it("accepts unordered canonical keyring pairs and selects the highest version", () => {
    const ring = readConfig({
      VAULT_KEYS: `2:${TEST_MASTER},1:${generateMasterKey()},3:${generateMasterKey()}`,
    });
    expect(ring.active).toBe(3);
    expect([...ring.keys.keys()]).toEqual([2, 1, 3]);
  });
  it.each([
    undefined,
    "",
    "bad",
    `0:${TEST_MASTER}`,
    `-1:${TEST_MASTER}`,
    `1.5:${TEST_MASTER}`,
    `01:${TEST_MASTER}`,
    `9007199254740992:${TEST_MASTER}`,
    `1:${TEST_MASTER},1:${TEST_MASTER}`,
    `1:${TEST_MASTER},`,
    `1:${TEST_MASTER}=`,
    "1:AA",
    `1:${TEST_MASTER}A`,
    `1: ${TEST_MASTER}`,
    `1:${TEST_MASTER.slice(0, -1)}9`,
    "1:!",
    ` 1:${TEST_MASTER}`,
    `1:${TEST_MASTER}\n`,
    `1:${TEST_MASTER}\ud800`,
  ])("rejects malformed keyrings (%s)", (config) => {
    expect(() => readConfig({ VAULT_KEYS: config })).toThrowError("VAULT_NOT_CONFIGURED");
  });
  it.each(["!", "A", "AB", "AA=", "AA+", "A/"])("rejects noncanonical base64url %s", (value) => {
    expect(() => base64urlDecode(value)).toThrowError("VAULT_INVALID_ARGUMENT");
  });
  it("roundtrips bytes, generates values within bounds, and builds hints from whole code points", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
    expect(base64urlDecode(generateMasterKey())).toHaveLength(32);
    expect(generateValue()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const value = generateValue("sk_", 16);
    expect(value).toMatch(/^sk_[A-Za-z0-9_-]{22}$/);
    expect(valueHint(value, true, "sk_")).toBe(`sk_…${value.slice(-4)}`);
    expect(valueHint("short", true)).toBeUndefined();
    expect(valueHint(`${"x".repeat(15)}\u{1F600}abc`, true)).toBe("…\u{1F600}abc");
    expect(valueHint(`${"x".repeat(14)}\u{1F600}`, true)).toBeUndefined();
    expect(valueHint(value, false)).toBeUndefined();
  });
  it("recognizes only structured vault codes and gives each code a sentence message", () => {
    for (const code of VAULT_ERROR_CODES) {
      const error = vaultError(code);
      expect(isVaultError(error)).toBe(true);
      expect(error.data.code).toBe(code);
      expect(error.data.message).toMatch(/^[A-Z].+\.$/);
    }
    expect(isVaultError(new Error("VAULT_NOT_FOUND"))).toBe(false);
    expect(isVaultError({ data: { code: "VAULT_NOT_FOUND" } })).toBe(false);
    expect(isVaultError(new ConvexError({ code: "VAULT_INACTIVE" }))).toBe(false);
    expect(isVaultError(new ConvexError({ code: "VAULT_INACTIVE", message: 42 }))).toBe(false);
    expect(
      isVaultError(new ConvexError({ code: "VAULT_INACTIVE", message: "Wrong message." })),
    ).toBe(false);
  });
});
