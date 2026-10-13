// Snapshot imports deliberately corrupt this disposable anonymous local deployment.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { ConvexHttpClient } from "convex/browser";
import { anyApi } from "convex/server";
import { runSmoke, step } from "./smoke-harness.mjs";

const root = resolve(import.meta.dirname, "..");
const plaintexts = new Set();
const keys = [];
let backend;
let publicClient;
let snapshotNumber = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
function equal(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), message);
}
async function item(description, fn) {
  await step(description, async () => {
    const failure = await fn().then(
      () => null,
      (error) => ({ error }),
    );
    // Never echo a server response, command arguments, snapshot data, plaintext or keys.
    if (failure !== null)
      throw new Error(
        failure.error instanceof Error && failure.error.message.startsWith("Smoke:")
          ? failure.error.message
          : "check failed",
      );
  });
}
async function waitFor(description, fn, timeout = 300_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const result = await fn();
    if (result) return result;
    await sleep(100);
  }
  throw new Error(`Smoke: timed out waiting for ${description}`);
}
async function cli(args, input) {
  try {
    return await backend.runConvexCli(args, input);
  } catch {
    throw new Error("Smoke: local Convex CLI command failed");
  }
}
async function cliRunComponent(name, args) {
  try {
    await backend.runConvexCli(["run", "--component", "vault", name, JSON.stringify(args)]);
    return "no_error";
  } catch (error) {
    return /VAULT_[A-Z_]+/.exec(String(error?.message))?.[0] ?? "unknown_error";
  }
}
const mutation = (name, args = {}) => backend.client.mutation(anyApi.admin[name], args);
const query = (name, args = {}) => backend.client.query(anyApi.admin[name], args);
async function code(promise) {
  try {
    await promise;
    return "no_error";
  } catch (error) {
    let data = error.data;
    if (typeof data === "string") {
      try {
        data = JSON.parse(data);
      } catch {
        data = undefined;
      }
    }
    return data?.code ?? /VAULT_[A-Z_]+/.exec(String(error.message))?.[0] ?? "unknown_error";
  }
}
function generateTestValue() {
  const value = `test_${crypto.randomUUID()}_${crypto.randomUUID()}`;
  plaintexts.add(value);
  return value;
}
async function create(kind, options = {}) {
  const result = await mutation("create", { kind, owner: "smoke", ...options });
  if (result.value) plaintexts.add(result.value);
  return result;
}
async function replace(ref, options = {}) {
  const result = await mutation("replace", { ref, ...options });
  if (result.value) plaintexts.add(result.value);
  return result;
}
async function setKeys(config) {
  try {
    await backend.setEnvironmentVariable("VAULT_KEYS", config);
  } catch {
    throw new Error("Smoke: setting VAULT_KEYS failed");
  }
}
async function configured(config, version) {
  await setKeys(config);
  await waitFor("keyring update", async () => {
    try {
      return (await query("keysGetStatus")).activeVersion === version;
    } catch {
      return false;
    }
  });
}
function generateKey(version) {
  const line = execFileSync(
    process.execPath,
    [join(root, "bin/convex-vault.js"), "generate-key", "--version", String(version)],
    { encoding: "utf8" },
  ).trim();
  assert(new RegExp(`^${version}:[A-Za-z0-9_-]{43}$`).test(line), "Smoke: CLI key format");
  const key = line.slice(line.indexOf(":") + 1);
  keys.push(key);
  return line;
}
async function snapshot() {
  const path = join(backend.workspace, `snapshot-${snapshotNumber++}.zip`);
  await cli(["export", "--path", path]);
  const names = execFileSync("unzip", ["-Z1", path], { encoding: "utf8" }).trim().split("\n");
  const tables = new Map();
  for (const name of names.filter(
    (member) => member.endsWith("/documents.jsonl") && member.includes("/vault/"),
  )) {
    const table = name.split("/").at(-2);
    const text = execFileSync("unzip", ["-p", path, name], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    tables.set(
      table,
      text.trim()
        ? text
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line))
        : [],
    );
  }
  assert(
    ["credentials", "values", "events", "kinds"].every((table) => tables.has(table)),
    "Smoke: snapshot missing a component table",
  );
  return tables;
}
async function areValuesDeleted(credentialIds) {
  const tables = await snapshot();
  return credentialIds.every(
    (credentialId) =>
      !tables.get("values").some((row) => row.credentialId === credentialId) &&
      tables.get("credentials").find((row) => row._id === credentialId)?.valuesDeletedAt !==
        undefined,
  );
}
async function runCleanup(credentialIds) {
  equal(await cliRunComponent("cleanup:run", {}), "no_error", "Smoke: cleanup run failed");
  await waitFor("cleanup", () => areValuesDeleted(credentialIds));
}
async function importValues(rows) {
  const path = join(backend.workspace, "values.jsonl");
  writeFileSync(path, rows.map((row) => JSON.stringify(row)).join("\n"));
  await cli(["import", "--component", "vault", "--table", "values", "--replace", "--yes", path]);
}
async function chunks(items, fn, size = 8) {
  for (let start = 0; start < items.length; start += size)
    await Promise.all(items.slice(start, start + size).map(fn));
}

async function journey(smokeBackend) {
  backend = smokeBackend;
  publicClient = new ConvexHttpClient(backend.url, { logger: false });
  const one = generateKey(1);
  const two = generateKey(2);
  await configured(one, 1);
  await item("six combinations create, reveal/verify, replace with grace, revoke", async () => {
    for (const [kind, storage, generated] of [
      ["providerKey", "encrypted", false],
      ["signingKey", "encrypted", true],
      ["sharedToken", "hashed", false],
      ["apiKey", "hashed", true],
      ["importedKey", "both", false],
      ["dashboardKey", "both", true],
    ]) {
      const first = generated ? undefined : generateTestValue();
      const credential = await create(kind, {
        name: kind,
        ...(generated ? {} : { value: first }),
        scopes: ["read"],
        metadata: { tier: 1 },
      });
      const ref = { credentialId: credential.credentialId };
      const value = credential.value ?? first;
      assert(generated === (credential.value !== undefined), "Smoke: plaintext return policy");
      if (storage !== "hashed")
        equal((await mutation("reveal", { ref })).value, value, "Smoke: reveal differs");
      if (storage !== "encrypted")
        assert(
          (await mutation("verify", { kind, owner: "smoke", value, requiredScopes: ["read"] })).ok,
          "Smoke: verify rejected",
        );
      const next = generated ? undefined : generateTestValue();
      const changed = await replace(ref, {
        graceMs: 60_000,
        ...(generated ? {} : { value: next }),
      });
      const current = changed.value ?? next;
      if (storage !== "hashed") {
        const revealed = await mutation("reveal", { ref, includePrevious: true });
        equal(revealed.value, current, "Smoke: replacement differs");
        equal(revealed.previous?.value, value, "Smoke: missing previous");
      }
      if (storage !== "encrypted")
        for (const token of [value, current])
          assert(
            (await mutation("verify", { kind, owner: "smoke", value: token })).ok,
            "Smoke: grace verification rejected",
          );
      await mutation("revoke", { ref });
      await mutation("revoke", { ref });
      equal((await query("get", { ref })).status, "revoked", "Smoke: revoke status");
      if (storage !== "hashed")
        equal(
          await code(mutation("reveal", { ref })),
          "VAULT_INACTIVE",
          "Smoke: revoked reveal accepted",
        );
      if (storage !== "encrypted")
        assert(
          !(await mutation("verify", { kind, owner: "smoke", value: current })).ok,
          "Smoke: revoked verify accepted",
        );
      equal(
        await code(query("get", { ref: { owner: "smoke", kind, name: kind } })),
        "VAULT_NOT_FOUND",
        "Smoke: revoked name resolves",
      );
      await create(kind, { name: kind, ...(generated ? {} : { value: generateTestValue() }) });
    }
    const page = await query("list", {
      owner: "smoke",
      paginationOpts: { numItems: 2, cursor: null },
    });
    assert(page.page.length === 2 && !page.isDone, "Smoke: paginator failed");
    const next = await query("list", {
      owner: "smoke",
      paginationOpts: { numItems: 2, cursor: page.continueCursor },
    });
    assert(
      next.page.length === 2 && next.page[0].credentialId !== page.page[0].credentialId,
      "Smoke: paginator did not advance",
    );
    const events = await query("eventsList", {
      ref: { owner: "smoke" },
      paginationOpts: { numItems: 100, cursor: null },
    });
    assert(
      events.page.some((event) => event.type === "revoked"),
      "Smoke: revoke event missing",
    );
    const rejectedCreate = await publicClient
      .mutation(anyApi.example.create, { kind: "apiKey", name: "unauthenticated" })
      .then(
        () => "accepted",
        (error) => error.message,
      );
    assert(
      rejectedCreate.includes("Not signed in"),
      "Smoke: public create accepts anonymous caller",
    );
    const unauthenticated = await publicClient
      .query(anyApi.example.list, { paginationOpts: { numItems: 1, cursor: null } })
      .then(
        () => "accepted",
        (error) => error.message,
      );
    assert(
      unauthenticated.includes("Not signed in"),
      "Smoke: public list accepts anonymous caller",
    );
  });
  await item("ciphertext/wrapped-key swaps and byte flips: 8/8 reveals fail", async () => {
    const a = await create("providerKey", { value: generateTestValue() });
    const b = await create("providerKey", { value: generateTestValue(), owner: "other" });
    const tables = await snapshot();
    const rows = tables.get("values");
    const credentials = tables.get("credentials");
    const ids = [a, b].map(
      (credential) => credentials.find((row) => row._id === credential.credentialId)._id,
    );
    const indexes = ids.map((id) =>
      rows.findIndex((row) => row.credentialId === id && row.state === "current"),
    );
    assert(
      indexes.every((index) => index >= 0),
      "Smoke: tamper targets missing",
    );
    let failed = 0;
    try {
      for (const field of ["ciphertext", "wrappedKey"]) {
        for (const mode of ["swap", "flip"]) {
          const changed = structuredClone(rows);
          if (mode === "swap")
            [changed[indexes[0]][field], changed[indexes[1]][field]] = [
              changed[indexes[1]][field],
              changed[indexes[0]][field],
            ];
          else
            for (const index of indexes) {
              const bytes = Buffer.from(changed[index][field], "base64url");
              bytes[0] ^= 1;
              changed[index][field] = bytes.toString("base64url");
            }
          await importValues(changed);
          for (const credential of [a, b]) {
            equal(
              await code(mutation("reveal", { ref: { credentialId: credential.credentialId } })),
              "VAULT_DECRYPT_FAILED",
              "Smoke: tampered payload revealed",
            );
            failed++;
          }
        }
      }
    } finally {
      await importValues(rows);
    }
    equal(failed, 8, "Smoke: incomplete tamper checks");
  });
  await item("concurrent single-use verify and reveal: exactly 1 success each", async () => {
    const hashed = await create("apiKey", { maxUses: 1, name: "once-hash" });
    const verifications = await Promise.all(
      [1, 2].map(() => mutation("verify", { kind: "apiKey", value: hashed.value })),
    );
    equal(verifications.filter((result) => result.ok).length, 1, "Smoke: single-use verify count");
    const encrypted = await create("signingKey", { maxUses: 1, name: "once-encrypted" });
    const reveals = await Promise.allSettled(
      [1, 2].map(() => mutation("reveal", { ref: { credentialId: encrypted.credentialId } })),
    );
    equal(
      reveals.filter((result) => result.status === "fulfilled").length,
      1,
      "Smoke: single-use reveal count",
    );
    for (const [kind, credential, name] of [
      ["apiKey", hashed, "once-hash"],
      ["signingKey", encrypted, "once-encrypted"],
    ]) {
      const events = await query("eventsList", {
        ref: { credentialId: credential.credentialId },
        paginationOpts: { numItems: 100, cursor: null },
      });
      equal(
        events.page.filter((event) => event.type === "exhausted").length,
        1,
        "Smoke: exhausted event count",
      );
      await create(kind, { name });
    }
  });
  await item(
    "encrypted previous value disappears at grace; expired replace renews TTL",
    async () => {
      const credential = await create("providerKey", { value: generateTestValue() });
      const ref = { credentialId: credential.credentialId };
      const first = (await mutation("reveal", { ref })).value;
      const current = generateTestValue();
      await replace(ref, { value: current, graceMs: 1000 });
      const during = await mutation("reveal", { ref, includePrevious: true });
      equal([during.value, during.previous?.value], [current, first], "Smoke: grace plaintexts");
      await waitFor(
        "previous grace expiry",
        async () => !(await mutation("reveal", { ref, includePrevious: true })).previous,
      );
      const expiring = await create("providerKey", { value: generateTestValue(), ttlMs: 1000 });
      const expiredRef = { credentialId: expiring.credentialId };
      await waitFor(
        "credential expiry",
        async () => (await code(mutation("reveal", { ref: expiredRef }))) === "VAULT_INACTIVE",
      );
      const renewed = generateTestValue();
      await replace(expiredRef, { value: renewed, ttlMs: 60_000 });
      equal(
        (await mutation("reveal", { ref: expiredRef })).value,
        renewed,
        "Smoke: renewal failed",
      );
    },
  );
  await item("immutable kind policy and cross-version duplicate rejection", async () => {
    // Deliberately bypass the wrapper to attempt an incompatible component policy.
    const incompatible = await cliRunComponent("credentials:create", {
      hint: false,
      auditReveals: true,
      owner: "smoke",
      kind: "providerKey",
      storage: "hashed",
      origin: "supplied",
      lookup: "owner",
      value: generateTestValue(),
    });
    equal(incompatible, "VAULT_KIND_CONFLICT", "Smoke: policy change accepted");
    const value = generateTestValue();
    await create("sharedToken", { value });
    await configured(`${two},${one}`, 2);
    equal(
      await code(create("sharedToken", { value })),
      "VAULT_DUPLICATE_VALUE",
      "Smoke: cross-version duplicate accepted",
    );
    await configured(one, 1);
  });
  await item(
    "cleanup deletes exhausted and expired values, marks them done, and cleans a renewed credential again",
    async () => {
      const exhausted = await create("signingKey", { maxUses: 1 });
      await mutation("reveal", { ref: { credentialId: exhausted.credentialId } });
      const expiring = await create("providerKey", { value: generateTestValue(), ttlMs: 1000 });
      const expiredRef = { credentialId: expiring.credentialId };
      const expired = async () =>
        (await code(mutation("reveal", { ref: expiredRef }))) === "VAULT_INACTIVE";
      await waitFor("credential expiry", expired);
      await runCleanup([exhausted.credentialId, expiring.credentialId]);
      await replace(expiredRef, { value: generateTestValue(), ttlMs: 1000 });
      assert(
        !(await areValuesDeleted([expiring.credentialId])),
        "Smoke: renewal kept values deleted",
      );
      await waitFor("renewed credential expiry", expired);
      await runCleanup([expiring.credentialId]);
    },
  );
  await item(
    "rotate 2,000 encrypted and 200 both-storage credentials: 0 old values; every reveal/verify passes",
    async () => {
      const encrypted = [];
      const both = [];
      await chunks(
        Array.from({ length: 2000 }, (_, i) => i),
        async () => {
          const value = generateTestValue();
          const credential = await create("providerKey", { owner: "rotation", value });
          encrypted.push({ ...credential, value });
        },
      );
      await chunks(
        Array.from({ length: 200 }, (_, i) => i),
        async () => {
          const value = generateTestValue();
          const credential = await create("importedKey", { owner: "rotation", value });
          both.push({ ...credential, value });
        },
      );
      const hashed = await create("apiKey", { owner: "rotation" });
      const before = await snapshot();
      const rotationCredentials = before
        .get("credentials")
        .filter((row) => row.owner === "rotation");
      equal(
        rotationCredentials.filter((row) => row.storage === "encrypted").length,
        2000,
        "Smoke: encrypted fixture count",
      );
      equal(
        rotationCredentials.filter((row) => row.storage === "both").length,
        200,
        "Smoke: both fixture count",
      );
      const ids = new Set(
        rotationCredentials.filter((row) => row.storage !== "hashed").map((row) => row._id),
      );
      equal(
        before.get("values").filter((row) => ids.has(row.credentialId) && row.keyVersion === 1)
          .length,
        2200,
        "Smoke: key-1 fixture count",
      );
      await configured(`${two},${one}`, 2);
      await mutation("keysRotate");
      await waitFor("rotation to stop referencing wrap key 1", async () => {
        const status = await query("keysGetStatus");
        return status.versions.find((row) => row.version === 1)?.encrypted === false;
      });
      const bothIds = new Set(
        rotationCredentials
          .filter((credential) => credential.storage === "both")
          .map((credential) => credential._id),
      );
      const after = await snapshot();
      equal(
        after.get("values").filter((row) => row.keyVersion === 1).length,
        0,
        "Smoke: old encrypted values remain",
      );
      equal(
        after.get("values").filter((row) => ids.has(row.credentialId) && row.keyVersion === 2)
          .length,
        2200,
        "Smoke: rotated fixture count",
      );
      equal(
        after.get("values").filter((row) => bothIds.has(row.credentialId) && row.hashVersion === 1)
          .length,
        0,
        "Smoke: old both hashes remain",
      );
      await chunks([...encrypted, ...both], async (credential) =>
        equal(
          (await mutation("reveal", { ref: { credentialId: credential.credentialId } })).value,
          credential.value,
          "Smoke: rotated reveal differs",
        ),
      );
      await chunks(both, async (credential) =>
        assert(
          (
            await mutation("verify", {
              kind: "importedKey",
              owner: "rotation",
              value: credential.value,
            })
          ).ok,
          "Smoke: rotated both verify rejected",
        ),
      );
      const hashCredential = rotationCredentials.find((row) => row._id === hashed.credentialId);
      const hashRow = after.get("values").find((row) => row.credentialId === hashCredential._id);
      equal(hashRow.hashVersion, 1, "Smoke: hashed-only version changed");
      assert(
        (await mutation("verify", { kind: "apiKey", value: hashed.value })).ok,
        "Smoke: old hashed-only key no longer verifies",
      );
      const events = after
        .get("events")
        .filter((row) => row.owner === "rotation" && row.type === "rekeyed");
      equal(events.length, 2200, "Smoke: rekey event count");
    },
  );
  await item("unset and malformed VAULT_KEYS both fail with VAULT_NOT_CONFIGURED", async () => {
    await cli(["env", "remove", "VAULT_KEYS"]);
    await waitFor(
      "unset configuration",
      async () => (await code(query("keysGetStatus"))) === "VAULT_NOT_CONFIGURED",
    );
    equal(await code(create("apiKey")), "VAULT_NOT_CONFIGURED", "Smoke: unset create accepted");
    for (const malformed of ["bad", `1:${keys[0]},1:${keys[0]}`, "1:AA"]) {
      await setKeys(malformed);
      await waitFor(
        "malformed configuration",
        async () => (await code(query("keysGetStatus"))) === "VAULT_NOT_CONFIGURED",
      );
      equal(
        await code(create("apiKey")),
        "VAULT_NOT_CONFIGURED",
        "Smoke: malformed create accepted",
      );
    }
    await configured(`${two},${one}`, 2);
  });
  await item(
    "scan every component document: 0 plaintext and 0 master-key occurrences",
    async () => {
      const tables = await snapshot();
      const documents = JSON.stringify([...tables.values()].flat());
      for (const value of plaintexts) {
        for (const representation of [
          value,
          Buffer.from(value).toString("base64"),
          Buffer.from(value).toString("base64url"),
        ])
          assert(
            !documents.includes(representation),
            "Smoke: plaintext found in component snapshot",
          );
      }
      for (const key of keys) {
        const bytes = Buffer.from(key, "base64url");
        for (const representation of [
          key,
          bytes.toString("base64"),
          bytes.toString("latin1"),
          bytes.toString("utf8"),
          Array.from(bytes).join(","),
        ])
          assert(
            !documents.includes(representation) &&
              !documents.includes(JSON.stringify(representation).slice(1, -1)),
            "Smoke: master key found in component snapshot",
          );
      }
    },
  );
}

await runSmoke(journey);
