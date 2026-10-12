// Snapshot imports deliberately corrupt this disposable anonymous local deployment.
import { execFileSync, spawn } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { ConvexHttpClient } from "convex/browser";
import { anyApi } from "convex/server";
import { acquireLock } from "./with-local-lock.mjs";

const root = resolve(import.meta.dirname, "..");
const convexBin = join(root, "node_modules/convex/bin/main.js");
const workspace = mkdtempSync(join(tmpdir(), "vault-smoke-"));
const cliEnv = {
  ...process.env,
  CONVEX_AGENT_MODE: "anonymous",
};
// Selection always comes from the fresh workspace, never inherited cloud/self-hosted credentials.
for (const key of [
  "CONVEX_DEPLOYMENT",
  "CONVEX_DEPLOY_KEY",
  "CONVEX_SELF_HOSTED_URL",
  "CONVEX_SELF_HOSTED_ADMIN_KEY",
])
  delete cliEnv[key];
const results = [
  {
    number: "1",
    description: "six combinations create, reveal/verify, replace with grace, revoke",
    ok: false,
  },
  {
    number: "3",
    description: "ciphertext/wrapped-key swaps and byte flips: 8/8 reveals fail",
    ok: false,
  },
  {
    number: "5",
    description: "concurrent single-use verify and reveal: exactly 1 success each",
    ok: false,
  },
  {
    number: "5a",
    description: "encrypted previous value disappears at grace; expired replace renews TTL",
    ok: false,
  },
  {
    number: "5b",
    description: "immutable kind policy and cross-version duplicate rejection",
    ok: false,
  },
  {
    number: "4",
    description:
      "rotate 2,000 encrypted and 200 both-storage entries: 0 old values; every reveal/verify passes",
    ok: false,
  },
  {
    number: "7",
    description: "unset and malformed VAULT_KEYS both fail with VAULT_NOT_CONFIGURED",
    ok: false,
  },
  {
    number: "2",
    description: "scan every component document: 0 plaintext and 0 master-key occurrences",
    ok: false,
  },
];
const plaintexts = new Set();
const keys = [];
let client;
let publicClient;
let dev;
let snapshotNumber = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
function equal(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), message);
}
async function item(number, description, fn) {
  const result = results.find((check) => check.number === number);
  assert(result?.description === description, "Smoke: unexpected item");
  try {
    await fn();
    result.ok = true;
  } catch (error) {
    // Never echo a server response, command arguments, snapshot data, plaintext or keys.
    console.error(
      `Item ${number}: ${error instanceof Error && error.message.startsWith("Smoke:") ? error.message : "check failed"}`,
    );
  }
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
function cli(...args) {
  try {
    return execFileSync(process.execPath, [convexBin, ...args], {
      cwd: workspace,
      env: cliEnv,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    throw new Error("Smoke: local Convex CLI command failed");
  }
}
async function freePort() {
  const server = createServer();
  await new Promise((resolvePort, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePort);
  });
  const address = server.address();
  assert(address && typeof address !== "string", "Smoke: no ephemeral port");
  await new Promise((resolveClose) => server.close(resolveClose));
  return address.port;
}
async function startDev() {
  for (const path of ["src", "dist", "example", "package.json", "convex.json"])
    cpSync(join(root, path), join(workspace, path), { recursive: true });
  symlinkSync(join(root, "node_modules"), join(workspace, "node_modules"), "dir");
  const cloud = await freePort();
  const site = await freePort();
  const child = spawn(
    process.execPath,
    [
      convexBin,
      "dev",
      "--typecheck",
      "disable",
      "--tail-logs",
      "disable",
      "--local-cloud-port",
      String(cloud),
      "--local-site-port",
      String(site),
    ],
    {
      cwd: workspace,
      env: cliEnv,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  const collect = (chunk) => {
    output += chunk.toString();
    writeFileSync(join(workspace, "dev.log"), output);
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  const stop = async () => {
    if (child.exitCode !== null) return;
    child.kill("SIGTERM");
    await Promise.race([new Promise((ended) => child.once("exit", ended)), sleep(10_000)]);
    if (child.exitCode === null) child.kill("SIGKILL");
  };
  dev = { stop };
  await waitFor("local functions ready", () => {
    if (child.exitCode !== null)
      throw new Error("Smoke: convex dev exited before functions were ready");
    return /Convex functions ready/.test(output);
  });
  const config = JSON.parse(
    readFileSync(join(workspace, ".convex/local/default/config.json"), "utf8"),
  );
  const url = `http://127.0.0.1:${config.ports.cloud}`;
  client = new ConvexHttpClient(url, { logger: false });
  client.setAdminAuth(config.adminKey);
  publicClient = new ConvexHttpClient(url, { logger: false });
}
const mutation = (name, args = {}) => client.mutation(anyApi.admin[name], args);
const query = (name, args = {}) => client.query(anyApi.admin[name], args);
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
function secret() {
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
async function configured(config, version) {
  cli("env", "set", "--", "VAULT_KEYS", config);
  await waitFor("keyring update", async () => {
    try {
      return (await query("keyStatus")).activeVersion === version;
    } catch {
      return false;
    }
  });
}
function generateKey(version) {
  const line = execFileSync(
    "node",
    [join(root, "bin/convex-vault.js"), "generate-key", "--version", String(version)],
    { encoding: "utf8" },
  ).trim();
  assert(new RegExp(`^${version}:[A-Za-z0-9_-]{43}$`).test(line), "Smoke: CLI key format");
  const key = line.slice(line.indexOf(":") + 1);
  keys.push(key);
  return line;
}
function snapshot() {
  const path = join(workspace, `snapshot-${snapshotNumber++}.zip`);
  cli("export", "--path", path);
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
    ["entries", "values", "events", "kinds"].every((table) => tables.has(table)),
    "Smoke: snapshot missing a component table",
  );
  return tables;
}
function importValues(rows) {
  const path = join(workspace, "values.jsonl");
  writeFileSync(path, rows.map((row) => JSON.stringify(row)).join("\n"));
  cli("import", "--component", "vault", "--table", "values", "--replace", "--yes", path);
}
async function chunks(items, fn, size = 8) {
  for (let start = 0; start < items.length; start += size)
    await Promise.all(items.slice(start, start + size).map(fn));
}

async function journey() {
  const one = generateKey(1);
  const two = generateKey(2);
  await configured(one, 1);
  await item(
    "1",
    "six combinations create, reveal/verify, replace with grace, revoke",
    async () => {
      for (const [kind, storage, generated] of [
        ["providerKey", "encrypted", false],
        ["signingSecret", "encrypted", true],
        ["sharedToken", "hashed", false],
        ["apiKey", "hashed", true],
        ["importedKey", "both", false],
        ["dashboardKey", "both", true],
      ]) {
        const first = generated ? undefined : secret();
        const entry = await create(kind, {
          name: kind,
          ...(generated ? {} : { value: first }),
          scopes: ["read"],
          metadata: { tier: 1 },
        });
        const ref = { entryId: entry.entryId };
        const value = entry.value ?? first;
        assert(generated === (entry.value !== undefined), "Smoke: plaintext return policy");
        if (storage !== "hashed")
          equal((await mutation("reveal", { ref })).value, value, "Smoke: reveal differs");
        if (storage !== "encrypted")
          assert(
            (await mutation("verify", { kind, owner: "smoke", value, requiredScopes: ["read"] }))
              .ok,
            "Smoke: verify rejected",
          );
        const next = generated ? undefined : secret();
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
        await create(kind, { name: kind, ...(generated ? {} : { value: secret() }) });
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
        next.page.length === 2 && next.page[0].entryId !== page.page[0].entryId,
        "Smoke: paginator did not advance",
      );
      const events = await query("listEvents", {
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
    },
  );
  await item("3", "ciphertext/wrapped-key swaps and byte flips: 8/8 reveals fail", async () => {
    const a = await create("providerKey", { value: secret() });
    const b = await create("providerKey", { value: secret(), owner: "other" });
    const tables = snapshot();
    const rows = tables.get("values");
    const entries = tables.get("entries");
    const ids = [a, b].map((entry) => entries.find((row) => row.entryId === entry.entryId)._id);
    const indexes = ids.map((id) =>
      rows.findIndex((row) => row.entry === id && row.state === "current"),
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
          importValues(changed);
          for (const entry of [a, b]) {
            equal(
              await code(mutation("reveal", { ref: { entryId: entry.entryId } })),
              "VAULT_DECRYPT_FAILED",
              "Smoke: tampered payload revealed",
            );
            failed++;
          }
        }
      }
    } finally {
      importValues(rows);
    }
    equal(failed, 8, "Smoke: incomplete tamper checks");
  });
  await item("5", "concurrent single-use verify and reveal: exactly 1 success each", async () => {
    const hashed = await create("apiKey", { maxUses: 1, name: "once-hash" });
    const verifications = await Promise.all(
      [1, 2].map(() => mutation("verify", { kind: "apiKey", value: hashed.value })),
    );
    equal(verifications.filter((result) => result.ok).length, 1, "Smoke: single-use verify count");
    const encrypted = await create("signingSecret", { maxUses: 1, name: "once-encrypted" });
    const reveals = await Promise.allSettled(
      [1, 2].map(() => mutation("reveal", { ref: { entryId: encrypted.entryId } })),
    );
    equal(
      reveals.filter((result) => result.status === "fulfilled").length,
      1,
      "Smoke: single-use reveal count",
    );
    for (const [kind, entry, name] of [
      ["apiKey", hashed, "once-hash"],
      ["signingSecret", encrypted, "once-encrypted"],
    ]) {
      const events = await query("listEvents", {
        ref: { entryId: entry.entryId },
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
    "5a",
    "encrypted previous value disappears at grace; expired replace renews TTL",
    async () => {
      const entry = await create("providerKey", { value: secret() });
      const ref = { entryId: entry.entryId };
      const first = (await mutation("reveal", { ref })).value;
      const current = secret();
      await replace(ref, { value: current, graceMs: 1000 });
      const during = await mutation("reveal", { ref, includePrevious: true });
      equal([during.value, during.previous?.value], [current, first], "Smoke: grace plaintexts");
      await waitFor(
        "previous grace expiry",
        async () => !(await mutation("reveal", { ref, includePrevious: true })).previous,
      );
      const expiring = await create("providerKey", { value: secret(), ttlMs: 1000 });
      const expiredRef = { entryId: expiring.entryId };
      await waitFor(
        "entry expiry",
        async () => (await code(mutation("reveal", { ref: expiredRef }))) === "VAULT_INACTIVE",
      );
      const renewed = secret();
      await replace(expiredRef, { value: renewed, ttlMs: 60_000 });
      equal(
        (await mutation("reveal", { ref: expiredRef })).value,
        renewed,
        "Smoke: renewal failed",
      );
    },
  );
  await item("5b", "immutable kind policy and cross-version duplicate rejection", async () => {
    // Deliberately bypass the wrapper to attempt an incompatible component policy.
    const incompatible = cliRunComponent("vault:create", {
      owner: "smoke",
      kind: "providerKey",
      storage: "hashed",
      origin: "supplied",
      lookup: "owner",
      value: secret(),
    });
    equal(incompatible, "VAULT_KIND_CONFLICT", "Smoke: policy change accepted");
    const value = secret();
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
    "4",
    "rotate 2,000 encrypted and 200 both-storage entries: 0 old values; every reveal/verify passes",
    async () => {
      const encrypted = [];
      const both = [];
      await chunks(
        Array.from({ length: 2000 }, (_, i) => i),
        async () => {
          const value = secret();
          const entry = await create("providerKey", { owner: "rotation", value });
          encrypted.push({ ...entry, value });
        },
      );
      await chunks(
        Array.from({ length: 200 }, (_, i) => i),
        async () => {
          const value = secret();
          const entry = await create("importedKey", { owner: "rotation", value });
          both.push({ ...entry, value });
        },
      );
      const hashed = await create("apiKey", { owner: "rotation" });
      const before = snapshot();
      const rotationEntries = before.get("entries").filter((row) => row.owner === "rotation");
      equal(
        rotationEntries.filter((row) => row.storage === "encrypted").length,
        2000,
        "Smoke: encrypted fixture count",
      );
      equal(
        rotationEntries.filter((row) => row.storage === "both").length,
        200,
        "Smoke: both fixture count",
      );
      const ids = new Set(
        rotationEntries.filter((row) => row.storage !== "hashed").map((row) => row._id),
      );
      equal(
        before.get("values").filter((row) => ids.has(row.entry) && row.keyVersion === 1).length,
        2200,
        "Smoke: key-1 fixture count",
      );
      await configured(`${two},${one}`, 2);
      await mutation("rotateKeys");
      await waitFor("rotation to stop referencing wrap key 1", async () => {
        const status = await query("keyStatus");
        return status.versions.find((row) => row.version === 1)?.encrypted === false;
      });
      const bothIds = new Set(
        rotationEntries.filter((entry) => entry.storage === "both").map((entry) => entry._id),
      );
      const after = snapshot();
      equal(
        after.get("values").filter((row) => row.keyVersion === 1).length,
        0,
        "Smoke: old encrypted values remain",
      );
      equal(
        after.get("values").filter((row) => ids.has(row.entry) && row.keyVersion === 2).length,
        2200,
        "Smoke: rotated fixture count",
      );
      equal(
        after.get("values").filter((row) => bothIds.has(row.entry) && row.hashVersion === 1).length,
        0,
        "Smoke: old both hashes remain",
      );
      await chunks([...encrypted, ...both], async (entry) =>
        equal(
          (await mutation("reveal", { ref: { entryId: entry.entryId } })).value,
          entry.value,
          "Smoke: rotated reveal differs",
        ),
      );
      await chunks(both, async (entry) =>
        assert(
          (await mutation("verify", { kind: "importedKey", owner: "rotation", value: entry.value }))
            .ok,
          "Smoke: rotated both verify rejected",
        ),
      );
      const hashEntry = rotationEntries.find((row) => row.entryId === hashed.entryId);
      const hashRow = after.get("values").find((row) => row.entry === hashEntry._id);
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
  await item(
    "7",
    "unset and malformed VAULT_KEYS both fail with VAULT_NOT_CONFIGURED",
    async () => {
      cli("env", "remove", "VAULT_KEYS");
      await waitFor(
        "unset configuration",
        async () => (await code(query("keyStatus"))) === "VAULT_NOT_CONFIGURED",
      );
      equal(await code(create("apiKey")), "VAULT_NOT_CONFIGURED", "Smoke: unset create accepted");
      for (const malformed of ["bad", `1:${keys[0]},1:${keys[0]}`, "1:AA"]) {
        cli("env", "set", "--", "VAULT_KEYS", malformed);
        await waitFor(
          "malformed configuration",
          async () => (await code(query("keyStatus"))) === "VAULT_NOT_CONFIGURED",
        );
        equal(
          await code(create("apiKey")),
          "VAULT_NOT_CONFIGURED",
          "Smoke: malformed create accepted",
        );
      }
      await configured(`${two},${one}`, 2);
    },
  );
  await item(
    "2",
    "scan every component document: 0 plaintext and 0 master-key occurrences",
    async () => {
      const tables = snapshot();
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
function cliRunComponent(name, args) {
  try {
    execFileSync(
      process.execPath,
      [convexBin, "run", "--component", "vault", name, JSON.stringify(args)],
      { cwd: workspace, env: cliEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    return "no_error";
  } catch (error) {
    return /VAULT_[A-Z_]+/.exec(String(error.stderr))?.[0] ?? "unknown_error";
  }
}

const release = await acquireLock();
try {
  console.log("Building and starting an isolated local Convex deployment...");
  execFileSync("pnpm", ["build"], { cwd: root, stdio: "inherit" });
  await startDev();
  await journey();
} catch {
  console.error("Smoke: failed to initialize or complete the local journey");
  process.exitCode = 1;
} finally {
  await dev?.stop();
  rmSync(workspace, { recursive: true, force: true });
  release();
}
console.log("Smoke summary");
for (const result of results.toSorted((a, b) =>
  a.number.localeCompare(b.number, undefined, { numeric: true }),
))
  console.log(`${result.ok ? "PASS" : "FAIL"} ${result.number} ${result.description}`);
if (results.length !== 8 || results.some((result) => !result.ok)) process.exitCode = 1;
