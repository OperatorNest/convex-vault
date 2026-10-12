import { expect, it } from "vitest";
import { runCli } from "./cli.js";
import { parseKeyring } from "./keyring.js";

it("generates fresh canonical 32-byte keys for the selected version", () => {
  for (const [args, version] of [
    [[], 1],
    [["--version", "2"], 2],
    [["--version=3"], 3],
  ] as const) {
    const a = runCli(["generate-key", ...args]);
    const b = runCli(["generate-key", ...args]);
    expect(a.code).toBe(0);
    expect(a.stderr).toBe("");
    expect(a.stdout).not.toBe(b.stdout);
    const ring = parseKeyring(a.stdout.trim());
    expect(ring.active).toBe(version);
    expect(ring.keys.get(version)).toHaveLength(32);
  }
});
it.each([
  [],
  ["bad"],
  ["generate-key", "--version"],
  ["generate-key", "--other"],
  ...["0", "-1", "01", "1.5", "1e2", "NaN", "9007199254740992", ""].map((n) => [
    "generate-key",
    "--version",
    n,
  ]),
  ["generate-key", "--version", "2", "--version", "3"],
])("rejects invalid CLI arguments without emitting a key: %j", (...args) => {
  expect(runCli(args).code).toBe(1);
  expect(runCli(args).stdout).not.toMatch(/[0-9]:[A-Za-z0-9_-]{43}/);
});
it.each(["--help", "-h"])("prints help for %s", (arg) => {
  expect(runCli([arg])).toMatchObject({ code: 0, stderr: "" });
});
