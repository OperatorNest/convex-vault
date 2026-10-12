import { generateMasterKey } from "./keyring.js";

export type CliResult = { code: number; stdout: string; stderr: string };
const USAGE = "Usage: convex-vault generate-key [--version <n>]\n";

export function runCli(argv: readonly string[]): CliResult {
  const [command, ...args] = argv;
  if (command === "--help" || command === "-h" || command === undefined)
    return { code: command === undefined ? 1 : 0, stdout: USAGE, stderr: "" };
  let version = "1";
  if (command !== "generate-key") return { code: 1, stdout: "", stderr: USAGE };
  if (args.length === 2 && args[0] === "--version") version = args[1] ?? "";
  else if (args.length === 1 && args[0]?.startsWith("--version=")) version = args[0].slice(10);
  else if (args.length !== 0) return { code: 1, stdout: "", stderr: USAGE };
  if (!/^[1-9][0-9]*$/.test(version) || !Number.isSafeInteger(Number(version)))
    return { code: 1, stdout: "", stderr: "Version must be a positive safe integer.\n" };
  return { code: 0, stdout: `${version}:${generateMasterKey()}\n`, stderr: "" };
}
