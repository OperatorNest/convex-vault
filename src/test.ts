import type { TestConvex } from "convex-test";
import type { GenericSchema, SchemaDefinition } from "convex/server";
import schema from "./component/schema.js";

type Modules = Parameters<
  TestConvex<SchemaDefinition<GenericSchema, boolean>>["registerComponent"]
>[2];
type GlobImportMeta = ImportMeta & { glob: (patterns: string[]) => Modules };
const modules = (import.meta as GlobImportMeta).glob([
  "./component/**/*.ts",
  "!./component/**/*.test.ts",
]);
/** Registers this component with a consumer's convex-test instance. */
export function register(t: TestConvex<SchemaDefinition<GenericSchema, boolean>>, name = "vault") {
  t.registerComponent(name, schema, modules);
}
