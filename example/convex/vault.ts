import { Vault, type CreateOptions, type CreateResult } from "@operatornest/convex-vault";
import { ConvexError, v, type Infer } from "convex/values";
import { components } from "./_generated/api.js";
import type { MutationCtx } from "./_generated/server.js";

export const vault = new Vault(components.vault, {
  kinds: {
    providerKey: { storage: "encrypted", hint: false, auditReveals: true, lookup: "owner" },
    signingKey: {
      storage: "encrypted",
      generate: { prefix: "sig_", bytes: 32 },
      hint: true,
      auditReveals: true,
    },
    sharedToken: { storage: "hashed", hint: false, auditReveals: true, lookup: "owner" },
    apiKey: {
      storage: "hashed",
      generate: { prefix: "sk_", bytes: 32 },
      hint: true,
      auditReveals: true,
    },
    importedKey: { storage: "both", hint: false, auditReveals: true, lookup: "owner" },
    dashboardKey: {
      storage: "both",
      generate: { prefix: "dash_", bytes: 32 },
      hint: true,
      auditReveals: true,
    },
  },
});
export const kindValidator = v.union(
  v.literal("providerKey"),
  v.literal("signingKey"),
  v.literal("sharedToken"),
  v.literal("apiKey"),
  v.literal("importedKey"),
  v.literal("dashboardKey"),
);
export const revealKindValidator = v.union(
  v.literal("providerKey"),
  v.literal("signingKey"),
  v.literal("importedKey"),
  v.literal("dashboardKey"),
);
export const verifyKindValidator = v.union(
  v.literal("sharedToken"),
  v.literal("apiKey"),
  v.literal("importedKey"),
  v.literal("dashboardKey"),
);
export type Kind = Infer<typeof kindValidator>;

export function create(
  ctx: MutationCtx,
  kind: Kind,
  options: CreateOptions & { value?: string },
): Promise<CreateResult> {
  const { value, ...common } = options;
  switch (kind) {
    case "providerKey":
    case "sharedToken":
    case "importedKey":
      if (value === undefined) throw new ConvexError("A supplied kind needs a value");
      return vault.credentials.create(ctx, {
        ...common,
        value,
        kind,
      });
    case "signingKey":
    case "apiKey":
    case "dashboardKey":
      if (value !== undefined) throw new ConvexError("A generated kind does not accept a value");
      return vault.credentials.create(ctx, { ...common, kind: kind });
  }
  throw new ConvexError("Unknown kind");
}
