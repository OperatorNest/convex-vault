import { Vault, type CreateOptions, type CreateResult } from "@operatornest/convex-vault";
import { ConvexError, v } from "convex/values";
import { components } from "./_generated/api.js";
import type { MutationCtx } from "./_generated/server.js";

export const vault = new Vault(components.vault, {
  kinds: {
    providerKey: { storage: "encrypted" },
    signingSecret: { storage: "encrypted", generate: { prefix: "sig_" } },
    sharedToken: { storage: "hashed" },
    apiKey: { storage: "hashed", generate: { prefix: "sk_" } },
    importedKey: { storage: "both" },
    dashboardKey: { storage: "both", generate: { prefix: "dash_" } },
  },
});
export const kindValidator = v.union(
  v.literal("providerKey"),
  v.literal("signingSecret"),
  v.literal("sharedToken"),
  v.literal("apiKey"),
  v.literal("importedKey"),
  v.literal("dashboardKey"),
);
export const revealKindValidator = v.union(
  v.literal("providerKey"),
  v.literal("signingSecret"),
  v.literal("importedKey"),
  v.literal("dashboardKey"),
);
export const verifyKindValidator = v.union(
  v.literal("sharedToken"),
  v.literal("apiKey"),
  v.literal("importedKey"),
  v.literal("dashboardKey"),
);
export type Kind = keyof typeof vault.options.kinds;

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
      return vault.create(ctx, kind, { ...common, value });
    case "signingSecret":
    case "apiKey":
    case "dashboardKey":
      if (value !== undefined) throw new ConvexError("A generated kind does not accept a value");
      return vault.create(ctx, kind, common);
  }
  throw new ConvexError("Unknown kind");
}
