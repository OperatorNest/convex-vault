import { v } from "convex/values";
import { paginator } from "convex-helpers/server/pagination";
import { internalMutation, type MutationCtx } from "./_generated/server.js";
import { internal } from "./_generated/api.js";
import { deleteValues, keyring } from "./helpers.js";
import schema from "./schema.js";

const DAY_MS = 86400000;
const CREDENTIAL_RETENTION_DAYS = 30;
const EVENT_RETENTION_DAYS = 90;
const phaseValidator = v.union(
  v.literal("exhausted"),
  v.literal("revoked"),
  v.literal("expired"),
  v.literal("previous"),
  v.literal("events"),
);
type Phase = "exhausted" | "revoked" | "expired" | "previous" | "events";
const NEXT_PHASE = {
  exhausted: "revoked",
  revoked: "expired",
  expired: "previous",
  previous: "events",
  events: undefined,
} as const satisfies Record<Phase, Phase | undefined>;
// At most two values per credential: 50 credentials means at most 100 value deletions.
async function batch(
  ctx: MutationCtx,
  phase: Phase,
  cursor: string | null,
  now: number,
): Promise<void> {
  const retainedAfter = now - CREDENTIAL_RETENTION_DAYS * DAY_MS;
  const pages = paginator(ctx.db, schema);
  let page;
  if (phase === "exhausted" || phase === "revoked") {
    page = await pages
      .query("credentials")
      .withIndex("by_status_and_updatedAt", (q) =>
        phase === "exhausted"
          ? q.eq("status", phase)
          : q.eq("status", phase).lte("updatedAt", retainedAfter),
      )
      .paginate({ numItems: 50, cursor });
    for (const credential of page.page) {
      await deleteValues(ctx, credential);
      if (credential.updatedAt <= retainedAfter) await ctx.db.delete("credentials", credential._id);
    }
  } else if (phase === "expired") {
    page = await pages
      .query("credentials")
      .withIndex("by_expiresAt", (q) => q.gt("expiresAt", undefined).lte("expiresAt", now))
      .paginate({ numItems: 50, cursor });
    for (const credential of page.page) {
      if (credential.status !== "active") continue;
      await deleteValues(ctx, credential);
      if (credential.expiresAt !== undefined && credential.expiresAt <= retainedAfter)
        await ctx.db.delete("credentials", credential._id);
    }
  } else if (phase === "previous") {
    page = await pages
      .query("values")
      .withIndex("by_validUntilAt", (q) => q.gt("validUntilAt", undefined).lte("validUntilAt", now))
      .paginate({ numItems: 100, cursor });
    for (const row of page.page)
      if (row.state === "previous") await ctx.db.delete("values", row._id);
  } else {
    const rows = await ctx.db
      .query("events")
      .withIndex("by_occurredAt", (q) => q.lt("occurredAt", now - EVENT_RETENTION_DAYS * DAY_MS))
      .take(100);
    for (const row of rows) await ctx.db.delete("events", row._id);
    if (rows.length === 100)
      await ctx.scheduler.runAfter(0, internal.cleanup.continueCleanup, {
        phase: "events",
        cursor: null,
        now,
      });
    return;
  }
  const next = page.isDone ? NEXT_PHASE[phase] : phase;
  if (next !== undefined)
    await ctx.scheduler.runAfter(0, internal.cleanup.continueCleanup, {
      phase: next,
      cursor: page.isDone ? null : page.continueCursor,
      now,
    });
}
export const run = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    keyring();
    await batch(ctx, "exhausted", null, Date.now());
    return null;
  },
});
export const continueCleanup = internalMutation({
  args: { phase: phaseValidator, cursor: v.union(v.string(), v.null()), now: v.number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    keyring();
    await batch(ctx, args.phase, args.cursor, args.now);
    return null;
  },
});
