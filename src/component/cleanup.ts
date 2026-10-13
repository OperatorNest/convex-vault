import { v, type Infer } from "convex/values";
import type { PaginationOptions, PaginationResult } from "convex/server";
import { paginator } from "convex-helpers/server/pagination";
import { internalMutation, type MutationCtx } from "./_generated/server.js";
import type { Doc } from "./_generated/dataModel.js";
import { internal } from "./_generated/api.js";
import { boundedPage } from "../shared/bounds.js";
import { deleteValues } from "./helpers.js";
import schema from "./schema.js";

const DAY_MS = 86400000;
const CREDENTIAL_RETENTION_DAYS = 30;
const EVENT_RETENTION_DAYS = 90;
const PHASES = [
  "exhaustedValues",
  "exhaustedCredentials",
  "revokedCredentials",
  "expiredValues",
  "expiredCredentials",
  "previousValues",
  "events",
] as const;
const phaseValidator = v.union(...PHASES.map((phase) => v.literal(phase)));
type Phase = Infer<typeof phaseValidator>;
// At most two values per credential: 50 credentials means at most 100 value deletions.
const CREDENTIALS_PER_PAGE = 50;
async function credentialPage(
  ctx: MutationCtx,
  phase: Exclude<Phase, "previousValues" | "events">,
  request: PaginationOptions,
  now: number,
): Promise<PaginationResult<Doc<"credentials">>> {
  const retainedAfter = now - CREDENTIAL_RETENTION_DAYS * DAY_MS;
  const credentials = paginator(ctx.db, schema).query("credentials");
  if (phase === "exhaustedValues")
    return credentials
      .withIndex("by_status_and_valuesDeletedAt_and_expiresAt", (q) =>
        q.eq("status", "exhausted").eq("valuesDeletedAt", undefined),
      )
      .paginate(request);
  if (phase === "expiredValues")
    return credentials
      .withIndex("by_status_and_valuesDeletedAt_and_expiresAt", (q) =>
        q
          .eq("status", "active")
          .eq("valuesDeletedAt", undefined)
          .gt("expiresAt", undefined)
          .lte("expiresAt", now),
      )
      .paginate(request);
  if (phase === "expiredCredentials")
    return credentials
      .withIndex("by_status_and_expiresAt", (q) =>
        q.eq("status", "active").gt("expiresAt", undefined).lte("expiresAt", retainedAfter),
      )
      .paginate(request);
  return credentials
    .withIndex("by_status_and_updatedAt", (q) =>
      q
        .eq("status", phase === "exhaustedCredentials" ? "exhausted" : "revoked")
        .lte("updatedAt", retainedAfter),
    )
    .paginate(request);
}
async function cleanCredential(
  ctx: MutationCtx,
  phase: Phase,
  credential: Doc<"credentials">,
  now: number,
): Promise<void> {
  await deleteValues(ctx, credential);
  if (phase === "exhaustedValues" || phase === "expiredValues")
    await ctx.db.patch("credentials", credential._id, { valuesDeletedAt: now });
  else await ctx.db.delete("credentials", credential._id);
}
async function batch(
  ctx: MutationCtx,
  phase: Phase,
  cursor: string | null,
  now: number,
): Promise<void> {
  let isDone;
  let continueCursor;
  if (phase === "events") {
    const rows = await ctx.db
      .query("events")
      .withIndex("by_occurredAt", (q) => q.lt("occurredAt", now - EVENT_RETENTION_DAYS * DAY_MS))
      .take(100);
    for (const row of rows) await ctx.db.delete("events", row._id);
    isDone = rows.length < 100;
    continueCursor = null;
  } else if (phase === "previousValues") {
    const page = await paginator(ctx.db, schema)
      .query("values")
      .withIndex("by_validUntilAt", (q) => q.gt("validUntilAt", undefined).lte("validUntilAt", now))
      .paginate(boundedPage({ numItems: 100, cursor }));
    for (const row of page.page) await ctx.db.delete("values", row._id);
    ({ isDone, continueCursor } = page);
  } else {
    const page = await credentialPage(
      ctx,
      phase,
      boundedPage({ numItems: CREDENTIALS_PER_PAGE, cursor }),
      now,
    );
    for (const credential of page.page) await cleanCredential(ctx, phase, credential, now);
    ({ isDone, continueCursor } = page);
  }
  const next = isDone ? PHASES[PHASES.indexOf(phase) + 1] : phase;
  if (next !== undefined)
    await ctx.scheduler.runAfter(0, internal.cleanup.continueCleanup, {
      phase: next,
      cursor: isDone ? null : continueCursor,
      now,
    });
}
export const run = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    await batch(ctx, PHASES[0], null, Date.now());
    return null;
  },
});
export const continueCleanup = internalMutation({
  args: { phase: phaseValidator, cursor: v.union(v.string(), v.null()), now: v.number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await batch(ctx, args.phase, args.cursor, args.now);
    return null;
  },
});
