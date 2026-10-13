import { v } from "convex/values";
import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { paginator } from "convex-helpers/server/pagination";
import { query } from "./_generated/server.js";
import schema from "./schema.js";
import { keyring } from "./helpers.js";
import { boundedPage, boundedString } from "../shared/bounds.js";
import { eventValidator } from "../shared/validators.js";

export const list = query({
  args: {
    ref: v.union(v.object({ credentialId: v.string() }), v.object({ owner: v.string() })),
    paginationOpts: paginationOptsValidator,
  },
  returns: paginationResultValidator(eventValidator),
  handler: async (ctx, args) => {
    keyring();
    const pageRequest = boundedPage(args.paginationOpts);
    const ref = args.ref;
    if ("credentialId" in ref) boundedString(ref.credentialId, 128);
    else boundedString(ref.owner, 256);
    const stream = paginator(ctx.db, schema).query("events");
    const page = await (
      "credentialId" in ref
        ? stream.withIndex("by_credentialId_and_occurredAt", (q) =>
            q.eq("credentialId", ref.credentialId),
          )
        : stream.withIndex("by_owner_and_occurredAt", (q) => q.eq("owner", ref.owner))
    )
      .order("desc")
      .paginate(pageRequest);
    return { ...page, page: page.page.map(({ _id, _creationTime, ...fields }) => fields) };
  },
});
