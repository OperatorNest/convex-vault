import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";
import {
  entryValidator,
  eventValidator,
  storageValidator,
  originValidator,
  lookupValidator,
} from "../shared/validators.js";

export default defineSchema({
  kinds: defineTable({
    kind: v.string(),
    storage: storageValidator,
    origin: originValidator,
    lookup: lookupValidator,
    createdAt: v.number(),
  }).index("by_kind", ["kind"]),
  entries: defineTable(entryValidator)
    .index("by_entryId", ["entryId"])
    .index("by_owner_and_kind_and_name", ["owner", "kind", "name"])
    .index("by_owner_and_kind_and_createdAt", ["owner", "kind", "createdAt"])
    .index("by_status_and_updatedAt", ["status", "updatedAt"])
    .index("by_expiresAt", ["expiresAt"]),
  values: defineTable({
    valueId: v.string(),
    entry: v.id("entries"),
    state: v.union(v.literal("current"), v.literal("previous")),
    validUntil: v.optional(v.number()),
    keyVersion: v.optional(v.number()),
    ciphertext: v.optional(v.string()),
    iv: v.optional(v.string()),
    wrappedKey: v.optional(v.string()),
    keyIv: v.optional(v.string()),
    lookupHash: v.optional(v.string()),
    hashVersion: v.optional(v.number()),
    hint: v.optional(v.string()),
    createdAt: v.number(),
  })
    .index("by_entry_and_state", ["entry", "state"])
    .index("by_lookupHash", ["lookupHash"])
    .index("by_keyVersion", ["keyVersion"])
    .index("by_hashVersion", ["hashVersion"])
    .index("by_validUntil", ["validUntil"]),
  events: defineTable(eventValidator)
    .index("by_entryId_and_at", ["entryId", "at"])
    .index("by_owner_and_at", ["owner", "at"])
    .index("by_at", ["at"]),
});
