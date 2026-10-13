import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";
import {
  credentialValidator,
  valueStateValidator,
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
  credentials: defineTable(credentialValidator)
    .index("by_owner_and_kind_and_name", ["owner", "kind", "name"])
    .index("by_owner_and_kind_and_createdAt", ["owner", "kind", "createdAt"])
    .index("by_owner_and_createdAt", ["owner", "createdAt"])
    .index("by_status_and_updatedAt", ["status", "updatedAt"])
    .index("by_status_and_expiresAt", ["status", "expiresAt"])
    .index("by_status_and_valuesDeletedAt_and_expiresAt", [
      "status",
      "valuesDeletedAt",
      "expiresAt",
    ]),
  values: defineTable({
    valueId: v.string(),
    credentialId: v.id("credentials"),
    state: valueStateValidator,
    validUntilAt: v.optional(v.number()),
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
    .index("by_credentialId_and_state", ["credentialId", "state"])
    .index("by_lookupHash", ["lookupHash"])
    .index("by_keyVersion", ["keyVersion"])
    .index("by_hashVersion", ["hashVersion"])
    .index("by_validUntilAt", ["validUntilAt"]),
  events: defineTable(eventValidator)
    .index("by_credentialId_and_occurredAt", ["credentialId", "occurredAt"])
    .index("by_owner_and_occurredAt", ["owner", "occurredAt"])
    .index("by_occurredAt", ["occurredAt"]),
});
