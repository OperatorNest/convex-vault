import { defineComponent } from "convex/server";
import { v } from "convex/values";
export default defineComponent("vault", { env: { VAULT_KEYS: v.optional(v.string()) } });
