import { defineApp } from "convex/server";
import { v } from "convex/values";
import vault from "@operatornest/convex-vault/convex.config.js";

const app = defineApp({ env: { VAULT_KEYS: v.optional(v.string()) } });
app.use(vault, { env: { VAULT_KEYS: app.env.VAULT_KEYS } });
export default app;
