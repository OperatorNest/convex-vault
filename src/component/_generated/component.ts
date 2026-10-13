/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    credentials: {
      create: FunctionReference<
        "mutation",
        "internal",
        {
          actor?: string;
          auditReveals: boolean;
          bytes?: number;
          expiresAt?: number;
          hint: boolean;
          kind: string;
          label?: string;
          lookup: "owner" | "global";
          maxUses?: number;
          metadata?: Record<string, string | number | boolean | null>;
          name?: string;
          origin: "generated" | "supplied";
          owner: string;
          prefix?: string;
          scopes?: Array<string>;
          storage: "encrypted" | "hashed" | "both";
          ttlMs?: number;
          value?: string;
        },
        { credentialId: string; hint?: string; value?: string },
        Name
      >;
      get: FunctionReference<
        "query",
        "internal",
        {
          ref:
            | { credentialId: string; kind?: string }
            | { kind: string; name: string; owner: string };
        },
        {
          auditReveals: boolean;
          bytes?: number;
          createdAt: number;
          credentialId: string;
          expiresAt?: number;
          hint?: string;
          kind: string;
          label?: string;
          lastUsedAt?: number;
          lookup: "owner" | "global";
          maxUses?: number;
          metadata: Record<string, string | number | boolean | null>;
          name?: string;
          origin: "generated" | "supplied";
          owner: string;
          prefix?: string;
          scopes: Array<string>;
          status: "active" | "revoked" | "exhausted";
          storage: "encrypted" | "hashed" | "both";
          updatedAt: number;
          useCount: number;
        },
        Name
      >;
      list: FunctionReference<
        "query",
        "internal",
        {
          kind?: string;
          owner: string;
          paginationOpts: {
            cursor: string | null;
            endCursor?: string | null;
            id?: number;
            maximumBytesRead?: number;
            maximumRowsRead?: number;
            numItems: number;
          };
        },
        {
          continueCursor: string;
          isDone: boolean;
          page: Array<{
            auditReveals: boolean;
            bytes?: number;
            createdAt: number;
            credentialId: string;
            expiresAt?: number;
            hint?: string;
            kind: string;
            label?: string;
            lastUsedAt?: number;
            lookup: "owner" | "global";
            maxUses?: number;
            metadata: Record<string, string | number | boolean | null>;
            name?: string;
            origin: "generated" | "supplied";
            owner: string;
            prefix?: string;
            scopes: Array<string>;
            status: "active" | "revoked" | "exhausted";
            storage: "encrypted" | "hashed" | "both";
            updatedAt: number;
            useCount: number;
          }>;
          pageStatus?: "SplitRecommended" | "SplitRequired" | null;
          splitCursor?: string | null;
        },
        Name
      >;
      replace: FunctionReference<
        "mutation",
        "internal",
        {
          actor?: string;
          expiresAt?: number;
          graceMs?: number;
          ref:
            | { credentialId: string; kind?: string }
            | { kind: string; name: string; owner: string };
          ttlMs?: number;
          value?: string;
        },
        { hint?: string; value?: string },
        Name
      >;
      reveal: FunctionReference<
        "mutation",
        "internal",
        {
          actor?: string;
          includePrevious?: boolean;
          ref:
            | { credentialId: string; kind?: string }
            | { kind: string; name: string; owner: string };
        },
        { previous?: { validUntilAt: number; value: string }; value: string },
        Name
      >;
      revoke: FunctionReference<
        "mutation",
        "internal",
        {
          actor?: string;
          ref:
            | { credentialId: string; kind?: string }
            | { kind: string; name: string; owner: string };
        },
        null,
        Name
      >;
      verify: FunctionReference<
        "mutation",
        "internal",
        {
          kind: string;
          owner?: string;
          requiredScopes?: Array<string>;
          value: string;
        },
        | {
            credentialId: string;
            kind: string;
            metadata: Record<string, string | number | boolean | null>;
            ok: true;
            owner: string;
            scopes: Array<string>;
            usesLeft?: number;
          }
        | {
            ok: false;
            reason: "not_found" | "expired" | "exhausted" | "missing_scope";
          },
        Name
      >;
    };
    events: {
      list: FunctionReference<
        "query",
        "internal",
        {
          paginationOpts: {
            cursor: string | null;
            endCursor?: string | null;
            id?: number;
            maximumBytesRead?: number;
            maximumRowsRead?: number;
            numItems: number;
          };
          ref: { credentialId: string } | { owner: string };
        },
        {
          continueCursor: string;
          isDone: boolean;
          page: Array<{
            actor?: string;
            credentialId: string;
            kind: string;
            occurredAt: number;
            owner: string;
            type:
              | "created"
              | "revealed"
              | "replaced"
              | "revoked"
              | "exhausted"
              | "rekeyed";
          }>;
          pageStatus?: "SplitRecommended" | "SplitRequired" | null;
          splitCursor?: string | null;
        },
        Name
      >;
    };
    keys: {
      getStatus: FunctionReference<
        "query",
        "internal",
        {},
        {
          activeVersion: number;
          missingVersions: Array<number>;
          missingVersionsTruncated: boolean;
          versions: Array<{
            encrypted: boolean;
            hashed: boolean;
            version: number;
          }>;
        },
        Name
      >;
      rotate: FunctionReference<"mutation", "internal", {}, null, Name>;
    };
  };
