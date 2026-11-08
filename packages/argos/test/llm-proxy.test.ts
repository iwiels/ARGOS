import { describe, expect } from "bun:test"
import * as http from "node:http"
import { mkdtempSync } from "node:fs"
import { rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Flag } from "@argos/core/flag/flag"
import { Database } from "@argos/core/database/database"
import { Pseudonymize } from "@argos/core/security/pseudonymize"
import { EngagementPseudonymTable } from "@argos/core/security/pseudonymize/sql"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Server } from "../src/server/server"
import { resetDatabase } from "./fixture/db"
import { testEffect } from "./lib/effect"

// Real integration test: drives an actual server started via Server.listen()
// over real HTTP, against a real (local) mock "upstream provider" server.
// The previous version of this file called Pseudonymize's pure functions
// directly and never touched handleLlmProxy at all — this one does.

const testStateLayer = Layer.effectDiscard(
  Effect.gen(function* () {
    const original = Flag.ARGOS_SERVER_PASSWORD
    Flag.ARGOS_SERVER_PASSWORD = undefined

    // The global test preload sets OPENCODE_DB=":memory:", but
    // Database.defaultLayer opens a brand-new connection every time it's
    // provided (Layer.unwrap) -- handleLlmProxy self-provides it fresh per
    // request (see the comment on that handler for why). Two separate
    // ":memory:" connections are two separate, unrelated databases, so a row
    // written by the request's connection would never be visible to this
    // test's own Database.Service. A real file, like production uses, is
    // shared across connections the way ":memory:" isn't.
    const originalDb = Flag.ARGOS_DB
    const tmpDir = mkdtempSync(join(tmpdir(), "argos-llm-proxy-test-"))
    Flag.ARGOS_DB = join(tmpDir, "test.db")

    yield* Effect.promise(() => resetDatabase())
    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        await resetDatabase()
        Flag.ARGOS_SERVER_PASSWORD = original
        Flag.ARGOS_DB = originalDb
        // Best-effort: the sqlite file handle may still be closing on Windows
        // (EBUSY) -- this is just tmpdir housekeeping, not correctness.
        await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined)
      }),
    )
  }),
)

// Layer.provide (not mergeAll) so testStateLayer's Flag.ARGOS_DB override
// is guaranteed to run before Database.defaultLayer reads it -- sibling
// layers in mergeAll have no build-order guarantee.
const it = testEffect(Database.defaultLayer.pipe(Layer.provide(testStateLayer)))

async function startMockUpstream(
  handler: (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void,
): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer((req, res) => {
    let body = ""
    req.on("data", (chunk) => (body += chunk))
    req.on("end", () => handler(req, res, body))
  })
  const port = await new Promise<number>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address()
      resolve(typeof addr === "object" && addr ? addr.port : 0)
    })
  })
  return { server, port }
}

describe("LLM proxy handler (real HTTP)", () => {
  it.live("tokenizes outgoing requests, detokenizes responses, and persists the vault", () =>
    Effect.gen(function* () {
      const engagementId = "eng_senati_test"
      const receivedPayloads: string[] = []

      const { server: mockUpstream, port: mockPort } = yield* Effect.promise(() =>
        startMockUpstream((_req, res, body) => {
          receivedPayloads.push(body)
          res.writeHead(200, { "content-type": "application/json" })
          res.end(
            JSON.stringify({
              choices: [{ message: { role: "assistant", content: "Auditing complete for ZXDOM001 (ZXIP001)." } }],
            }),
          )
        }),
      )
      process.env.LLM_PROXY_UPSTREAM_ANTHROPIC = `http://127.0.0.1:${mockPort}`

      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))

      try {
        const clientBody = {
          model: "claude-3-5-sonnet",
          messages: [
            {
              role: "user",
              content: "Audit server 192.0.2.10 on www.organization.example.org with API key AKIA1234567890ABCDEF",
            },
          ],
        }

        const proxyResponse = yield* Effect.promise(() =>
          fetch(new URL(`/llm-proxy/anthropic/v1/messages`, listener.url), {
            method: "POST",
            headers: { "content-type": "application/json", "x-engagement-id": engagementId },
            body: JSON.stringify(clientBody),
          }),
        )

        expect(proxyResponse.status).toBe(200)

        // The mock upstream must never see the real target or the real secret.
        expect(receivedPayloads.length).toBe(1)
        expect(receivedPayloads[0]).not.toContain("192.0.2.10")
        expect(receivedPayloads[0]).not.toContain("organization.example.org")
        expect(receivedPayloads[0]).not.toContain("AKIA1234567890ABCDEF")
        expect(receivedPayloads[0]).toContain("ZXIP")
        expect(receivedPayloads[0]).toContain("ZXDOM")
        expect(receivedPayloads[0]).toContain("[SECRET-REDACTED]")

        // The client must get the real values back, not tokens — and the
        // response's Content-Length must actually match the rewritten body
        // (the previous version forwarded the upstream's now-stale length).
        const responseText = yield* Effect.promise(() => proxyResponse.text())
        expect(responseText).toContain("organization.example.org")
        expect(responseText).toContain("192.0.2.10")
        expect(responseText).not.toContain("ZXDOM001")
        expect(responseText).not.toContain("ZXIP001")
        const declaredLength = proxyResponse.headers.get("content-length")
        if (declaredLength !== null) {
          expect(Number(declaredLength)).toBe(new TextEncoder().encode(responseText).length)
        }
        expect(proxyResponse.headers.get("content-encoding")).toBeNull()

        // The vault must actually be persisted, not just cached in memory.
        const { db } = yield* Database.Service
        const rows = yield* db
          .select()
          .from(EngagementPseudonymTable)
          .where(eq(EngagementPseudonymTable.engagement_id, engagementId))
          .all()
          .pipe(Effect.orDie)
        expect(rows.length).toBeGreaterThan(0)
        expect(rows.some((r) => r.real_value === "www.organization.example.org")).toBe(true)
        expect(rows.some((r) => r.real_value === "192.0.2.10")).toBe(true)
      } finally {
        yield* Effect.promise(() => listener.stop(true))
        mockUpstream.close()
        delete process.env.LLM_PROXY_UPSTREAM_ANTHROPIC
      }
    }),
  )

  it.live("reassembles a token split across two SSE chunks before it reaches the client", () =>
    Effect.gen(function* () {
      const engagementId = "eng_sse_split_test"

      const { server: mockUpstream, port: mockPort } = yield* Effect.promise(() =>
        startMockUpstream((_req, res) => {
          res.writeHead(200, {
            "content-type": "text/event-stream",
            "cache-control": "no-cache",
            connection: "keep-alive",
          })
          // Deliberately split the token "ZXDOM001" mid-word across two raw
          // writes (no boundary between them) so the sliding-window buffer,
          // not per-delta replacement, has to reassemble it.
          res.write("data: Found issue on ZXDO")
          res.write("M001 confirmed.\n\n")
          res.end()
        }),
      )
      process.env.LLM_PROXY_UPSTREAM_OPENAI = `http://127.0.0.1:${mockPort}`

      const { db } = yield* Database.Service
      yield* Pseudonymize.getOrAllocateToken(engagementId, "domain", "split-target.example.com", db)

      const listener = yield* Effect.promise(() => Server.listen({ hostname: "127.0.0.1", port: 0 }))

      try {
        const proxyResponse = yield* Effect.promise(() =>
          fetch(new URL(`/llm-proxy/openai/v1/messages`, listener.url), {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "text/event-stream",
              "x-engagement-id": engagementId,
            },
            body: JSON.stringify({ messages: [] }),
          }),
        )

        const text = yield* Effect.promise(() => proxyResponse.text())
        expect(text).toContain("split-target.example.com")
        expect(text).not.toContain("ZXDOM")
      } finally {
        yield* Effect.promise(() => listener.stop(true))
        mockUpstream.close()
        delete process.env.LLM_PROXY_UPSTREAM_OPENAI
      }
    }),
  )
})
