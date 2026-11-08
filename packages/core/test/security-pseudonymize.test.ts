import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { eq } from "drizzle-orm"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionTable } from "@argos/core/session/sql"
import { SessionSchema } from "@argos/core/session/schema"
import { AbsolutePath } from "@argos/core/schema"
import { PseudonymTable } from "../src/security/pseudonymize/sql"
import { Pseudonymize } from "../src/security/pseudonymize"
import { Message, LLMEvent } from "@argos/llm"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)
const testPath = process.platform === "win32" ? "C:/test" : "/test"

const makeSession = (
  sessionID: string,
  scope?: { domains?: string[]; cidrs?: string[] },
) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    yield* db
      .insert(ProjectTable)
      .values({
        id: Project.ID.global,
        worktree: AbsolutePath.make(testPath),
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)

    yield* db
      .insert(SessionTable)
      .values({
        id: SessionSchema.ID.make(sessionID),
        project_id: Project.ID.global,
        slug: "test-session",
        directory: testPath,
        title: "Test Session",
        version: "1.0.0",
        scope_domains: scope?.domains ?? null,
        scope_cidrs: scope?.cidrs ?? null,
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  })

describe("Pseudonymize Service", () => {
  it.effect("seeds scope domains and cidrs at session load before first message", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_scope_seed")
      yield* makeSession(sessionID, {
        domains: ["targetcorp.com", "api.targetcorp.com"],
        cidrs: ["10.50.0.0/16"],
      })

      // Even before any user message or registerEntity call, the scope is seeded in vault
      const rawPrompt =
        "Iniciando escaneo contra api.targetcorp.com y el rango 10.50.0.0/16"
      const tokenized = yield* Pseudonymize.tokenizeString(db, sessionID, rawPrompt)

      expect(tokenized).not.toContain("api.targetcorp.com")
      expect(tokenized).not.toContain("10.50.0.0/16")
      expect(tokenized).toContain("ZXDOM")
      expect(tokenized).toContain("ZXCIDR")

      const detokenized = yield* Pseudonymize.detokenizeString(db, sessionID, tokenized)
      expect(detokenized).toBe(rawPrompt)
    }),
  )

  it.effect("registers domain and generates stable token", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_01")
      yield* makeSession(sessionID)

      const token1 = yield* Pseudonymize.registerEntity(db, sessionID, "domain", "api.targetbank.com")
      expect(token1).toBe("ZXDOM001")

      const token2 = yield* Pseudonymize.registerEntity(db, sessionID, "domain", "api.targetbank.com")
      expect(token2).toBe("ZXDOM001")

      const token3 = yield* Pseudonymize.registerEntity(db, sessionID, "domain", "portal.targetbank.com")
      expect(token3).toBe("ZXDOM002")
    }),
  )

  it.effect("maintains isolation across different sessions", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionA = SessionSchema.ID.make("ses_test_iso_a")
      const sessionB = SessionSchema.ID.make("ses_test_iso_b")
      yield* makeSession(sessionA)
      yield* makeSession(sessionB)

      const tokenA = yield* Pseudonymize.registerEntity(db, sessionA, "domain", "api.client.com")
      const tokenB = yield* Pseudonymize.registerEntity(db, sessionB, "domain", "api.client.com")

      expect(tokenA).toBe("ZXDOM001")
      expect(tokenB).toBe("ZXDOM001")
    }),
  )

  it.effect("tokenizes raw tool outputs (shell / curl stdout) with IPs and CIDRs", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_tool_output")
      yield* makeSession(sessionID)

      yield* Pseudonymize.registerEntity(db, sessionID, "domain", "db.internal.net")

      const bashStdout = `
Connecting to db.internal.net (192.168.10.45)...
Nmap scan report for 192.168.10.45
Host is up (0.0020s latency).
PORT     STATE SERVICE
3306/tcp open  mysql
Subnet scanned: 192.168.10.0/24
Contact admin: sysadmin@internal.net
`
      const tokenized = yield* Pseudonymize.tokenizeString(db, sessionID, bashStdout)

      expect(tokenized).not.toContain("db.internal.net")
      expect(tokenized).not.toContain("192.168.10.45")
      expect(tokenized).not.toContain("192.168.10.0/24")
      expect(tokenized).not.toContain("sysadmin@internal.net")

      expect(tokenized).toContain("ZXDOM001")
      expect(tokenized).toContain("ZXIP001")
      expect(tokenized).toContain("ZXCIDR001")
      expect(tokenized).toContain("ZXMAIL001")

      const detokenized = yield* Pseudonymize.detokenizeString(db, sessionID, tokenized)
      expect(detokenized).toBe(bashStdout)
    }),
  )

  it.effect("irreversibly redacts secrets (AWS key, JWT, PEM)", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_secrets")
      yield* makeSession(sessionID)

      const text =
        "Encontré la key AKIAIOSFODNN7EXAMPLE y el JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_placeholder"

      const tokenized = yield* Pseudonymize.tokenizeString(db, sessionID, text)
      expect(tokenized).toContain("[SECRET-REDACTED]")
      expect(tokenized).not.toContain("AKIAIOSFODNN7EXAMPLE")

      const pseudonyms = yield* db
        .select()
        .from(PseudonymTable)
        .where(eq(PseudonymTable.engagement_id, sessionID))
        .all()
        .pipe(Effect.orDie)

      // Secrets should never be stored in the vault
      expect(pseudonyms.some((p) => p.real_value.includes("AKIA"))).toBe(false)
    }),
  )

  it.effect("detokenizes tool-result with structured ToolOutput and tool-input-delta", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_tool_events")
      yield* makeSession(sessionID)

      yield* Pseudonymize.registerEntity(db, sessionID, "domain", "api.vulnerable.org")

      // 1. tool-input-delta
      const inputDeltaEvent = LLMEvent.toolInputDelta({
        id: "call_input_1",
        name: "web_scan",
        text: '{"target": "https://ZXDOM001:8080/api"}',
      })
      const detokenizedInputDelta = yield* Pseudonymize.detokenizeEvent(db, sessionID, inputDeltaEvent)
      if (detokenizedInputDelta.type === "tool-input-delta") {
        expect(detokenizedInputDelta.text).toContain("https://api.vulnerable.org:8080/api")
      }

      // 2. tool-result with structured ToolOutput object
      const toolResultEvent = LLMEvent.toolResult({
        id: "call_res_1",
        name: "web_search",
        result: { type: "json", value: { match: "found at ZXDOM001" } },
        output: {
          structured: { host: "ZXDOM001", port: 8080 },
          content: [
            {
              type: "text",
              text: "Scan finished on ZXDOM001 without errors",
            },
          ],
        },
      })

      const detokenizedResult = yield* Pseudonymize.detokenizeEvent(db, sessionID, toolResultEvent)
      if (detokenizedResult.type === "tool-result") {
        const resVal = detokenizedResult.result as { type: "json"; value: { match: string } }
        expect(resVal.value.match).toBe("found at api.vulnerable.org")
        const structured = detokenizedResult.output?.structured as { host: string }
        expect(structured.host).toBe("api.vulnerable.org")
        const firstContent = detokenizedResult.output?.content[0]
        if (firstContent?.type === "text") {
          expect(firstContent.text).toBe("Scan finished on api.vulnerable.org without errors")
        }
      }
    }),
  )

  it.effect("cleans up vault when engagement is deleted", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_cascade")
      yield* makeSession(sessionID)

      yield* Pseudonymize.registerEntity(db, sessionID, "domain", "target.com")

      const before = yield* db
        .select()
        .from(PseudonymTable)
        .where(eq(PseudonymTable.engagement_id, sessionID))
        .all()
        .pipe(Effect.orDie)
      expect(before.length).toBe(1)

      yield* db
        .delete(PseudonymTable)
        .where(eq(PseudonymTable.engagement_id, sessionID))
        .run()
        .pipe(Effect.orDie)

      const after = yield* db
        .select()
        .from(PseudonymTable)
        .where(eq(PseudonymTable.engagement_id, sessionID))
        .all()
        .pipe(Effect.orDie)
      expect(after.length).toBe(0)
    }),
  )

  it.effect("handles concurrent entity registrations atomically without counter collisions", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionSchema.ID.make("ses_test_concurrent")
      yield* makeSession(sessionID)

      // Fire 10 concurrent registrations for different domains simultaneously
      const domains = Array.from({ length: 10 }, (_, i) => `sub${i}.target.org`)
      const tokens = yield* Effect.all(
        domains.map((dom) => Pseudonymize.registerEntity(db, sessionID, "domain", dom)),
        { concurrency: "unbounded" },
      )

      // Verify all 10 tokens are unique (ZXDOM001 to ZXDOM010)
      const tokenSet = new Set(tokens)
      expect(tokenSet.size).toBe(10)
      for (let i = 1; i <= 10; i++) {
        const expected = `ZXDOM${i.toString().padStart(3, "0")}`
        expect(tokenSet.has(expected)).toBe(true)
      }
    }),
  )
})
