import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { AbsolutePath } from "@argos/core/schema"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { ingestToolPart } from "@argos/core/security/ingest"
import { ThreatIntelEnrichment } from "@argos/core/threat-intel/enrichment"
import { testEffect } from "./lib/effect"

const SESSION_ID = SessionV2.ID.make("ses_cvss_enrichment_test")
const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

const seedSessionAndProject = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db
    .insert(ProjectTable)
    .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
  yield* db
    .insert(SessionTable)
    .values({
      id: SESSION_ID,
      project_id: Project.ID.global,
      slug: SESSION_ID,
      directory: "/project",
      title: "cvss enrichment test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

describe("CVSS de punta a punta: ingest.ts → cvss_input → enrichment.ts → EnrichmentInfo.cvss", () => {
  it.effect(
    "un hallazgo con vector CVSS explícito termina con score calculado en enrichment",
    () =>
      Effect.gen(function* () {
        yield* seedSessionAndProject
        const { db } = yield* Database.Service

        yield* ingestToolPart(db, {
          sessionID: SESSION_ID,
          type: "tool",
          tool: "argos_memory_save",
          state: {
            status: "completed",
            input: {
              kind: "finding",
              title: "SQL injection en /login",
              severity: "critical",
              target: "https://target.test/login",
              evidence: "The payload altered the query response and exposed records beyond the authenticated account.",
              agent_assessment: "I compared normal and quote payload responses and confirmed the query behavior changed.",
              impact: "An unauthenticated visitor can read records outside the intended account.",
              vector: "http://target/login",
              cwe: "CWE-89",
              tags: ["sqli"],
              cvss: { av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "H", a: "H" },
            },
          },
        })

        const row = yield* db
          .select({ id: FindingTable.id, cvssInput: FindingTable.cvss_input })
          .from(FindingTable)
          .where(eq(FindingTable.session_id, SESSION_ID))
          .get()
          .pipe(Effect.orDie)

        expect(row?.cvssInput).toEqual({
          attackVector: "N",
          attackComplexity: "L",
          privilegesRequired: "N",
          userInteraction: "N",
          scope: "U",
          confidentiality: "H",
          integrity: "H",
          availability: "H",
        })

        const enrichment = yield* ThreatIntelEnrichment.Service
        yield* enrichment.enrich(row!.id)

        const enriched = yield* db
          .select({ enrichment: FindingTable.enrichment })
          .from(FindingTable)
          .where(eq(FindingTable.id, row!.id))
          .get()
          .pipe(Effect.orDie)

        expect(enriched?.enrichment?.cvss?.score).toBe(9.8)
        expect(enriched?.enrichment?.cvss?.severity).toBe("critical")
        expect(enriched?.enrichment?.cvss?.vectorString).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      }).pipe(Effect.provide(Layer.mergeAll(Project.defaultLayer, ThreatIntelEnrichment.defaultLayer))),
    { timeout: 15000 },
  )

  it.effect(
    "un hallazgo SIN vector CVSS no produce ningún score inventado",
    () =>
      Effect.gen(function* () {
        yield* seedSessionAndProject
        const { db } = yield* Database.Service

        yield* ingestToolPart(db, {
          sessionID: SESSION_ID,
          type: "tool",
          tool: "argos_memory_save",
          state: {
            status: "completed",
            input: {
              kind: "finding",
              title: "Puerto de gestión expuesto",
              severity: "high",
              target: "https://10.0.0.5:8443/",
              evidence: "The service exposed a management interface to an untrusted network segment.",
              agent_assessment: "I verified the management interface responds without an approved access control.",
              impact: "An untrusted network user can reach administrative functions on the host.",
              vector: "10.0.0.5:8443",
            },
          },
        })

        const row = yield* db
          .select({ id: FindingTable.id, cvssInput: FindingTable.cvss_input })
          .from(FindingTable)
          .where(eq(FindingTable.session_id, SESSION_ID))
          .get()
          .pipe(Effect.orDie)
        expect(row?.cvssInput).toBeNull()

        const enrichment = yield* ThreatIntelEnrichment.Service
        yield* enrichment.enrich(row!.id)

        const enriched = yield* db
          .select({ enrichment: FindingTable.enrichment })
          .from(FindingTable)
          .where(eq(FindingTable.id, row!.id))
          .get()
          .pipe(Effect.orDie)

        expect(enriched?.enrichment?.cvss).toBeUndefined()
      }).pipe(Effect.provide(Layer.mergeAll(Project.defaultLayer, ThreatIntelEnrichment.defaultLayer))),
    { timeout: 15000 },
  )

  it.effect(
    "un vector CVSS mal formado se descarta silenciosamente en vez de romper la ingesta",
    () =>
      Effect.gen(function* () {
        yield* seedSessionAndProject
        const { db } = yield* Database.Service

        yield* ingestToolPart(db, {
          sessionID: SESSION_ID,
          type: "tool",
          tool: "argos_memory_save",
          state: {
            status: "completed",
            input: {
              kind: "finding",
              title: "XSS reflejado",
              severity: "medium",
              target: "https://target.test/search",
              evidence: "The reflected payload altered the rendered page in the controlled test response.",
              agent_assessment: "I checked the escaped and unescaped responses and confirmed script-context reflection.",
              impact: "A crafted link can execute script in the victim's authenticated browser session.",
              cvss: { av: "NETWORK", ac: "L", pr: "N", ui: "N", s: "U", c: "L", i: "N", a: "N" },
            },
          },
        })

        const row = yield* db
          .select({ cvssInput: FindingTable.cvss_input })
          .from(FindingTable)
          .where(eq(FindingTable.session_id, SESSION_ID))
          .get()
          .pipe(Effect.orDie)
        expect(row?.cvssInput).toBeNull()
      }),
    { timeout: 15000 },
  )
})
