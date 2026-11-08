import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingObservationTable, FindingTable } from "@argos/core/security/sql"
import { reconcileAgentFindings } from "@argos/core/security/agent-findings-reconcile"
import { AbsolutePath } from "@argos/core/schema"
import { eq } from "drizzle-orm"
import { testEffect } from "./lib/effect"

const SESSION_ID = SessionV2.ID.make("ses_agent_reconcile")
const OTHER_SESSION_ID = SessionV2.ID.make("ses_agent_other")

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

/** Escribe un store de memoria como el que produce el binario Go. */
const makeMemoryDir = (findings: Array<Record<string, unknown> | string>) =>
  Effect.promise(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "argos-agent-memory-"))
    const findingsDir = path.join(dir, "findings")
    await mkdir(findingsDir, { recursive: true })
    await Promise.all(
      findings.map((finding, index) =>
        writeFile(
          path.join(findingsDir, `entry-${index}.json`),
          typeof finding === "string" ? finding : JSON.stringify(finding, null, 2),
        ),
      ),
    )
    return dir
  })

const cleanup = (dir: string) => Effect.promise(() => rm(dir, { recursive: true, force: true }))

const seed = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db
    .insert(ProjectTable)
    .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
  for (const id of [SESSION_ID, OTHER_SESSION_ID]) {
    yield* db
      .insert(SessionTable)
      .values({
        id,
        project_id: Project.ID.global,
        slug: id,
        directory: "/project",
        title: "agent reconcile test",
        version: "test",
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  }
})

const findingsFor = (sessionID: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    return yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all().pipe(Effect.orDie)
  })

// Forma real de un archivo del store de Go (ver Finding en
// argos-bin/cmd/orquestador/tools/memory.go).
const goFinding = (overrides: Record<string, unknown> = {}) => ({
  kind: "finding",
  agent: "security-scout",
  session: "example-target-2026-08-14",
  argos_session_id: SESSION_ID,
  title: "Subdominio expuesto sin inventario",
  target: "sub.example.com",
  severity: "MEDIUM",
  status: "observed",
  cwe: "CWE-200",
  evidence: "subfinder pasivo: sub.example.com",
  agent_assessment: "Verifiqué que el subdominio respondió y confirmé que no figura en el inventario autorizado.",
  impact: "Un servicio desconocido puede exponer una superficie de ataque sin supervisión.",
  vector: "sub.example.com",
  tags: ["recon"],
  source_tool: "web.subdomains",
  timestamp: "2026-08-14T17:46:32Z",
  ...overrides,
})

describe("reconcileAgentFindings", () => {
  it.effect("brings a peer agent's finding into the Session's panel", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([goFinding()])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toEqual({ scanned: 1, matched: 1, inserted: 1, skipped: 0 })

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({
        title: "Subdominio expuesto sin inventario",
        severity: "medium",
        status: "observed",
        agent: "security-scout",
        source_tool: "web.subdomains",
        cwe: "CWE-200",
        evidence: { text: "subfinder pasivo: sub.example.com" },
        tags: ["recon"],
      })
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("maps the contract fields the Go tools emit", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([
        goFinding({
          title: "SQL Injection Confirmada (sqlmap)",
          severity: "critical",
          confidence: "confirmed",
          rule_id: "sqlmap",
          owasp: ["A03:2021"],
          references: ["https://example.com/advisory"],
          cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
          source_tool: "web.sqli",
        }),
      ])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ matched: 1, inserted: 1 })

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({
        confidence: "confirmed",
        rule_id: "sqlmap",
        owasp: ["A03:2021"],
        references: ["https://example.com/advisory"],
        cvss_input: {
          attackVector: "N",
          attackComplexity: "L",
          privilegesRequired: "N",
          userInteraction: "N",
          scope: "U",
          confidentiality: "H",
          integrity: "H",
          availability: "H",
        },
      })
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("ignores findings belonging to a different Session", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([
        goFinding({ argos_session_id: OTHER_SESSION_ID, title: "Otra sesión" }),
      ])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ scanned: 1, matched: 0, inserted: 0 })
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(0)
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("ignores entries with no session id", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const legacy = goFinding()
      delete (legacy as Record<string, unknown>)["argos_session_id"]
      const memoryDir = yield* makeMemoryDir([legacy])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ matched: 0, inserted: 0 })
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("ignores non-finding kinds (note, phase-complete)", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([
        goFinding({ kind: "note", title: "Contexto" }),
        goFinding({ kind: "phase-complete", title: "Fase 1 lista" }),
      ])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ scanned: 2, matched: 0, inserted: 0 })
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("is idempotent and does not duplicate on a second run", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([goFinding(), goFinding({ title: "Segundo hallazgo", vector: "b.example.com" })])

      const first = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(first).toMatchObject({ matched: 2, inserted: 2 })
      const second = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(second).toMatchObject({ matched: 2, inserted: 0, skipped: 2 })

      expect(yield* findingsFor(SESSION_ID)).toHaveLength(2)
      const observations = yield* db
        .select()
        .from(FindingObservationTable)
        .where(eq(FindingObservationTable.session_id, SESSION_ID))
        .all()
      expect(observations).toHaveLength(2)
      expect(new Set(observations.map((row) => row.source_event_id)).size).toBe(2)
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("preserves a changed shared-store snapshot as a new observation", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([goFinding()])
      yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      yield* Effect.promise(() =>
        writeFile(
          path.join(memoryDir, "findings", "entry-0.json"),
          JSON.stringify(goFinding({ evidence: "new independent scanner evidence" }), null, 2),
        ),
      )
      yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })

      const observations = yield* db
        .select()
        .from(FindingObservationTable)
        .where(eq(FindingObservationTable.session_id, SESSION_ID))
        .all()
      expect(observations).toHaveLength(2)
      expect(new Set(observations.map((row) => row.finding_id)).size).toBe(1)
      expect(observations.map((row) => row.snapshot).join("\n")).toContain("new independent scanner evidence")
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("does not re-insert a finding ingest.ts already captured (same fingerprint)", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const { findingFingerprint } = yield* Effect.promise(() => import("@argos/core/security/ingest"))
      const finding = goFinding()
      const fingerprint = findingFingerprint(finding)
      yield* db
        .insert(FindingTable)
        .values({
          id: "finding_already_ingested",
          session_id: SESSION_ID,
          project_id: Project.ID.global,
          fingerprint,
          title: finding.title,
          severity: "medium",
          status: "observed",
          source: "memory",
          source_tool: "argos_memory_save",
          vector: finding.vector,
          evidence: {},
          tags: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      const memoryDir = yield* makeMemoryDir([finding])
      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ matched: 1, inserted: 0, skipped: 1 })
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(1)
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("skips a corrupt JSON file instead of aborting the whole run", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir(["{ not valid json", goFinding()])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ scanned: 2, matched: 1, inserted: 1 })
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("no-ops when the memory store does not exist yet", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const result = yield* reconcileAgentFindings(db, {
        sessionID: SESSION_ID,
        memoryDir: path.join(tmpdir(), "argos-store-that-does-not-exist"),
      })
      expect(result).toEqual({ scanned: 0, matched: 0, inserted: 0, skipped: 0 })
    }),
  )

  it.effect("no-ops for a Session that isn't recorded", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const memoryDir = yield* makeMemoryDir([goFinding({ argos_session_id: "ses_missing" })])
      const result = yield* reconcileAgentFindings(db, {
        sessionID: SessionV2.ID.make("ses_missing"),
        memoryDir,
      })
      expect(result).toMatchObject({ scanned: 1, inserted: 0 })
      yield* cleanup(memoryDir)
    }),
  )
})
