import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { afterEach, describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { defaultAgentMemoryDir, reconcileAgentFindings } from "@argos/core/security/agent-findings-reconcile"
import { AgentFindingsScheduler } from "@argos/core/security/agent-findings-scheduler"
import { ingestToolPart } from "@argos/core/security/ingest"
import { AbsolutePath } from "@argos/core/schema"
import { eq } from "drizzle-orm"
import { testEffect } from "./lib/effect"

/**
 * Resolución del directorio de memoria compartida (hallazgos persistidos +
 * runs del orquestador).
 *
 * Ruta canónica: `~/.argos/memory`.
 */
describe("defaultAgentMemoryDir", () => {
  const homes: string[] = []
  const originalArgos = process.env.ARGOS_MEMORY_DIR

  const makeHome = async () => {
    const home = await mkdtemp(path.join(tmpdir(), "argos-home-"))
    homes.push(home)
    return home
  }

  afterEach(async () => {
    if (originalArgos === undefined) delete process.env.ARGOS_MEMORY_DIR
    else process.env.ARGOS_MEMORY_DIR = originalArgos
    await Promise.all(homes.splice(0).map((home) => rm(home, { recursive: true, force: true })))
  })

  test("defaults to ~/.argos/memory", async () => {
    delete process.env.ARGOS_MEMORY_DIR
    const home = await makeHome()

    expect(defaultAgentMemoryDir(home)).toBe(path.join(home, ".argos", "memory"))
  })

  test("ARGOS_MEMORY_DIR overrides the default", async () => {
    const home = await makeHome()
    const override = path.join(home, "custom-memory")
    process.env.ARGOS_MEMORY_DIR = override

    expect(defaultAgentMemoryDir(home)).toBe(override)
  })
})

/**
 * Reconciliación por taxonomía: el mismo bug reingerido con otra prosa
 * actualiza la fila que ya está en el panel. Si insertara una nueva, el
 * panel contaría dos veces la misma vulnerabilidad.
 */
const SESSION_ID = SessionV2.ID.make("ses_agent_taxonomy")

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

const seed = Effect.gen(function* () {
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
      slug: "agent-taxonomy",
      directory: "/project",
      title: "agent taxonomy test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

/** Escribe el store de memoria compartido como lo produce el binario Go. */
const makeStore = (findings: Array<Record<string, unknown>>) =>
  Effect.promise(async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "argos-agent-taxonomy-"))
    const findingsDir = path.join(dir, "findings")
    await mkdir(findingsDir, { recursive: true })
    await Promise.all(
      findings.map((finding, index) => writeFile(path.join(findingsDir, `entry-${index}.json`), JSON.stringify(finding))),
    )
    return dir
  })

const cleanup = (dir: string) => Effect.promise(() => rm(dir, { recursive: true, force: true }))

const findingsFor = (sessionID: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    return yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all().pipe(Effect.orDie)
  })

const agentFinding = (overrides: Record<string, unknown> = {}) => ({
  kind: "finding",
  agent: "security-web",
  session: "example-target-2026-08-14",
  argos_session_id: SESSION_ID,
  title: "SQL Injection",
  target: "https://example.com/item",
  vector: "id",
  severity: "HIGH",
  status: "observed",
  cwe: "CWE-89",
  evidence: "A controlled parameter test changed the SQL response in a reproducible way.",
  agent_assessment: "Repeated the parameter test and confirmed the query result depends on the injected value.",
  impact: "An attacker can read or modify records through the affected endpoint.",
  source_tool: "nuclei",
  ...overrides,
})

describe("reconcileAgentFindings por taxonomía", () => {
  it.effect("reingerir el mismo bug con un título distinto actualiza la fila en vez de duplicar", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([agentFinding()])

      const first = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(first).toMatchObject({ matched: 1, inserted: 1, skipped: 0 })
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(1)

      // Otro agente reporta el MISMO bug (misma taxonomía) con otra prosa y
      // una severidad distinta: la fila se actualiza.
      const second = yield* makeStore([
        agentFinding(),
        agentFinding({
          title: "SQL Injection Confirmada (sqlmap)",
          severity: "CRITICAL",
          source_tool: "sqlmap",
        }),
      ])
      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir: second })
      expect(result).toMatchObject({ matched: 2, inserted: 0, skipped: 2 })

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({ severity: "critical" })
      yield* cleanup(second)
    }),
  )

  it.effect("bugs distintos (CWE distinto) no se fusionan", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([
        agentFinding(),
        agentFinding({ title: "XSS reflejado", cwe: "CWE-79", source_tool: "web.xss" }),
      ])

      const result = yield* reconcileAgentFindings(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ matched: 2, inserted: 2 })
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(2)
      yield* cleanup(memoryDir)
    }),
  )
})

/**
 * ARG-013 — ingesta directa: tool Go → store → panel.
 *
 * Las tools escriben sus hallazgos en el store de memoria con el contrato
 * canónico completo (`argos-bin/internal/contract`), sin que ningún LLM los
 * transcriba. Lo que llega al panel es lo que la tool observó: el CWE, las
 * tags y el vector de CVSS los decide la tool.
 */
const GO_SESSION_ID = SessionV2.ID.make("ses_agent_go_store")

/** El registro que escribe el binario Go, campo por campo. */
const goFinding = (overrides: Record<string, unknown> = {}) => ({
  kind: "finding",
  agent: "argos-web",
  session: "example-target-2026-08-14",
  argos_session_id: GO_SESSION_ID,
  title: "SQL Injection",
  target: "https://example.com/item",
  vector: "id",
  severity: "high",
  status: "observed",
  confidence: "confirmed",
  cwe: "CWE-89",
  rule_id: "nuclei:sql-injection",
  owasp: ["A03:2021"],
  evidence: { parameter: "id", payload: "' OR 1=1--" },
  remediation: "Use parameterized queries",
  cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  tags: ["sqli", "injection"],
  references: ["https://example.com/advisory"],
  source_tool: "web.scan",
  source: "web.scan",
  timestamp: "2026-08-14T17:46:32Z",
  ...overrides,
})

const seedGo = Effect.gen(function* () {
  yield* seed
  const { db } = yield* Database.Service
  yield* db
    .insert(SessionTable)
    .values({
      id: GO_SESSION_ID,
      project_id: Project.ID.global,
      slug: "agent-go-store",
      directory: "/project",
      title: "agent go store test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

describe("store escrito por la tool Go (ARG-013)", () => {
  it.effect("un resultado automático de scanner no se reconcilia como hallazgo aceptado", () =>
    Effect.gen(function* () {
      yield* seedGo
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([goFinding()])

      const result = yield* reconcileAgentFindings(db, { sessionID: GO_SESSION_ID, memoryDir })
      expect(result).toMatchObject({ matched: 0, inserted: 0, skipped: 1 })

      const rows = yield* findingsFor(GO_SESSION_ID)
      expect(rows).toHaveLength(0)
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("sin argos_session_id el hallazgo NO llega al panel (el match es exacto)", () =>
    Effect.gen(function* () {
      yield* seedGo
      const { db } = yield* Database.Service
      const orphan = goFinding({ title: "SQL Injection sin sesión" })
      delete (orphan as Record<string, unknown>)["argos_session_id"]
      const memoryDir = yield* makeStore([orphan])

      const result = yield* reconcileAgentFindings(db, { sessionID: GO_SESSION_ID, memoryDir })
      expect(result).toMatchObject({ scanned: 1, matched: 0, inserted: 0 })
      expect(yield* findingsFor(GO_SESSION_ID)).toHaveLength(0)
      yield* cleanup(memoryDir)
    }),
  )

  it.effect("la transcripción del LLM no crea una segunda fila ni pisa los datos de la tool", () =>
    Effect.gen(function* () {
      yield* seedGo
      const { db } = yield* Database.Service

      // 1. El agente transcribe el hallazgo a su manera (el flujo viejo): el
      //    LLM resume la evidencia y le pone otro título.
      yield* ingestToolPart(db, {
        sessionID: GO_SESSION_ID,
        type: "tool",
        tool: "argos_memory_save",
        state: {
          status: "completed",
          input: {
            kind: "finding",
            title: "Posible SQLi en el item",
            severity: "high",
            status: "observed",
            cwe: "CWE-89",
            target: "https://example.com/item",
            vector: "id",
            evidence: "el modelo resume la evidencia",
            agent_assessment: "Revisé la respuesta con la cuenta autenticada y confirmé el cambio reproducible del resultado SQL.",
            impact: "Un atacante puede leer datos de otros usuarios mediante el endpoint afectado.",
            source_tool: "web.scan",
          },
        },
      })
      expect(yield* findingsFor(GO_SESSION_ID)).toHaveLength(1)

      // 2. La tool escribió el hallazgo canónico en el store: el
      //    reconciliador lo trae y sus datos mandan sobre la transcripción.
      const memoryDir = yield* makeStore([goFinding()])
      const result = yield* reconcileAgentFindings(db, { sessionID: GO_SESSION_ID, memoryDir })
      expect(result).toMatchObject({ matched: 0, inserted: 0, skipped: 1 })

      const rows = yield* findingsFor(GO_SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({
        cwe: "CWE-89",
        source: "agent-reviewed",
        evidence: { text: "el modelo resume la evidencia" },
      })
      yield* cleanup(memoryDir)
    }),
  )
})

/**
 * E2E entre los dos lenguajes: el binario Go escribe el store de verdad
 * (scripts/argos-013-e2e.ts deja el directorio en ARGOS_E2E_STORE_DIR) y el
 * backend lo reconcilia tal cual, sin tocar un byte.
 */
const GO_STORE_DIR = process.env.ARGOS_E2E_STORE_DIR

it.effect("el store que produce el binario Go se reconcilia sin tocarlo", () =>
  Effect.gen(function* () {
    if (!GO_STORE_DIR) {
      console.warn(
        "ARGOS_E2E_STORE_DIR no está definido: el E2E con el binario Go se salta (bun scripts/argos-013-e2e.ts)",
      )
      return
    }
    yield* seedGo
    const { db } = yield* Database.Service

    const entries = yield* Effect.promise(() => readdir(path.join(GO_STORE_DIR, "findings")))
    const files = entries.filter((entry) => entry.endsWith(".json"))
    expect(files.length).toBeGreaterThan(0)

    const result = yield* reconcileAgentFindings(db, { sessionID: GO_SESSION_ID, memoryDir: GO_STORE_DIR })
    expect(result).toMatchObject({ matched: 1, inserted: 1 })

    const rows = yield* findingsFor(GO_SESSION_ID)
    expect(rows).toHaveLength(1)
    // El CWE del panel es el de la tool, no el de un LLM.
    expect(rows[0]).toMatchObject({
      cwe: "CWE-200",
      source_tool: "web.scan",
      agent: "argos-web",
      status: "observed",
      confidence: "confirmed",
    })
  }),
)

describe("AgentFindingsScheduler.schedule", () => {
  it.effect("schedules without throwing iterable error", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = SessionV2.ID.make("session-scheduler-test")
      yield* AgentFindingsScheduler.schedule(db, sessionID)
    }),
  )
})
