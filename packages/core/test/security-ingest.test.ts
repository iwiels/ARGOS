import { describe, expect, test } from "bun:test"
import { Effect, Fiber, Layer, Stream } from "effect"
import { Database } from "@argos/core/database/database"
import { EventV2 } from "@argos/core/event"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingObservationTable, FindingTable } from "@argos/core/security/sql"
import { FindingUpserted } from "@argos/core/security/events"
import {
  findingFingerprint,
  findingId,
  ingestToolPart,
  isFindingInput,
  legacyFindingFingerprint,
  normalizeFindingSeverity,
  normalizeFindingStatus,
  normalizeTargetIdentity,
  normalizeVectorIdentity,
  resolveSourceTool,
} from "@argos/core/security/ingest"
import { AbsolutePath } from "@argos/core/schema"
import { eq } from "drizzle-orm"
import { testEffect } from "./lib/effect"

describe("isFindingInput", () => {
  const cases: Array<[string, Record<string, unknown>, boolean]> = [
    ["complete agent-reviewed finding accepted", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "Response returned another user's record", agent_assessment: "Compared the record with the authenticated account and confirmed the mismatch", impact: "An attacker can read another user's data" }, true],
    ["finding without agent assessment rejected", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "Response returned another user's record", impact: "An attacker can read another user's data" }, false],
    ["finding without impact rejected", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "Response returned another user's record", agent_assessment: "Compared the record with the authenticated account and confirmed the mismatch" }, false],
    ["trivial agent assessment rejected", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "Response returned another user's record", agent_assessment: "Confirmed", impact: "An attacker can read another user's data" }, false],
    ["assessment copied from evidence rejected", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "The response returns another user's private account record", agent_assessment: "The response returns another user's private account record", impact: "An attacker can read another user's private account data" }, false],
    ["placeholder impact rejected", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "Response returned another user's record", agent_assessment: "Compared the record with the authenticated account and confirmed the mismatch", impact: "N/A" }, false],
    ["kind: finding without evidence rejected", { kind: "finding", title: "X", target: "https://x.test/a", severity: "high" }, false],
    ["kind: finding without target rejected", { kind: "finding", title: "X", severity: "high", evidence: "Verified disclosure" }, false],
    ["kind: finding without severity rejected", { kind: "finding", title: "X", target: "https://x.test/a", evidence: "Verified disclosure" }, false],
    ["kind case-insensitive", { kind: "Finding", title: "X", target: "https://x.test/a", severity: "high", evidence: "Response returned another user's record", agent_assessment: "Compared the response with the authenticated account and confirmed the mismatch", impact: "An attacker can read another user's data" }, true],
    ["kind omitted, title+severity present", { title: "X", target: "https://x.test/a", severity: "high", evidence: "Verified disclosure" }, false],
    ["kind omitted, only title", { title: "X" }, false],
    ["kind omitted, only severity", { severity: "high" }, false],
    ["kind: note explicitly excluded", { kind: "note", title: "X", severity: "high" }, false],
    ["kind: phase-complete explicitly excluded", { kind: "phase-complete", title: "X", severity: "high" }, false],
    ["empty input", {}, false],
  ]
  for (const [name, input, expected] of cases) {
    test(name, () => expect(isFindingInput(input)).toBe(expected))
  }
})

describe("normalizeFindingSeverity", () => {
  const cases: Array<[unknown, string]> = [
    ["critical", "critical"],
    ["CRÍTICO", "critical"],
    ["critico", "critical"],
    ["High", "high"],
    ["alto", "high"],
    ["medium", "medium"],
    ["media", "medium"],
    ["moderate", "medium"],
    ["low", "low"],
    ["baja", "low"],
    ["unknown-value", "info"],
    [undefined, "info"],
    [42, "info"],
  ]
  for (const [input, expected] of cases) {
    test(`${JSON.stringify(input)} -> ${expected}`, () => expect(normalizeFindingSeverity(input)).toBe(expected))
  }
})

describe("normalizeFindingStatus", () => {
  test("accepts a known status", () => expect(normalizeFindingStatus("mitigated")).toBe("mitigated"))
  test("accepts canonical status values: verified, false-positive, accepted-risk", () => {
    expect(normalizeFindingStatus("verified")).toBe("verified")
    expect(normalizeFindingStatus("false-positive")).toBe("false-positive")
    expect(normalizeFindingStatus("accepted-risk")).toBe("accepted-risk")
  })
  test("is case-insensitive", () => expect(normalizeFindingStatus("Resolved")).toBe("resolved"))
  test("falls back to open for unknown values", () => expect(normalizeFindingStatus("bogus")).toBe("open"))
  test("falls back to open when missing", () => expect(normalizeFindingStatus(undefined)).toBe("open"))
})

describe("resolveSourceTool", () => {
  test("uses the explicit source_tool when present", () =>
    expect(resolveSourceTool({ source_tool: "web.probe" })).toBe("web.probe"))
  test("falls back to the memory_save constant when absent", () =>
    expect(resolveSourceTool({})).toBe("argos_memory_save"))
})

describe("findingFingerprint / findingId", () => {
  test("is deterministic for the same title+vector", () => {
    const a = findingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })
    const b = findingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })
    expect(a).toBe(b)
  })
  test("is insensitive to whitespace and case in the identity fields", () => {
    const a = findingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })
    const b = findingFingerprint({ title: "  missing   hsts  ", vector: "HTTPS://EXAMPLE.COM" })
    expect(a).toBe(b)
  })
  test("falls back to target when vector is absent", () => {
    const a = findingFingerprint({ title: "Open port", target: "10.0.0.1" })
    const b = findingFingerprint({ title: "Open port", vector: "10.0.0.1" })
    expect(a).toBe(b)
  })
  test("differs when the title differs", () => {
    const a = findingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })
    const b = findingFingerprint({ title: "Missing CSP", vector: "https://example.com" })
    expect(a).not.toBe(b)
  })
  test("findingId is scoped per session for the same fingerprint", () => {
    const fp = findingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })
    expect(findingId("ses_a", fp)).not.toBe(findingId("ses_b", fp))
    expect(findingId("ses_a", fp)).toBe(findingId("ses_a", fp))
  })
})

// El fingerprint decide si dos hallazgos son el mismo bug. Con taxonomía, la
// prosa del título deja de decidirlo: tres herramientas describen el mismo
// SQLi con tres títulos distintos y el panel tenía que contar uno.
describe("findingFingerprint por taxonomía", () => {
  test("el mismo bug con títulos distintos es el mismo hallazgo", () => {
    const base = { cwe: "CWE-89", target: "https://example.com/item", vector: "id" }
    const a = findingFingerprint({ ...base, title: "SQL Injection" })
    const b = findingFingerprint({ ...base, title: "Posible SQLi (boolean/time-based)" })
    const c = findingFingerprint({ ...base, title: "SQL Injection Confirmada (sqlmap)" })
    expect(a).toBe(b)
    expect(b).toBe(c)
  })

  test("el mismo nombre de parámetro en otro target es otro bug", () => {
    const a = findingFingerprint({ cwe: "CWE-89", title: "SQLi", target: "https://example.com/a", vector: "id" })
    const b = findingFingerprint({ cwe: "CWE-89", title: "SQLi", target: "https://example.com/b", vector: "id" })
    expect(a).not.toBe(b)
  })

  test("otro CWE en el mismo target es otro bug", () => {
    const a = findingFingerprint({ cwe: "CWE-89", title: "SQLi", target: "https://example.com/item", vector: "id" })
    const b = findingFingerprint({ cwe: "CWE-79", title: "SQLi", target: "https://example.com/item", vector: "id" })
    expect(a).not.toBe(b)
  })

  test("el fingerprint es sha256 de la taxonomía normalizada", () => {
    expect(findingFingerprint({ cwe: "CWE-89", target: "https://example.com/item", vector: "id" })).toBe(
      "0493cf2b60a164845120c32dd24c7e861d7dd75ba0d1056537b954f4b62710bf",
    )
  })

  test("sin CWE cae al fingerprint histórico por título (mismo hash que antes)", () => {
    // La fórmula v1 (sha256 de "title|vector||target") se conserva byte a
    // byte: los hallazgos sin taxonomía no tienen otra señal de identidad y
    // las filas ya persistidas deben seguir coincidiendo.
    expect(findingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })).toBe(
      "93a574c45314289fb2a5c3e0ddeb60cec868311d2b4059c5af90b9a77d8cce4c",
    )
    expect(legacyFindingFingerprint({ title: "Missing HSTS", vector: "https://example.com" })).toBe(
      "93a574c45314289fb2a5c3e0ddeb60cec868311d2b4059c5af90b9a77d8cce4c",
    )
  })

  test("un CWE sin vector no activa identidad taxonómica", () => {
    const base = { cwe: "CWE-89", target: "https://example.com/item" }
    const first = findingFingerprint({ ...base, title: "SQL injection en id" })
    const second = findingFingerprint({ ...base, title: "SQL injection en search" })
    expect(first).not.toBe(second)
    expect(first).toBe(legacyFindingFingerprint({ ...base, title: "SQL injection en id" }))
  })
})

describe("normalización de identidad (target/vector)", () => {
  test("el target normalizado descarta esquema, query, fragment y barras finales", () => {
    expect(normalizeTargetIdentity("HTTPS://Example.com:8080/path/?x=1#frag")).toBe("example.com:8080/path")
    expect(normalizeTargetIdentity("https://example.com/path/")).toBe("example.com/path")
    expect(normalizeTargetIdentity("https://example.com")).toBe("example.com")
    expect(normalizeTargetIdentity("https://example.com/")).toBe("example.com")
  })

  test("el puerto por defecto no discrimina, uno distinto sí", () => {
    expect(normalizeTargetIdentity("https://example.com:443/path")).toBe("example.com/path")
    expect(normalizeTargetIdentity("http://example.com:80/path")).toBe("example.com/path")
    expect(normalizeTargetIdentity("https://example.com:8080/path")).toBe("example.com:8080/path")
  })

  test("un target sin esquema también pierde el puerto por defecto", () => {
    expect(normalizeTargetIdentity("192.168.1.1:22")).toBe("192.168.1.1:22")
    expect(normalizeTargetIdentity("example.com:443")).toBe("example.com")
  })

  test("el vector conserva los nombres de parámetros y descarta los valores variables", () => {
    expect(normalizeVectorIdentity("https://x/item?id=1")).toBe("https://x/item?id")
    expect(normalizeVectorIdentity("https://x/item?search=2&id=1")).toBe("https://x/item?id&search")
    expect(normalizeVectorIdentity("  ID  ")).toBe("id")
    expect(normalizeVectorIdentity("/admin/")).toBe("/admin")
    expect(normalizeVectorIdentity("")).toBe("")
  })
})

// ── ingestToolPart: DB-backed integration coverage ─────────────────────────
// This is the bridge between "an agent called argos_memory_save" and a
// row existing in security_finding — the hinge of the finding -> memory ->
// panel critical path.

const database = Database.layerFromPath(":memory:")
const events = EventV2.layer.pipe(Layer.provide(database))
const it = testEffect(Layer.mergeAll(database, events))

const SESSION_ID = SessionV2.ID.make("ses_ingest_test")

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
      slug: "ingest-test",
      directory: "/project",
      title: "ingest test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

const completedMemorySave = (input: Record<string, unknown>, callID = "call-memory-save") => ({
  sessionID: SESSION_ID,
  type: "tool" as const,
  callID,
  tool: "argos_memory_save",
  state: {
    status: "completed" as const,
    input: {
      target: "https://example.test/verified",
      evidence: "The agent verified a concrete security impact.",
      agent_assessment: "I independently checked the response and confirmed the security behavior.",
      impact: "An unauthorized actor can access protected data.",
      ...input,
    },
    output: "ok",
  },
})

const findingsFor = Effect.fn("test.findingsFor")(function* (sessionID: string) {
  const { db } = yield* Database.Service
  return yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all().pipe(Effect.orDie)
})

describe("ingestToolPart", () => {
  it.effect("inserts a normalized Finding row for a completed memory_save with a finding", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      yield* ingestToolPart(
        db,
        completedMemorySave({
          kind: "finding",
          title: "Missing HSTS header on example.com",
          severity: "ALTO",
          status: "OPEN",
          source_tool: "web.probe",
          agent: "security-web",
          target: "https://example.com",
          cwe: "CWE-319",
          vector: "https://example.com",
          evidence: "Response lacks Strict-Transport-Security",
          remediation: "Add HSTS header",
          tags: ["tls", "headers"],
        }),
      )

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({
        session_id: SESSION_ID,
        title: "Missing HSTS header on example.com",
        severity: "high",
        status: "open",
        source: "agent-reviewed",
        source_tool: "web.probe",
        agent: "security-web",
        target: "https://example.com",
        cwe: "CWE-319",
        vector: "https://example.com",
        evidence: { text: "Response lacks Strict-Transport-Security" },
        remediation: "Add HSTS header",
        tags: ["tls", "headers"],
      })
    }),
  )

  it.effect("records each memory_save observation once per tool call", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const input = { kind: "finding", title: "Missing HSTS", severity: "medium", target: "https://example.com" }
      yield* ingestToolPart(db, completedMemorySave(input, "call-one"))
      yield* ingestToolPart(db, completedMemorySave(input, "call-one"))
      yield* ingestToolPart(db, completedMemorySave(input, "call-two"))

      const observations = yield* db
        .select()
        .from(FindingObservationTable)
        .where(eq(FindingObservationTable.session_id, SESSION_ID))
        .all()
        .pipe(Effect.orDie)
      expect(observations).toHaveLength(2)
      expect(observations.map((row) => row.source_event_id).sort()).toEqual(["tool:call-one", "tool:call-two"])
      expect(observations.every((row) => row.finding_id === observations[0].finding_id)).toBe(true)
    }),
  )

  it.effect("does not promote a memory save that omitted the finding decision", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      yield* ingestToolPart(db, completedMemorySave({ title: "Open port 22", severity: "medium" }))
      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(0)
    }),
  )

  it.effect("ignores a memory_save that is not a finding (kind: note)", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      yield* ingestToolPart(db, completedMemorySave({ kind: "note", title: "Context", severity: "info" }))
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(0)
    }),
  )

  it.effect("ignores a memory_save missing a title", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      yield* ingestToolPart(db, completedMemorySave({ kind: "finding", severity: "high" }))
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(0)
    }),
  )

  it.effect("ignores parts that are not a completed memory_save tool call", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const finding = { kind: "finding", title: "Should be ignored", severity: "high" }
      yield* ingestToolPart(db, { ...completedMemorySave(finding), type: "text" as const })
      yield* ingestToolPart(db, { ...completedMemorySave(finding), tool: "other_tool" })
      yield* ingestToolPart(db, { ...completedMemorySave(finding), state: { status: "running", input: finding } })
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(0)
    }),
  )

  it.effect("ignores a finding for a Session that isn't recorded", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* ingestToolPart(db, {
        sessionID: SessionV2.ID.make("ses_missing"),
        type: "tool",
        tool: "argos_memory_save",
        state: { status: "completed", input: { kind: "finding", title: "Orphan finding", severity: "high" } },
      })
      expect(yield* findingsFor("ses_missing")).toHaveLength(0)
    }),
  )

  it.effect("upserts on the same session+fingerprint instead of duplicating", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const base = { kind: "finding", title: "Missing HSTS", vector: "https://example.com" }
      yield* ingestToolPart(db, completedMemorySave({ ...base, severity: "low", status: "open" }))
      yield* ingestToolPart(db, completedMemorySave({ ...base, severity: "critical", status: "validated" }))

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({ severity: "critical", status: "validated" })
    }),
  )

  it.effect("tres herramientas reportando el mismo bug con títulos distintos → una sola fila", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const base = {
        kind: "finding",
        cwe: "CWE-89",
        target: "https://example.com/item",
        vector: "id",
        severity: "high",
      }
      yield* ingestToolPart(db, completedMemorySave({ ...base, title: "SQL Injection", source_tool: "nuclei" }))
      yield* ingestToolPart(
        db,
        completedMemorySave({ ...base, title: "Posible SQLi (boolean/time-based)", source_tool: "web.sqli" }),
      )
      yield* ingestToolPart(
        db,
        completedMemorySave({ ...base, title: "SQL Injection Confirmada (sqlmap)", source_tool: "sqlmap" }),
      )

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({ cwe: "CWE-89", target: "https://example.com/item" })
    }),
  )

  it.effect("el mismo nombre de parámetro en targets distintos → dos filas", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const base = { kind: "finding", cwe: "CWE-89", title: "SQL Injection", vector: "id", severity: "high" }
      yield* ingestToolPart(db, completedMemorySave({ ...base, target: "https://example.com/a" }))
      yield* ingestToolPart(db, completedMemorySave({ ...base, target: "https://example.com/b" }))

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(2)
      expect(rows.map((row) => row.target).sort((a, b) => (a ?? "").localeCompare(b ?? ""))).toEqual([
        "https://example.com/a",
        "https://example.com/b",
      ])
    }),
  )

  it.effect("los valores de query no duplican y los parámetros distintos no se fusionan", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const base = { kind: "finding", cwe: "CWE-89", title: "SQL Injection", target: "https://example.com/item", severity: "high" }
      yield* ingestToolPart(db, completedMemorySave({ ...base, vector: "https://example.com/item?id=1" }))
      yield* ingestToolPart(db, completedMemorySave({ ...base, vector: "https://example.com/item?id=2" }))
      yield* ingestToolPart(db, completedMemorySave({ ...base, vector: "https://example.com/item?search=test" }))

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(2)
      expect(rows.map((row) => row.vector).sort()).toEqual([
        "https://example.com/item?id=1",
        "https://example.com/item?search=test",
      ])
    }),
  )

  it.effect("sin vector explícito no fusiona problemas distintos por CWE y target", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const base = { kind: "finding", cwe: "CWE-89", target: "https://example.com/item", severity: "high" }
      yield* ingestToolPart(db, completedMemorySave({ ...base, title: "SQL injection en id" }))
      yield* ingestToolPart(db, completedMemorySave({ ...base, title: "SQL injection en search" }))

      expect(yield* findingsFor(SESSION_ID)).toHaveLength(2)
    }),
  )

  it.effect("un hallazgo sin CWE conserva el comportamiento histórico (identidad por título)", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const base = { kind: "finding", target: "https://example.com/item", vector: "id", severity: "high" }
      yield* ingestToolPart(db, completedMemorySave({ ...base, title: "Open port 22" }))
      yield* ingestToolPart(db, completedMemorySave({ ...base, title: "Puerto 22 abierto" }))

      // Sin taxonomía la prosa sigue siendo la única señal: son dos filas.
      expect(yield* findingsFor(SESSION_ID)).toHaveLength(2)

      // El mismo título sí es el mismo hallazgo (fingerprint v1).
      yield* ingestToolPart(db, completedMemorySave({ ...base, title: "Open port 22", severity: "critical" }))
      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(2)
      expect(rows.find((row) => row.title === "Open port 22")).toMatchObject({ severity: "critical" })
    }),
  )

  it.effect("reingerir un hallazgo histórico (fingerprint v1) actualiza la fila en vez de duplicarla", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const legacy = {
        kind: "finding",
        title: "SQL Injection",
        severity: "high",
        target: "https://example.com/item",
        cwe: "CWE-89",
        vector: "id",
      }
      yield* db
        .insert(FindingTable)
        .values({
          id: "finding_legacy_row",
          session_id: SESSION_ID,
          project_id: Project.ID.global,
          fingerprint: legacyFindingFingerprint(legacy),
          title: "SQL Injection",
          severity: "high",
          status: "open",
          source: "web.scan",
          source_tool: "nuclei",
          target: "https://example.com/item",
          cwe: "CWE-89",
          vector: "id",
          evidence: {},
          tags: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      // Misma taxonomía, otra prosa y otra herramienta: la fila vieja se
      // actualiza, no se crea una segunda (el panel contaría dos bugs).
      yield* ingestToolPart(
        db,
        completedMemorySave({
          kind: "finding",
          title: "SQL Injection Confirmada (sqlmap)",
          severity: "critical",
          source_tool: "sqlmap",
          target: "https://example.com/item",
          cwe: "CWE-89",
          vector: "id",
        }),
      )

      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({ id: "finding_legacy_row", severity: "critical", source: "agent-reviewed" })
    }),
  )

  it.effect("truncates oversized fields instead of failing", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      yield* ingestToolPart(
        db,
        completedMemorySave({
          kind: "finding",
          title: "T".repeat(600),
          severity: "high",
          evidence: "E".repeat(33_000),
          tags: Array.from({ length: 40 }, (_, i) => `tag-${i}`),
        }),
      )
      const rows = yield* findingsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      const [row] = rows
      expect(row.title.length).toBe(512)
      expect((row.evidence.text as string).length).toBe(32_000)
      expect(row.tags).toHaveLength(32)
    }),
  )

  it.effect("publishes FindingUpserted when an events service is provided", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const eventsService = yield* EventV2.Service
      const fiber = yield* eventsService
        .subscribe(FindingUpserted)
        .pipe(Stream.take(1), Stream.runCollect, Effect.forkScoped)
      yield* Effect.yieldNow

      yield* ingestToolPart(db, completedMemorySave({ kind: "finding", title: "Published finding", severity: "high" }), {
        events: eventsService,
      })

      const collected = yield* Fiber.join(fiber)
      const [published] = collected
      expect(published).toBeDefined()
      expect(published?.data.sessionID).toBe(SESSION_ID)
    }),
  )
})
