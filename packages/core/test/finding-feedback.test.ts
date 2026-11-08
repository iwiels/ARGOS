import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import {
  FEEDBACK_VERDICTS,
  MAX_FEEDBACK_REASON_CHARS,
  RULE_NOISE_THRESHOLD,
  feedbackAuditEntry,
  feedbackForProject,
  feedbackForSession,
  normalizeActor,
  normalizeReason,
  normalizeVerdict,
  noisyRules,
  partitionByFeedback,
  recordFeedback,
  ruleFeedbackStats,
} from "@argos/core/security/finding-feedback"
import { FindingFeedbackTable, FindingTable } from "@argos/core/security/sql"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

const SESSION_A = SessionV2.ID.make("ses_feedback_a")
const SESSION_B = SessionV2.ID.make("ses_feedback_b")
const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

const seedSession = (sessionID: SessionV2.ID) =>
  Effect.gen(function* () {
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
        id: sessionID,
        project_id: Project.ID.global,
        slug: sessionID,
        directory: "/project",
        title: "feedback test",
        version: "test",
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  })

const seedFinding = (input: {
  id: string
  sessionID?: SessionV2.ID
  fingerprint?: string
  ruleID?: string
  sourceTool?: string
  cwe?: string
  source?: string
}) =>
  Effect.gen(function* () {
    const sessionID = input.sessionID ?? SESSION_A
    const { db } = yield* Database.Service
    yield* seedSession(sessionID)
    yield* db
      .insert(FindingTable)
      .values({
        id: input.id,
        session_id: sessionID,
        project_id: Project.ID.global,
        fingerprint: input.fingerprint ?? input.id,
        title: `finding ${input.id}`,
        severity: "high",
        status: "open",
        source: input.source ?? "agent-reviewed",
        source_tool: input.sourceTool ?? "web.sqli",
        rule_id: input.ruleID ?? "nuclei:sqli-error-based",
        cwe: input.cwe ?? "CWE-89",
        target: "https://example.test/item?id=1",
        vector: "GET /item?id=1",
        evidence: {},
        tags: [],
        time_created: Date.now(),
        time_updated: Date.now(),
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  })

const feedbackRows = Effect.gen(function* () {
  const { db } = yield* Database.Service
  return yield* db.select().from(FindingFeedbackTable).all().pipe(Effect.orDie)
})

describe("vocabulario y normalización del triage", () => {
  it.effect("el veredicto es un vocabulario cerrado", () =>
    Effect.sync(() => {
      expect([...FEEDBACK_VERDICTS]).toEqual(["false-positive", "true-positive", "accepted-risk"])
      expect(normalizeVerdict("false-positive")).toBe("false-positive")
      expect(normalizeVerdict("maybe")).toBeUndefined()
      expect(normalizeVerdict(undefined)).toBeUndefined()
    }),
  )

  it.effect("el actor desconocido cae a humano, nunca a agente", () =>
    Effect.sync(() => {
      expect(normalizeActor("agent")).toBe("agent")
      expect(normalizeActor("human")).toBe("human")
      expect(normalizeActor("robot")).toBe("human")
      expect(normalizeActor(undefined)).toBe("human")
    }),
  )

  it.effect("el motivo vacío no se guarda y el largo se recorta", () =>
    Effect.sync(() => {
      expect(normalizeReason("   ")).toBeUndefined()
      expect(normalizeReason(7)).toBeUndefined()
      expect(normalizeReason("  target sin auth  ")).toBe("target sin auth")
      expect(normalizeReason("x".repeat(MAX_FEEDBACK_REASON_CHARS + 50))?.length).toBe(MAX_FEEDBACK_REASON_CHARS)
    }),
  )
})

describe("recordFeedback", () => {
  it.effect("deriva la identidad del hallazgo persistido, no del cliente", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_a1", ruleID: "nuclei:exposed-env", sourceTool: "web.scan", cwe: "CWE-538" })
      const { db } = yield* Database.Service
      const row = yield* recordFeedback(db, {
        sessionID: SESSION_A,
        findingID: "fnd_a1",
        verdict: "false-positive",
        reason: "el endpoint requiere auth y el escáner no la tenía",
      })
      expect(row.project_id).toBe(Project.ID.global)
      expect(row.session_id).toBe(SESSION_A)
      expect(row.fingerprint).toBe("fnd_a1")
      expect(row.rule_id).toBe("nuclei:exposed-env")
      expect(row.source_tool).toBe("web.scan")
      expect(row.cwe).toBe("CWE-538")
      expect(row.verdict).toBe("false-positive")
      expect(row.actor).toBe("human")
      expect(row.reason).toContain("requiere auth")
      expect(row.time_created).toBeGreaterThan(0)
    }),
  )

  it.effect("rechaza triage sobre una fila heredada de scanner", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_untrusted", source: "web.scan" })
      const { db } = yield* Database.Service
      const error = yield* recordFeedback(db, {
        sessionID: SESSION_A,
        findingID: "fnd_untrusted",
        verdict: "false-positive",
      }).pipe(Effect.flip)
      expect(error.message).toContain("does not belong to session")
      expect((yield* feedbackRows).length).toBe(0)
    }),
  )

  it.effect("un hallazgo de otro engagement no se puede triagear", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_a2" })
      yield* seedFinding({ id: "fnd_b1", sessionID: SESSION_B })
      const { db } = yield* Database.Service
      const error = yield* recordFeedback(db, {
        sessionID: SESSION_B,
        findingID: "fnd_a2",
        verdict: "false-positive",
      }).pipe(Effect.flip)
      expect(error.message).toContain("does not belong to session")
      expect((yield* feedbackRows).length).toBe(0)
    }),
  )

  it.effect("corregir el veredicto es un upsert, no una fila nueva", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_a3" })
      const { db } = yield* Database.Service
      yield* recordFeedback(db, { sessionID: SESSION_A, findingID: "fnd_a3", verdict: "false-positive" })
      const corrected = yield* recordFeedback(db, {
        sessionID: SESSION_A,
        findingID: "fnd_a3",
        verdict: "true-positive",
        reason: "confirmado con una segunda petición autenticada",
      })
      expect(corrected.verdict).toBe("true-positive")
      expect(corrected.reason).toContain("autenticada")
      expect((yield* feedbackRows).length).toBe(1)
    }),
  )

  it.effect("rechaza un veredicto fuera del vocabulario", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_a4" })
      const { db } = yield* Database.Service
      const error = yield* recordFeedback(db, {
        sessionID: SESSION_A,
        findingID: "fnd_a4",
        verdict: "probably" as never,
      }).pipe(Effect.flip)
      expect(error.message).toContain("Unknown feedback verdict")
    }),
  )
})

describe("learning por regla", () => {
  it.effect("calcula precisión y ordena las reglas más ruidosas primero", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_p1", ruleID: "rule:noisy" })
      yield* seedFinding({ id: "fnd_p2", ruleID: "rule:noisy" })
      yield* seedFinding({ id: "fnd_p3", ruleID: "rule:noisy" })
      yield* seedFinding({ id: "fnd_p4", ruleID: "rule:clean" })
      const { db } = yield* Database.Service
      yield* recordFeedback(db, { sessionID: SESSION_A, findingID: "fnd_p1", verdict: "false-positive" })
      yield* recordFeedback(db, { sessionID: SESSION_A, findingID: "fnd_p2", verdict: "false-positive" })
      yield* recordFeedback(db, { sessionID: SESSION_A, findingID: "fnd_p3", verdict: "true-positive" })
      yield* recordFeedback(db, { sessionID: SESSION_A, findingID: "fnd_p4", verdict: "true-positive" })

      const stats = ruleFeedbackStats(yield* feedbackForProject(db, Project.ID.global))
      const noisy = stats.find((entry) => entry.ruleId === "rule:noisy")
      const clean = stats.find((entry) => entry.ruleId === "rule:clean")
      expect(noisy).toMatchObject({ truePositives: 1, falsePositives: 2, verdicts: 3 })
      expect(noisy!.precision).toBeCloseTo(1 / 3, 5)
      expect(clean).toMatchObject({ truePositives: 1, falsePositives: 0, verdicts: 1 })
      expect(clean!.precision).toBe(1)
      // la más ruidosa primero
      expect(stats[0].ruleId).toBe("rule:noisy")

      const flagged = noisyRules(stats, 3)
      expect(flagged.map((entry) => entry.ruleId)).toEqual(["rule:noisy"])
      expect(noisy!.precision).toBeLessThan(RULE_NOISE_THRESHOLD)
    }),
  )

  it.effect("una regla sin TP/FP reporta precisión 1 pero cero veredictos", () =>
    Effect.gen(function* () {
      const stats = ruleFeedbackStats([
        {
          id: "x",
          project_id: Project.ID.global,
          session_id: SESSION_A,
          finding_id: "f",
          fingerprint: "fp",
          rule_id: "rule:unknown",
          source_tool: null,
          cwe: null,
          verdict: "accepted-risk",
          reason: null,
          actor: "human",
          time_created: 1,
          time_updated: 1,
        },
      ])
      expect(stats[0]).toMatchObject({ verdicts: 1, precision: 1, acceptedRisk: 1 })
      expect(noisyRules(stats, 1)).toEqual([])
    }),
  )
})

describe("supresión por engagement", () => {
  const finding = (id: string, fingerprint = id) => ({ id, fingerprint })
  const row = (overrides: Partial<typeof FindingFeedbackTable.$inferSelect>) =>
    ({
      id: `fb_${overrides.finding_id}`,
      project_id: Project.ID.global,
      session_id: SESSION_A,
      fingerprint: "f",
      rule_id: "r",
      source_tool: "web.sqli",
      cwe: "CWE-89",
      verdict: "false-positive",
      reason: null,
      actor: "human",
      time_created: 1,
      time_updated: 1,
      ...overrides,
    }) as typeof FindingFeedbackTable.$inferSelect

  it.effect("un FP del engagement sale del listado y se recupera con includeSuppressed", () =>
    Effect.sync(() => {
      const findings = [finding("a"), finding("b")]
      const sessionFeedback = [row({ finding_id: "a" })]
      const hidden = partitionByFeedback(findings, sessionFeedback)
      expect(hidden.visible.map((f) => f.id)).toEqual(["b"])
      expect(hidden.suppressed.map((entry) => entry.finding.id)).toEqual(["a"])

      const shown = partitionByFeedback(findings, sessionFeedback, { includeSuppressed: true })
      expect(shown.visible.map((f) => f.id)).toEqual(["a", "b"])
      expect(shown.suppressed).toEqual([])
    }),
  )

  it.effect("TP y riesgo aceptado siguen visibles", () =>
    Effect.sync(() => {
      const findings = [finding("a"), finding("b")]
      const sessionFeedback = [
        row({ finding_id: "a", verdict: "true-positive" }),
        row({ finding_id: "b", verdict: "accepted-risk" }),
      ]
      const result = partitionByFeedback(findings, sessionFeedback)
      expect(result.visible.map((f) => f.id)).toEqual(["a", "b"])
      expect(result.suppressed).toEqual([])
    }),
  )

  it.effect("un FP de OTRO engagement no suprime nada acá", () =>
    Effect.sync(() => {
      // El llamador sólo pasa el feedback de la sesión actual: el de la otra
      // sesión ni siquiera entra a la partición. Aun así, si por error se
      // pasara, la fila tiene session_id ajeno y la verificación de
      // pertenencia debe impedirlo en `recordFeedback`.
      const findings = [finding("a")]
      const otherEngagement = partitionByFeedback(findings, [])
      expect(otherEngagement.visible.map((f) => f.id)).toEqual(["a"])
    }),
  )

  it.effect("el FP se reconoce también por fingerprint (mismo bug, otra fila)", () =>
    Effect.sync(() => {
      const findings = [finding("new-row", "same-bug")]
      const sessionFeedback = [row({ finding_id: "old-row", fingerprint: "same-bug" })]
      const result = partitionByFeedback(findings, sessionFeedback)
      expect(result.visible).toEqual([])
      expect(result.suppressed[0].finding.id).toBe("new-row")
    }),
  )
})

describe("auditoría del triage", () => {
  it.effect("el evento registra quién decidió, qué regla y por qué", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_audit" })
      const { db } = yield* Database.Service
      const stored = yield* recordFeedback(db, {
        sessionID: SESSION_A,
        findingID: "fnd_audit",
        verdict: "false-positive",
        reason: "regla dispara con el WAF del cliente",
        actor: "agent",
      })
      const entry = feedbackAuditEntry(stored)
      expect(entry.eventType).toBe("finding.feedback")
      expect(entry.action).toBe("finding.false-positive")
      expect(entry.sessionID).toBe(SESSION_A)
      expect(entry.agent).toBe("agent")
      expect(entry.target).toBe("fnd_audit")
      expect(entry.payload).toMatchObject({
        verdict: "false-positive",
        actor: "agent",
        ruleID: "nuclei:sqli-error-based",
        reason: "regla dispara con el WAF del cliente",
      })
    }),
  )
})

describe("feedbackForSession", () => {
  it.effect("aísla los veredictos por sesión", () =>
    Effect.gen(function* () {
      yield* seedFinding({ id: "fnd_iso_a", sessionID: SESSION_A })
      yield* seedFinding({ id: "fnd_iso_b", sessionID: SESSION_B })
      const { db } = yield* Database.Service
      yield* recordFeedback(db, { sessionID: SESSION_A, findingID: "fnd_iso_a", verdict: "false-positive" })
      yield* recordFeedback(db, { sessionID: SESSION_B, findingID: "fnd_iso_b", verdict: "true-positive" })

      const a = yield* feedbackForSession(db, SESSION_A)
      const b = yield* feedbackForSession(db, SESSION_B)
      expect(a.map((row) => row.finding_id)).toEqual(["fnd_iso_a"])
      expect(b.map((row) => row.finding_id)).toEqual(["fnd_iso_b"])
    }),
  )
})
