import { describe, expect, test } from "bun:test"
import { Effect, Layer } from "effect"
import { eq } from "drizzle-orm"
import { Compliance, ComplianceCatalogTable } from "@argos/core/compliance"
import { deriveProjectStatuses } from "@argos/core/compliance/derive"
import type { ComplianceCatalogRow } from "@argos/core/compliance/sql"
import type { FindingLike } from "@argos/core/compliance/types"
import type { SessionComplianceNode } from "@argos/core/compliance/types"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { FindingTable } from "@argos/core/security/sql"
import { recordFeedback } from "@argos/core/security/finding-feedback"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { testEffect } from "./lib/effect"

// ── Catálogo mínimo: una función NIST con dos subcategorías y un tema ISO ────

const CATALOG: ComplianceCatalogRow[] = [
  {
    framework: "nist_csf_v2",
    control_id: "PR",
    title: "PROTECT",
    parent_id: null,
    level: "function",
    sort_id: "00003",
    attributes: {},
    source: "test",
    time_updated: 0,
  },
  {
    framework: "nist_csf_v2",
    control_id: "PR.PS",
    title: "Platform Security",
    parent_id: "PR",
    level: "category",
    sort_id: "00003.00001",
    attributes: {},
    source: "test",
    time_updated: 0,
  },
  {
    framework: "nist_csf_v2",
    control_id: "PR.PS-06",
    title: "Software is free from known vulnerabilities",
    parent_id: "PR.PS",
    level: "subcategory",
    sort_id: "00003.00001.00002",
    attributes: {},
    source: "test",
    time_updated: 0,
  },
  {
    framework: "nist_csf_v2",
    control_id: "PR.PS-04",
    title: "Software is maintained and replaced",
    parent_id: "PR.PS",
    level: "subcategory",
    sort_id: "00003.00001.00001",
    attributes: {},
    source: "test",
    time_updated: 0,
  },
  {
    framework: "nist_csf_v2",
    control_id: "PR.PS-01",
    title: "Control of the hardware used",
    parent_id: "PR.PS",
    level: "subcategory",
    sort_id: "00003.00001.00001",
    attributes: {},
    source: "test",
    time_updated: 0,
  },
  {
    framework: "nist_csf_v2",
    control_id: "PR.DS-02",
    title: "Data in transit is protected",
    parent_id: "PR",
    level: "subcategory",
    sort_id: "00003.00003.00002",
    // Check externo de cabecera: un hallazgo que nombre "HSTS" en el título es
    // evidencia directa de que el escáner verificó la cabecera.
    attributes: { checks: ["HSTS"] },
    source: "test",
    time_updated: 0,
  },
  {
    framework: "iso27001_2022",
    control_id: "A.8",
    title: "Technological controls",
    parent_id: null,
    level: "theme",
    sort_id: null,
    attributes: {},
    source: "test",
    time_updated: 0,
  },
  {
    framework: "iso27001_2022",
    control_id: "A.8.28",
    title: "Secure coding",
    parent_id: "A.8",
    level: "control",
    sort_id: null,
    attributes: {},
    source: "test",
    time_updated: 0,
  },
]

// ── Hallazgos: uno por nivel de la escalera de confianza ──────────────────────

const CWE_EXACT: FindingLike = {
  id: "f-cwe",
  title: "SQL injection in /login",
  tags: [],
  severity: "high",
  status: "open",
  sourceTool: "web.scan",
  cwe: "CWE-89",
  confidence: "confirmed",
}

const CWE_ONLY: FindingLike = {
  id: "f-cwe-only",
  title: "Command injection in /admin",
  tags: [],
  severity: "medium",
  status: "open",
  sourceTool: "argos_memory_save",
  cwe: "CWE-78",
}

const TAG_EXACT: FindingLike = {
  id: "f-tag",
  title: "Reflected XSS in search",
  tags: ["xss"],
  severity: "medium",
  status: "open",
  sourceTool: "argos_memory_save",
}

const HEURISTIC: FindingLike = {
  id: "f-technique",
  title: "Log tampering detected",
  tags: [],
  severity: "low",
  status: "open",
  sourceTool: "code.review",
  attackTechniques: ["T1070"],
}

const HEADER_CHECK: FindingLike = {
  id: "f-hsts",
  title: "Missing HSTS header on example.com",
  tags: [],
  severity: "high",
  status: "open",
  sourceTool: "web.scan",
}

const derive = (findings: FindingLike[]) => deriveProjectStatuses({ projectID: "p", findings, catalog: CATALOG })
const rowOf = (rows: ReturnType<typeof derive>, framework: string, controlId: string) =>
  rows.find((row) => row.framework === framework && row.controlId === controlId)

// ── Evidencia auditable ──────────────────────────────────────────────────────

describe("deriveProjectStatuses — evidencia auditable (ARG-042)", () => {
  test("un control deficient lleva el finding que lo activa y la regla que lo derivó", () => {
    const rows = derive([CWE_EXACT])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-06")
    expect(control?.status).toBe("deficient")

    const evidence = control?.evidence ?? []
    expect(evidence.length).toBe(1)
    expect(evidence[0]?.findingID).toBe("f-cwe")
    expect(evidence[0]?.title).toBe("SQL injection in /login")
    expect(evidence[0]?.severity).toBe("high")
    expect(evidence[0]?.cwe).toBe("CWE-89")
    // La regla queda a la vista: el auditor sabe qué derivó el control.
    expect(evidence[0]?.derivedFrom).toBe("cwe:web-vuln")

    const derivation = control?.derivation ?? []
    expect(derivation.length).toBe(1)
    expect(derivation[0]?.derivedFrom).toBe("cwe:web-vuln")
    expect(derivation[0]?.findings.map((finding) => finding.id)).toEqual(["f-cwe"])
    expect(derivation[0]?.findings[0]?.cwe).toBe("CWE-89")
    expect(derivation[0]?.findings[0]?.sourceTool).toBe("web.scan")
    // La confianza del hallazgo viaja aparte de la de la derivación.
    expect(derivation[0]?.findings[0]?.confidence).toBe("confirmed")
  })

  test("la confianza es high con CWE exacto corroborado por la herramienta de la regla", () => {
    const rows = derive([CWE_EXACT])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-06")
    expect(control?.evidence[0]?.confidence).toBe("high")
    expect(control?.derivation[0]?.confidence).toBe("high")
    expect(control?.confidence).toBe("high")
  })

  test("la confianza es medium con CWE exacto sin herramienta corroborante", () => {
    const rows = derive([CWE_ONLY])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-06")
    expect(control?.evidence[0]?.derivedFrom).toBe("cwe:web-vuln")
    expect(control?.evidence[0]?.confidence).toBe("medium")
    expect(control?.confidence).toBe("medium")
  })

  test("la confianza es medium con tag exacto de la regla", () => {
    const rows = derive([TAG_EXACT])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-06")
    expect(control?.evidence[0]?.derivedFrom).toBe("vuln:web-app")
    expect(control?.evidence[0]?.confidence).toBe("medium")
    expect(control?.confidence).toBe("medium")
  })

  test("la confianza es low con match heurístico (técnica ATT&CK)", () => {
    const rows = derive([HEURISTIC])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-04")
    expect(control?.status).toBe("partial")
    expect(control?.evidence[0]?.derivedFrom).toBe("logging-monitoring")
    expect(control?.evidence[0]?.confidence).toBe("low")
    expect(control?.confidence).toBe("low")
  })

  test("un control sin findings tiene evidencia vacía y confianza high", () => {
    const rows = derive([CWE_EXACT])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-01")
    expect(control?.status).toBe("compliant")
    expect(control?.evidence).toEqual([])
    expect(control?.derivation).toEqual([])
    expect(control?.confidence).toBe("high")
  })

  test("un control con dos findings de distinta confianza expone ambas entradas", () => {
    const rows = derive([CWE_EXACT, TAG_EXACT])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-06")
    expect(control?.evidence.length).toBe(2)
    expect(control?.evidence.map((entry) => entry.findingID).sort()).toEqual(["f-cwe", "f-tag"])
    expect(control?.evidence.map((entry) => entry.confidence).sort()).toEqual(["high", "medium"])
    // La confianza agregada es la mayor: un finding fuerte no se degrada porque
    // el otro match fue heurístico.
    expect(control?.confidence).toBe("high")
    // Cada regla queda registrada por separado en la evidencia auditable.
    expect(control?.derivation.map((entry) => entry.derivedFrom).sort()).toEqual([
      "cwe:web-vuln",
      "vuln:web-app",
    ])
  })

  test("un check externo de cabecera verificado es una derivación de confianza alta", () => {
    const rows = derive([HEADER_CHECK])
    const control = rowOf(rows, "nist_csf_v2", "PR.DS-02")
    expect(control?.status).toBe("deficient")
    expect(control?.evidence[0]?.derivedFrom).toBe("check:hsts")
    expect(control?.evidence[0]?.confidence).toBe("high")
    expect(control?.confidence).toBe("high")
  })

  test("los padres heredan la evidencia de sus hijos y su confianza agregada", () => {
    const rows = derive([CWE_EXACT, HEURISTIC])
    const category = rowOf(rows, "nist_csf_v2", "PR.PS")
    expect(category?.status).toBe("deficient")
    expect(category?.evidence.length).toBe(2)
    expect(category?.confidence).toBe("high")
    expect(category?.derivation.length).toBe(2)
  })

  test("la evidencia sobrevive a la serialización (el panel la recibe tal cual)", () => {
    const rows = derive([CWE_EXACT, TAG_EXACT, HEURISTIC])
    const control = rowOf(rows, "nist_csf_v2", "PR.PS-06")
    const roundtrip = JSON.parse(JSON.stringify(control))
    expect(roundtrip.evidence).toEqual(control?.evidence)
    expect(roundtrip.derivation).toEqual(control?.derivation)
    expect(roundtrip.confidence).toBe(control?.confidence)
    expect(roundtrip.evidence[0]?.derivedFrom).toBe("cwe:web-vuln")
    expect(roundtrip.derivation[0]?.derivedFrom).toBe("cwe:web-vuln")
  })
})

// ── Persistencia: la evidencia sobrevive al roundtrip por la BD ──────────────

const database = Database.layerFromPath(":memory:")
const compliance = Compliance.defaultLayer.pipe(Layer.provideMerge(database))
const it = testEffect(compliance)
const flattenSessionTree = (node: SessionComplianceNode): SessionComplianceNode[] => [
  node,
  ...node.children.flatMap(flattenSessionTree),
]

describe("Compliance service — persistencia de la evidencia", () => {
  it.effect("getStatus devuelve la evidencia y la confianza persistidas", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* db
        .insert(ProjectTable)
        .values({ id: Project.ID.global, worktree: "/project", sandboxes: [] })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(SessionTable)
        .values({
          id: SessionV2.ID.make("ses_evidence"),
          project_id: Project.ID.global,
          slug: "evidence",
          directory: "/project",
          title: "evidence",
          version: "test",
          agent: "analyst",
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(ComplianceCatalogTable)
        .values(
          CATALOG.map((row) => ({
            framework: row.framework,
            control_id: row.control_id,
            title: row.title,
            parent_id: row.parent_id,
            level: row.level,
            sort_id: row.sort_id,
            attributes: row.attributes,
            source: row.source,
            time_updated: row.time_updated,
          })),
        )
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(FindingTable)
        .values({
          id: "finding_evidence_1",
          session_id: "ses_evidence",
          project_id: Project.ID.global,
          fingerprint: "fp-evidence-1",
          title: "SQL injection in /login",
          severity: "high",
          status: "open",
          source: "agent-reviewed",
          source_tool: "web.scan",
          agent: "analyst",
          target: "https://example.com",
          cwe: "CWE-89",
          vector: "https://example.com",
          evidence: {},
          remediation: null,
          tags: [],
          raw: null,
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      const service = yield* Compliance.Service
      yield* service.recomputeProject(Project.ID.global)

      const rows = yield* service.getStatus(Project.ID.global)
      const control = rows.find((row) => row.controlId === "PR.PS-06")
      expect(control?.status).toBe("deficient")
      expect(control?.evidence[0]?.derivedFrom).toBe("cwe:web-vuln")
      expect(control?.evidence[0]?.cwe).toBe("CWE-89")
      expect(control?.derivation[0]?.derivedFrom).toBe("cwe:web-vuln")
      expect(control?.derivation[0]?.findings[0]?.id).toBe("finding_evidence_1")
      expect(control?.confidence).toBe("high")

      // Un control sin hallazgos queda con confianza high y sin evidencia.
      const empty = rows.find((row) => row.controlId === "PR.PS-01")
      expect(empty?.evidence).toEqual([])
      expect(empty?.derivation).toEqual([])
      expect(empty?.confidence).toBe("high")

      // La fila persistida conserva la evidencia (columna JSON).
      const stored = yield* db
        .select()
        .from(ComplianceCatalogTable)
        .where(eq(ComplianceCatalogTable.control_id, "PR.PS-06"))
        .all()
        .pipe(Effect.orDie)
      expect(stored.length).toBe(1)

      yield* recordFeedback(db, {
        sessionID: "ses_evidence",
        findingID: "finding_evidence_1",
        verdict: "false-positive",
        reason: "Revisado y no reproducible dentro del alcance.",
      })
      yield* service.recomputeProject(Project.ID.global)
      const projectAfterTriage = yield* service.getStatus(Project.ID.global)
      const projectControlAfterTriage = projectAfterTriage.find((row) => row.controlId === "PR.PS-06")
      expect(projectControlAfterTriage?.evidence.some((item) => item.findingID === "finding_evidence_1")).toBe(false)

      const sessionAfterTriage = yield* service.getSessionStatus("ses_evidence")
      const sessionControlAfterTriage = sessionAfterTriage.frameworks
        .find((framework) => framework.framework === "nist_csf_v2")
        ?.tree.children.flatMap(flattenSessionTree)
        .find((control) => control.id === "PR.PS-06")
      expect(sessionControlAfterTriage?.evidence.some((item) => item.findingID === "finding_evidence_1")).toBe(false)
    }),
  )

  it.effect("getGlobalSummary agrega la confianza del framework (la más débil)", () =>
    Effect.gen(function* () {
      const service = yield* Compliance.Service
      yield* service.recomputeProject(Project.ID.global)
      const summary = yield* service.getGlobalSummary()
      const nist = summary.frameworks.find((framework) => framework.framework === "nist_csf_v2")
      expect(nist?.confidence).toBe("high")
      // Un framework sin ningún hallazgo mapeado tampoco degrada la confianza.
      const dora = summary.frameworks.find((framework) => framework.framework === "dora")
      expect(dora?.confidence).toBe("high")
    }),
  )
})
