import { afterAll, describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Compliance } from "@argos/core/compliance"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { FindingTable } from "@argos/core/security/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

// ── Fixtures (recortes fieles de las fuentes públicas reales) ─────────────────

const NIST_FIXTURE = {
  catalog: {
    metadata: { title: "NIST CSF 2.0", version: "1.2.0" },
    groups: [
      {
        id: "PR",
        class: "function",
        title: "PROTECT",
        controls: [
          {
            id: "PR.DS",
            class: "category",
            title: "Data Security",
            controls: [
              {
                id: "PR.DS-02",
                class: "subcategory",
                title: "PR.DS-02",
                parts: [
                  {
                    id: "PR.DS-02_statement",
                    name: "statement",
                    prose: "The confidentiality, integrity, and availability of data-in-transit are protected",
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        id: "DE",
        class: "function",
        title: "DETECT",
        controls: [
          {
            id: "DE.CM",
            class: "category",
            title: "Continuous Monitoring",
            controls: [
              {
                id: "DE.CM-01",
                class: "subcategory",
                title: "DE.CM-01",
                parts: [
                  {
                    id: "DE.CM-01_statement",
                    name: "statement",
                    prose: "Networks and network services are monitored to find potentially adverse events",
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },
}

const CROSSWALK_FIXTURE = {
  meta: { title: "ISO 27001:2022 <-> NIST CSF 2.0 crosswalk" },
  controls: [
    { iso_id: "A.8.24", iso_name: "Use of cryptography", iso_theme: "Technological", nist_csf: ["PR.DS-02"], nis2: [], dora: [], soc2: [] },
    { iso_id: "A.5.1", iso_name: "Policies for information security", iso_theme: "Organizational", nist_csf: ["GV.PO-01"], nis2: [], dora: [], soc2: [] },
  ],
}

const CHECKS_NIST_FIXTURE = {
  controls: [{ control: "NIST.PR.DS", title: "Protect — Data Security", checks: ["HSTS", "CAA record"] }],
}

const CHECKS_ISO_FIXTURE = {
  controls: [{ control: "ISO27001 A.8.24", checks: ["HSTS", "CAA record"] }],
}

// ── Service con BD en memoria y fuentes mockeadas ────────────────────────────

const database = Database.layerFromPath(":memory:")
const compliance = Compliance.defaultLayer.pipe(Layer.provideMerge(database))
const it = testEffect(compliance)

const jsonResponse = (value: unknown) => new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } })

const originalFetch = globalThis.fetch

afterAll(() => {
  globalThis.fetch = originalFetch
})

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
      id: SessionV2.ID.make("ses_ccm"),
      project_id: Project.ID.global,
      slug: "ccm",
      directory: "/project",
      title: "ccm",
      version: "test",
      agent: "analyst",
    })
    .run()
    .pipe(Effect.orDie)
})

const insertFinding = (id: string, title: string, severity: string, tool: string, cwe?: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    yield* db
      .insert(FindingTable)
      .values({
        id,
        session_id: SessionV2.ID.make("ses_ccm"),
        project_id: Project.ID.global,
        fingerprint: id,
        title,
        severity,
        status: "open",
        source: "agent-reviewed",
        source_tool: tool,
        agent: "analyst",
        target: "https://example.com",
        cwe: cwe ?? null,
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
  })

const setOnlineFetch = () => {
  globalThis.fetch = (async (input: unknown) => {
    const url = input instanceof Request ? input.url : String(input)
    if (url.includes("NIST_CSF_v2.0_catalog")) return jsonResponse(NIST_FIXTURE)
    if (url.includes("crosswalk")) return jsonResponse(CROSSWALK_FIXTURE)
    if (url.includes("nist-csf-v2-mapping")) return jsonResponse(CHECKS_NIST_FIXTURE)
    if (url.includes("iso27001-mapping")) return jsonResponse(CHECKS_ISO_FIXTURE)
    return new Response("not found", { status: 404 })
  }) as typeof fetch
}

describe("Compliance CCM (continuous compliance monitoring)", () => {
  it.effect("detecta drift cuando el estado de un control cambia entre recomputes", () =>
    Effect.gen(function* () {
      setOnlineFetch()
      try {
        yield* seed
        const service = yield* Compliance.Service
        yield* service.refresh()
        const { db } = yield* Database.Service

        // Primer recompute: sin findings → todos compliant (estado inicial, sin drift).
        yield* service.recomputeProject(Project.ID.global)
        let drift = yield* service.getDriftEvents({ projectID: Project.ID.global })
        expect(drift).toEqual([])

        // Finding crítico → PR.DS-02 pasa a deficient: un evento de drift por control.
        yield* insertFinding("ccm_f1", "Missing HSTS header", "high", "web.scan", "CWE-319")
        yield* service.recomputeProject(Project.ID.global)
        drift = yield* service.getDriftEvents({ projectID: Project.ID.global })
        const prds = drift.filter((event) => event.controlId === "PR.DS-02")
        expect(prds.length).toBe(1)
        expect(prds[0]?.statusFrom).toBe("compliant")
        expect(prds[0]?.statusTo).toBe("deficient")
        expect(prds[0]?.framework).toBe("nist_csf_v2")

        // Recompute sin cambios de findings → no genera eventos nuevos.
        yield* service.recomputeProject(Project.ID.global)
        drift = yield* service.getDriftEvents({ projectID: Project.ID.global })
        expect(drift.filter((event) => event.controlId === "PR.DS-02").length).toBe(1)

        // Cierre del finding → el control vuelve a compliant: segundo drift.
        yield* db
          .update(FindingTable)
          .set({ status: "fixed", time_updated: Date.now() })
          .where(eq(FindingTable.id, "ccm_f1"))
          .run()
          .pipe(Effect.orDie)
        yield* service.recomputeProject(Project.ID.global)
        drift = yield* service.getDriftEvents({ projectID: Project.ID.global })
        const prdsFixed = drift.filter((event) => event.controlId === "PR.DS-02")
        expect(prdsFixed.length).toBe(2)
        // getDriftEvents devuelve DESC (más reciente primero). Al cerrar el
        // finding, el hallazgo sigue presente (sin crítico/alto abierto) → el
        // control pasa de deficient a partial.
        expect(prdsFixed[0]?.statusFrom).toBe("deficient")
        expect(prdsFixed[0]?.statusTo).toBe("partial")

        // Historial del control: orden cronológico ascendente.
        const history = yield* service.getHistory(Project.ID.global, "nist_csf_v2", "PR.DS-02")
        expect(history.length).toBe(2)
        expect(history[0]?.statusTo).toBe("deficient")
        expect(history[1]?.statusTo).toBe("partial")
        expect(history[0]!.timeRecorded <= history[1]!.timeRecorded).toBe(true)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )

  it.effect("getGlobalSummary agrega el estado por framework y calcula el score", () =>
    Effect.gen(function* () {
      setOnlineFetch()
      try {
        yield* seed
        const service = yield* Compliance.Service
        yield* service.refresh()
        yield* insertFinding("ccm_f2", "Missing HSTS header", "high", "web.scan", "CWE-319")
        yield* service.recomputeProject(Project.ID.global)

        const summary = yield* service.getGlobalSummary()
        expect(summary.projectCount).toBe(1)
        const nist = summary.frameworks.find((framework) => framework.framework === "nist_csf_v2")
        expect(nist).toBeDefined()
        // totalControls cuenta SOLO hojas (subcategorías NIST / controles ISO):
        // el catálogo tiene 2 subcategorías NIST (PR.DS-02, DE.CM-01).
        expect(nist!.totalControls).toBe(2)
        expect(nist!.counts.deficient).toBe(1)
        expect(nist!.counts.compliant).toBe(1)
        // Score = % de controles compliant sobre evaluados (sin deficiencias).
        expect(nist!.score).toBeGreaterThanOrEqual(0)
        expect(nist!.score).toBeLessThanOrEqual(100)
        const iso = summary.frameworks.find((framework) => framework.framework === "iso27001_2022")
        expect(iso).toBeDefined()
        // 2 controles ISO hoja en el fixture (A.8.24 y A.5.1); solo A.8.24 es
        // deficient (match HSTS/crypto).
        expect(iso!.totalControls).toBe(2)
        expect(iso!.counts.deficient).toBe(1)
        expect(iso!.counts.compliant).toBe(1)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )

  it.effect("sweepAll re-deriva todos los proyectos con hallazgos sin bloquear", () =>
    Effect.gen(function* () {
      setOnlineFetch()
      try {
        yield* seed
        const service = yield* Compliance.Service
        yield* service.refresh()
        yield* insertFinding("ccm_f3", "Weak cipher", "high", "web.scan", "CWE-326")
        yield* service.recomputeProject(Project.ID.global)

        yield* service.sweepAll()
        const summary = yield* service.getGlobalSummary()
        expect(summary.projectCount).toBe(1)
        const nist = summary.frameworks.find((framework) => framework.framework === "nist_csf_v2")
        expect(nist!.counts.deficient).toBeGreaterThan(0)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )
})
