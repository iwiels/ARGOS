import { afterAll, describe, expect, test } from "bun:test"
import { Effect, Layer } from "effect"
import { Compliance, ComplianceCatalogTable, ComplianceStatusTable } from "@argos/core/compliance"
import { deriveProjectStatuses } from "@argos/core/compliance/derive"
import { parseChecks, parseDerivedCatalog, parseIsoCrosswalk, parseNistOscal } from "@argos/core/compliance/parse"
import type { ControlNode } from "@argos/core/compliance/types"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { FindingTable } from "@argos/core/security/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { AbsolutePath } from "@argos/core/schema"
import { eq, inArray, sql } from "drizzle-orm"
import { testEffect } from "./lib/effect"
import bundledSoc2 from "../src/compliance/bundled/soc2.json"
import bundledNis2 from "../src/compliance/bundled/nis2.json"
import bundledDora from "../src/compliance/bundled/dora.json"
import bundledPciDss from "../src/compliance/bundled/pci_dss_v4.json"

// ── Fixtures: recortes fieles de las fuentes públicas reales ──────────────────

const NIST_FIXTURE = {
  catalog: {
    metadata: { title: "NIST CSF 2.0", version: "1.2.0" },
    groups: [
      {
        id: "PR",
        class: "function",
        title: "PROTECT",
        props: [{ name: "sort-id", value: "00003" }],
        controls: [
          {
            id: "PR.DS",
            class: "category",
            title: "Data Security",
            props: [{ name: "sort-id", value: "00003.00003" }],
            controls: [
              {
                id: "PR.DS-02",
                class: "subcategory",
                title: "PR.DS-02",
                props: [{ name: "sort-id", value: "00003.00003.00002" }],
                parts: [
                  {
                    id: "PR.DS-02_statement",
                    name: "statement",
                    prose: "The confidentiality, integrity, and availability of data-in-transit are protected",
                  },
                ],
              },
              {
                id: "PR.DS-11",
                class: "subcategory",
                title: "PR.DS-11",
                parts: [
                  {
                    id: "PR.DS-11_statement",
                    name: "statement",
                    prose: "Backups of data are created, protected, maintained, and tested",
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
        props: [{ name: "sort-id", value: "00004" }],
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
    { iso_id: "A.8.20", iso_name: "Networks security", iso_theme: "Technological", nist_csf: ["PR.IR-01"], nis2: [], dora: [], soc2: [] },
    { iso_id: "A.5.1", iso_name: "Policies for information security", iso_theme: "Organizational", nist_csf: ["GV.PO-01"], nis2: [], dora: [], soc2: [] },
  ],
}

const CHECKS_NIST_FIXTURE = {
  controls: [{ control: "NIST.PR.DS", title: "Protect — Data Security", checks: ["HSTS", "CAA record"] }],
}

const CHECKS_ISO_FIXTURE = {
  controls: [{ control: "ISO27001 A.8.24", checks: ["HSTS", "CAA record"] }],
}

// ── Catálogo tipado para derive (mismo pipeline que el service) ───────────────

function buildCatalog() {
  const nodes: ControlNode[] = [
    ...parseNistOscal(NIST_FIXTURE),
    ...parseIsoCrosswalk(CROSSWALK_FIXTURE).controls,
    // Catálogos derivados (SOC 2 / NIS2 / DORA): snapshots bundled que el
    // runtime carga siempre, sin depender de la red.
    ...parseDerivedCatalog(bundledSoc2, "soc2"),
    ...parseDerivedCatalog(bundledNis2, "nis2"),
    ...parseDerivedCatalog(bundledDora, "dora"),
    // PCI DSS v4.0.1: catálogo propio, también bundled.
    ...parseDerivedCatalog(bundledPciDss, "pci_dss_v4"),
  ]
  const checks = new Map<string, Map<string, string[]>>()
  checks.set("nist_csf_v2", parseChecks(CHECKS_NIST_FIXTURE, "nist_csf_v2"))
  checks.set("iso27001_2022", parseChecks(CHECKS_ISO_FIXTURE, "iso27001_2022"))
  return nodes.map((node) => ({
    framework: node.framework,
    control_id: node.id,
    title: node.title,
    parent_id: node.parentId,
    level: node.level,
    sort_id: node.sortId ?? null,
    attributes: {
      ...node.attributes,
      ...(checks.get(node.framework)?.get(node.id) ? { checks: checks.get(node.framework)!.get(node.id)! } : {}),
    },
    source: node.source,
    time_updated: 0,
  }))
}

// ── Parsers puros ─────────────────────────────────────────────────────────────

describe("compliance parsers", () => {
  test("parseNistOscal mapea funciones, categorías y subcategorías con su texto", () => {
    const nodes = parseNistOscal(NIST_FIXTURE)
    const functions = nodes.filter((node) => node.level === "function")
    const categories = nodes.filter((node) => node.level === "category")
    const subcategories = nodes.filter((node) => node.level === "subcategory")
    expect(functions.map((node) => node.id)).toEqual(["PR", "DE"])
    expect(categories.map((node) => node.id)).toEqual(["PR.DS", "DE.CM"])
    expect(subcategories.map((node) => node.id)).toEqual(["PR.DS-02", "PR.DS-11", "DE.CM-01"])
    expect(subcategories.find((node) => node.id === "PR.DS-02")?.title).toContain("data-in-transit")
    expect(subcategories.every((node) => node.parentId === "PR.DS" || node.parentId === "DE.CM")).toBe(true)
  })

  test("parseIsoCrosswalk mapea temas y controles y genera mappings bidireccionales", () => {
    const { controls, mappings } = parseIsoCrosswalk(CROSSWALK_FIXTURE)
    expect(controls.filter((node) => node.level === "theme").map((node) => node.id)).toEqual(["A.8", "A.5"])
    expect(controls.filter((node) => node.level === "control").map((node) => node.id)).toEqual(["A.8.24", "A.8.20", "A.5.1"])
    expect(controls.find((node) => node.id === "A.8.24")?.parentId).toBe("A.8")
    expect(mappings).toContainEqual({
      sourceFramework: "iso27001_2022",
      sourceControlId: "A.8.24",
      targetFramework: "nist_csf_v2",
      targetControlId: "PR.DS-02",
    })
    expect(mappings).toContainEqual({
      sourceFramework: "nist_csf_v2",
      sourceControlId: "PR.DS-02",
      targetFramework: "iso27001_2022",
      targetControlId: "A.8.24",
    })
  })

  test("parseChecks normaliza prefijos por framework", () => {
    const nist = parseChecks(CHECKS_NIST_FIXTURE, "nist_csf_v2")
    expect(nist.get("PR.DS")).toEqual(["HSTS", "CAA record"])
    const iso = parseChecks(CHECKS_ISO_FIXTURE, "iso27001_2022")
    expect(iso.get("A.8.24")).toEqual(["HSTS", "CAA record"])
  })
})

// ── Derivación de estado (pura) ───────────────────────────────────────────────

const FINDINGS = [
  {
    id: "f1",
    title: "Missing HSTS header on example.com",
    tags: ["tls"],
    severity: "high",
    status: "open",
    sourceTool: "web.scan",
    cwe: "CWE-319",
    vector: "https://example.com",
  },
  {
    id: "f2",
    title: "es.search: login events across indices",
    tags: [],
    severity: "low",
    status: "open",
    sourceTool: "es.search",
  },
  {
    id: "f3",
    title: "Weak cipher suite allowed",
    tags: ["weak-cipher"],
    severity: "medium",
    status: "open",
    sourceTool: "web.scan",
    cwe: "CWE-326",
  },
]

describe("deriveProjectStatuses", () => {
  const catalog = buildCatalog()
  const statusOf = (controlId: string) => deriveProjectStatuses({ projectID: "p", findings: FINDINGS, catalog }).find((row) => row.controlId === controlId)

  test("hallazgo crítico/alto abierto => deficient, propagado a padres", () => {
    expect(statusOf("PR.DS-02")?.status).toBe("deficient")
    expect(statusOf("PR.DS")?.status).toBe("deficient")
    expect(statusOf("PR")?.status).toBe("deficient")
    expect(statusOf("A.8.24")?.status).toBe("deficient")
    expect(statusOf("A.8")?.status).toBe("deficient")
  })

  test("hallazgo bajo de Elasticsearch => partial en controles de logging/monitoring", () => {
    expect(statusOf("DE.CM-01")?.status).toBe("partial")
    const evidence = statusOf("DE.CM-01")?.evidence ?? []
    expect(evidence.some((entry) => entry.fromElasticsearch)).toBe(true)
    expect(evidence.some((entry) => entry.findingID === "f2")).toBe(true)
  })

  test("controles sin hallazgos => compliant", () => {
    expect(statusOf("A.5.1")?.status).toBe("compliant")
    expect(statusOf("PR.DS-11")?.status).toBe("compliant")
    expect(statusOf("DE.CM-01")?.evidence.some((entry) => entry.findingID === "f2")).toBe(true)
  })
})

// ── Evidencia auditable: qué regla derivó el control y con qué confianza ────

describe("deriveProjectStatuses — evidencia auditable", () => {
  const catalog = buildCatalog()
  const statusOf = (controlId: string) => deriveProjectStatuses({ projectID: "p", findings: FINDINGS, catalog }).find((row) => row.controlId === controlId)

  test("un control deficient lleva el finding que lo activa y la regla que lo derivó", () => {
    const control = statusOf("PR.DS-02")
    expect(control?.status).toBe("deficient")
    const evidence = control?.evidence ?? []
    expect(evidence.some((entry) => entry.findingID === "f1")).toBe(true)
    expect(evidence.find((entry) => entry.findingID === "f1")?.derivedFrom).toBe("crypto-tls")
    expect(evidence.find((entry) => entry.findingID === "f1")?.cwe).toBe("CWE-319")
    const derivation = control?.derivation ?? []
    expect(derivation.some((entry) => entry.derivedFrom === "crypto-tls")).toBe(true)
    expect(derivation.find((entry) => entry.derivedFrom === "crypto-tls")?.findings.map((f) => f.id)).toContain("f1")
  })

  test("la confianza de la derivación es la mayor entre las entradas de evidencia", () => {
    // f1 y f3 matchean la regla crypto-tls con CWE exacto corroborado por la
    // herramienta (web.scan) → confianza alta.
    const control = statusOf("PR.DS-02")
    expect(control?.confidence).toBe("high")
    expect(control?.evidence.every((entry) => entry.confidence === "high")).toBe(true)
  })

  test("un control sin hallazgos tiene evidencia vacía y confianza high", () => {
    const control = statusOf("A.5.1")
    expect(control?.status).toBe("compliant")
    expect(control?.evidence).toEqual([])
    expect(control?.derivation).toEqual([])
    expect(control?.confidence).toBe("high")
  })

  test("la evidencia sobrevive a la serialización", () => {
    const control = statusOf("PR.DS-02")
    const roundtrip = JSON.parse(JSON.stringify(control))
    expect(roundtrip.evidence).toEqual(control?.evidence)
    expect(roundtrip.derivation).toEqual(control?.derivation)
    expect(roundtrip.confidence).toBe(control?.confidence)
  })
})

// ── Frameworks derivados (SOC 2 / NIS2 / DORA) ───────────────────────────────

describe("deriveProjectStatuses — frameworks derivados", () => {
  const catalog = buildCatalog()
  const SECRET_FINDING = {
    id: "f-secret",
    title: "API key committed in public repository",
    tags: ["secret-exposure"],
    severity: "high",
    status: "open",
    sourceTool: "web.scan",
  }
  const rows = deriveProjectStatuses({ projectID: "p", findings: [SECRET_FINDING], catalog })
  const statusOf = (framework: string, controlId: string) =>
    rows.find((row) => row.framework === framework && row.controlId === controlId)

  test("un hallazgo de secret-exposure deja deficient el control equivalente de cada framework", () => {
    // SOC 2 — Logical and Physical Access Controls (CC6) y Confidentiality (C1).
    expect(statusOf("soc2", "CC6")?.status).toBe("deficient")
    expect(statusOf("soc2", "C1")?.status).toBe("deficient")
    expect(statusOf("soc2", "PI1")?.status).toBe("deficient")
    // NIS2 — Art. 21(2)(i) (control de acceso) y Art. 21(2)(a) (políticas).
    expect(statusOf("nis2", "21.2.i")?.status).toBe("deficient")
    expect(statusOf("nis2", "21.2.a")?.status).toBe("deficient")
    // DORA — Art. 9 (protection and prevention) y Art. 6 (ICT risk management).
    expect(statusOf("dora", "Art.9")?.status).toBe("deficient")
    expect(statusOf("dora", "Art.6")?.status).toBe("deficient")
  })

  test("el grupo padre hereda el peor estado de sus hijos", () => {
    expect(statusOf("soc2", "Security")?.status).toBe("deficient")
    expect(statusOf("nis2", "Art.21.2")?.status).toBe("deficient")
    expect(statusOf("dora", "ICTRiskManagement")?.status).toBe("deficient")
  })

  test("los controles de los frameworks derivados sin hallazgos quedan compliant", () => {
    expect(statusOf("soc2", "CC2")?.status).toBe("compliant")
    expect(statusOf("nis2", "21.2.f")?.status).toBe("compliant")
    expect(statusOf("dora", "Art.24")?.status).toBe("compliant")
  })
})

// ── PCI DSS v4.0.1 ────────────────────────────────────────────────────────────

describe("deriveProjectStatuses — PCI DSS v4.0.1", () => {
  const catalog = buildCatalog()
  const derive = (finding: Record<string, unknown>) =>
    deriveProjectStatuses({ projectID: "p", findings: [finding], catalog })
  const statusOf = (rows: ReturnType<typeof derive>, controlId: string) =>
    rows.find((row) => row.framework === "pci_dss_v4" && row.controlId === controlId)?.status

  const SECRET_FINDING = {
    id: "f-secret",
    title: "API key committed in public repository",
    tags: ["secret-exposure"],
    severity: "high",
    status: "open",
    sourceTool: "web.scan",
  }

  const SQLI_FINDING = {
    id: "f-sqli",
    title: "SQL injection in search parameter",
    tags: ["sqli"],
    severity: "critical",
    status: "open",
    sourceTool: "web.scan",
    cwe: "CWE-89",
  }

  test("un hallazgo de secret-exposure deja deficient el control PCI-DSS equivalente", () => {
    const rows = derive(SECRET_FINDING)
    // Req.3.5 (PAN protegido donde se almacena) y su control hoja 3.5.1.
    expect(statusOf(rows, "3.5")).toBe("deficient")
    expect(statusOf(rows, "3.5.1")).toBe("deficient")
    // Req.8.3 (autenticación fuerte) por el factor de autenticación expuesto.
    expect(statusOf(rows, "8.3")).toBe("deficient")
    expect(statusOf(rows, "8.3.2")).toBe("deficient")
    // El requisito 3 hereda el peor estado de sus hijos.
    expect(statusOf(rows, "3")).toBe("deficient")
    // Y el resto de frameworks también lo ven.
    expect(rows.find((row) => row.framework === "soc2" && row.controlId === "CC6")?.status).toBe("deficient")
    expect(rows.find((row) => row.framework === "dora" && row.controlId === "Art.9")?.status).toBe("deficient")
  })

  test("un hallazgo de sqli deja deficient los controles de inyección y de escaneo de PCI-DSS", () => {
    const rows = derive(SQLI_FINDING)
    // Req.6.2.4 (prevención de ataques de inyección).
    expect(statusOf(rows, "6.2.4")).toBe("deficient")
    // Req.11.3.2 (escaneo externo de vulnerabilidades).
    expect(statusOf(rows, "11.3.2")).toBe("deficient")
    // Los sub-requisitos que los agrupan.
    expect(statusOf(rows, "6.2")).toBe("deficient")
    expect(statusOf(rows, "11.3")).toBe("deficient")
    expect(statusOf(rows, "11")).toBe("deficient")
  })

  test("los controles que Argos no puede medir quedan sin evaluar, nunca conformes", () => {
    const rows = deriveProjectStatuses({ projectID: "p", findings: [SECRET_FINDING], catalog })
    // Req.9 (acceso físico a los datos de tarjeta): fuera del alcance de un
    // escáner, así que no se declara conforme.
    expect(statusOf(rows, "9")).toBe("unassessed")
    expect(statusOf(rows, "9.2")).toBe("unassessed")
    expect(statusOf(rows, "9.2.1")).toBe("unassessed")
  })

  test("la evidencia de PCI-DSS registra la regla que derivó el control", () => {
    const rows = derive(SECRET_FINDING)
    const control = rows.find((row) => row.framework === "pci_dss_v4" && row.controlId === "3.5.1")
    expect(control?.evidence.some((entry) => entry.findingID === "f-secret")).toBe(true)
    expect(control?.derivation.some((entry) => entry.derivedFrom === "secrets")).toBe(true)
  })
})

// ── Service con BD en memoria y fuentes públicas mockeadas ───────────────────

const database = Database.layerFromPath(":memory:")
const compliance = Compliance.defaultLayer.pipe(Layer.provideMerge(database))
const it = testEffect(compliance)

const jsonResponse = (value: unknown) =>
  new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } })

const originalFetch = globalThis.fetch

afterAll(() => {
  globalThis.fetch = originalFetch
})

const seedProjectAndSession = Effect.gen(function* () {
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
      id: SessionV2.ID.make("ses_compliance"),
      project_id: Project.ID.global,
      slug: "compliance",
      directory: "/project",
      title: "compliance",
      version: "test",
      agent: "analyst",
    })
    .run()
    .pipe(Effect.orDie)
})

describe("Compliance service", () => {
  // Corre primero, antes de que cualquier otro test en este describe pueble el
  // catálogo — el estado de la BD en memoria es compartido entre todos los
  // tests del bloque, así que el catálogo "vacío" solo es real acá.
  it.effect("getSessionStatus devuelve un estado vacío si el catálogo no está cargado", () =>
    Effect.gen(function* () {
      yield* seedProjectAndSession
      const service = yield* Compliance.Service
      const status = yield* service.getSessionStatus("ses_compliance")
      expect(status).toEqual({ frameworks: [], catalogCount: 0, mappingCount: 0, lastRefreshed: undefined })
    }),
  )

  it.effect("refresh carga el catálogo desde fuentes públicas y deriva el estado", () =>
    Effect.gen(function* () {
      globalThis.fetch = (async (input: unknown) => {
        const url = input instanceof Request ? input.url : String(input)
        if (url.includes("NIST_CSF_v2.0_catalog")) return jsonResponse(NIST_FIXTURE)
        if (url.includes("crosswalk")) return jsonResponse(CROSSWALK_FIXTURE)
        if (url.includes("nist-csf-v2-mapping")) return jsonResponse(CHECKS_NIST_FIXTURE)
        if (url.includes("iso27001-mapping")) return jsonResponse(CHECKS_ISO_FIXTURE)
        return new Response("not found", { status: 404 })
      }) as typeof fetch

      try {
        yield* seedProjectAndSession
        const service = yield* Compliance.Service

        const summary = yield* service.refresh()
        // 4 fuentes de red + 4 catálogos bundled (SOC 2 / NIS2 / DORA / PCI-DSS).
        expect(summary.sources.filter((source) => source.ok).length).toBe(8)
        expect(summary.sources.filter((source) => source.bundled).length).toBe(4)
        expect(summary.catalogControlCount).toBeGreaterThan(0)
        expect(summary.mappingCount).toBeGreaterThan(0)

        const { db } = yield* Database.Service
        const catalogCount = yield* db
          .select({ total: sql<number>`count(*)` })
          .from(ComplianceCatalogTable)
          .get()
          .pipe(Effect.orDie)
        expect(Number(catalogCount?.total)).toBe(summary.catalogControlCount)

        yield* db
          .insert(FindingTable)
          .values({
            id: "finding_compliance_1",
            session_id: SessionV2.ID.make("ses_compliance"),
            project_id: Project.ID.global,
            fingerprint: "fp1",
            title: "Missing HSTS header on example.com",
            severity: "high",
            status: "open",
            source: "agent-reviewed",
            source_tool: "web.scan",
            agent: "analyst",
            target: "https://example.com",
            cwe: "CWE-319",
            vector: "https://example.com",
            evidence: {},
            remediation: null,
            tags: ["tls"],
            raw: null,
            time_created: Date.now(),
            time_updated: Date.now(),
          })
          .run()
          .pipe(Effect.orDie)

        yield* service.recomputeProject(Project.ID.global)

        const rows = yield* service.getStatus(Project.ID.global)
        expect(rows.length).toBe(summary.catalogControlCount)
        const prds = rows.find((row) => row.controlId === "PR.DS-02")
        expect(prds?.status).toBe("deficient")
        const a51 = rows.find((row) => row.controlId === "A.5.1")
        expect(a51?.status).toBe("compliant")

        const stored = yield* db
          .select()
          .from(ComplianceStatusTable)
          .where(eq(ComplianceStatusTable.project_id, Project.ID.global))
          .all()
          .pipe(Effect.orDie)
        expect(stored.length).toBe(summary.catalogControlCount)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )

  it.effect("getSessionStatus arma el árbol anidado con rollup de status y findingCount", () =>
    Effect.gen(function* () {
      globalThis.fetch = (async (input: unknown) => {
        const url = input instanceof Request ? input.url : String(input)
        if (url.includes("NIST_CSF_v2.0_catalog")) return jsonResponse(NIST_FIXTURE)
        if (url.includes("crosswalk")) return jsonResponse(CROSSWALK_FIXTURE)
        if (url.includes("nist-csf-v2-mapping")) return jsonResponse(CHECKS_NIST_FIXTURE)
        if (url.includes("iso27001-mapping")) return jsonResponse(CHECKS_ISO_FIXTURE)
        return new Response("not found", { status: 404 })
      }) as typeof fetch

      try {
        yield* seedProjectAndSession
        const service = yield* Compliance.Service
        const { db } = yield* Database.Service

        const summary = yield* service.refresh()

        yield* db
          .insert(FindingTable)
          .values({
            id: "finding_compliance_tree_1",
            session_id: SessionV2.ID.make("ses_compliance"),
            project_id: Project.ID.global,
            fingerprint: "fp-tree-1",
            title: "Missing HSTS header on example.com",
            severity: "high",
            status: "open",
            source: "agent-reviewed",
            source_tool: "web.scan",
            agent: "analyst",
            target: "https://example.com",
            cwe: "CWE-319",
            vector: "https://example.com",
            evidence: {},
            remediation: null,
            tags: ["tls"],
            raw: null,
            time_created: Date.now(),
            time_updated: Date.now(),
          })
          .run()
          .pipe(Effect.orDie)

        yield* service.recomputeProject(Project.ID.global)

        const status = yield* service.getSessionStatus("ses_compliance")
        expect(status.catalogCount).toBe(summary.catalogControlCount)
        expect(status.mappingCount).toBe(summary.mappingCount)
        expect(status.frameworks).toHaveLength(6)

        const nist = status.frameworks.find((f) => f.framework === "nist_csf_v2")
        expect(nist).toBeDefined()
        expect(nist!.tree.level).toBe("root")

        const pr = nist!.tree.children.find((n) => n.id === "PR")
        expect(pr).toBeDefined()
        const prDs = pr!.children.find((n) => n.id === "PR.DS")
        expect(prDs).toBeDefined()
        const prDs02 = prDs!.children.find((n) => n.id === "PR.DS-02")
        const prDs11 = prDs!.children.find((n) => n.id === "PR.DS-11")

        // Hoja con hallazgo: deficient, con la evidencia adjunta.
        expect(prDs02?.status).toBe("deficient")
        expect(prDs02?.findingCount).toBe(1)
        expect(prDs02?.evidence[0]?.title).toBe("Missing HSTS header on example.com")
        // Hoja sin hallazgos: compliant (mismo default que deriveProjectStatuses), sin evidencia.
        expect(prDs11?.status).toBe("compliant")
        expect(prDs11?.findingCount).toBe(0)

        // Rollup: la categoría y la función se ven afectadas por su hijo más grave.
        expect(prDs?.status).toBe("deficient")
        expect(prDs?.findingCount).toBe(1)
        expect(pr?.status).toBe("deficient")

        // Una función sin ningún hallazgo bajo ella se mantiene compliant.
        const de = nist!.tree.children.find((n) => n.id === "DE")
        expect(de?.status).toBe("compliant")
        expect(de?.findingCount).toBe(0)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )

  it.effect("getSessionStatus devuelve un estado vacío para una Session sin proyecto", () =>
    Effect.gen(function* () {
      globalThis.fetch = (async (input: unknown) => {
        const url = input instanceof Request ? input.url : String(input)
        if (url.includes("NIST_CSF_v2.0_catalog")) return jsonResponse(NIST_FIXTURE)
        if (url.includes("crosswalk")) return jsonResponse(CROSSWALK_FIXTURE)
        if (url.includes("nist-csf-v2-mapping")) return jsonResponse(CHECKS_NIST_FIXTURE)
        if (url.includes("iso27001-mapping")) return jsonResponse(CHECKS_ISO_FIXTURE)
        return new Response("not found", { status: 404 })
      }) as typeof fetch
      try {
        const service = yield* Compliance.Service
        yield* service.refresh()
        const status = yield* service.getSessionStatus("ses_does_not_exist")
        expect(status.frameworks).toEqual([])
        expect(status.catalogCount).toBeGreaterThan(0)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )

  it.effect("refresh fallido conserva el catálogo cacheado (degradación con gracia)", () =>
    Effect.gen(function* () {
      globalThis.fetch = (async (input: unknown) => {
        const url = input instanceof Request ? input.url : String(input)
        if (url.includes("NIST_CSF_v2.0_catalog")) return jsonResponse(NIST_FIXTURE)
        if (url.includes("crosswalk")) return jsonResponse(CROSSWALK_FIXTURE)
        if (url.includes("nist-csf-v2-mapping")) return jsonResponse(CHECKS_NIST_FIXTURE)
        if (url.includes("iso27001-mapping")) return jsonResponse(CHECKS_ISO_FIXTURE)
        return new Response("not found", { status: 404 })
      }) as typeof fetch

      try {
        const service = yield* Compliance.Service
        const first = yield* service.refresh()
        const cachedCount = first.catalogControlCount
        expect(cachedCount).toBeGreaterThan(0)

        // Ahora simulamos offline total: refresh no debe vaciar el caché. Las
        // fuentes bundled (SOC 2 / NIS2 / DORA) siguen disponibles.
        globalThis.fetch = (async () => new Response("unreachable", { status: 503 })) as unknown as typeof fetch
        const failed = yield* service.refresh()
        expect(failed.sources.filter((source) => !source.bundled).every((source) => !source.ok)).toBe(true)
        expect(failed.sources.filter((source) => source.bundled).every((source) => source.ok)).toBe(true)

        const { db } = yield* Database.Service
        const count = yield* db
          .select({ total: sql<number>`count(*)` })
          .from(ComplianceCatalogTable)
          .get()
          .pipe(Effect.orDie)
        expect(Number(count?.total)).toBe(cachedCount)
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )

  it.effect("ensureCatalog recarga los catálogos derivados en instalaciones previas", () =>
    Effect.gen(function* () {
      globalThis.fetch = (async (input: unknown) => {
        const url = input instanceof Request ? input.url : String(input)
        if (url.includes("NIST_CSF_v2.0_catalog")) return jsonResponse(NIST_FIXTURE)
        if (url.includes("crosswalk")) return jsonResponse(CROSSWALK_FIXTURE)
        if (url.includes("nist-csf-v2-mapping")) return jsonResponse(CHECKS_NIST_FIXTURE)
        if (url.includes("iso27001-mapping")) return jsonResponse(CHECKS_ISO_FIXTURE)
        return new Response("not found", { status: 404 })
      }) as typeof fetch

      try {
        const service = yield* Compliance.Service
        const { db } = yield* Database.Service
        yield* service.refresh()

        // Instalación previa a ARG-040: el catálogo solo tiene NIST + ISO.
        yield* db
          .delete(ComplianceCatalogTable)
          .where(inArray(ComplianceCatalogTable.framework, ["soc2", "nis2", "dora", "pci_dss_v4"]))
          .run()
          .pipe(Effect.orDie)

        // Sin red: los catálogos bundled se recargan igual.
        globalThis.fetch = (async () => new Response("unreachable", { status: 503 })) as unknown as typeof fetch
        yield* service.ensureCatalog()

        const frameworks = yield* db
          .selectDistinct({ framework: ComplianceCatalogTable.framework })
          .from(ComplianceCatalogTable)
          .all()
          .pipe(Effect.orDie)
        const present = frameworks.map((row) => row.framework)
        expect(present).toContain("soc2")
        expect(present).toContain("nis2")
        expect(present).toContain("dora")
        expect(present).toContain("pci_dss_v4")
        // NIST e ISO (fuentes de red) no se vacían.
        expect(present).toContain("nist_csf_v2")
        expect(present).toContain("iso27001_2022")
      } finally {
        globalThis.fetch = originalFetch
      }
    }),
  )
})
