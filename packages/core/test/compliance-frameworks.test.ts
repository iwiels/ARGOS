import { describe, expect, test } from "bun:test"
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { buildDerivedCatalogs } from "@argos/core/compliance/catalogs"
import { SEMANTIC, deriveProjectStatuses } from "@argos/core/compliance/derive"
import { parseDerivedCatalog, parseIsoCrosswalk, parseNistOscal } from "@argos/core/compliance/parse"
import { buildPciDssCatalog } from "@argos/core/compliance/pci-dss"
import { FRAMEWORKS, type ControlNode, type Framework } from "@argos/core/compliance/types"
import bundledNist from "../src/compliance/bundled/nist_csf_v2.json"
import bundledCrosswalk from "../src/compliance/bundled/iso27001_crosswalk.json"
import bundledSoc2 from "../src/compliance/bundled/soc2.json"
import bundledNis2 from "../src/compliance/bundled/nis2.json"
import bundledDora from "../src/compliance/bundled/dora.json"
import bundledPciDss from "../src/compliance/bundled/pci_dss_v4.json"

const BUNDLED_DIR = join(import.meta.dir, "..", "src", "compliance", "bundled")

const DERIVED_FRAMEWORKS = [FRAMEWORKS.soc2, FRAMEWORKS.nis2, FRAMEWORKS.dora] as const

const FILE_BY_FRAMEWORK: Record<string, string> = {
  [FRAMEWORKS.soc2]: "soc2.json",
  [FRAMEWORKS.nis2]: "nis2.json",
  [FRAMEWORKS.dora]: "dora.json",
  [FRAMEWORKS.pciDssV4]: "pci_dss_v4.json",
}

/** Catálogo real completo (el mismo que el runtime carga en la BD). */
function realCatalog() {
  const nodes: ControlNode[] = [
    ...parseNistOscal(bundledNist),
    ...parseIsoCrosswalk(bundledCrosswalk).controls,
    ...parseDerivedCatalog(bundledSoc2, FRAMEWORKS.soc2),
    ...parseDerivedCatalog(bundledNis2, FRAMEWORKS.nis2),
    ...parseDerivedCatalog(bundledDora, FRAMEWORKS.dora),
    ...parseDerivedCatalog(bundledPciDss, FRAMEWORKS.pciDssV4),
  ]
  return nodes.map((node) => ({
    framework: node.framework,
    control_id: node.id,
    title: node.title,
    parent_id: node.parentId,
    level: node.level,
    sort_id: node.sortId ?? null,
    attributes: node.attributes,
    source: node.source,
    time_updated: 0,
  }))
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

describe("catálogos derivados (SOC 2 / NIS2 / DORA)", () => {
  test("los 6 frameworks tienen entradas en el catálogo", () => {
    const catalog = realCatalog()
    for (const framework of Object.values(FRAMEWORKS)) {
      const controls = catalog.filter((row) => row.framework === framework)
      expect(controls.length).toBeGreaterThan(0)
      // Cada framework expondrá hojas (nivel control/subcategory) para el score.
      expect(controls.filter((row) => row.level === "control" || row.level === "subcategory").length).toBeGreaterThan(0)
    }
  })

  test("los catálogos generados están sincronizados con el crosswalk", async () => {
    const regenerated = buildDerivedCatalogs(bundledCrosswalk)
    for (const framework of DERIVED_FRAMEWORKS) {
      const file = join(BUNDLED_DIR, FILE_BY_FRAMEWORK[framework])
      const committed = (await readFile(file, "utf-8")).replaceAll("\r\n", "\n")
      // Comparación byte a byte: si el crosswalk cambia, hay que regenerar.
      expect(committed).toBe(`${JSON.stringify(regenerated[framework], null, 2)}\n`)
    }
  })

  test("todo control del catálogo existe en el crosswalk (no se inventa ninguno)", () => {
    const crosswalk = bundledCrosswalk as unknown as Record<string, unknown>
    const declared: Record<string, Set<string>> = {
      [FRAMEWORKS.soc2]: new Set(Object.keys((crosswalk["soc2_trust_services_criteria"] ?? {}) as object)),
      [FRAMEWORKS.nis2]: new Set(Object.keys((crosswalk["nis2_article21_measures"] ?? {}) as object)),
      [FRAMEWORKS.dora]: new Set(Object.keys((crosswalk["dora_articles"] ?? {}) as object)),
    }
    for (const framework of DERIVED_FRAMEWORKS) {
      const controls = parseDerivedCatalog(
        framework === FRAMEWORKS.soc2 ? bundledSoc2 : framework === FRAMEWORKS.nis2 ? bundledNis2 : bundledDora,
        framework,
      ).filter((node) => node.level === "control")
      expect(controls.length).toBeGreaterThan(0)
      for (const control of controls) {
        expect(declared[framework].has(control.id)).toBe(true)
      }
    }
  })

  test("todo target de las reglas semánticas existe en el catálogo de su framework", () => {
    const catalog = realCatalog()
    const ids = new Set(catalog.map((row) => `${row.framework}:${row.control_id}`))
    for (const rule of SEMANTIC) {
      for (const [framework, controlId] of rule.targets) {
        expect(ids.has(`${framework}:${controlId}`)).toBe(true)
      }
    }
  })

  test("los targets de SOC 2 / NIS2 / DORA están justificados por el crosswalk", () => {
    const catalog = realCatalog()
    const isoEquivalentsOf = (framework: Framework, controlId: string): string[] => {
      const row = catalog.find((entry) => entry.framework === framework && entry.control_id === controlId)
      const equivalents = row?.attributes["isoEquivalents"]
      return Array.isArray(equivalents) ? equivalents.filter((value): value is string => typeof value === "string") : []
    }
    for (const rule of SEMANTIC) {
      const isoTargets = rule.targets
        .filter(([framework]) => framework === FRAMEWORKS.iso27001)
        .map(([, controlId]) => controlId)
      for (const [framework, controlId] of rule.targets) {
        if (!DERIVED_FRAMEWORKS.includes(framework as (typeof DERIVED_FRAMEWORKS)[number])) continue
        const equivalents = isoEquivalentsOf(framework, controlId)
        expect(equivalents.length).toBeGreaterThan(0)
        // El control destino tiene que estar enlazado por el crosswalk a
        // alguno de los controles ISO que la regla ya apunta.
        expect(equivalents.some((isoId) => isoTargets.includes(isoId))).toBe(true)
      }
    }
  })

  test("el control padre toma el peor estado de sus hijos", () => {
    const catalog = realCatalog()
    const rows = deriveProjectStatuses({
      projectID: "p",
      findings: [
        {
          id: "f1",
          title: "Weak cipher suite allowed",
          tags: ["weak-crypto"],
          severity: "medium",
          status: "open",
          sourceTool: "web.scan",
        },
      ],
      catalog,
    })
    const statusOf = (framework: string, controlId: string) =>
      rows.find((row) => row.framework === framework && row.controlId === controlId)?.status

    // Hoja con hallazgo medio → partial; el padre hereda el peor estado.
    expect(statusOf(FRAMEWORKS.soc2, "CC6")).toBe("partial")
    expect(statusOf(FRAMEWORKS.soc2, "Security")).toBe("partial")
    expect(statusOf(FRAMEWORKS.nis2, "21.2.h")).toBe("partial")
    expect(statusOf(FRAMEWORKS.nis2, "Art.21.2")).toBe("partial")
    expect(statusOf(FRAMEWORKS.dora, "Art.9")).toBe("partial")
    expect(statusOf(FRAMEWORKS.dora, "ICTRiskManagement")).toBe("partial")
    // Un grupo sin hallazgos quedan compliant.
    expect(statusOf(FRAMEWORKS.dora, "ICTThirdPartyRisk")).toBe("compliant")
  })

  test("los catálogos derivados declaran su base de equivalencia (direct vs equivalence)", () => {
    const generated = buildDerivedCatalogs(bundledCrosswalk)
    for (const framework of DERIVED_FRAMEWORKS) {
      const catalog = generated[framework]
      expect(catalog.meta.crosswalkVersion).toBe("0.4.0")
      for (const control of catalog.controls.filter((node) => node.level === "control")) {
        const basis = control.attributes["mappingBasis"]
        expect(basis === "direct" || basis === "equivalence").toBe(true)
        const equivalents = control.attributes["isoEquivalents"]
        expect(Array.isArray(equivalents)).toBe(true)
        // Todo control computable tiene al menos un control ISO equivalente
        // declarado por el crosswalk: nada se inventó.
        expect((equivalents as string[]).length).toBeGreaterThan(0)
        // La cobertura heredada por equivalencia NIST se declara aparte.
        expect(Array.isArray(control.attributes["isoEquivalentsByEquivalence"])).toBe(true)
        expect(Array.isArray(control.attributes["nistEquivalents"])).toBe(true)
      }
    }
  })

  test("el crosswalk marca los controles ISO sin mapeo a SOC 2 / NIS2 / DORA", () => {
    const generated = buildDerivedCatalogs(bundledCrosswalk)
    // El crosswalk no mapea todos los controles ISO a los tres frameworks:
    // los que quedan fuera se declaran explícitamente (no se inventan).
    expect(generated[FRAMEWORKS.soc2].meta.unmappedIsoControls.length).toBeGreaterThan(0)
    expect(generated[FRAMEWORKS.nis2].meta.unmappedIsoControls.length).toBeGreaterThan(0)
    expect(generated[FRAMEWORKS.dora].meta.unmappedIsoControls.length).toBeGreaterThan(0)
    // DORA declara Art.26 en su mapa pero ningún control ISO lo referencia:
    // queda fuera del catálogo computable y registrado como tal.
    expect(generated[FRAMEWORKS.dora].meta.declaredButUnmappedControls).toContain("Art.26")
    const doraControls = generated[FRAMEWORKS.dora].controls.filter((node) => node.level === "control")
    expect(doraControls.some((node) => node.id === "Art.26")).toBe(false)
  })

  test("el crosswalk declara los títulos de los controles de los frameworks derivados", () => {
    const crosswalk = bundledCrosswalk as unknown as Record<string, unknown>
    const titleMaps = [
      crosswalk["soc2_trust_services_criteria"],
      crosswalk["nis2_article21_measures"],
      crosswalk["dora_articles"],
    ]
    for (const map of titleMaps) {
      expect(isRecord(map)).toBe(true)
      for (const [id, title] of Object.entries(map as Record<string, unknown>)) {
        expect(typeof title).toBe("string")
        expect((title as string).length).toBeGreaterThan(0)
        expect(id.length).toBeGreaterThan(0)
      }
    }
  })
})

// ── PCI DSS v4.0.1 (catálogo propio, no derivado del crosswalk) ─────────────

describe("catálogo de PCI DSS v4.0.1", () => {
  test("el catálogo commiteado está sincronizado con la fuente (PCI DSS v4.0.1)", async () => {
    const committed = await readFile(join(BUNDLED_DIR, FILE_BY_FRAMEWORK[FRAMEWORKS.pciDssV4]), "utf-8")
    expect(committed).toBe(`${JSON.stringify(buildPciDssCatalog(), null, 2)}\n`)
  })

  test("el catálogo conserva referencias neutrales sin distribuir texto normativo ni afirmar cumplimiento", () => {
    const catalog = buildPciDssCatalog()
    expect(catalog.meta.disclaimer).toContain("does not constitute a PCI DSS compliance assessment")
    for (const control of catalog.controls) {
      expect(control.title).toBe(`PCI DSS reference ${control.id}`)
      expect(control.attributes["description"]).toBe(
        `Consult the official PCI DSS documentation for reference ${control.id}.`,
      )
    }
  })

  test("el catálogo cubre los 12 requisitos de la norma", () => {
    const catalog = buildPciDssCatalog()
    expect(catalog.meta.requirements).toBe(12)
    const requirements = catalog.controls.filter((control) => control.level === "theme")
    expect(requirements.map((control) => control.id)).toEqual([
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "10",
      "11",
      "12",
    ])
    // Cada requisito agrupa sus sub-requisitos.
    for (const requirement of requirements) {
      const children = catalog.controls.filter((control) => control.parentId === requirement.id)
      expect(children.length).toBeGreaterThan(0)
    }
  })

  test("todo id de control cumple la nomenclatura del estándar y apunta a un requisito existente", () => {
    const catalog = buildPciDssCatalog()
    const ids = new Set(catalog.controls.map((control) => control.id))
    // `requisito.sub.sub`: tres niveles como máximo, como en la norma.
    const idPattern = /^\d{1,2}(\.\d{1,2}){0,2}$/
    for (const control of catalog.controls) {
      expect(idPattern.test(control.id)).toBe(true)
      expect(control.id.split(".").length).toBeLessThanOrEqual(3)
      if (control.parentId) expect(ids.has(control.parentId)).toBe(true)
      // El padre de un control es su prefijo (jerarquía real de PCI-DSS).
      if (control.parentId && control.id.split(".").length > 1) {
        expect(control.id.startsWith(`${control.parentId}.`)).toBe(true)
      }
    }
    // Los 12 requisitos de primer nivel cuelgan de la raíz.
    const roots = catalog.controls.filter((control) => control.parentId === null)
    expect(roots.length).toBe(12)
  })

  test("el catálogo declara su base documental y los controles anidados que deja fuera", () => {
    const catalog = buildPciDssCatalog()
    expect(catalog.meta.source).toContain("PCI DSS v4.0.1")
    expect(catalog.meta.sourceUrl).toContain("pcisecuritystandards.org")
    // Los controles de cuarto/quinto nivel del estándar no se truncan: se
    // declaran aparte para que la diferencia con la norma sea auditable.
    expect(catalog.meta.excludedNestedControls.length).toBeGreaterThan(0)
    for (const id of catalog.meta.excludedNestedControls) {
      expect(id.split(".").length).toBeGreaterThan(3)
    }
  })

  test("la cobertura coincide con las reglas semánticas del motor", () => {
    const catalog = buildPciDssCatalog()
    const targeted = new Set<string>()
    for (const rule of SEMANTIC) {
      for (const [framework, controlId] of rule.targets) {
        if (framework === FRAMEWORKS.pciDssV4) targeted.add(controlId)
      }
    }
    const leaves = catalog.controls.filter((control) => control.level === "control")
    const evaluable = leaves.filter((control) => control.attributes["coverage"] === "evaluable")
    // Todo control evaluable tiene al menos una regla que lo activa.
    for (const control of evaluable) expect(targeted.has(control.id)).toBe(true)
    // Y todo control activado por una regla es evaluable.
    for (const id of targeted) {
      const control = catalog.controls.find((entry) => entry.id === id)
      expect(control).toBeDefined()
      expect(control!.attributes["coverage"]).toBe("evaluable")
    }
    // El resto se declara no evaluable: nunca conforme.
    expect(catalog.meta.evaluableControls).toBe(evaluable.length)
    expect(catalog.meta.notEvaluableControls).toBe(leaves.length - evaluable.length)
  })

  test("un control que Argos no puede medir queda sin evaluar, nunca conforme", () => {
    const catalog = realCatalog()
    const rows = deriveProjectStatuses({ projectID: "p", findings: [], catalog })
    // 9.2 (control físico de acceso a las instalaciones) no lo puede medir un
    // escáner: se reporta como no evaluado, no como conforme.
    const physical = rows.find((row) => row.framework === FRAMEWORKS.pciDssV4 && row.controlId === "9.2")
    expect(physical?.status).toBe("unassessed")
    // Y el requisito que lo agrupa tampoco se declara conforme.
    const requirement = rows.find((row) => row.framework === FRAMEWORKS.pciDssV4 && row.controlId === "9")
    expect(requirement?.status).toBe("unassessed")
    // Un control evaluable sin hallazgos mantiene el default del motor.
    const evaluable = rows.find((row) => row.framework === FRAMEWORKS.pciDssV4 && row.controlId === "6.2.4")
    expect(evaluable?.status).toBe("compliant")
  })

  test("los targets PCI de las reglas semánticas existen en el catálogo", () => {
    const catalog = realCatalog()
    const ids = new Set(catalog.map((row) => `${row.framework}:${row.control_id}`))
    for (const rule of SEMANTIC) {
      for (const [framework, controlId] of rule.targets) {
        if (framework !== FRAMEWORKS.pciDssV4) continue
        expect(ids.has(`${framework}:${controlId}`)).toBe(true)
      }
    }
  })

})
