/**
 * Genera los catálogos de SOC 2, NIS2, DORA y PCI-DSS v4.0.
 *
 * Uso: bun scripts/gen-compliance-catalogs.ts
 *
 * - SOC 2 / NIS2 / DORA se derivan del crosswalk de ISO 27001:2022 bundled
 *   (fuente única de verdad).
 * - PCI-DSS no está en ese crosswalk: su catálogo es propio y se construye
 *   desde `packages/core/src/compliance/pci-dss.ts` (transcripción de la
 *   estructura pública de PCI DSS v4.0.1), con la cobertura evaluable derivada
 *   de las reglas semánticas del motor.
 *
 * Los JSON resultantes se commitean en
 * `packages/core/src/compliance/bundled/` y el runtime los carga como
 * snapshots bundled. El test `packages/core/test/compliance-frameworks.test.ts`
 * falla si los archivos commiteados divergen de lo que genera este script.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { buildDerivedCatalogs, type DerivedCatalog } from "../packages/core/src/compliance/catalogs"
import { buildPciDssCatalog } from "../packages/core/src/compliance/pci-dss"
import { FRAMEWORKS, type DerivedFramework } from "../packages/core/src/compliance/types"

const BUNDLED_DIR = join(import.meta.dir, "..", "packages", "core", "src", "compliance", "bundled")
const CROSSWALK_PATH = join(BUNDLED_DIR, "iso27001_crosswalk.json")

const FILE_BY_FRAMEWORK: Record<DerivedFramework, string> = {
  [FRAMEWORKS.soc2]: "soc2.json",
  [FRAMEWORKS.nis2]: "nis2.json",
  [FRAMEWORKS.dora]: "dora.json",
}

const crosswalk = JSON.parse(await readFile(CROSSWALK_PATH, "utf-8")) as unknown
const catalogs = buildDerivedCatalogs(crosswalk)

await mkdir(BUNDLED_DIR, { recursive: true })

for (const framework of [FRAMEWORKS.soc2, FRAMEWORKS.nis2, FRAMEWORKS.dora] as DerivedFramework[]) {
  const catalog: DerivedCatalog = catalogs[framework]
  const target = join(BUNDLED_DIR, FILE_BY_FRAMEWORK[framework])
  await writeFile(target, `${JSON.stringify(catalog, null, 2)}\n`, "utf-8")
  const leaves = catalog.controls.filter((control) => control.level === "control").length
  console.log(`${FILE_BY_FRAMEWORK[framework]}: ${catalog.controls.length} nodos (${leaves} controles)`)
}

// PCI-DSS v4.0.1: catálogo propio (no hay crosswalk que lo cubra).
const pciCatalog = buildPciDssCatalog()
const pciTarget = join(BUNDLED_DIR, "pci_dss_v4.json")
await writeFile(pciTarget, `${JSON.stringify(pciCatalog, null, 2)}\n`, "utf-8")
const pciLeaves = pciCatalog.controls.filter((control) => control.level === "control")
console.log(
  `pci_dss_v4.json: ${pciCatalog.controls.length} nodos (${pciLeaves.length} controles, ` +
    `${pciCatalog.meta.evaluableControls} evaluables, ${pciCatalog.meta.notEvaluableControls} no evaluables)`,
)
