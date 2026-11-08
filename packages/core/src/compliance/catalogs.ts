/** Generador de los catálogos de SOC 2, NIS2 y DORA.
 *
 *  Fuente única de verdad: el crosswalk de ISO 27001:2022 bundled
 *  (`bundled/iso27001_crosswalk.json`). Cada control ISO de ese archivo trae
 *  ya los identificadores del framework destino (`soc2[]`, `nis2[]`, `dora[]`)
 *  y el crosswalk declara los títulos de cada control destino
 *  (`soc2_trust_services_criteria`, `nis2_article21_measures`, `dora_articles`).
 *
 *  Este módulo es puro (sin IO): `scripts/gen-compliance-catalogs.ts` lo usa
 *  para escribir los JSON generados y el test de sincronización los compara
 *  contra los archivos commiteados. El runtime carga esos JSON como un
 *  snapshot bundled más (mismo camino que NIST/ISO).
 *
 *  Regla de oro: no se inventa ningún control. Todo identificador del catálogo
 *  sale literalmente del crosswalk. Cuando un control ISO no tiene mapeo a un
 *  framework, el catálogo lo registra como `unmappedIsoControls` en vez de
 *  inventar un vínculo; y cuando el vínculo existe solo a través del
 *  equivalente NIST CSF 2.0 se marca `equivalence` (no `direct`).
 */

import { FRAMEWORKS, type ControlLevel, type DerivedFramework } from "./types"
import { FRAMEWORK_META } from "./sources"

const CROSSWALK_SOURCE = "iso27001_crosswalk.json (bundled)"

/** Base de los controles de cada framework derivada (del crosswalk). */
export interface DerivedControl {
  id: string
  title: string
  parentId: string | null
  level: ControlLevel
  sortId: string
  framework: DerivedFramework
  attributes: Record<string, unknown>
  source: string
}

export interface DerivedCatalogMeta {
  framework: DerivedFramework
  title: string
  version: string
  generatedFrom: string
  crosswalkVersion: string
  disclaimer: string
  /** Controles ISO sin mapeo directo a este framework en el crosswalk. */
  unmappedIsoControls: string[]
  /** Controles ISO sin mapeo directo que quedan cubiertos por equivalencia NIST. */
  isoControlsCoveredByEquivalence: string[]
  /** Controles que el crosswalk declara para el framework pero que ningún
   *  control ISO referencia: se excluyen del catálogo computable (contar un
   *  control que nunca se evalúa inflaría el score de cumplimiento). */
  declaredButUnmappedControls: string[]
}

export interface DerivedCatalog {
  meta: DerivedCatalogMeta
  controls: DerivedControl[]
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

const stringList = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []

interface CrosswalkRow {
  isoId: string
  isoName: string
  nist: string[]
  soc2: string[]
  nis2: string[]
  dora: string[]
}

interface GroupDef {
  id: string
  title: string
  /** Base documental de la agrupación (capítulo del reglamento, categoría…). */
  basis: string
  match: (controlId: string) => boolean
}

/** Categorías de la AICPA TSC (Common Criteria + Availability, Confidentiality,
 *  Processing Integrity y Privacy). El prefijo decide el grupo: CC → Security,
 *  PI → Processing Integrity, A → Availability, C → Confidentiality, P → Privacy. */
const SOC2_GROUPS: GroupDef[] = [
  {
    id: "Security",
    title: "Security (Common Criteria)",
    basis: "AICPA TSC 2017 (rev. 2022) — categoría Security (Common Criteria CC1–CC9)",
    match: (id) => /^CC\d+$/.test(id),
  },
  {
    id: "ProcessingIntegrity",
    title: "Processing Integrity",
    basis: "AICPA TSC 2017 (rev. 2022) — categoría Processing Integrity (PI1)",
    match: (id) => /^PI\d+$/.test(id),
  },
  {
    id: "Availability",
    title: "Availability",
    basis: "AICPA TSC 2017 (rev. 2022) — categoría Availability (A1)",
    match: (id) => /^A\d+$/.test(id),
  },
  {
    id: "Confidentiality",
    title: "Confidentiality",
    basis: "AICPA TSC 2017 (rev. 2022) — categoría Confidentiality (C1)",
    match: (id) => /^C\d+$/.test(id),
  },
  {
    id: "Privacy",
    title: "Privacy",
    basis: "AICPA TSC 2017 (rev. 2022) — categoría Privacy (P1–P8)",
    match: (id) => /^P\d+$/.test(id),
  },
]

/** NIS2: las medidas de gestión de riesgo del Art. 21(2) son un solo bloque. */
const NIS2_GROUPS: GroupDef[] = [
  {
    id: "Art.21.2",
    title: "Article 21(2) — Cybersecurity risk-management measures (a)–(j)",
    basis: "Directive (EU) 2022/2555 (NIS2), Article 21(2)",
    match: () => true,
  },
]

/** DORA: agrupación por capítulo del Reglamento (EU) 2022/2554. */
const DORA_GROUPS: GroupDef[] = [
  {
    id: "ICTRiskManagement",
    title: "Chapter II — ICT risk management",
    basis: "Regulation (EU) 2022/2554 (DORA), Chapter II (Art. 5–16)",
    match: (id) => doraArticleNumber(id) >= 5 && doraArticleNumber(id) <= 16,
  },
  {
    id: "IncidentManagementAndReporting",
    title: "Chapter III — ICT-related incident management and reporting",
    basis: "Regulation (EU) 2022/2554 (DORA), Chapter III (Art. 17–23)",
    match: (id) => doraArticleNumber(id) >= 17 && doraArticleNumber(id) <= 23,
  },
  {
    id: "DigitalOperationalResilienceTesting",
    title: "Chapter IV — Digital operational resilience testing",
    basis: "Regulation (EU) 2022/2554 (DORA), Chapter IV (Art. 24–27)",
    match: (id) => doraArticleNumber(id) >= 24 && doraArticleNumber(id) <= 27,
  },
  {
    id: "ICTThirdPartyRisk",
    title: "Chapter V — ICT third-party risk",
    basis: "Regulation (EU) 2022/2554 (DORA), Chapter V (Art. 28–44)",
    match: (id) => doraArticleNumber(id) >= 28 && doraArticleNumber(id) <= 44,
  },
]

function doraArticleNumber(controlId: string): number {
  const match = /^Art\.(\d+)$/.exec(controlId)
  return match ? Number(match[1]) : -1
}

const FRAMEWORK_GROUPS: Record<DerivedFramework, GroupDef[]> = {
  soc2: SOC2_GROUPS,
  nis2: NIS2_GROUPS,
  dora: DORA_GROUPS,
}

/** Campo del crosswalk donde vive el mapeo ISO → framework destino. */
const FRAMEWORK_FIELD: Record<DerivedFramework, "soc2" | "nis2" | "dora"> = {
  soc2: "soc2",
  nis2: "nis2",
  dora: "dora",
}

/** Mapa de títulos de los controles declarados por el crosswalk. */
const FRAMEWORK_TITLES: Record<DerivedFramework, string> = {
  soc2: "soc2_trust_services_criteria",
  nis2: "nis2_article21_measures",
  dora: "dora_articles",
}

function readRows(crosswalk: Record<string, unknown>): CrosswalkRow[] {
  const controls = Array.isArray(crosswalk["controls"]) ? crosswalk["controls"] : []
  const rows: CrosswalkRow[] = []
  for (const entry of controls) {
    if (!isRecord(entry)) continue
    const isoId = entry["iso_id"]
    if (typeof isoId !== "string" || isoId.length === 0) continue
    rows.push({
      isoId,
      isoName: typeof entry["iso_name"] === "string" ? entry["iso_name"] : isoId,
      nist: stringList(entry["nist_csf"]),
      soc2: stringList(entry["soc2"]),
      nis2: stringList(entry["nis2"]),
      dora: stringList(entry["dora"]),
    })
  }
  return rows
}

/** Genera los tres catálogos derivados a partir del crosswalk de ISO 27001:2022. */
export function buildDerivedCatalogs(crosswalk: unknown): Record<DerivedFramework, DerivedCatalog> {
  if (!isRecord(crosswalk)) throw new Error("crosswalk inválido: se esperaba un objeto")
  const rows = readRows(crosswalk)
  if (rows.length === 0) throw new Error("crosswalk inválido: sin controles ISO")

  const meta = isRecord(crosswalk["meta"]) ? crosswalk["meta"] : {}
  const crosswalkVersion = typeof meta["version"] === "string" ? meta["version"] : "desconocida"
  const disclaimer =
    typeof meta["disclaimer"] === "string"
      ? meta["disclaimer"]
      : "Los mapeos entre frameworks son interpretativos: revísalos contra el estándar de origen antes de usarlos como evidencia de auditoría."

  const out = {} as Record<DerivedFramework, DerivedCatalog>
  for (const framework of [FRAMEWORKS.soc2, FRAMEWORKS.nis2, FRAMEWORKS.dora] as DerivedFramework[]) {
    out[framework] = buildCatalog(framework, crosswalk, rows, { crosswalkVersion, disclaimer })
  }
  return out
}

function buildCatalog(
  framework: DerivedFramework,
  crosswalk: Record<string, unknown>,
  rows: CrosswalkRow[],
  metaInfo: { crosswalkVersion: string; disclaimer: string },
): DerivedCatalog {
  const field = FRAMEWORK_FIELD[framework]
  const titles = crosswalk[FRAMEWORK_TITLES[framework]]
  if (!isRecord(titles)) throw new Error(`crosswalk inválido: falta ${FRAMEWORK_TITLES[framework]}`)

  const declared = Object.entries(titles).filter(
    (entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].length > 0,
  )
  if (declared.length === 0) throw new Error(`crosswalk inválido: ${FRAMEWORK_TITLES[framework]} vacío`)

  // Mapeo directo: control del framework → controles ISO que lo referencian.
  const direct = new Map<string, { iso: string[]; nist: string[] }>()
  for (const [controlId] of declared) direct.set(controlId, { iso: [], nist: [] })
  for (const row of rows) {
    for (const controlId of row[field]) {
      const entry = direct.get(controlId)
      if (!entry) continue
      if (!entry.iso.includes(row.isoId)) entry.iso.push(row.isoId)
      for (const nistId of row.nist) if (!entry.nist.includes(nistId)) entry.nist.push(nistId)
    }
  }

  // Equivalencia NIST: controles ISO sin mapeo directo a este framework pero
  // que comparten subcategoría NIST CSF 2.0 con un control mapeado directamente.
  const unmappedRows = rows.filter((row) => row[field].length === 0)
  const equivalenceFor = (controlId: string): string[] => {
    const entry = direct.get(controlId)
    if (!entry || entry.nist.length === 0) return []
    const nistSet = new Set(entry.nist)
    return unmappedRows
      .filter((row) => row.nist.some((nistId) => nistSet.has(nistId)))
      .map((row) => row.isoId)
      .sort()
  }

  const groups = FRAMEWORK_GROUPS[framework]
  const controls: DerivedControl[] = []
  let sort = 0
  const nextSort = () => String(++sort).padStart(5, "0")

  // Un control declarado que ningún control ISO referencia no se puede
  // evaluar: se excluye del catálogo computable y queda registrado en el meta
  // (inventarlo o contarlo como conforme mentiría en el informe).
  const declaredButUnmapped = declared
    .filter(([controlId]) => (direct.get(controlId)?.iso.length ?? 0) === 0)
    .map(([controlId]) => controlId)

  const coveredByEquivalence = new Set<string>()
  for (const group of groups) {
    const members = declared.filter(
      ([controlId]) => group.match(controlId) && !declaredButUnmapped.includes(controlId),
    )
    if (members.length === 0) continue
    controls.push({
      id: group.id,
      title: group.title,
      parentId: null,
      level: "theme",
      sortId: nextSort(),
      framework,
      attributes: { groupingBasis: group.basis, mappingBasis: "structure" },
      source: CROSSWALK_SOURCE,
    })
    for (const [controlId, title] of members) {
      const entry = direct.get(controlId)
      const isoEquivalents = entry?.iso ?? []
      const nistEquivalents = entry?.nist ?? []
      const isoByEquivalence = equivalenceFor(controlId)
      for (const isoId of isoByEquivalence) coveredByEquivalence.add(isoId)
      if (isoEquivalents.length === 0 && nistEquivalents.length === 0 && isoByEquivalence.length === 0) {
        throw new Error(
          `${framework}: el control ${controlId} no tiene equivalencia trazable en el crosswalk — no se inventa`,
        )
      }
      controls.push({
        id: controlId,
        title,
        parentId: group.id,
        level: "control",
        sortId: nextSort(),
        framework,
        attributes: {
          // El control queda mapeado directamente por el crosswalk. Los
          // controles ISO que NO tienen fila para este framework pero que
          // comparten subcategoría NIST CSF 2.0 con los que sí la tienen
          // quedan listados aparte: su cobertura es heredada por
          // equivalencia, no directa.
          mappingBasis: isoEquivalents.length > 0 ? "direct" : "equivalence",
          isoEquivalents,
          isoEquivalentsByEquivalence: isoByEquivalence,
          nistEquivalents,
        },
        source: CROSSWALK_SOURCE,
      })
    }
  }

  // Controles declarados que no caen en ningún grupo: no se descartan en
  // silencio, se fail-ea para que el crosswalk y el catálogo vuelvan a
  // alinearse (nunca queda un control huérfano sin grupo).
  const grouped = new Set(controls.filter((node) => node.level === "control").map((node) => node.id))
  const orphans = declared
    .map(([controlId]) => controlId)
    .filter((controlId) => !grouped.has(controlId) && !declaredButUnmapped.includes(controlId))
  if (orphans.length > 0) {
    throw new Error(`${framework}: controles declarados sin grupo: ${orphans.join(", ")}`)
  }

  const unmappedIsoControls = rows
    .filter((row) => row[field].length === 0)
    .map((row) => row.isoId)
    .sort()

  return {
    meta: {
      framework,
      title: FRAMEWORK_META[framework].title,
      version: FRAMEWORK_META[framework].version,
      generatedFrom: CROSSWALK_SOURCE,
      crosswalkVersion: metaInfo.crosswalkVersion,
      disclaimer: metaInfo.disclaimer,
      unmappedIsoControls,
      isoControlsCoveredByEquivalence: [...coveredByEquivalence].sort(),
      declaredButUnmappedControls: declaredButUnmapped.sort(),
    },
    controls,
  }
}
