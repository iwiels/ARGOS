/** Parsers puros de las fuentes públicas de compliance. Sin IO ni Effect:
 *  reciben el JSON descargado y devuelven nodos de catálogo y mappings. */

import { FRAMEWORKS, type ControlMapping, type ControlNode, type Framework } from "./types"

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

const stringOf = (value: unknown) => (typeof value === "string" ? value : undefined)

const sortIdOf = (node: unknown) => {
  if (!isRecord(node) || !Array.isArray(node["props"])) return undefined
  for (const prop of node["props"]) {
    if (isRecord(prop) && prop["name"] === "sort-id") return stringOf(prop["value"])
  }
  return undefined
}

/** El catálogo OSCAL conserva subcategorías retiradas (status: withdrawn). */
const isWithdrawn = (node: unknown) => {
  if (!isRecord(node) || !Array.isArray(node["props"])) return false
  for (const prop of node["props"]) {
    if (isRecord(prop) && prop["name"] === "status" && prop["value"] === "withdrawn") return true
  }
  return false
}

/**
 * NIST CSF 2.0 (OSCAL). Estructura:
 * catalog.groups[] = funciones → controls[] = categorías → controls[] = subcategorías
 * (título real en parts[].prose con name === "statement").
 */
export function parseNistOscal(json: unknown): ControlNode[] {
  if (!isRecord(json) || !isRecord(json["catalog"])) return []
  const groups = Array.isArray(json["catalog"]["groups"]) ? json["catalog"]["groups"] : []
  const out: ControlNode[] = []

  for (const group of groups) {
    if (!isRecord(group)) continue
    const functionId = stringOf(group["id"])
    if (!functionId) continue
    const functionTitle = stringOf(group["title"]) ?? functionId
    out.push({
      id: functionId,
      title: functionTitle,
      parentId: null,
      level: "function",
      sortId: sortIdOf(group),
      framework: FRAMEWORKS.nistCsfV2,
      attributes: { functionId, functionTitle },
      source: "NIST CSF 2.0 OSCAL",
    })

    const categories = Array.isArray(group["controls"]) ? group["controls"] : []
  for (const category of categories) {
    if (!isRecord(category) || isWithdrawn(category)) continue
    const categoryId = stringOf(category["id"])
    if (!categoryId) continue
      const categoryTitle = stringOf(category["title"]) ?? categoryId
      out.push({
        id: categoryId,
        title: categoryTitle,
        parentId: functionId,
        level: "category",
        sortId: sortIdOf(category),
        framework: FRAMEWORKS.nistCsfV2,
        attributes: { functionId, functionTitle, categoryId, categoryTitle },
        source: "NIST CSF 2.0 OSCAL",
      })

      const subcategories = Array.isArray(category["controls"]) ? category["controls"] : []
      for (const sub of subcategories) {
        if (!isRecord(sub) || isWithdrawn(sub)) continue
        const subId = stringOf(sub["id"])
        if (!subId) continue
        const title = statementProse(sub) ?? stringOf(sub["title"]) ?? subId
        out.push({
          id: subId,
          title,
          parentId: categoryId,
          level: "subcategory",
          sortId: sortIdOf(sub),
          framework: FRAMEWORKS.nistCsfV2,
          attributes: { functionId, functionTitle, categoryId, categoryTitle, subcategoryId: subId },
          source: "NIST CSF 2.0 OSCAL",
        })
      }
    }
  }
  return out
}

function statementProse(node: Record<string, unknown>): string | undefined {
  if (!Array.isArray(node["parts"])) return undefined
  for (const part of node["parts"]) {
    if (isRecord(part) && part["name"] === "statement") return stringOf(part["prose"])
  }
  return undefined
}

/** Temas ISO 27001:2022 → prefijo de ID (A.5..A.8). */
const ISO_THEMES: Record<string, string> = {
  Organizational: "A.5",
  People: "A.6",
  Physical: "A.7",
  Technological: "A.8",
}

/**
 * workmcg/control-crosswalk: ISO 27001:2022 (93/93) ↔ NIST CSF 2.0.
 * Devuelve los nodos ISO (temas + controles) y el cross-mapping en ambas
 * direcciones (ISO → NIST y NIST → ISO).
 */
export function parseIsoCrosswalk(json: unknown): { controls: ControlNode[]; mappings: ControlMapping[] } {
  if (!isRecord(json) || !Array.isArray(json["controls"])) return { controls: [], mappings: [] }
  const out: ControlNode[] = []
  const mappings: ControlMapping[] = []
  const themeSeen = new Set<string>()

  for (const entry of json["controls"]) {
    if (!isRecord(entry)) continue
    const isoId = stringOf(entry["iso_id"])
    const isoName = stringOf(entry["iso_name"])
    if (!isoId || !isoName) continue
    const themeName = stringOf(entry["iso_theme"]) ?? "Organizational"
    const themeId = ISO_THEMES[themeName] ?? "A.5"

    if (!themeSeen.has(themeId)) {
      themeSeen.add(themeId)
      out.push({
        id: themeId,
        title: themeName,
        parentId: null,
        level: "theme",
        framework: FRAMEWORKS.iso27001,
        attributes: { themeId, themeTitle: themeName },
        source: "workmcg/control-crosswalk",
      })
    }

    out.push({
      id: isoId,
      title: isoName,
      parentId: themeId,
      level: "control",
      framework: FRAMEWORKS.iso27001,
      attributes: { themeId, themeTitle: themeName, isoId },
      source: "workmcg/control-crosswalk",
    })

    const nist = Array.isArray(entry["nist_csf"]) ? entry["nist_csf"].filter(stringOf) : []
    for (const nistId of nist) {
      if (typeof nistId !== "string") continue
      mappings.push(
        {
          sourceFramework: FRAMEWORKS.iso27001,
          sourceControlId: isoId,
          targetFramework: FRAMEWORKS.nistCsfV2,
          targetControlId: nistId,
        },
        {
          sourceFramework: FRAMEWORKS.nistCsfV2,
          sourceControlId: nistId,
          targetFramework: FRAMEWORKS.iso27001,
          targetControlId: isoId,
        },
      )
    }
  }
  return { controls: out, mappings }
}

/**
 * Catálogo derivado (SOC 2 / NIS2 / DORA) generado desde el crosswalk de
 * ISO 27001:2022 con `scripts/gen-compliance-catalogs.ts`.
 * Formato: `{ meta, controls: [{ id, title, parentId, level, sortId, framework,
 * attributes, source }] }` — los nodos ya vienen con su jerarquía.
 */
export function parseDerivedCatalog(json: unknown, framework: Framework): ControlNode[] {
  if (!isRecord(json) || !Array.isArray(json["controls"])) return []
  const out: ControlNode[] = []
  for (const entry of json["controls"]) {
    if (!isRecord(entry)) continue
    const id = stringOf(entry["id"])
    const title = stringOf(entry["title"])
    if (!id || !title) continue
    const level = stringOf(entry["level"])
    if (!level || !isControlLevel(level)) continue
    out.push({
      id,
      title,
      parentId: stringOf(entry["parentId"]) ?? null,
      level,
      sortId: stringOf(entry["sortId"]),
      framework,
      attributes: isRecord(entry["attributes"]) ? entry["attributes"] : {},
      source: stringOf(entry["source"]) ?? "iso27001_crosswalk.json (bundled)",
    })
  }
  return out
}

const CONTROL_LEVELS = new Set(["function", "category", "subcategory", "theme", "control"])

const isControlLevel = (value: string): value is ControlNode["level"] => CONTROL_LEVELS.has(value)

/**
 * saasfort/nis2-controls: keywords de checks externos por control.
 * - NIST: `control: "NIST.PR.DS"` (nivel categoría).
 * - ISO: `control: "ISO27001 A.8.24"` (nivel control).
 */
export function parseChecks(json: unknown, framework: Framework): Map<string, string[]> {
  const out = new Map<string, string[]>()
  if (!isRecord(json) || !Array.isArray(json["controls"])) return out
  for (const entry of json["controls"]) {
    if (!isRecord(entry)) continue
    const raw = stringOf(entry["control"])
    if (!raw) continue
    const controlId = framework === FRAMEWORKS.nistCsfV2 ? raw.replace(/^NIST\./, "") : raw.replace(/^ISO27001\s+/, "")
    const checks = Array.isArray(entry["checks"]) ? entry["checks"].filter(stringOf) : []
    if (checks.length > 0) out.set(controlId, checks as string[])
  }
  return out
}

/**
 * Fusiona checks de NIST e ISO en un índice keyword → controles.
 *  Cada entrada preserva el framework: los IDs pueden colisionar entre
 *  frameworks y un keyword no debe mapear el mismo control de ambos.
 *
 *  La señal conserva su **naturaleza** (`kind`) para que la derivación pueda
 *  calibrar la confianza del vínculo finding↔control:
 *  - `header`: el check nombra una cabecera de seguridad HTTP verificable
 *    (HSTS, CSP, X-Frame-Options…) — evidencia directa del header.
 *  - `check`: el check completo de un catálogo externo ("CAA record").
 *  - `word`: fragmento de una palabra del check (≥4 chars) — coincidencia
 *    léxica débil.
 */
export function buildSignalIndex(
  nistChecks: Map<string, string[]>,
  isoChecks: Map<string, string[]>,
): SignalIndex {
  const index: SignalIndex = new Map()
  const add = (framework: Framework, controlId: string, keyword: string, kind: SignalKind) => {
    const key = normalizeKeyword(keyword)
    if (!key) return
    const existing = index.get(key)
    if (existing) {
      const hit = existing.find((entry) => entry.framework === framework && entry.controlId === controlId)
      if (hit) {
        // El mismo keyword puede llegar como check completo y como fragmento:
        // gana la señal más fuerte.
        if (SIGNAL_RANK[kind] > SIGNAL_RANK[hit.kind]) hit.kind = kind
        return
      }
      existing.push({ framework, controlId, kind })
      return
    }
    index.set(key, [{ framework, controlId, kind }])
  }
  for (const [controlId, checks] of nistChecks) {
    for (const check of checks) {
      const kind = checkKind(check)
      add(FRAMEWORKS.nistCsfV2, controlId, check, kind)
      // Palabras significativas del check (≥4 chars) para matchear títulos largos.
      for (const word of check.toLowerCase().split(/[^a-z0-9-]+/)) {
        if (word.length >= 4 && !STOPWORDS.has(word)) add(FRAMEWORKS.nistCsfV2, controlId, word, "word")
      }
    }
  }
  for (const [controlId, checks] of isoChecks) {
    for (const check of checks) {
      const kind = checkKind(check)
      add(FRAMEWORKS.iso27001, controlId, check, kind)
      for (const word of check.toLowerCase().split(/[^a-z0-9-]+/)) {
        if (word.length >= 4 && !STOPWORDS.has(word)) add(FRAMEWORKS.iso27001, controlId, word, "word")
      }
    }
  }
  return index
}

/** Naturaleza de una señal del catálogo de checks externos. */
export type SignalKind = "header" | "check" | "word"

export interface SignalTarget {
  framework: Framework
  controlId: string
  kind: SignalKind
}

export type SignalIndex = Map<string, SignalTarget[]>

const SIGNAL_RANK: Record<SignalKind, number> = { word: 1, check: 2, header: 3 }

/**
 * Cabeceras de seguridad HTTP. Un check que nombra una de ellas es evidencia
 * directa de que el escáner verificó esa cabecera: confianza `high`.
 */
const SECURITY_HEADERS = new Set([
  "hsts",
  "strict-transport-security",
  "csp",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "x-xss-protection",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "access-control-allow-origin",
])

/** Clasifica un check externo: cabecera de seguridad, check completo o genérico. */
export function checkKind(check: string): SignalKind {
  const normalized = normalizeKeyword(check)
  if (SECURITY_HEADERS.has(normalized)) return "header"
  // "Strict Transport Security" y "Strict-Transport-Security" son la misma
  // cabecera: se comparan también con los separadores unificados.
  if (SECURITY_HEADERS.has(normalized.replace(/[^a-z0-9]+/g, "-"))) return "header"
  const words = normalized.split(/[^a-z0-9-]+/).filter(Boolean)
  if (words.some((word) => SECURITY_HEADERS.has(word))) return "header"
  return "check"
}

const normalizeKeyword = (value: string) => value.trim().toLowerCase().replace(/\s+/g, " ")

const STOPWORDS = new Set([
  "check",
  "with",
  "from",
  "this",
  "that",
  "have",
  "been",
  "being",
  "into",
  "over",
  "under",
  "using",
  "based",
  "against",
  "during",
  "content",
])
