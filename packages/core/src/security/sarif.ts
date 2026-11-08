import type { FindingTable } from "./sql"

/**
 * One step of the taint path of a finding: the ordered source → propagator →
 * sink chain that explains why a static analyzer flagged the code.
 */
export interface SarifDataflowStep {
  file?: string
  line?: number
  endLine?: number
  message?: string
  snippet?: string
  importance?: string
}

/** A suppression declared by the engine for a result it already discarded. */
export interface SarifSuppression {
  kind: "inSource" | "external"
  status?: string
  justification?: string
}

/**
 * Forma mínima que necesita el generador SARIF — desacoplada de `FindingRow`
 * para que tanto el motor server-side (findings con fila en BD) como el
 * cliente (findings vivos parseados de tool-calls, sin `id` persistido)
 * compartan un único generador en vez de reimplementarlo cada uno por su lado.
 */
export interface SarifFinding {
  id: string
  fingerprint?: string
  title: string
  severity: string
  status: string
  cwe?: string
  owasp?: string[]
  references?: string[]
  vector?: string
  target?: string
  remediation?: string
  tags?: string[]
  attackTechniqueIds?: string[]
  sourceTool?: string
  epssScore?: number
  epssPercentile?: number
  cisaKev?: boolean
  /** Solo presente si el agente declaró un vector CVSS explícito — ver security/cvss.ts. Nunca inferido. */
  cvssScore?: number
  cvssVector?: string
  /** Taint path de la regla: se exporta como `codeFlows` del resultado SARIF. */
  dataflow?: SarifDataflowStep[]
  /** Identificadores estables del hallazgo — se exportan como `partialFingerprints`. */
  partialFingerprints?: Record<string, string>
  /** Supresiones declaradas por el motor — se exportan como `suppressions`. */
  suppressions?: SarifSuppression[]
  feedback?: {
    verdict: "false-positive" | "true-positive" | "accepted-risk"
    reason?: string
    actor: "human" | "agent"
    updatedAt?: number
  }
}

export interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription?: { text: string }
  defaultConfiguration: { level: "error" | "warning" | "note" | "none" }
  helpUri?: string
  properties?: {
    tags?: string[]
    cwe?: string[]
    owasp?: string[]
    attack?: string[]
    epssScore?: number
    epssPercentile?: number
    cisaKev?: boolean
    cvssScore?: number
    cvssVector?: string
    "security-severity"?: string
  }
}

export interface SarifTaxonomy {
  id: string
  name: string
  toolComponent: { name: string }
  informationUri?: string
}

/**
 * Referencia a taxonomía en la forma que exige el JSON Schema oficial de
 * SARIF 2.1.0 (`result.taxa` → `reportingDescriptorReference`): sólo admite
 * `id`, `toolComponent`, `index`, `guid` y `properties`. El nombre legible y
 * la URL viajan en `properties` porque el schema los rechaza en la raíz.
 */
export interface SarifTaxon {
  id: string
  toolComponent: { name: string }
  properties?: Record<string, string>
}

export interface SarifCodeFlow {
  message?: { text: string }
  threadFlows: Array<{
    locations: Array<{
      location: {
        physicalLocation: {
          artifactLocation: { uri: string }
          region?: { startLine?: number; endLine?: number; snippet?: { text: string } }
        }
        message?: { text: string }
      }
      importance?: string
    }>
  }>
}

export interface SarifResult {
  ruleId: string
  ruleIndex?: number
  message: { text: string }
  level: "error" | "warning" | "note" | "none"
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string }
      region?: { startLine?: number; endLine?: number; snippet?: { text: string } }
    }
  }>
  codeFlows?: SarifCodeFlow[]
  partialFingerprints?: Record<string, string>
  suppressions?: SarifSuppression[]
  /** Taxonomías en la forma estándar del schema SARIF 2.1.0 (`result.taxa`). */
  taxa?: SarifTaxon[]
  /**
   * Taxonomías con la forma extendida que consume el parser Go
   * (`argos-bin/cmd/web/tools/sarif.go`). Se mantiene por compatibilidad: el
   * export profesional los traduce a `taxa`.
   */
  taxonomies?: SarifTaxonomy[]
  fixes?: Array<{ description?: { text: string } }>
  properties?: {
    findingId: string
    severity: string
    status: string
    sourceTool?: string
    remediation?: string
    epssScore?: number
    cisaKev?: boolean
    cvssScore?: number
    cvssVector?: string
    cwe?: string[]
    owasp?: string[]
    "security-severity"?: string
    dataflow?: SarifDataflowStep[]
    partialFingerprints?: Record<string, string>
    argosFeedback?: SarifFinding["feedback"]
  }
}

export interface SarifLog {
  $schema: string
  version: "2.1.0"
  runs: Array<{
    tool: {
      driver: {
        name: string
        version: string
        informationUri: string
        rules: SarifRule[]
      }
    }
    results: SarifResult[]
  }>
}

type FindingRow = typeof FindingTable.$inferSelect

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

/** Extrae la forma genérica `SarifFinding` de una fila persistida — digiere el JSON de `enrichment`. */
export function fromFindingRow(f: FindingRow): SarifFinding {
  const enrichment = f.enrichment as unknown as Record<string, unknown> | null | undefined
  const epssKev = enrichment?.epssKev as Record<string, unknown> | undefined
  const epssScore =
    typeof epssKev?.epssScore === "number"
      ? epssKev.epssScore
      : typeof (epssKev?.epss as Record<string, unknown> | undefined)?.epssScore === "number"
        ? ((epssKev?.epss as Record<string, unknown>).epssScore as number)
        : undefined
  const epssPercentile =
    typeof epssKev?.epssPercentile === "number"
      ? epssKev.epssPercentile
      : typeof (epssKev?.epss as Record<string, unknown> | undefined)?.epssPercentile === "number"
        ? ((epssKev?.epss as Record<string, unknown>).epssPercentile as number)
        : undefined
  const cisaKev =
    typeof epssKev?.cisaKev === "boolean"
      ? epssKev.cisaKev
      : typeof (epssKev?.cisaKev as Record<string, unknown> | undefined)?.isKev === "boolean"
        ? ((epssKev?.cisaKev as Record<string, unknown>).isKev as boolean)
        : undefined
  const cvss = enrichment?.cvss as Record<string, unknown> | undefined
  const cvssScore = typeof cvss?.score === "number" ? cvss.score : undefined
  const cvssVector = typeof cvss?.vectorString === "string" ? cvss.vectorString : undefined

  const evidence = isRecord(f.evidence) ? f.evidence : {}
  const dataflow = Array.isArray(evidence.dataflow) ? (evidence.dataflow as SarifDataflowStep[]) : undefined
  const partialFingerprints = isRecord(evidence.partialFingerprints)
    ? (evidence.partialFingerprints as Record<string, string>)
    : undefined
  const suppressions = Array.isArray(evidence.suppressions) ? (evidence.suppressions as SarifSuppression[]) : undefined

  return {
    id: f.id,
    fingerprint: f.fingerprint,
    title: f.title,
    severity: f.severity,
    status: f.status,
    cwe: f.cwe ?? undefined,
    owasp: f.owasp ?? undefined,
    references: f.references ?? undefined,
    vector: f.vector ?? undefined,
    target: f.target ?? undefined,
    remediation: f.remediation ?? undefined,
    tags: f.tags ?? undefined,
    attackTechniqueIds: f.attack_techniques?.map((t) => t.id),
    sourceTool: f.source_tool ?? undefined,
    epssScore,
    epssPercentile,
    cisaKev,
    cvssScore,
    cvssVector,
    dataflow,
    partialFingerprints,
    suppressions,
  }
}

function severityToSarifLevel(severity: string): "error" | "warning" | "note" | "none" {
  switch (severity.toLowerCase().trim()) {
    case "critical":
    case "critico":
    case "high":
    case "alto":
      return "error"
    case "medium":
    case "medio":
      return "warning"
    case "low":
    case "bajo":
    case "info":
    case "informativo":
      return "note"
    default:
      return "warning"
  }
}

/** Nivel SARIF a partir de un score CVSS numérico real — más autoritativo que la severidad de texto libre cuando está disponible. */
function cvssScoreToSarifLevel(score: number): "error" | "warning" | "note" | "none" {
  if (score >= 7) return "error"
  if (score >= 4) return "warning"
  if (score > 0) return "note"
  return "none"
}

/**
 * Convierte un arreglo de hallazgos en formato estándar OASIS SARIF v2.1.0
 * compatible con GitHub Code Scanning, Azure DevOps, GitLab SAST/DAST y DefectDojo.
 *
 * Acepta `SarifFinding` genérico, no filas de BD — así el mismo generador
 * sirve tanto para hallazgos persistidos (vía `fromFindingRow`) como para
 * hallazgos vivos parseados de tool-calls que todavía no tienen fila propia.
 *
 * El documento lleva la señal completa del hallazgo (taxonomías CWE/OWASP,
 * `codeFlows` con el dataflow del taint, `partialFingerprints` para deduplicar
 * entre corridas y `suppressions`): un export reparseado por el parser Go
 * (argos-bin/cmd/web/tools/sarif.go) conserva el hallazgo completo.
 */
export function generateSarifLog(findings: SarifFinding[], meta?: { target?: string; runName?: string }): SarifLog {
  const rules: SarifRule[] = []
  const ruleIndexes = new Map<string, number>()
  const results: SarifResult[] = []

  for (const f of findings) {
    const ruleId = f.cwe
      ? `ARGOS-${f.cwe.toUpperCase().replace(/[^A-Z0-9-]/g, "")}`
      : `ARGOS-${(f.fingerprint ?? f.title)
          .slice(0, 8)
          .toUpperCase()
          .replace(/[^A-Z0-9]/g, "")}`

    const { epssScore, epssPercentile, cisaKev, cvssScore, cvssVector } = f
    const level = cvssScore !== undefined ? cvssScoreToSarifLevel(cvssScore) : severityToSarifLevel(f.severity)

    let ruleIndex = ruleIndexes.get(ruleId)
    if (ruleIndex === undefined) {
      const attackIds = f.attackTechniqueIds ?? []
      const tags = [...(f.tags ?? [])]
      if (f.cwe) tags.push(f.cwe)
      if (attackIds.length > 0) tags.push(...attackIds)
      if (cisaKev) tags.push("CISA-KEV-ACTIVE")

      const rule: SarifRule = {
        id: ruleId,
        name: f.title.replace(/[^a-zA-Z0-9]/g, "_").slice(0, 64) || ruleId,
        shortDescription: { text: f.title },
        fullDescription: f.remediation ? { text: `${f.title}\n\nRemediación: ${f.remediation}` } : undefined,
        defaultConfiguration: { level },
        helpUri: f.cwe
          ? `https://cwe.mitre.org/data/definitions/${f.cwe.replace(/^CWE-/i, "")}.html`
          : "https://github.com/iwiels/ARGOS",
        properties: {
          tags,
          cwe: f.cwe ? [f.cwe] : undefined,
          owasp: f.owasp && f.owasp.length > 0 ? f.owasp : undefined,
          attack: attackIds.length > 0 ? attackIds : undefined,
          epssScore,
          epssPercentile,
          cisaKev,
          cvssScore,
          cvssVector,
          "security-severity": cvssScore !== undefined ? cvssScore.toFixed(1) : undefined,
        },
      }
      ruleIndex = rules.length
      rules.push(rule)
      ruleIndexes.set(ruleId, ruleIndex)
    }

    const uri = f.vector || f.target || meta?.target || "https://target.local"

    const taxonomies: SarifTaxonomy[] = []
    if (f.cwe) {
      taxonomies.push({
        id: f.cwe,
        name: f.cwe,
        toolComponent: { name: "CWE" },
        informationUri: `https://cwe.mitre.org/data/definitions/${f.cwe.replace(/^CWE-/i, "")}.html`,
      })
    }
    for (const owasp of f.owasp ?? []) {
      taxonomies.push({ id: owasp, name: owasp, toolComponent: { name: "OWASP" } })
    }

    // La misma taxonomía, en la forma que exige el schema oficial (`taxa`).
    const taxa: SarifTaxon[] = taxonomies.map((taxonomy) => ({
      id: taxonomy.id,
      toolComponent: { name: taxonomy.toolComponent.name },
      properties: {
        name: taxonomy.name,
        ...(taxonomy.informationUri ? { informationUri: taxonomy.informationUri } : {}),
      },
    }))

    const partialFingerprints: Record<string, string> = { ...(f.partialFingerprints ?? {}) }
    if (f.fingerprint && !partialFingerprints["argos/v1"]) {
      partialFingerprints["argos/v1"] = f.fingerprint
    }

    const statusSuppressions = f.suppressions && f.suppressions.length > 0 ? f.suppressions : defaultSuppressions(f.status)
    const feedbackSuppression: SarifSuppression[] =
      f.feedback && f.feedback.verdict !== "true-positive"
        ? [
            {
              kind: "external",
              status: "accepted",
              justification: [f.feedback.verdict, f.feedback.reason].filter(Boolean).join(": "),
            },
          ]
        : []
    const suppressions = [...feedbackSuppression, ...(statusSuppressions ?? [])]

    results.push({
      ruleId,
      ruleIndex,
      message: {
        text: `${f.title} [Severidad: ${f.severity.toUpperCase()}${cvssScore !== undefined ? ` | CVSS ${cvssScore.toFixed(1)}` : ""}${cisaKev ? " | CISA KEV ACTIVO" : ""}${epssScore !== undefined ? ` | EPSS: ${(epssScore * 100).toFixed(1)}%` : ""}]`,
      },
      level,
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
          },
        },
      ],
      codeFlows: buildCodeFlows(f.dataflow, uri),
      partialFingerprints: Object.keys(partialFingerprints).length > 0 ? partialFingerprints : undefined,
      suppressions,
      taxa: taxa.length > 0 ? taxa : undefined,
      taxonomies: taxonomies.length > 0 ? taxonomies : undefined,
      properties: {
        findingId: f.id,
        severity: f.severity,
        status: f.status,
        sourceTool: f.sourceTool || undefined,
        remediation: f.remediation || undefined,
        epssScore,
        cisaKev,
        cvssScore,
        cvssVector,
        cwe: f.cwe ? [f.cwe] : undefined,
        owasp: f.owasp && f.owasp.length > 0 ? f.owasp : undefined,
        "security-severity": cvssScore !== undefined ? cvssScore.toFixed(1) : undefined,
        dataflow: f.dataflow,
        partialFingerprints: Object.keys(partialFingerprints).length > 0 ? partialFingerprints : undefined,
        argosFeedback: f.feedback,
      },
    })
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Argos Security Operations Engine",
            version: "1.0.0",
            informationUri: "https://github.com/iwiels/ARGOS",
            rules,
          },
        },
        results,
      },
    ],
  }
}

/** Un hallazgo marcado como falso positivo viaja suprimido: el parser Go lo descarta. */
function defaultSuppressions(status: string | undefined): SarifSuppression[] | undefined {
  const normalized = status?.trim().toLowerCase()
  if (normalized === "false-positive" || normalized === "accepted-risk") {
    return [{ kind: "external", status: "accepted" }]
  }
  return undefined
}

/** El schema SARIF sólo admite estos tres valores de `importance`. */
const SARIF_IMPORTANCE = new Set(["important", "essential", "unimportant"])

/** Convierte el dataflow del hallazgo en los `codeFlows` del resultado SARIF. */
function buildCodeFlows(dataflow: SarifDataflowStep[] | undefined, fallbackUri: string): SarifCodeFlow[] | undefined {
  if (!dataflow || dataflow.length === 0) return undefined
  return [
    {
      message: { text: "Taint path reported by the analyzer" },
      threadFlows: [
        {
          locations: dataflow.map((step) => ({
            location: {
              physicalLocation: {
                artifactLocation: { uri: step.file ?? fallbackUri },
                region: {
                  ...(step.line && step.line >= 1 ? { startLine: step.line } : {}),
                  ...(step.endLine && step.endLine >= 1 ? { endLine: step.endLine } : {}),
                  ...(step.snippet ? { snippet: { text: step.snippet } } : {}),
                },
              },
              ...(step.message ? { message: { text: step.message } } : {}),
            },
            ...(step.importance && SARIF_IMPORTANCE.has(step.importance) ? { importance: step.importance } : {}),
          })),
        },
      ],
    },
  ]
}

/** Lee el identificador CWE de una lista de etiquetas o taxonomías. */
function extractCweId(values: unknown): string | undefined {
  if (!Array.isArray(values)) return undefined
  for (const value of values) {
    if (typeof value !== "string") continue
    const match = value.match(/cwe[-_ ]?(\d{1,6})/i)
    if (match) return `CWE-${match[1]}`
  }
  return undefined
}

/** Lee el identificador OWASP ("A03:2021") de una lista de etiquetas o taxonomías. */
function extractOwaspId(values: unknown): string[] {
  if (!Array.isArray(values)) return []
  const out: string[] = []
  for (const value of values) {
    if (typeof value !== "string") continue
    const match = value.match(/owasp[^a-z0-9]*(a\d{2}(?::\d{4})?)/i) ?? value.match(/^(a\d{2}:\d{4})$/i)
    if (match) {
      const id = match[1].toUpperCase()
      if (!out.includes(id)) out.push(id)
    }
  }
  return out
}

/** Aplana los `codeFlows` de un resultado SARIF en los pasos del dataflow. */
function extractDataflow(result: SarifResult): SarifDataflowStep[] | undefined {
  const steps: SarifDataflowStep[] = []
  for (const flow of result.codeFlows ?? []) {
    for (const thread of flow.threadFlows ?? []) {
      for (const entry of thread.locations ?? []) {
        const phys = entry.location?.physicalLocation
        if (!phys) continue
        const step: SarifDataflowStep = {
          file: phys.artifactLocation?.uri,
          line: phys.region?.startLine,
          endLine: phys.region?.endLine,
          message: entry.location?.message?.text,
          snippet: phys.region?.snippet?.text,
          importance: entry.importance,
        }
        steps.push(step)
      }
    }
  }
  return steps.length > 0 ? steps : undefined
}

/**
 * Ingesta y normaliza un documento SARIF v2.1.0 a la estructura canónica SarifFinding[].
 */
export function fromSarifLog(sarif: SarifLog): SarifFinding[] {
  const findings: SarifFinding[] = []
  for (const run of sarif.runs ?? []) {
    const toolName = run.tool?.driver?.name || "unknown-tool"
    const rules = run.tool?.driver?.rules ?? []
    for (const res of run.results ?? []) {
      const loc = res.locations?.[0]?.physicalLocation
      const uri = loc?.artifactLocation?.uri || ""
      const line = loc?.region?.startLine

      let severity = "medium"
      switch (res.level) {
        case "error":
          severity = "high"
          break
        case "warning":
          severity = "medium"
          break
        case "note":
          severity = "low"
          break
      }

      const taxonomyIds = (res.taxonomies ?? []).map((taxonomy) => taxonomy.id)
      const rule = typeof res.ruleIndex === "number" ? rules[res.ruleIndex] : undefined
      const cwe =
        extractCweId(res.properties?.cwe) ??
        extractCweId(taxonomyIds) ??
        extractCweId(rule?.properties?.cwe) ??
        extractCweId(rule?.properties?.tags)
      const owasp = Array.from(
        new Set([
          ...extractOwaspId(res.properties?.owasp),
          ...extractOwaspId(taxonomyIds),
          ...extractOwaspId(rule?.properties?.owasp),
          ...extractOwaspId(rule?.properties?.tags),
        ]),
      )

      findings.push({
        id: res.properties?.findingId || `sarif_${res.ruleId}_${Date.now()}_${findings.length}`,
        title: res.ruleId || res.message?.text || "SARIF Finding",
        severity: res.properties?.severity || severity,
        status: res.properties?.status || "suspected",
        cwe,
        owasp: owasp.length > 0 ? owasp : undefined,
        target: uri,
        vector: line ? `${uri}#L${line}` : uri,
        sourceTool: res.properties?.sourceTool || toolName,
        remediation: res.properties?.remediation,
        tags: ["sarif", toolName.toLowerCase()],
        cvssScore: res.properties?.cvssScore,
        cvssVector: res.properties?.cvssVector,
        dataflow: extractDataflow(res) ?? res.properties?.dataflow,
        partialFingerprints: {
          ...(res.properties?.partialFingerprints ?? {}),
          ...(res.partialFingerprints ?? {}),
        },
        suppressions: res.suppressions,
      })
    }
  }
  return findings
}
