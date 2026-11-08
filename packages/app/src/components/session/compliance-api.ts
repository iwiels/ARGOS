import type { Requester } from "./security-findings-api"
import { booleanValue, numberValue, safeJson, stringValue } from "./api-utils"

export type ComplianceStatus = "deficient" | "partial" | "compliant" | "unassessed"

/** Confianza de la derivación (no la del hallazgo). */
export type EvidenceConfidence = "high" | "medium" | "low"

export interface ComplianceEvidence {
  findingID: string
  title: string
  severity: string
  status: string
  tool?: string
  fromElasticsearch: boolean
  timeUpdated: number
  /** CWE del hallazgo. */
  cwe?: string
  /** Regla que derivó el control a partir de este hallazgo. */
  derivedFrom?: string
  /** Confianza de esa derivación. */
  confidence?: EvidenceConfidence
}

/** Hallazgo resumido dentro de una entrada de evidencia auditable. */
export interface ControlEvidenceFinding {
  id: string
  title: string
  severity: string
  cwe?: string
  sourceTool?: string
  confidence?: string
}

/** Regla que derivó el control + los hallazgos que la activaron. */
export interface ControlEvidence {
  derivedFrom: string
  findings: ControlEvidenceFinding[]
  confidence: EvidenceConfidence
}

export interface ComplianceNode {
  id: string
  title: string
  level: string
  status: ComplianceStatus
  findingCount: number
  evidence: ComplianceEvidence[]
  /** Evidencia auditable agrupada por regla. */
  derivation: ControlEvidence[]
  /** Confianza agregada del control. */
  confidence: EvidenceConfidence
  children: ComplianceNode[]
}

export interface ComplianceFramework {
  framework: string
  title: string
  version: string
  refreshedAt?: number
  tree: ComplianceNode
}

export interface ComplianceStatusResponse {
  frameworks: ComplianceFramework[]
  catalogCount: number
  mappingCount: number
  lastRefreshed?: number
}

export function findingBelongsToSession(findingID: string | undefined | null, sessionFindingIDs: ReadonlySet<string>) {
  return typeof findingID === "string" && findingID.length > 0 && sessionFindingIDs.has(findingID)
}

export interface ComplianceRefreshSource {
  key: string
  url: string
  license: string
  ok: boolean
  error?: string
  controls?: number
  mappings?: number
}

export interface ComplianceRefreshSummary {
  refreshedAt: number
  sources: ComplianceRefreshSource[]
  catalogControlCount: number
  mappingCount: number
}

const CONFIDENCE_VALUES: EvidenceConfidence[] = ["high", "medium", "low"]

function confidenceValue(value: unknown): EvidenceConfidence | undefined {
  const normalized = stringValue(value)?.toLowerCase()
  return CONFIDENCE_VALUES.includes(normalized as EvidenceConfidence) ? (normalized as EvidenceConfidence) : undefined
}

function mapEvidence(value: unknown): ComplianceEvidence | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const findingID = stringValue(record.findingID)
  const title = stringValue(record.title)
  if (!findingID && !title) return undefined
  return {
    findingID: findingID ?? "",
    title: title ?? "",
    severity: stringValue(record.severity) ?? "info",
    status: stringValue(record.status) ?? "open",
    tool: stringValue(record.tool),
    fromElasticsearch: booleanValue(record.fromElasticsearch),
    timeUpdated: numberValue(record.timeUpdated) ?? 0,
    cwe: stringValue(record.cwe),
    derivedFrom: stringValue(record.derivedFrom),
    confidence: confidenceValue(record.confidence),
  }
}

function mapEvidenceFinding(value: unknown): ControlEvidenceFinding | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = stringValue(record.id)
  if (!id) return undefined
  return {
    id,
    title: stringValue(record.title) ?? "",
    severity: stringValue(record.severity) ?? "info",
    cwe: stringValue(record.cwe),
    sourceTool: stringValue(record.sourceTool),
    confidence: stringValue(record.confidence),
  }
}

function mapDerivation(value: unknown): ControlEvidence[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return []
    const record = entry as Record<string, unknown>
    const derivedFrom = stringValue(record.derivedFrom)
    if (!derivedFrom) return []
    return [
      {
        derivedFrom,
        findings: Array.isArray(record.findings)
          ? record.findings.flatMap((finding) => {
              const mapped = mapEvidenceFinding(finding)
              return mapped ? [mapped] : []
            })
          : [],
        confidence: confidenceValue(record.confidence) ?? "low",
      },
    ]
  })
}

function mapNode(value: unknown): ComplianceNode | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = stringValue(record.id)
  const title = stringValue(record.title)
  if (!id || !title) return undefined
  return {
    id,
    title,
    level: stringValue(record.level) ?? "control",
    status: (stringValue(record.status) as ComplianceStatus) ?? "unassessed",
    findingCount: numberValue(record.findingCount) ?? 0,
    evidence: Array.isArray(record.evidence)
      ? record.evidence.flatMap((entry) => {
          const evidence = mapEvidence(entry)
          return evidence ? [evidence] : []
        })
      : [],
    derivation: mapDerivation(record.derivation),
    confidence: confidenceValue(record.confidence) ?? "high",
    children: Array.isArray(record.children)
      ? record.children.flatMap((child) => {
          const node = mapNode(child)
          return node ? [node] : []
        })
      : [],
  }
}

function mapFramework(value: unknown): ComplianceFramework | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const framework = stringValue(record.framework)
  const title = stringValue(record.title)
  if (!framework || !title) return undefined
  const tree = mapNode(record.tree)
  if (!tree) return undefined
  return {
    framework,
    title,
    version: stringValue(record.version) ?? "",
    refreshedAt: numberValue(record.refreshedAt),
    tree,
  }
}

/** Returns undefined only when the connected server does not expose the compliance API yet. */
export async function loadComplianceStatus(
  request: Requester,
  sessionID: string,
): Promise<ComplianceStatusResponse | undefined> {
  const enc = encodeURIComponent(sessionID)
  const response = await request(`/session/${enc}/compliance/status`)
  if (response.status === 404 || response.status === 405) return undefined
  if (!response.ok) throw new Error(`Unable to load compliance status (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object") throw new Error("Invalid compliance status response")
  const record = body as Record<string, unknown>
  return {
    frameworks: Array.isArray(record.frameworks)
      ? record.frameworks.flatMap((framework) => {
          const mapped = mapFramework(framework)
          return mapped ? [mapped] : []
        })
      : [],
    catalogCount: numberValue(record.catalogCount) ?? 0,
    mappingCount: numberValue(record.mappingCount) ?? 0,
    lastRefreshed: numberValue(record.lastRefreshed),
  }
}

export async function refreshComplianceCatalog(request: Requester): Promise<ComplianceRefreshSummary | undefined> {
  const response = await request("/compliance/refresh", { method: "POST" })
  if (response.status === 404 || response.status === 405) return undefined
  if (!response.ok) throw new Error(`Unable to refresh compliance catalog (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object") throw new Error("Invalid compliance refresh response")
  const record = body as Record<string, unknown>
  return {
    refreshedAt: numberValue(record.refreshedAt) ?? 0,
    sources: Array.isArray(record.sources)
      ? record.sources.flatMap((source): ComplianceRefreshSource[] => {
          if (!source || typeof source !== "object") return []
          const s = source as Record<string, unknown>
          const key = stringValue(s.key)
          if (!key) return []
          return [
            {
              key,
              url: stringValue(s.url) ?? "",
              license: stringValue(s.license) ?? "",
              ok: booleanValue(s.ok) ?? false,
              error: stringValue(s.error),
              controls: numberValue(s.controls),
              mappings: numberValue(s.mappings),
            },
          ]
        })
      : [],
    catalogControlCount: numberValue(record.catalogControlCount) ?? 0,
    mappingCount: numberValue(record.mappingCount) ?? 0,
  }
}
