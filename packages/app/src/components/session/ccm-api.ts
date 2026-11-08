import type { Requester } from "./security-findings-api"
import { numberValue, safeJson, stringValue } from "./api-utils"

export type ControlStatus = "deficient" | "partial" | "compliant" | "unassessed"

/** Confianza de la derivación (no la del hallazgo). */
export type EvidenceConfidence = "high" | "medium" | "low"

export interface ComplianceDriftEvent {
  id: number
  projectID: string
  framework: string
  controlId: string
  statusFrom: ControlStatus
  statusTo: ControlStatus
  timeRecorded: number
}

export interface ComplianceHistoryEntry {
  id: number
  statusFrom: ControlStatus
  statusTo: ControlStatus
  timeRecorded: number
}

export interface ComplianceFrameworkSummary {
  framework: string
  title: string
  version: string
  totalControls: number
  counts: Record<ControlStatus, number>
  score: number
  /** Confianza agregada del framework (la más débil entre sus hojas). */
  confidence: EvidenceConfidence
}

export interface ComplianceSummary {
  generatedAt: number
  projectCount: number
  frameworks: ComplianceFrameworkSummary[]
  lastUpdated?: number
}

const STATUS_VALUES: ControlStatus[] = ["deficient", "partial", "compliant", "unassessed"]
const CONFIDENCE_VALUES: EvidenceConfidence[] = ["high", "medium", "low"]

function statusValue(value: unknown): ControlStatus {
  return STATUS_VALUES.includes(value as ControlStatus) ? (value as ControlStatus) : "unassessed"
}

function confidenceValue(value: unknown): EvidenceConfidence {
  const normalized = stringValue(value)?.toLowerCase()
  return CONFIDENCE_VALUES.includes(normalized as EvidenceConfidence) ? (normalized as EvidenceConfidence) : "high"
}

function mapDriftEvent(value: unknown): ComplianceDriftEvent | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = numberValue(record.id)
  const projectID = stringValue(record.projectID)
  const controlId = stringValue(record.controlId)
  if (id === undefined || !projectID || !controlId) return undefined
  return {
    id,
    projectID,
    framework: stringValue(record.framework) ?? "nist_csf_v2",
    controlId,
    statusFrom: statusValue(record.statusFrom),
    statusTo: statusValue(record.statusTo),
    timeRecorded: numberValue(record.timeRecorded) ?? 0,
  }
}

function mapFrameworkSummary(value: unknown): ComplianceFrameworkSummary | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const framework = stringValue(record.framework)
  const title = stringValue(record.title)
  if (!framework || !title) return undefined
  const rawCounts = record.counts && typeof record.counts === "object" ? (record.counts as Record<string, unknown>) : {}
  const counts = { deficient: 0, partial: 0, compliant: 0, unassessed: 0 } as Record<ControlStatus, number>
  for (const status of STATUS_VALUES) {
    counts[status] = numberValue(rawCounts[status]) ?? 0
  }
  return {
    framework,
    title,
    version: stringValue(record.version) ?? "",
    totalControls: numberValue(record.totalControls) ?? 0,
    counts,
    score: numberValue(record.score) ?? 0,
    confidence: confidenceValue(record.confidence),
  }
}

/** Returns undefined when the server does not expose the CCM API yet. */
export async function loadComplianceSummary(request: Requester): Promise<ComplianceSummary | undefined> {
  try {
    const response = await request("/compliance/summary")
    if (response.status === 404 || response.status === 405) return undefined
    if (!response.ok) return undefined
    const body = await safeJson(response)
    if (!body || typeof body !== "object") return undefined
    const record = body as Record<string, unknown>
    return {
      generatedAt: numberValue(record.generatedAt) ?? 0,
      projectCount: numberValue(record.projectCount) ?? 0,
      frameworks: Array.isArray(record.frameworks)
        ? record.frameworks.flatMap((framework) => {
            const mapped = mapFrameworkSummary(framework)
            return mapped ? [mapped] : []
          })
        : [],
      lastUpdated: numberValue(record.lastUpdated),
    }
  } catch {
    return undefined
  }
}

export async function loadComplianceDrift(request: Requester, limit = 50): Promise<ComplianceDriftEvent[] | undefined> {
  try {
    const response = await request(`/compliance/drift?limit=${limit}`)
    if (response.status === 404 || response.status === 405) return undefined
    if (!response.ok) return undefined
    const body = await safeJson(response)
    if (!Array.isArray(body)) return undefined
    return body.flatMap((event) => {
      const mapped = mapDriftEvent(event)
      return mapped ? [mapped] : []
    })
  } catch {
    return undefined
  }
}
