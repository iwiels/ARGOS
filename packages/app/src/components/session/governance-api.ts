import type { Requester } from "./security-findings-api"
import { booleanValue, numberValue, safeJson, stringValue } from "./api-utils"

export interface AgentToolSummary {
  tool: string
  count: number
}

export interface AgentSummary {
  agent: string
  total: number
  completed: number
  errors: number
  topTools: AgentToolSummary[]
}

export interface AuditIntegrity {
  valid: boolean
  total: number
  /** true cuando la integridad proviene de la verificación criptográfica completa (verify). */
  verified?: boolean
  firstInvalidSeq?: number
}

export interface GovernanceSummary {
  generatedAt: number
  integrity: AuditIntegrity
  agents: AgentSummary[]
  events: Array<{ eventType: string; count: number }>
  activity: { total: number; lastEntryAt?: number }
}

export interface AuditEntry {
  id: string
  seq: number
  project_id?: string | null
  session_id?: string | null
  event_type: string
  action: string
  agent?: string | null
  target?: string | null
  summary: string
  payload: string
  prev_hash: string
  hash: string
  time_created: number
}

function mapTool(value: unknown): AgentToolSummary | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const tool = stringValue(record.tool)
  if (!tool) return undefined
  return { tool, count: numberValue(record.count) ?? 0 }
}

function mapAgent(value: unknown): AgentSummary | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const agent = stringValue(record.agent)
  if (!agent) return undefined
  return {
    agent,
    total: numberValue(record.total) ?? 0,
    completed: numberValue(record.completed) ?? 0,
    errors: numberValue(record.errors) ?? 0,
    topTools: Array.isArray(record.topTools)
      ? record.topTools.flatMap((tool) => {
          const mapped = mapTool(tool)
          return mapped ? [mapped] : []
        })
      : [],
  }
}

function mapIntegrity(value: unknown): AuditIntegrity | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  return {
    valid: booleanValue(record.valid),
    total: numberValue(record.total) ?? 0,
    verified: record.verified === undefined ? booleanValue(record.valid) : booleanValue(record.verified),
    firstInvalidSeq: numberValue(record.firstInvalidSeq),
  }
}

/** Returns undefined when the server does not expose the governance API yet.
 *  El `request` del SDK ya inyecta el directorio (header x-opencode-directory). */
export async function loadGovernanceSummary(request: Requester): Promise<GovernanceSummary | undefined> {
  try {
    const response = await request("/audit/summary")
    if (response.status === 404 || response.status === 405) return undefined
    if (!response.ok) return undefined
    const body = await safeJson(response)
    if (!body || typeof body !== "object") return undefined
    const record = body as Record<string, unknown>
    return {
      generatedAt: numberValue(record.generatedAt) ?? 0,
      integrity:
        mapIntegrity(record.integrity) ?? { valid: false, total: 0, verified: false, firstInvalidSeq: undefined },
      agents: Array.isArray(record.agents)
        ? record.agents.flatMap((agent) => {
            const mapped = mapAgent(agent)
            return mapped ? [mapped] : []
          })
        : [],
      events: Array.isArray(record.events)
        ? record.events.flatMap((event): Array<{ eventType: string; count: number }> => {
            if (!event || typeof event !== "object") return []
            const e = event as Record<string, unknown>
            const eventType = stringValue(e.eventType)
            if (!eventType) return []
            return [{ eventType, count: numberValue(e.count) ?? 0 }]
          })
        : [],
      activity:
        record.activity && typeof record.activity === "object"
          ? {
              total: numberValue((record.activity as Record<string, unknown>).total) ?? 0,
              lastEntryAt: numberValue((record.activity as Record<string, unknown>).lastEntryAt),
            }
        : { total: 0, lastEntryAt: undefined },
  }
} catch {
    return undefined
  }
}

export async function verifyAuditChain(request: Requester): Promise<AuditIntegrity | undefined> {
  try {
    const response = await request("/audit/verify")
    if (response.status === 404 || response.status === 405) return undefined
    if (!response.ok) return undefined
    const body = await safeJson(response)
    if (!body || typeof body !== "object") return undefined
    const mapped = mapIntegrity(body)
    return mapped ? { ...mapped, verified: true } : mapped
  } catch {
    return undefined
  }
}

export async function loadAuditEntries(request: Requester, limit = 50): Promise<AuditEntry[] | undefined> {
  try {
    const response = await request(`/audit?limit=${limit}`)
    if (response.status === 404 || response.status === 405) return undefined
    if (!response.ok) return undefined
    const body = await safeJson(response)
    if (!body || typeof body !== "object") return undefined
    const items = (body as Record<string, unknown>).items
    if (!Array.isArray(items)) return undefined
    return items.flatMap((entry): AuditEntry[] => {
      if (!entry || typeof entry !== "object") return []
      const record = entry as Record<string, unknown>
      const id = stringValue(record.id)
      if (!id) return []
      return [
        {
          id,
          seq: numberValue(record.seq) ?? 0,
          project_id: record.project_id === null ? null : stringValue(record.project_id),
          session_id: record.session_id === null ? null : stringValue(record.session_id),
          event_type: stringValue(record.event_type) ?? "",
          action: stringValue(record.action) ?? "",
          agent: record.agent === null ? null : stringValue(record.agent),
          target: record.target === null ? null : stringValue(record.target),
          summary: stringValue(record.summary) ?? "",
          payload: typeof record.payload === "string" ? record.payload : "",
          prev_hash: stringValue(record.prev_hash) ?? "",
          hash: stringValue(record.hash) ?? "",
          time_created: numberValue(record.time_created) ?? 0,
        },
      ]
    })
  } catch {
    return undefined
  }
}
