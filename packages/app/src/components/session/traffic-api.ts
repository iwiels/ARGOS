/**
 * Cliente del tráfico HTTP de la sesión.
 *
 * El store en disco (lo escribe el binario Go) es la fuente de verdad; el
 * servidor lo reconcilia contra el índice `traffic_exchange` antes de
 * responder. La UI nunca lee el disco: pregunta al servidor.
 */

import { numberValue, safeJson, stringValue } from "./api-utils"

type Requester = (path: string, init?: RequestInit) => Promise<Response>

export interface TrafficExchange {
  id: string
  timestamp: number
  method: string
  url: string
  host: string
  status: number
  durationMs: number
  sourceTool: string
  target: string
  scopeAllowed: boolean
  requestHeaders: Record<string, string[]>
  responseHeaders: Record<string, string[]>
  requestBody: string
  responseBody: string
  requestBodySHA256: string
  responseBodySHA256: string
  requestBodySize: number
  responseBodySize: number
}

export interface TrafficHeaderChange {
  name: string
  a: string
  b: string
}

export interface TrafficDiff {
  aId: string
  bId: string
  identical: boolean
  statusChanged: boolean
  statusA: number
  statusB: number
  headersAdded: TrafficHeaderChange[]
  headersRemoved: TrafficHeaderChange[]
  headersChanged: TrafficHeaderChange[]
  bodyChanged: boolean
  bodySHA256A: string
  bodySHA256B: string
  bodyDiff: string
  bodyLinesAdded: number
  bodyLinesRemoved: number
}

export interface TrafficFilter {
  host?: string
  method?: string
  status?: string
  tool?: string
}

export interface TrafficHistory {
  exchanges: TrafficExchange[]
  total: number
}

function headers(value: unknown): Record<string, string[]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  const out: Record<string, string[]> = {}
  for (const [name, raw] of Object.entries(value as Record<string, unknown>)) {
    if (Array.isArray(raw)) {
      out[name] = raw.filter((item): item is string => typeof item === "string")
      continue
    }
    if (typeof raw === "string") out[name] = [raw]
  }
  return out
}

function mapExchange(value: unknown): TrafficExchange | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = stringValue(record.id)
  const url = stringValue(record.url)
  if (!id || !url) return undefined
  return {
    id,
    timestamp: numberValue(record.timestamp) ?? 0,
    method: stringValue(record.method) ?? "GET",
    url,
    host: stringValue(record.host) ?? "",
    status: numberValue(record.status) ?? 0,
    durationMs: numberValue(record.durationMs) ?? 0,
    sourceTool: stringValue(record.sourceTool) ?? "",
    target: stringValue(record.target) ?? "",
    scopeAllowed: record.scopeAllowed === true,
    requestHeaders: headers(record.requestHeaders),
    responseHeaders: headers(record.responseHeaders),
    requestBody: stringValue(record.requestBody) ?? "",
    responseBody: stringValue(record.responseBody) ?? "",
    requestBodySHA256: stringValue(record.requestBodySHA256) ?? "",
    responseBodySHA256: stringValue(record.responseBodySHA256) ?? "",
    requestBodySize: numberValue(record.requestBodySize) ?? 0,
    responseBodySize: numberValue(record.responseBodySize) ?? 0,
  }
}

function mapHeaderChange(value: unknown): TrafficHeaderChange {
  const record = (value ?? {}) as Record<string, unknown>
  return {
    name: stringValue(record.name) ?? "",
    a: stringValue(record.a) ?? "",
    b: stringValue(record.b) ?? "",
  }
}

function mapDiff(value: unknown): TrafficDiff | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const aId = stringValue(record.aId)
  const bId = stringValue(record.bId)
  if (!aId || !bId) return undefined
  const list = (raw: unknown) => (Array.isArray(raw) ? raw.map(mapHeaderChange) : [])
  return {
    aId,
    bId,
    identical: record.identical === true,
    statusChanged: record.statusChanged === true,
    statusA: numberValue(record.statusA) ?? 0,
    statusB: numberValue(record.statusB) ?? 0,
    headersAdded: list(record.headersAdded),
    headersRemoved: list(record.headersRemoved),
    headersChanged: list(record.headersChanged),
    bodyChanged: record.bodyChanged === true,
    bodySHA256A: stringValue(record.bodySHA256A) ?? "",
    bodySHA256B: stringValue(record.bodySHA256B) ?? "",
    bodyDiff: stringValue(record.bodyDiff) ?? "",
    bodyLinesAdded: numberValue(record.bodyLinesAdded) ?? 0,
    bodyLinesRemoved: numberValue(record.bodyLinesRemoved) ?? 0,
  }
}

/** Returns undefined when the server does not expose the traffic API yet. */
export async function loadTrafficHistory(
  request: Requester,
  sessionID: string,
  filter: TrafficFilter = {},
  limit = 50,
): Promise<TrafficHistory | undefined> {
  const params = new URLSearchParams()
  if (filter.host) params.set("host", filter.host)
  if (filter.method) params.set("method", filter.method)
  if (filter.status) params.set("status", filter.status)
  if (filter.tool) params.set("tool", filter.tool)
  params.set("limit", String(limit))
  const query = params.toString()
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/traffic${query ? `?${query}` : ""}`,
  )
  if (response.status === 404 || response.status === 405) return undefined
  if (!response.ok) throw new Error(`Unable to load the traffic of session ${sessionID} (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object") return undefined
  const record = body as Record<string, unknown>
  const items = Array.isArray(record.exchanges)
    ? record.exchanges
    : Array.isArray((record as { data?: unknown }).data)
      ? ((record as { data: unknown[] }).data as unknown[])
      : []
  const exchanges = items.flatMap((item) => {
    const exchange = mapExchange(item)
    return exchange ? [exchange] : []
  })
  return { exchanges, total: numberValue(record.total) ?? exchanges.length }
}

/** Returns undefined when the server does not expose the diff endpoint yet. */
export async function loadTrafficDiff(
  request: Requester,
  sessionID: string,
  aID: string,
  bID: string,
): Promise<TrafficDiff | undefined> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/traffic/diff/${encodeURIComponent(aID)}/${encodeURIComponent(bID)}`,
  )
  if (response.status === 404 || response.status === 405) return undefined
  if (!response.ok) throw new Error(`Unable to compare the exchanges (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object") return undefined
  const record = body as Record<string, unknown>
  const payload = record.data && typeof record.data === "object" ? record.data : record
  return mapDiff(payload)
}
