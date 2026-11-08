/**
 * Export HAR (HTTP Archive 1.2).
 *
 * El HAR es el formato que permite reproducir a mano lo que encontró la
 * IA: es lo que abren las devtools del navegador, Burp Suite y `mitmproxy`.
 *
 * No hay un store de traffic en el core, así que las entradas se derivan de
 * la evidencia de red que los hallazgos ya trajeron (la petición HTTP y la
 * respuesta que el scanner guardó). Si una sesión no tiene exchanges, el
 * documento sale con `entries: []` — un HAR vacío pero válido, que es
 * exactamente lo que espera un visor.
 */

import { toIsoDateTime, type ReportDocument, type ReportFinding } from "./model"
import type { TrafficExchange } from "../traffic"

export interface HarNameValue {
  name: string
  value: string
}

export interface HarExchange {
  method: string
  url: string
  status: number
  statusText?: string
  httpVersion?: string
  requestHeaders?: HarNameValue[]
  responseHeaders?: HarNameValue[]
  requestBody?: string
  responseBody?: string
  startedDateTime?: string
  time?: number
  mimeType?: string
}

export interface HarDocument {
  log: {
    version: "1.2"
    creator: { name: string; version: string }
    browser?: { name: string; version: string }
    pages: unknown[]
    entries: unknown[]
  }
}

function parseHeaderBlock(raw: string): { startLine: string; headers: HarNameValue[] } {
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0)
  const startLine = lines[0]?.trim() ?? ""
  const headers: HarNameValue[] = []
  for (const line of lines.slice(1)) {
    const index = line.indexOf(":")
    if (index <= 0) continue
    headers.push({ name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() })
  }
  return { startLine, headers }
}

function headerValue(headers: HarNameValue[], name: string): string | undefined {
  const found = headers.find((header) => header.name.toLowerCase() === name.toLowerCase())
  return found?.value
}

function absoluteUrl(path: string, headers: HarNameValue[], target: string | undefined): string {
  if (/^https?:\/\//i.test(path)) return path
  const host = headerValue(headers, "host")
  const scheme = target?.startsWith("https://") ? "https" : "http"
  if (!host) return path
  return `${scheme}://${host}${path.startsWith("/") ? "" : "/"}${path}`
}

/** Deriva un exchange de la evidencia HTTP de un hallazgo. */
export function exchangeFromFinding(finding: ReportFinding, startedDateTime: string): HarExchange | undefined {
  if (!finding.httpRequest) return undefined
  const request = parseHeaderBlock(finding.httpRequest)
  const requestParts = request.startLine.split(/\s+/)
  const method = requestParts[0]?.toUpperCase() || "GET"
  const path = requestParts[1] ?? "/"
  const httpVersion = requestParts[2] ?? "HTTP/1.1"

  const response = finding.httpResponse ? parseHeaderBlock(finding.httpResponse) : undefined
  const statusParts = response?.startLine.split(/\s+/) ?? []
  const status = Number.parseInt(statusParts[1] ?? "", 10)
  const statusText = statusParts.slice(2).join(" ") || undefined

  return {
    method,
    url: absoluteUrl(path, request.headers, finding.target),
    status: Number.isFinite(status) ? status : 0,
    statusText,
    httpVersion,
    requestHeaders: request.headers,
    responseHeaders: response?.headers,
    responseBody: finding.httpResponse,
    startedDateTime,
    time: 0,
    mimeType: response ? headerValue(response.headers, "content-type") : undefined,
  }
}

export function harExchangesFromFindings(document: ReportDocument): HarExchange[] {
  const started = toIsoDateTime(document.meta.generatedAt)
  const exchanges: HarExchange[] = []
  for (const finding of document.findings) {
    const exchange = exchangeFromFinding(finding, started)
    if (exchange) exchanges.push(exchange)
  }
  return exchanges
}

function headerList(headers: Record<string, string[]> | undefined): HarNameValue[] {
  if (!headers) return []
  const out: HarNameValue[] = []
  for (const [name, values] of Object.entries(headers)) {
    for (const value of values) out.push({ name, value })
  }
  return out
}

/**
 * Convierte los exchanges del store de traffic (`security/traffic.ts`) en
 * entries de HAR. Es la fuente preferida: el store tiene la petición y la
 * respuesta reales que capturó el binario, con sus cabeceras y sus tiempos.
 */
export function harExchangesFromTraffic(exchanges: TrafficExchange[]): HarExchange[] {
  return exchanges.map((exchange) => ({
    method: exchange.method || "GET",
    url: exchange.url,
    status: exchange.status,
    statusText: exchange.status ? String(exchange.status) : "",
    httpVersion: "HTTP/1.1",
    requestHeaders: headerList(exchange.requestHeaders),
    responseHeaders: headerList(exchange.responseHeaders),
    requestBody: exchange.requestBody || undefined,
    responseBody: exchange.responseBody || undefined,
    startedDateTime: new Date(exchange.timestamp).toISOString(),
    time: Math.max(exchange.durationMs, 0),
    mimeType: exchange.responseHeaders?.["content-type"]?.[0],
  }))
}

export function exportHar(document: ReportDocument, exchanges?: HarExchange[]): string {
  const entries = exchanges ?? harExchangesFromFindings(document)
  const pages: unknown[] = []
  const log: HarDocument["log"] = {
    version: "1.2",
    creator: {
      name: document.meta.engine ?? "argos-security-operations",
      version: document.meta.engineVersion ?? "1.0.0",
    },
    pages,
    entries: entries.map((exchange, index) => ({
      pageref: `page_${index + 1}`,
      startedDateTime: exchange.startedDateTime ?? toIsoDateTime(document.meta.generatedAt),
      time: exchange.time ?? 0,
      request: {
        method: exchange.method,
        url: exchange.url,
        httpVersion: exchange.httpVersion ?? "HTTP/1.1",
        cookies: [],
        headers: exchange.requestHeaders ?? [],
        queryString: [],
        ...(exchange.requestBody ? { postData: { mimeType: "text/plain", text: exchange.requestBody } } : {}),
        headersSize: -1,
        bodySize: exchange.requestBody?.length ?? 0,
      },
      response: {
        status: exchange.status,
        statusText: exchange.statusText ?? "",
        httpVersion: exchange.httpVersion ?? "HTTP/1.1",
        cookies: [],
        headers: exchange.responseHeaders ?? [],
        content: {
          size: exchange.responseBody?.length ?? 0,
          mimeType: exchange.mimeType ?? "text/plain",
          ...(exchange.responseBody ? { text: exchange.responseBody } : {}),
        },
        redirectURL: "",
        headersSize: -1,
        bodySize: exchange.responseBody?.length ?? 0,
      },
      cache: {},
      timings: { send: 0, wait: 0, receive: 0 },
    })),
  }

  return JSON.stringify({ log }, null, 2)
}
