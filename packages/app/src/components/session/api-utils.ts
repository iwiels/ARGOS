/** Shared parsers for the session API client modules (findings, compliance, CCM, governance). */

export function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined
}

export function numberValue(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined
}

export function booleanValue(value: unknown): boolean {
  return typeof value === "boolean" ? value : false
}

export function responseItems(value: unknown): unknown[] | undefined {
  if (Array.isArray(value)) return value
  if (!value || typeof value !== "object") return undefined
  const record = value as { data?: unknown; findings?: unknown }
  if (Array.isArray(record.data)) return record.data
  if (Array.isArray(record.findings)) return record.findings
  return undefined
}

/** Safe JSON extraction that tolerates non-JSON fallbacks (HTML error pages, empty bodies). */
export async function safeJson(response: Response): Promise<unknown | undefined> {
  const contentType = response.headers.get("content-type") ?? ""
  if (contentType.includes("html") || contentType.includes("xml")) return undefined
  try {
    const text = await response.text()
    if (!text || (!text.trim().startsWith("{") && !text.trim().startsWith("["))) return undefined
    return JSON.parse(text)
  } catch {
    return undefined
  }
}
