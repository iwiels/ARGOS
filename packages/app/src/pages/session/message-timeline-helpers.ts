export function reasoningHeading(text: string) {
  const markdown = text.replace(/\r\n?/g, "\n")
  const html = markdown.match(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/i)
  if (html?.[1]) {
    const value = cleanHeading(html[1].replace(/<[^>]+>/g, " "))
    if (value) return value
  }

  const atx = markdown.match(/^\s{0,3}#{1,6}[ \t]+(.+?)(?:[ \t]+#+[ \t]*)?$/m)
  if (atx?.[1]) {
    const value = cleanHeading(atx[1])
    if (value) return value
  }

  const setext = markdown.match(/^([^\n]+)\n(?:=+|-+)\s*$/m)
  if (setext?.[1]) {
    const value = cleanHeading(setext[1])
    if (value) return value
  }

  const strong = markdown.match(/^\s*(?:\*\*|__)(.+?)(?:\*\*|__)\s*$/m)
  if (strong?.[1]) {
    const value = cleanHeading(strong[1])
    if (value) return value
  }
}

export type StreamErrorKind =
  | "queueFull"
  | "rateLimit"
  | "server"
  | "auth"
  | "contextOverflow"
  | "structuredOutput"
  | "generic"

export type StreamErrorMeta = {
  kind: StreamErrorKind
  retryable: boolean
  statusCode?: number
}

type StreamErrorLike = {
  name?: unknown
  data?: unknown
}

export function resolveStreamErrorKind(error: unknown): StreamErrorMeta {
  const generic = { kind: "generic" as const, retryable: false }
  if (!error || typeof error !== "object") return generic

  const value = error as StreamErrorLike
  if (value.name !== "APIError" || typeof value.data !== "object" || value.data === null) {
    if (value.name === "ProviderAuthError") return { kind: "auth", retryable: false }
    if (value.name === "ContextOverflowError") return { kind: "contextOverflow", retryable: false }
    if (value.name === "StructuredOutputError") return { kind: "structuredOutput", retryable: false }
    return generic
  }

  const data = value.data as { statusCode?: unknown; isRetryable?: unknown }
  const statusCode = typeof data.statusCode === "number" ? data.statusCode : undefined
  const retryable =
    typeof data.isRetryable === "boolean"
      ? data.isRetryable
      : statusCode !== undefined && statusCode >= 500

  if (statusCode === 429) return { kind: "rateLimit", retryable, statusCode }
  if (statusCode === 503 || statusCode === 529) return { kind: "queueFull", retryable, statusCode }
  if (statusCode !== undefined && statusCode >= 500) return { kind: "server", retryable, statusCode }
  if (statusCode === 401 || statusCode === 403) return { kind: "auth", retryable: false, statusCode }
  return { kind: "generic", retryable, statusCode }
}

function messageText(message: unknown) {
  if (typeof message === "string") return message
  if (typeof message === "number" || typeof message === "boolean") return String(message)
  return ""
}

export function errorRowFor<T>(error: T | undefined) {
  if (!error || typeof error !== "object") return
  const data = (error as { data?: unknown }).data
  const message =
    data && typeof data === "object" && "message" in data ? (data as { message?: unknown }).message : undefined
  return {
    error,
    text: unwrapErrorMessage(messageText(message)),
  }
}

export function cleanHeading(value: string) {
  return value
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[*_~]+/g, "")
    .trim()
}

export function unwrapErrorMessage(message: string) {
  const text = message.replace(/^Error:\s*/, "").trim()

  const parse = (value: string) => {
    try {
      return JSON.parse(value) as unknown
    } catch {
      return undefined
    }
  }

  const read = (value: string) => {
    const first = parse(value)
    if (typeof first === "string") return parse(first.trim())
    return first
  }

  let json = read(text)

  if (json === undefined) {
    const start = text.indexOf("{")
    const end = text.lastIndexOf("}")
    if (start !== -1 && end > start) json = read(text.slice(start, end + 1))
  }

  if (!record(json)) return message

  const err = record(json.error) ? json.error : undefined
  if (err) {
    const type = typeof err.type === "string" ? err.type : undefined
    const msg = typeof err.message === "string" ? err.message : undefined
    if (type && msg) return `${type}: ${msg}`
    if (msg) return msg
    if (type) return type
    const code = typeof err.code === "string" ? err.code : undefined
    if (code) return code
  }

  const msg = typeof json.message === "string" ? json.message : undefined
  if (msg) return msg

  const reason = typeof json.error === "string" ? json.error : undefined
  if (reason) return reason

  return message
}

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}

