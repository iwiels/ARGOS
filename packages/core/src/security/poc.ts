import { createHash } from "node:crypto"

export type PayloadCategory = "safe-read" | "safe-timing" | "safe-boolean" | "safe-echo" | "destructive" | "unknown"

export interface PocSafetyEvaluation {
  safe: boolean
  category: PayloadCategory
  reason: string
  reproducibleCurl: string
}

/**
 * Cómo se compara la respuesta nueva con la original para decidir si el
 * hallazgo dejó de reproducirse.
 *
 * Cada matcher dice una cosa distinta y su dirección (si se cumplir significa
 * "remediado" o "sigue vulnerable") es explícita: ver
 * {@link pocMatcherDirection}.
 */
export type PocMatcher =
  /** El endpoint responde con el estado que confirma la vulnerabilidad. */
  | { kind: "status"; expected: number | number[] }
  /** El payload ya no aparece reflejado en la respuesta. */
  | { kind: "body_absent"; needle: string }
  /** La respuesta cambió respecto de la original. */
  | { kind: "body_changed" }
  /** El valor reflejado ya no está en la respuesta. */
  | { kind: "value_absent"; needle: string }
  /** La cabecera que faltaba sigue faltando. */
  | { kind: "header_absent"; header: string }
  /** El retardo ya no ocurre. */
  | { kind: "timing_under"; ms: number }

/**
 * La respuesta original contra la que se compara la nueva.
 *
 * El cuerpo completo no se guarda: con el hash y un fragmento alcanza para
 * comparar sin arrastrar el body entero en la base.
 */
export interface PocBaseline {
  status: number
  bodyDigest?: string
  bodySnippet?: string
}

/**
 * El PoC de un hallazgo: la petición que lo reproduce y el matcher que
 * decide si la re-ejecución lo confirma o lo descarta.
 *
 * Lo escribe la tool que confirmó el vector (en Go, dentro de
 * `Evidence["poc"]`) y lo re-ejecuta el motor de re-test (ver `retest.ts`).
 */
export interface PocRecord {
  /** Tipo de vector: "sqli" | "xss" | "ssti" | "ssrf" | "csrf" | "jwt" | "prompt_injection" | … */
  kind: string
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  payload?: string
  matcher: PocMatcher
  /** Respuesta original contra la que comparar. */
  baseline?: PocBaseline
}

/** La respuesta de la re-ejecución del PoC. */
export interface PocResponse {
  status: number
  headers: Record<string, string>
  body: string
  /** Latencia de la respuesta, en milisegundos. */
  durationMs?: number
}

/**
 * Dirección de un matcher: qué significa que se cumpla.
 *
 * - "remediated": se cumple cuando la vulnerabilidad dejó de reproducirse
 *   (el payload ya no se refleja, el retardo ya no ocurre, la respuesta
 *   cambió).
 * - "vulnerable": se cumple cuando la condición vulnerable sigue presente
 *   (la cabecera que faltaba sigue faltando, el endpoint sigue respondiendo
 *   con el estado que la prueba).
 */
export type PocMatcherDirection = "remediated" | "vulnerable"

export type PocConfidence = "high" | "medium" | "low"

export interface PocMatchOutcome {
  /** El matcher se cumplió. */
  matched: boolean
  /** Qué se comprobó, en prosa. */
  detail: string
  /** Dirección del matcher aplicado. */
  direction: PocMatcherDirection
  /** El matcher que realmente se aplicó (difiere del pedido si degradó). */
  applied: PocMatcher
  /** true cuando el matcher se degradó por falta de evidencia del baseline. */
  degraded: boolean
  /** false cuando el matcher no se puede aplicar con la evidencia disponible. */
  applicable: boolean
  /** Confianza del veredicto. */
  confidence: PocConfidence
}

/** Límites canónicos de un PoC: acotan lo que una tool puede persistir. */
export const MAX_POC_KIND_CHARS = 64
export const MAX_POC_URL_CHARS = 2048
export const MAX_POC_METHOD_CHARS = 16
export const MAX_POC_HEADERS = 32
export const MAX_POC_HEADER_NAME_CHARS = 128
export const MAX_POC_HEADER_VALUE_CHARS = 1024
export const MAX_POC_BODY_CHARS = 8192
export const MAX_POC_PAYLOAD_CHARS = 4096
export const MAX_POC_NEEDLE_CHARS = 4096
export const MAX_POC_BASELINE_SNIPPET_CHARS = 2048

const DESTRUCTIVE_PATTERNS = [
  /\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/i,
  /\bTRUNCATE\s+TABLE\b/i,
  /\bDELETE\s+FROM\b/i,
  /\bUPDATE\s+[^\n]+\s+SET\b/i,
  /\bINSERT\s+INTO\b/i,
  /\bSHUTDOWN\b/i,
  /\bEXEC(?:\s+|\()xp_cmdshell\b/i,
  /\brm\s+-rf\b/i,
  /\bformat\s+[c-z]:/i,
  /\bmkfs\b/i,
  />\s*\/dev\/sd[a-z]/i,
  /\bbenchmark\s*\(\s*[0-9]{7,}/i, // Heavy CPU exhaustion
  /\bsleep\s*\(\s*(?:[3-9][0-9]|[1-9][0-9]{2,})\s*\)/i, // Sleep > 30s
]

const SAFE_TIMING_PATTERNS = [
  /\b(?:pg_sleep|sleep|waitfor\s+delay)\s*\(?\s*['"]?([1-5])\b/i,
]

const SAFE_BOOLEAN_PATTERNS = [
  /'\s*(?:OR|AND)\s+'?1'?='?1/i,
  /"\s*(?:OR|AND)\s+"?1"?="?1/i,
  /\bAND\s+1=1\b/i,
  /\bOR\s+1=1\b/i,
]

const SAFE_ECHO_PATTERNS = [
  /<script>alert\(['"]?(?:1|xss|test)['"]?\)<\/script>/i,
  /\{\{7\*7\}\}/i,
  /\{\{constructor\.constructor\('return\s+49'\)\(\)\}\}/i,
]

/**
 * Evalúa si un payload de PoC es seguro y no destructivo para ser ejecutado.
 */
export function evaluatePocSafety(input: {
  target: string
  payload?: string
  method?: string
  headers?: Record<string, string>
}): PocSafetyEvaluation {
  const target = input.target.trim()
  const payload = input.payload?.trim() || ""
  const method = (input.method || "GET").toUpperCase()

  // 1. Detectar patrones destructivos conocidos
  for (const pattern of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(payload) || pattern.test(target)) {
      return {
        safe: false,
        category: "destructive",
        reason: "Destructive payload pattern detected (Data manipulation, heavy exhaustion, or shell invocation)",
        reproducibleCurl: generateCurlCommand({ target, method, payload, headers: input.headers }),
      }
    }
  }

  // 2. Clasificar tipos seguros
  let category: PayloadCategory = "safe-read"
  if (SAFE_TIMING_PATTERNS.some((p) => p.test(payload) || p.test(target))) {
    category = "safe-timing"
  } else if (SAFE_BOOLEAN_PATTERNS.some((p) => p.test(payload) || p.test(target))) {
    category = "safe-boolean"
  } else if (SAFE_ECHO_PATTERNS.some((p) => p.test(payload) || p.test(target))) {
    category = "safe-echo"
  }

  return {
    safe: true,
    category,
    reason: "Payload is non-destructive (safe proof of concept)",
    reproducibleCurl: generateCurlCommand({ target, method, payload, headers: input.headers }),
  }
}

/**
 * Genera un comando cURL reproducible y formateado para terminal.
 */
export function generateCurlCommand(opts: {
  target: string
  method?: string
  payload?: string
  headers?: Record<string, string>
}): string {
  const method = (opts.method || "GET").toUpperCase()
  const parts = [`curl -i -s -k -X ${method} "${opts.target}"`]

  parts.push(`  -H "User-Agent: Argos-Auditor-PoC/3.2"`)
  if (opts.headers) {
    for (const [k, v] of Object.entries(opts.headers)) {
      if (k.toLowerCase() !== "user-agent") {
        parts.push(`  -H "${k}: ${v}"`)
      }
    }
  }

  if (opts.payload && method !== "GET") {
    parts.push(`  --data-raw '${opts.payload.replace(/'/g, "\\'")}'`)
  }

  return parts.join(" \\\n")
}

/** Hash SHA-256 del cuerpo: permite comparar respuestas sin guardarlas enteras. */
export function digestBody(body: string): string {
  return createHash("sha256").update(body).digest("hex")
}

/**
 * Dirección de un matcher: si cumplirse significa "remediado" o "sigue
 * vulnerable".
 *
 * El matcher de estado y el de cabecera faltante son los dos que describen
 * una condición que el endpoint tiene que SEGUIR cumpliendo para que la
 * vulnerabilidad siga presente; los demás describen la ausencia del síntoma.
 */
export function pocMatcherDirection(matcher: PocMatcher): PocMatcherDirection {
  switch (matcher.kind) {
    case "status":
    case "header_absent":
      return "vulnerable"
    default:
      return "remediated"
  }
}

/**
 * Aplica el matcher a la respuesta de la re-ejecución.
 *
 * El resultado dice si el matcher se cumplió y con qué confianza. Cuando el
 * matcher no se puede aplicar (no hay con qué comparar) devuelve
 * `applicable: false`: el re-test no puede afirmar nada y el hallazgo queda
 * para confirmación manual — nunca "verified".
 */
export function applyMatcher(
  matcher: PocMatcher,
  response: PocResponse,
  baseline?: PocBaseline,
): PocMatchOutcome {
  const direction = pocMatcherDirection(matcher)

  switch (matcher.kind) {
    case "status": {
      const expected = (Array.isArray(matcher.expected) ? matcher.expected : [matcher.expected]).filter((value) =>
        Number.isFinite(value),
      )
      if (expected.length === 0) {
        return notApplicable(matcher, direction, "El matcher no declara el estado esperado.")
      }
      const matched = expected.includes(response.status)
      return {
        matched,
        direction,
        applied: matcher,
        degraded: false,
        applicable: true,
        confidence: "high",
        detail: matched
          ? `El endpoint respondió ${response.status}: el estado que confirma la vulnerabilidad.`
          : `El endpoint respondió ${response.status} y ya no el ${expected.join(" / ")} que la confirmaba.`,
      }
    }

    case "header_absent": {
      const header = matcher.header.trim()
      if (!header) return notApplicable(matcher, direction, "El matcher no declara la cabecera a comprobar.")
      const present = Object.keys(response.headers).some((key) => key.toLowerCase() === header.toLowerCase())
      const matched = !present
      return {
        matched,
        direction,
        applied: matcher,
        degraded: false,
        applicable: true,
        confidence: "high",
        detail: matched
          ? `La cabecera ${header} sigue faltando en la respuesta.`
          : `La cabecera ${header} ya está presente en la respuesta.`,
      }
    }

    case "timing_under": {
      if (!Number.isFinite(matcher.ms) || matcher.ms <= 0) {
        return notApplicable(matcher, direction, "El matcher no declara un umbral de tiempo válido.")
      }
      const elapsed = Math.max(0, Math.round(response.durationMs ?? 0))
      const matched = elapsed < matcher.ms
      return {
        matched,
        direction,
        applied: matcher,
        degraded: false,
        applicable: true,
        confidence: "high",
        detail: matched
          ? `La respuesta llegó en ${elapsed} ms, por debajo del umbral de ${matcher.ms} ms: el retardo ya no ocurre.`
          : `La respuesta tardó ${elapsed} ms y el umbral es ${matcher.ms} ms: el retardo sigue ocurriendo.`,
      }
    }

    case "body_changed": {
      const changed = bodyChangedOutcome(response, baseline)
      return { ...changed, direction, applied: matcher, degraded: false }
    }

    case "body_absent":
    case "value_absent": {
      const needle = matcher.needle
      if (!needle.trim()) return notApplicable(matcher, direction, "El matcher no declara el valor a comprobar.")

      // Degradación: con sólo el hash del cuerpo original se puede afirmar que
      // la respuesta cambió, pero no que el payload dejó de aparecer. El
      // matcher cae a "body_changed" y la confianza baja.
      if (baseline && !baseline.bodySnippet && baseline.bodyDigest) {
        const changed = bodyChangedOutcome(response, baseline)
        if (!changed.applicable) return { ...changed, direction, applied: matcher, degraded: true }
        return {
          ...changed,
          direction,
          applied: matcher,
          degraded: true,
          confidence: "low",
          detail: `${changed.detail} El cuerpo original no se conservó: sólo se pudo comparar el hash, así que la ausencia del payload no quedó confirmada.`,
        }
      }

      const present = containsNeedle(response.body, needle)
      const reflected = baseline?.bodySnippet ? containsNeedle(baseline.bodySnippet, needle) : undefined
      const confidence: PocConfidence = baseline?.bodySnippet ? (reflected ? "high" : "medium") : "low"
      const detail = present
        ? `El valor "${truncate(needle, 120)}" sigue apareciendo en la respuesta.`
        : `El valor "${truncate(needle, 120)}" ya no aparece en la respuesta.`
      return {
        matched: !present,
        direction,
        applied: matcher,
        degraded: false,
        applicable: true,
        confidence,
        detail:
          confidence === "low"
            ? `${detail} No se conservó el cuerpo original, así que la comprobación se apoya sólo en la respuesta nueva.`
            : detail,
      }
    }
  }
}

/**
 * ¿El payload sigue reflejado en el cuerpo?
 *
 * Un servidor que escapa el valor lo devuelve con las entidades HTML
 * (`&#39;` en vez de `'`), así que el needle se busca también en su versión
 * escapada: si no, un XSS escapado parecería remediado cuando no lo está.
 */
export function containsNeedle(body: string, needle: string): boolean {
  if (!needle) return false
  if (body.includes(needle)) return true
  const escaped = escapeHtml(needle)
  return escaped !== needle && body.includes(escaped)
}

/** Escapa mínima de HTML: la misma que aplica la mayoría de los frameworks. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

function bodyChangedOutcome(
  response: PocResponse,
  baseline?: PocBaseline,
): Omit<PocMatchOutcome, "direction" | "applied" | "degraded"> {
  if (!baseline?.bodyDigest) {
    return {
      matched: false,
      detail: "No hay hash del cuerpo original para comparar: no se puede afirmar que la respuesta cambió.",
      applicable: false,
      confidence: "low",
    }
  }
  const digest = digestBody(response.body)
  const matched = digest !== baseline.bodyDigest
  return {
    matched,
    detail: matched
      ? "La respuesta cambió respecto de la original (el hash del cuerpo es distinto)."
      : "La respuesta es idéntica a la original (el hash del cuerpo coincide).",
    applicable: true,
    // Una página dinámica cambia en cada request: el hash distinto no prueba
    // por sí solo que la vulnerabilidad esté remediada.
    confidence: "medium",
  }
}

function notApplicable(matcher: PocMatcher, direction: PocMatcherDirection, detail: string): PocMatchOutcome {
  return {
    matched: false,
    detail,
    direction,
    applied: matcher,
    degraded: false,
    applicable: false,
    confidence: "low",
  }
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value
}

/**
 * Normaliza un PoC crudo (el que llega de una tool o de un agente) al shape
 * canónico, recortando todo lo que exceda los límites.
 *
 * Un PoC sin matcher válido se descarta: sin matcher no hay forma de decidir
 * si el hallazgo dejó de reproducirse.
 */
export function normalizePocRecord(value: unknown): PocRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const record = value as Record<string, unknown>

  const url = stringValue(record.url, MAX_POC_URL_CHARS)
  if (!url) return undefined

  const matcher = normalizePocMatcher(record.matcher)
  if (!matcher) return undefined

  const kind = stringValue(record.kind, MAX_POC_KIND_CHARS) ?? "poc"
  const method = (stringValue(record.method, MAX_POC_METHOD_CHARS) ?? "GET").toUpperCase()

  const out: PocRecord = {
    kind,
    method,
    url,
    matcher,
  }

  const headers = normalizePocHeaders(record.headers)
  if (headers) out.headers = headers

  const body = stringValue(record.body, MAX_POC_BODY_CHARS)
  if (body) out.body = body

  const payload = stringValue(record.payload, MAX_POC_PAYLOAD_CHARS)
  if (payload) out.payload = payload

  const baseline = normalizePocBaseline(record.baseline)
  if (baseline) out.baseline = baseline

  return out
}

/** Normaliza el matcher: un matcher inválido se descarta (no se adivina). */
export function normalizePocMatcher(value: unknown): PocMatcher | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const record = value as Record<string, unknown>
  const kind = stringValue(record.kind, 32)

  switch (kind) {
    case "status": {
      const raw = record.expected
      const expected = Array.isArray(raw)
        ? raw.filter((entry): entry is number => typeof entry === "number" && Number.isFinite(entry))
        : typeof raw === "number" && Number.isFinite(raw)
          ? [raw]
          : []
      if (expected.length === 0) return undefined
      return { kind: "status", expected: Array.isArray(raw) ? expected : expected[0] }
    }
    case "body_absent":
    case "value_absent": {
      const needle = stringValue(record.needle, MAX_POC_NEEDLE_CHARS)
      if (!needle) return undefined
      return { kind, needle }
    }
    case "body_changed":
      return { kind: "body_changed" }
    case "header_absent": {
      const header = stringValue(record.header, MAX_POC_HEADER_NAME_CHARS)
      if (!header) return undefined
      return { kind: "header_absent", header }
    }
    case "timing_under": {
      const ms = record.ms
      if (typeof ms !== "number" || !Number.isFinite(ms) || ms <= 0) return undefined
      return { kind: "timing_under", ms }
    }
    default:
      return undefined
  }
}

function normalizePocBaseline(value: unknown): PocBaseline | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const record = value as Record<string, unknown>
  const status = record.status
  if (typeof status !== "number" || !Number.isFinite(status)) return undefined

  const baseline: PocBaseline = { status }
  const digest = stringValue(record.bodyDigest, 128)
  if (digest && /^[0-9a-f]{16,128}$/i.test(digest)) baseline.bodyDigest = digest.toLowerCase()
  const snippet = stringValue(record.bodySnippet, MAX_POC_BASELINE_SNIPPET_CHARS)
  if (snippet) baseline.bodySnippet = snippet
  return baseline
}

function normalizePocHeaders(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const entries = Object.entries(value as Record<string, unknown>)
  if (entries.length === 0) return undefined
  const out: Record<string, string> = {}
  let count = 0
  for (const [key, raw] of entries) {
    if (count >= MAX_POC_HEADERS) break
    const name = stringValue(key, MAX_POC_HEADER_NAME_CHARS)
    const header = stringValue(raw, MAX_POC_HEADER_VALUE_CHARS)
    if (!name || !header) continue
    out[name] = header
    count++
  }
  return count > 0 ? out : undefined
}

function stringValue(value: unknown, maxChars: number): string | undefined {
  if (typeof value !== "string") return undefined
  const normalized = value.trim()
  if (!normalized) return undefined
  return normalized.length > maxChars ? normalized.slice(0, maxChars) : normalized
}
