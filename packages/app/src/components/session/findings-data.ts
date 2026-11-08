/**
 * findings-data.ts
 *
 * Parser puro que extrae los hallazgos de una auditoría a partir de las tool
 * parts de la sesión (y sus subagentes). Sin dependencias de Solid/SDK → testeable.
 *
 * Los resultados de MCP y los informes de herramientas son candidatos. Solo se
 * muestran como hallazgos las decisiones explícitas `kind:"finding"` del
 * agente que incluyen target, evidencia, evaluación e impacto, o filas
 * persistidas con procedencia confiable desde la API.
 */

import { calculateCvss, parseCvssShortForm } from "@argos/core/security/cvss"

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"]

/** Claves i18n para los labels de severidad (traducir con language.t). */
export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "severity.critical",
  high: "severity.high",
  medium: "severity.medium",
  low: "severity.low",
  info: "severity.info",
}

export function severityLabelKey(severity: Severity | string): string | undefined {
  return SEVERITY_LABELS[severity as Severity]
}

export const FINDING_STATUS_LABELS: Record<string, string> = {
  validated: "findings.status.validated",
  suspected: "findings.status.suspected",
  observed: "findings.status.observed",
  "blocked-by-policy": "findings.status.blockedByPolicy",
  open: "findings.status.open",
  "in-progress": "findings.status.inProgress",
  remediated: "findings.status.remediated",
  verified: "findings.status.verified",
  "false-positive": "findings.status.falsePositive",
  "accepted-risk": "findings.status.acceptedRisk",
  resolved: "findings.status.resolved",
}

export function findingStatusLabelKey(status?: string): string | undefined {
  if (!status) return undefined
  return FINDING_STATUS_LABELS[status.toLowerCase().trim()]
}

export const LEDGER_LIFECYCLE = [
  "open",
  "in-progress",
  "remediated",
  "verified",
  "false-positive",
  "accepted-risk",
] as const

export type LedgerStatus = (typeof LEDGER_LIFECYCLE)[number]

export function nextLedgerStatus(current?: string): string {
  const idx = LEDGER_LIFECYCLE.indexOf(current as LedgerStatus)
  return LEDGER_LIFECYCLE[(idx + 1) % LEDGER_LIFECYCLE.length]
}

export type FindingSource = "memory" | "web-core" | "web-mcp" | "db" | "tool"

/** Veredictos de triage (mismo vocabulario cerrado que el backend). */
export const FEEDBACK_VERDICTS = ["false-positive", "true-positive", "accepted-risk"] as const
export type FeedbackVerdict = (typeof FEEDBACK_VERDICTS)[number]
export type FeedbackActor = "human" | "agent"

export interface FindingFeedback {
  verdict: FeedbackVerdict
  reason?: string
  actor: FeedbackActor
}

export interface Finding {
  title: string
  severity: Severity
  severityRaw?: string
  status?: string
  agent?: string
  /** Mecanismo que produjo el hallazgo (`code.review`, `web.scan`…). Tiene forma de dominio, así que se excluye de los IoCs mostrados. */
  sourceTool?: string
  cwe?: string
  evidence?: string
  vector?: string
  remediation?: string
  target?: string
  session?: string
  tags?: string[]
  id?: string
  caseID?: string
  /** Salida cruda (JSON) de la tool que produjo el hallazgo — p.ej. el resultado completo de web.scan. */
  raw?: string
  /** Petición HTTP cruda enviada (para inspección y PoC). */
  httpRequest?: string
  /** Respuesta HTTP cruda recibida del servidor. */
  httpResponse?: string
  /** Comando cURL reproducible generado para el hallazgo. */
  curlCommand?: string
  source: FindingSource
  /** Técnicas MITRE ATT&CK mapeadas (enrichment). */
  attack?: AttackTechnique[]
  /** Indicadores de compromiso extraídos con su reputación (enrichment). */
  iocs?: FindingIoc[]
  /** Enriquecimiento EPSS (First.org) y CISA KEV (Known Exploited Vulnerabilities). */
  epssKev?: EpssKev
  /** Score CVSS v3.1 — solo presente si el agente declaró el vector explícito. Nunca inferido. */
  cvss?: Cvss
  /** Timestamp del enrichment. */
  enrichedAt?: number
  fingerprint?: string
  observationID?: string
  /** Triage registrado en este engagement (ARG-064). */
  feedback?: FindingFeedback
}

export interface EpssKev {
  cve?: string
  epssScore?: number
  epssPercentile?: number
  cisaKev?: boolean
  cisaKevDateAdded?: string
  cisaKevDueDate?: string
}

export interface Cvss {
  score: number
  severity: string
  vectorString: string
}

export interface AttackTechnique {
  id: string
  name: string
  tactics: string[]
  reason?: string
}

export interface IocReputation {
  source: string
  verdict: string
  score: number
  detail: string
  checkedAt: number
}

export interface FindingIoc {
  type: string
  value: string
  reputation?: IocReputation[]
}

export interface FuzzingHit {
  url: string
  status?: number
}

export interface WebSurface {
  target?: string
  crawledUrls: string[]
  fuzzingHits: FuzzingHit[]
  findingsCount: number
}

/** Entrada mínima desacoplada del SDK. */
export interface FindingToolPart {
  tool: string
  status: string
  input?: Record<string, unknown>
  output?: string
}

export function normalizeToolPart(part: unknown): FindingToolPart | undefined {
  if (!isRecord(part) || part.type !== "tool" || typeof part.tool !== "string") return undefined
  const state = isRecord(part.state) ? part.state : part
  const status = typeof state.status === "string" ? state.status : undefined
  if (!status) return undefined
  return {
    tool: part.tool,
    status,
    input: isRecord(state.input) ? state.input : undefined,
    output: typeof state.output === "string" ? state.output : undefined,
  }
}

export function normalizeToolParts(parts: readonly unknown[]): FindingToolPart[] {
  return parts.flatMap((part) => {
    const normalized = normalizeToolPart(part)
    return normalized ? [normalized] : []
  })
}

export const MEMORY_SAVE_TOOL = "argos_memory_save"

export const isMemorySaveTool = (tool: string | undefined) => tool === MEMORY_SAVE_TOOL

/** Prefijo de las tools del motor MCP argos-web (web.scan, web.fuzz, …). */
export const WEB_MCP_PREFIX = "argos-web_web."

export const isWebMcpTool = (tool: string | undefined) =>
  typeof tool === "string" && tool.startsWith(WEB_MCP_PREFIX)

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  const out = value.filter((x): x is string => typeof x === "string")
  return out.length ? out : undefined
}

const SEVERITY_ALIASES: Record<string, Severity> = {
  critical: "critical",
  critico: "critical",
  crítico: "critical",
  high: "high",
  alto: "high",
  alta: "high",
  medium: "medium",
  medio: "medium",
  media: "medium",
  moderate: "medium",
  low: "low",
  bajo: "low",
  baja: "low",
  info: "info",
  informational: "info",
  informativo: "info",
  none: "info",
}

export function normalizeSeverity(value: unknown): Severity {
  const key =
    typeof value === "string"
      ? value
          .trim()
          .toLowerCase()
          .replace(/<[^>]+>/g, "")
          .replace(/\*+/g, "")
      : ""
  return SEVERITY_ALIASES[key] ?? "info"
}

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity)
}

/**
 * Determina si un memory_save representa una decisión explícita y sustentada
 * del agente. Mantener en sync con isFindingInput del core.
 *
 * MANTENER EN SYNC con isFindingInput en packages/core/src/security/ingest.ts.
 */
function isFindingInput(input: Record<string, unknown>): boolean {
  const kind = str(input.kind)?.toLowerCase() ?? ""
  const severity = str(input.severity)?.toLowerCase()
  const acceptedSeverities = new Set([
    "critical", "critico", "crítico", "high", "alto", "alta", "medium", "medio", "media", "moderate",
    "low", "bajo", "baja", "info", "informational", "informativo",
  ])
  return kind === "finding" &&
    !!str(input.title) &&
    !!str(input.target) &&
    !!severity && acceptedSeverities.has(severity) &&
    meaningfulEvidenceText(input.evidence) &&
    meaningfulAgentReviewText(input.agent_assessment, 40) &&
    meaningfulAgentReviewText(input.impact) &&
    reviewFieldsAreDistinct(input)
}

const UNHELPFUL_AGENT_REVIEW = new Set([
  "n/a", "na", "none", "unknown", "tbd", "pending", "unconfirmed", "not applicable", "not verified", "not assessed",
])

function meaningfulEvidenceText(value: unknown): boolean {
  const text = str(value)
  return !!text && [...text].length >= 24
}

function meaningfulAgentReviewText(value: unknown, minimumLength = 24): boolean {
  const text = str(value)
  if (!text || [...text].length < minimumLength) return false
  return !UNHELPFUL_AGENT_REVIEW.has(text.toLowerCase().replace(/[.!\s]+$/g, ""))
}

function reviewFieldsAreDistinct(input: Record<string, unknown>): boolean {
  const assessment = str(input.agent_assessment)?.toLowerCase()
  const evidence = str(input.evidence)?.toLowerCase()
  const title = str(input.title)?.toLowerCase()
  const impact = str(input.impact)?.toLowerCase()
  return !!assessment && assessment !== evidence && assessment !== title && assessment !== impact
}

const FILE_EXTENSIONS = new Set([
  "asp",
  "aspx",
  "exe",
  "xml",
  "json",
  "php",
  "js",
  "ts",
  "jsx",
  "tsx",
  "css",
  "html",
  "htm",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "webp",
  "ico",
  "woff",
  "woff2",
  "ttf",
  "eot",
  "pdf",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "zip",
  "tar",
  "gz",
  "7z",
  "rar",
  "bak",
  "old",
  "sql",
  "txt",
  "md",
  "log",
  "yaml",
  "yml",
  "toml",
  "ini",
  "conf",
  "sh",
  "bat",
  "py",
  "rb",
  "go",
  "dll",
  "bin",
  "so",
  "class",
  "jar",
  "war",
  "ear",
  "jsp",
  "jspx",
  "cgi",
  "pl",
  "env",
])

function isRealDomain(domain: string): boolean {
  const parts = domain.split(".")
  if (parts.length < 2) return false
  const tld = parts.at(-1)!.toLowerCase()
  if (FILE_EXTENSIONS.has(tld)) return false
  if (/^\d+$/.test(tld) || tld.length < 2) return false
  return true
}

export function cleanEvidence(value: unknown, depth = 0): string | undefined {
  if (value === undefined || value === null) return undefined
  if (depth > 5) return typeof value === "string" ? value : JSON.stringify(value)

  if (typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>
    const candidate =
      obj.text ??
      obj.evidence ??
      obj.detail ??
      obj.message ??
      obj.output ??
      obj.content ??
      obj.result ??
      obj.poc ??
      obj.summary
    if (candidate !== undefined && candidate !== null) return cleanEvidence(candidate, depth + 1)
    try {
      return JSON.stringify(value)
    } catch {
      return undefined
    }
  }

  let raw = str(value)
  if (!raw) return undefined
  raw = raw.trim()

  if (raw.startsWith("{") || raw.startsWith('"{\\"') || raw.startsWith('"{\\"text\\"')) {
    try {
      let unquoted = raw
      if (unquoted.startsWith('"') && unquoted.endsWith('"')) {
        unquoted = JSON.parse(unquoted)
      }
      const parsed: unknown = typeof unquoted === "string" && unquoted.startsWith("{") ? JSON.parse(unquoted) : unquoted
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return cleanEvidence(parsed, depth + 1) ?? raw
      }
    } catch {
      // Truncated or escaped JSON fallback: extract inner text value if wrapped in {"text": ...}
      const match = raw.match(
        /^\{?\s*\\?"(?:text|evidence|detail|message|output|content|result|poc)"\\?\s*:\s*\\?"?([\s\S]*)/i,
      )
      if (match && match[1]) {
        let inner = match[1].trim()
        // Strip trailing quotes or braces
        inner = inner.replace(/\\?"\s*\}?\s*$/, "").replace(/\}\s*$/, "")
        // Unescape standard JSON escape sequences
        inner = inner.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\\\/g, "\\")
        return inner.trim()
      }
    }
  }

  return raw
}

function cvssFromInput(
  input: Record<string, unknown>,
  enrichment: Record<string, unknown> | undefined,
): Cvss | undefined {
  // Ya computado por el backend (enrichment.ts) — preferido, evita recalcular.
  const computed = isRecord(enrichment?.cvss) ? enrichment.cvss : undefined
  if (computed && typeof computed.score === "number" && typeof computed.vectorString === "string") {
    return {
      score: computed.score,
      severity: str(computed.severity) ?? "",
      vectorString: computed.vectorString,
    }
  }
  // Fallback: el vector crudo del agente todavía no pasó por enrichment (finding
  // recién parseado en vivo, sin fila en BD) — se calcula igual acá, con la misma
  // función pura que usa el backend, para que el número coincida siempre.
  if (!isRecord(input.cvss)) return undefined
  const parsed = parseCvssShortForm(input.cvss)
  if (!parsed) return undefined
  return calculateCvss(parsed)
}

function fromMemorySave(input: Record<string, unknown>): Finding | undefined {
  if (!isFindingInput(input)) return undefined
  const title = str(input.title)
  if (!title) return undefined
  const enrichment = isRecord(input.enrichment) ? input.enrichment : undefined
  const epssKevRaw = isRecord(input.epssKev)
    ? (input.epssKev as Record<string, unknown>)
    : isRecord(enrichment?.epssKev)
      ? (enrichment.epssKev as Record<string, unknown>)
      : undefined
  return {
    title,
    severity: normalizeSeverity(input.severity),
    severityRaw: str(input.severity),
    status: str(input.status),
    agent: str(input.agent),
    cwe: str(input.cwe),
    evidence: cleanEvidence(input.evidence),
    vector: str(input.vector),
    remediation: str(input.remediation),
    target: str(input.target),
    session: str(input.session),
    tags: stringArray(input.tags),
    source: "memory",
    epssKev: epssKevRaw
      ? {
          cve: str(epssKevRaw.cve) ?? str(epssKevRaw.primaryCve),
          epssScore:
            typeof epssKevRaw.epssScore === "number"
              ? epssKevRaw.epssScore
              : isRecord(epssKevRaw.epss) && typeof epssKevRaw.epss.epssScore === "number"
                ? epssKevRaw.epss.epssScore
                : undefined,
          epssPercentile:
            typeof epssKevRaw.epssPercentile === "number"
              ? epssKevRaw.epssPercentile
              : isRecord(epssKevRaw.epss) && typeof epssKevRaw.epss.epssPercentile === "number"
                ? epssKevRaw.epss.epssPercentile
                : undefined,
          cisaKev:
            typeof epssKevRaw.cisaKev === "boolean"
              ? epssKevRaw.cisaKev
              : isRecord(epssKevRaw.cisaKev)
                ? Boolean(epssKevRaw.cisaKev.isKev)
                : undefined,
          cisaKevDateAdded:
            str(epssKevRaw.cisaKevDateAdded) ??
            (isRecord(epssKevRaw.cisaKev) ? str(epssKevRaw.cisaKev.dateAdded) : undefined),
          cisaKevDueDate:
            str(epssKevRaw.cisaKevDueDate) ??
            (isRecord(epssKevRaw.cisaKev) ? str(epssKevRaw.cisaKev.dueDate) : undefined),
        }
      : undefined,
    cvss: cvssFromInput(input, enrichment),
  }
}

/** Escáner de objetos JSON balanceados (respeta strings) — soporta JSON multilínea. */
function scanJsonObjects(text: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = []
  let depth = 0
  let start = -1
  let inStr = false
  let esc = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (inStr) {
      if (esc) esc = false
      else if (ch === "\\") esc = true
      else if (ch === '"') inStr = false
      continue
    }
    if (ch === '"') inStr = true
    else if (ch === "{") {
      if (depth === 0) start = i
      depth++
    } else if (ch === "}") {
      if (depth > 0) {
        depth--
        if (depth === 0 && start >= 0) {
          try {
            const parsed: unknown = JSON.parse(text.slice(start, i + 1))
            if (isRecord(parsed)) out.push(parsed)
          } catch {
            /* fragmento no parseable, ignorar */
          }
          start = -1
        }
      }
    }
  }
  return out
}

function looksLikeWebCore(part: FindingToolPart): boolean {
  const command = typeof part.input?.command === "string" ? part.input.command : ""
  if (command.includes("web-core")) return true
  const output = part.output ?? ""
  return output.includes("fuzzing_hits") || output.includes("crawled_urls")
}

function webCoreReport(part: FindingToolPart): Record<string, unknown> | undefined {
  if (!part.output) return undefined
  const objects = scanJsonObjects(part.output)
  for (let i = objects.length - 1; i >= 0; i--) {
    const obj = objects[i]
    const report = isRecord(obj.report) ? obj.report : Array.isArray(obj.findings) ? obj : undefined
    if (report && Array.isArray(report.findings)) return report
  }
  return undefined
}

function looksLikeWebMcp(part: FindingToolPart): boolean {
  return isWebMcpTool(part.tool)
}

/** Parsea un único objeto JSON tolerando texto circundante (mismo patrón que topology-data). */
function parseSingleJson(text: string): Record<string, unknown> | undefined {
  const t = text.trim()
  if (!t) return undefined
  try {
    const parsed: unknown = JSON.parse(t)
    if (isRecord(parsed)) return parsed
  } catch {
    /* sigue al extractor */
  }
  const start = t.indexOf("{")
  const end = t.lastIndexOf("}")
  if (start >= 0 && end > start) {
    try {
      const parsed: unknown = JSON.parse(t.slice(start, end + 1))
      if (isRecord(parsed)) return parsed
    } catch {
      /* fragmento no parseable */
    }
  }
  return undefined
}

/** Desenvuelve el wrapping de contenido del cliente MCP: { content: [{ type:"text", text:"{...}" }] }. */
function unwrapMcpResult(obj: Record<string, unknown>): Record<string, unknown> | undefined {
  const content = obj.content
  if (Array.isArray(content)) {
    for (const c of content) {
      if (isRecord(c) && c.type === "text" && typeof c.text === "string") {
        const inner = parseSingleJson(c.text)
        if (inner) return inner
      }
    }
  }
  return obj
}

/** Deriva la superficie web de las tools web.* (crawl → crawledUrls, fuzz → fuzzingHits, scan → count). */
function surfaceFromWebMcp(parts: FindingToolPart[]): WebSurface | undefined {
  let target: string | undefined
  let findingsCount = 0
  const crawledUrls: string[] = []
  const fuzzingHits: FuzzingHit[] = []
  for (const part of parts) {
    if (!looksLikeWebMcp(part) || part.status !== "completed" || !part.output) continue
    const result = unwrapMcpResult(parseSingleJson(part.output) ?? {})
    if (!result) continue
    if (!target) target = str(result.target)
    const tool = str(result.tool)
    if (tool === "web.crawl") {
      const eps = Array.isArray(result.endpoints) ? result.endpoints : []
      for (const e of eps) {
        if (!isRecord(e)) continue
        const url = str(e.url) ?? str(e.endpoint)
        if (url && !crawledUrls.includes(url)) crawledUrls.push(url)
      }
    } else if (tool === "web.fuzz") {
      const arr = Array.isArray(result.hits) ? result.hits : []
      for (const h of arr) {
        if (!isRecord(h)) continue
        const url = str(h.url)
        if (!url) continue
        const statusNum = Number(h.status)
        fuzzingHits.push({ url, status: Number.isFinite(statusNum) ? statusNum : undefined })
      }
    }
    const fcount = Array.isArray(result.findings) ? result.findings.length : 0
    if (fcount > findingsCount) findingsCount = fcount
  }
  // solo cuenta como superficie si hay URLs/hits reales; un escaneo sin crawl/fuzz
  // no debe ensombrecer un reporte web-core más rico
  if (crawledUrls.length === 0 && fuzzingHits.length === 0) return undefined
  return { target, crawledUrls, fuzzingHits, findingsCount }
}

function extractHost(targetOrUrl?: string): string {
  if (!targetOrUrl) return ""
  const trimmed = targetOrUrl.trim().replace(/^[`'"\s]+|[`'"\s]+$/g, "").toLowerCase()
  try {
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      return new URL(trimmed).hostname
    }
  } catch {
    return ""
  }

  const match = trimmed.match(/(?:^|[^a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?=$|[^a-z0-9-])/i)
  return match?.[1]?.toLowerCase() ?? ""
}

function normalizeFindingTitle(title: string): string {
  return title
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .toLowerCase()
    .replace(/\b20\d{2}-\d{2}-\d{2}\b/g, " ")
    .replace(/\b(?:registro local|local cache|copia en cache|cached copy)\b/g, " ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ")
}

function findingTitleTokens(title: string): Set<string> {
  const stopWords = new Set(["de", "del", "la", "las", "el", "los", "y", "en", "para", "con", "por", "un", "una"])
  return new Set(normalizeFindingTitle(title).split(" ").filter((word) => word.length > 1 && !stopWords.has(word)))
}

function similarFindingTitles(a: string, b: string): boolean {
  const normalizedA = normalizeFindingTitle(a)
  const normalizedB = normalizeFindingTitle(b)
  if (normalizedA === normalizedB) return true

  const tokensA = findingTitleTokens(a)
  const tokensB = findingTitleTokens(b)
  if (Math.min(tokensA.size, tokensB.size) < 3) return false

  let shared = 0
  for (const token of tokensA) {
    if (tokensB.has(token)) shared++
  }
  return shared / Math.min(tokensA.size, tokensB.size) >= 0.8
}

function normalizeFindingLocation(value?: string): string {
  const location = value?.trim().replace(/^[`'"\s]+|[`'"\s]+$/g, "")
  if (!location) return ""
  if ((location.match(/https?:\/\//gi)?.length ?? 0) > 1) return ""

  try {
    if (/^https?:\/\//i.test(location)) {
      const url = new URL(location)
      const path = url.pathname.replace(/\/+$/, "") || "/"
      return `${path}${url.search}`
    }
  } catch {
    return ""
  }

  if (!location.startsWith("/") || location.startsWith("//")) return ""
  const [path, ...query] = location.split("?")
  const normalizedPath = path.replace(/\/+$/, "") || "/"
  return query.length > 0 ? `${normalizedPath}?${query.join("?")}` : normalizedPath
}

function sameFindingIdentity(a: Finding, b: Finding): boolean {
  const differentIds = !!a.id && !!b.id && a.id !== b.id
  if (differentIds && a.source === "db" && b.source === "db") return false
  const associatedA = !!(a.id && a.session)
  const associatedB = !!(b.id && b.session)
  const cacheAgainstPersisted = associatedA !== associatedB
  const strongDuplicateMatch = differentIds || cacheAgainstPersisted
  if (differentIds && !cacheAgainstPersisted) return false
  if (a.session && b.session && a.session !== b.session && !cacheAgainstPersisted) return false
  if (strongDuplicateMatch && normalizeFindingTitle(a.title) !== normalizeFindingTitle(b.title)) return false
  if (a.severity !== b.severity || !similarFindingTitles(a.title, b.title)) return false

  const hostA = extractHost(a.target) || extractHost(a.vector)
  const hostB = extractHost(b.target) || extractHost(b.vector)
  if (hostA && hostB && hostA !== hostB) return false
  if (strongDuplicateMatch && (!hostA || !hostB || hostA !== hostB)) return false

  const cweA = a.cwe?.trim().toUpperCase().replace(/^CWE\s*/, "CWE-")
  const cweB = b.cwe?.trim().toUpperCase().replace(/^CWE\s*/, "CWE-")
  if (cweA && cweB && cweA !== cweB) return false

  const locationA = normalizeFindingLocation(a.vector)
  const locationB = normalizeFindingLocation(b.vector)
  if (locationA && locationB && locationA !== locationB) return false

  return true
}

function dedupeKey(f: Finding): string {
  if (f.fingerprint) return `fingerprint:${f.session ?? ""}:${f.fingerprint}`
  if (f.id) return `finding:${f.id}`
  if (f.observationID) return `observation:${f.observationID}`
  return `unidentified:${f.source}:${JSON.stringify({
    title: f.title,
    severity: f.severity,
    target: f.target,
    vector: f.vector,
    cwe: f.cwe,
    evidence: f.evidence,
    raw: f.raw,
  })}`
}

export function findingDedupeKey(f: Finding): string {
  if (f.id) return f.id
  return dedupeKey(f)
}

const SOURCE_PRIORITY: Record<string, number> = {
  db: 5,
  memory: 4,
  "web-mcp": 3,
  "web-core": 2,
}

function combineFindings(a: Finding, b: Finding): Finding {
  const priorityA = SOURCE_PRIORITY[a.source] ?? 1
  const priorityB = SOURCE_PRIORITY[b.source] ?? 1
  const associatedA = !!(a.id && a.session)
  const associatedB = !!(b.id && b.session)
  const primary = associatedA !== associatedB ? (associatedA ? a : b) : priorityA >= priorityB ? a : b
  const secondary = primary === a ? b : a

  return {
    ...secondary,
    ...primary,
    evidence: primary.evidence || secondary.evidence,
    remediation: primary.remediation || secondary.remediation,
    target: primary.target || secondary.target,
    vector: primary.vector || secondary.vector,
    status: primary.status || secondary.status,
    cwe: primary.cwe || secondary.cwe,
    agent: primary.agent || secondary.agent,
    attack: primary.attack?.length ? primary.attack : secondary.attack,
    iocs: primary.iocs?.length ? primary.iocs : secondary.iocs,
    feedback: primary.feedback ?? secondary.feedback,
    raw: primary.raw || secondary.raw,
    id: primary.id || secondary.id,
    caseID: primary.caseID || secondary.caseID,
    fingerprint: primary.fingerprint || secondary.fingerprint,
    observationID: primary.observationID || secondary.observationID,
    session: primary.session || secondary.session,
  }
}

export function mergeFindings(...lists: Finding[][]): Finding[] {
  const merged = new Map<string, Finding>()
  const unidentified: Finding[] = []
  for (const list of lists) {
    for (const finding of list) {
      const key = findingIdentity(finding)

      if (key && merged.has(key)) {
        merged.set(key, combineFindings(merged.get(key)!, finding))
        continue
      }

      const persistedMatch = [...merged.entries()].find(([, existing]) =>
        sameAgentPersistence(existing, finding) ||
        (!!(existing.id && existing.session) !== !!(finding.id && finding.session) && sameFindingIdentity(existing, finding)),
      )
      if (persistedMatch) {
        merged.set(persistedMatch[0], combineFindings(persistedMatch[1], finding))
        continue
      }

      const liveMatch = unidentified.findIndex((existing) =>
        sameAgentPersistence(existing, finding) ||
        (!!(existing.id && existing.session) !== !!(finding.id && finding.session) && sameFindingIdentity(existing, finding)),
      )
      if (liveMatch >= 0) {
        const combined = combineFindings(unidentified[liveMatch], finding)
        unidentified.splice(liveMatch, 1)
        if (key) merged.set(key, combined)
        else unidentified.push(combined)
        continue
      }

      if (key) merged.set(key, finding)
      else unidentified.push(finding)
    }
  }
  return [...merged.values(), ...unidentified].sort(bySeverity)
}

function normalizedIdentity(value?: string): string {
  return (value ?? "").trim().toLowerCase().replace(/\s+/g, " ").split("#", 1)[0].split("?", 1)[0].replace(/\/+$/, "")
}

function normalizedTarget(value?: string): string {
  let text = normalizedIdentity(value)
  const scheme = text.indexOf("://")
  if (scheme >= 0) text = text.slice(scheme + 3)
  const slash = text.indexOf("/")
  const authority = slash < 0 ? text : text.slice(0, slash)
  const path = slash < 0 ? "" : text.slice(slash)
  const colon = authority.lastIndexOf(":")
  if (colon > 0 && ["80", "443"].includes(authority.slice(colon + 1))) {
    text = authority.slice(0, colon) + path
  }
  return text
}

function normalizedVector(value?: string): string {
  let text = (value ?? "").trim().toLowerCase().replace(/\s+/g, " ").split("#", 1)[0] ?? ""
  if (!text) return ""
  const queryIndex = text.indexOf("?")
  const path = queryIndex === -1 ? text : text.slice(0, queryIndex)
  const query = queryIndex === -1 ? "" : text.slice(queryIndex + 1)
  const parameterNames = query
    .split("&")
    .map((parameter) => parameter.split("=", 1)[0]?.trim() ?? "")
    .filter(Boolean)
    .sort()
  const normalizedPath = path.replace(/\/+$/, "")
  return parameterNames.length > 0 ? `${normalizedPath}?${parameterNames.join("&")}` : normalizedPath
}

function findingIdentity(finding: Finding): string | undefined {
  if (finding.id) return `finding:${finding.id}`
  if (finding.fingerprint) return `fingerprint:${finding.session ?? ""}:${finding.fingerprint}`
  if (finding.observationID) return `observation:${finding.observationID}`
  const target = normalizedTarget(finding.target)
  const vector = normalizedVector(finding.vector)
  const cwe = normalizedCwe(finding.cwe)
  if (cwe && target && vector) return `taxonomy:${cwe}:${target}:${vector}`
  if (finding.title && target && vector) return `legacy:${cwe}:${normalizedIdentity(finding.title)}:${target}:${vector}`
  return undefined
}

function normalizedCwe(value?: string): string {
  const digits = value?.trim().match(/^(?:CWE[-\s]*)?(\d+)$/i)?.[1]
  return digits ? `CWE-${digits}` : ""
}

function sameAgentPersistence(a: Finding, b: Finding): boolean {
  const paired = (a.source === "memory" && b.source === "db") || (a.source === "db" && b.source === "memory")
  if (!paired || (a.id && b.id && a.id !== b.id) || !a.title || !b.title || !a.target || !b.target || !a.evidence || !b.evidence) return false
  const sameTaxonomy = !!normalizedCwe(a.cwe) && !!normalizedVector(a.vector) &&
    normalizedCwe(a.cwe) === normalizedCwe(b.cwe)
  return (normalizedIdentity(a.title) === normalizedIdentity(b.title) || sameTaxonomy) &&
    normalizedTarget(a.target) === normalizedTarget(b.target) &&
    normalizedVector(a.vector) === normalizedVector(b.vector) &&
    normalizedCwe(a.cwe) === normalizedCwe(b.cwe) &&
    normalizedIdentity(a.evidence) === normalizedIdentity(b.evidence)
}

export function bindFindingsToSession(findings: Finding[], sessionID: string): Finding[] {
  return findings.map((finding) => ({ ...finding, session: sessionID }))
}

export function mergeFindingBuckets(buckets: Finding[][]): Finding[] {
  return mergeFindings(...buckets)
}

const bySeverity = (a: Finding, b: Finding) => severityRank(a.severity) - severityRank(b.severity)

function normalizeDBFinding(f: Record<string, unknown>): Finding | undefined {
  if (typeof f.title !== "string" || !f.title) return undefined
  return {
    id: typeof f.id === "string" ? f.id : undefined,
    caseID: typeof f.caseID === "string" ? f.caseID : typeof f.case_id === "string" ? f.case_id : undefined,
    fingerprint: typeof f.fingerprint === "string" ? f.fingerprint : undefined,
    title: f.title,
    severity: normalizeSeverity(f.severity),
    severityRaw: String(f.severity ?? ""),
    status: String(f.status ?? ""),
    agent: String(f.agent ?? ""),
    cwe: f.cwe_id ? String(f.cwe_id) : undefined,
    evidence:
      cleanEvidence(f.evidence) ??
      (typeof f.evidence === "object" ? JSON.stringify(f.evidence) : String(f.evidence ?? "")),
    vector: f.vector ? String(f.vector) : undefined,
    remediation: f.remediation ? String(f.remediation) : undefined,
    target: typeof f.target === "string" ? f.target : undefined,
    tags: Array.isArray(f.tags) ? f.tags.map(String) : undefined,
    attack: normalizeAttackTechniques(f.attackTechniques),
    iocs: normalizeIocs(f.iocs),
    enrichedAt: typeof f.enrichedAt === "number" ? f.enrichedAt : undefined,
    source: str(f.source)?.toLowerCase() === "tool" ? "tool" : "db",
  }
}

function normalizeAttackTechniques(value: unknown): AttackTechnique[] | undefined {
  if (!Array.isArray(value)) return undefined
  const out: AttackTechnique[] = []
  for (const raw of value) {
    if (!isRecord(raw)) continue
    const id = str(raw.id)
    const name = str(raw.name)
    if (!id || !name) continue
    out.push({
      id,
      name,
      tactics: Array.isArray(raw.tactics) ? raw.tactics.filter((t): t is string => typeof t === "string") : [],
      reason: str(raw.reason),
    })
  }
  return out.length ? out : undefined
}

function normalizeIocs(value: unknown): FindingIoc[] | undefined {
  if (!Array.isArray(value)) return undefined
  const out: FindingIoc[] = []
  for (const raw of value) {
    if (!isRecord(raw)) continue
    const type = str(raw.type)
    const v = str(raw.value)
    if (!type || !v) continue
    if (type === "domain" && !isRealDomain(v)) continue
    const reputation = Array.isArray(raw.reputation)
      ? raw.reputation.filter((r): r is IocReputation => isRecord(r) && typeof r.verdict === "string")
      : undefined
    out.push({
      type,
      value: v,
      ...(reputation?.length ? { reputation } : {}),
    })
  }
  return out.length ? out : undefined
}

/**
 * Muestra decisiones explícitas del agente, filas revisadas en backend e
 * importaciones iniciadas expresamente por el operador. Las salidas MCP no se
 * convierten aquí en hallazgos.
 */
export function extractFindings(
  parts: FindingToolPart[],
  dbFindings?: Record<string, unknown>[],
): Finding[] {
  const memoryList: Finding[] = []
  for (const part of parts) {
    if (!isMemorySaveTool(part.tool) || part.status !== "completed" || !part.input) continue
    const finding = fromMemorySave(part.input)
    if (finding) memoryList.push(finding)
  }

  const dbList: Finding[] = []
  if (dbFindings) {
    for (const raw of dbFindings) {
      if (!raw || typeof raw !== "object") continue
      if (!new Set(["agent-reviewed", "import"]).has(str(raw.source)?.toLowerCase() ?? "")) continue
      const finding = normalizeDBFinding(raw)
      if (finding) dbList.push(finding)
    }
  }
  return mergeFindings(memoryList, dbList)
}

/**
 * Resumen de superficie web. Prioriza la superficie derivada de las tools
 * `argos-web_web.*` (crawl → URLs rastreadas, fuzz → rutas expuestas);
 * si no hay, cae al último reporte de web-core.ts (legacy).
 */
export function extractWebSurface(parts: FindingToolPart[]): WebSurface | undefined {
  const fromMcp = surfaceFromWebMcp(parts)
  if (fromMcp) return fromMcp

  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i]
    if (part.tool !== "bash" && !looksLikeWebCore(part)) continue
    const report = webCoreReport(part)
    if (!report) continue
    const fuzzingHits: FuzzingHit[] = []
    const rawHits = Array.isArray(report.fuzzing_hits) ? report.fuzzing_hits : []
    for (const raw of rawHits) {
      if (!isRecord(raw)) continue
      const hit = raw
      const url = str(hit.url)
      if (!url) continue
      const statusNum = Number(hit.status)
      fuzzingHits.push({ url, status: Number.isFinite(statusNum) ? statusNum : undefined })
    }
    return {
      target: str(report.target),
      crawledUrls: stringArray(report.crawled_urls) ?? [],
      fuzzingHits,
      findingsCount: Array.isArray(report.findings) ? report.findings.length : 0,
    }
  }
  return undefined
}

/** Conteo por severidad para tableros/resúmenes. */
export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) counts[f.severity]++
  return counts
}
