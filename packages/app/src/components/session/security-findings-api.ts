import {
  cleanEvidence,
  type Finding,
  type FindingFeedback,
  type FindingSource,
  type FeedbackVerdict,
  type Severity,
} from "./findings-data"
import { responseItems, safeJson, stringValue } from "./api-utils"
import type { FindingImportFormat, FindingImportPreview, FindingImportResult } from "@argos/core/security"

type Requester = (path: string, init?: RequestInit) => Promise<Response>
const PAGE_SIZE = 200

export type FindingCaseStatus = "open" | "in-progress" | "remediated" | "accepted-risk"

export interface FindingCase {
  id: string
  status: FindingCaseStatus
  statusReason?: string
  owner?: string
  dueAt?: number
  acceptedRiskUntil?: number
  findingCount: number
  sessionCount: number
  createdAt: number
  updatedAt: number
}

export interface FindingCaseTransition {
  id: string
  fromStatus?: FindingCaseStatus
  toStatus: FindingCaseStatus
  reason?: string
  actor: "human" | "system"
  sessionID?: string
  createdAt: number
}

export interface FindingCaseOperation {
  id: string
  kind: "merge" | "split"
  sourceCaseID: string
  targetCaseID: string
  reason: string
  actor: "human" | "system"
  sessionID?: string
  findingIDs: string[]
  createdAt: number
  reversedAt?: number
  reversedReason?: string
  reversedBy?: "human" | "system"
}

function mapFindingCase(value: unknown): FindingCase | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = stringValue(record.id)
  const status = stringValue(record.status)
  if (!id || (status !== "open" && status !== "in-progress" && status !== "remediated" && status !== "accepted-risk")) {
    return undefined
  }
  const numberValue = (input: unknown) => (typeof input === "number" && Number.isFinite(input) ? input : undefined)
  const findingCount = numberValue(record.findingCount)
  const sessionCount = numberValue(record.sessionCount)
  const createdAt = numberValue(record.createdAt)
  const updatedAt = numberValue(record.updatedAt)
  if (findingCount === undefined || sessionCount === undefined || createdAt === undefined || updatedAt === undefined) {
    return undefined
  }
  return {
    id,
    status,
    statusReason: stringValue(record.statusReason),
    owner: stringValue(record.owner),
    dueAt: numberValue(record.dueAt),
    acceptedRiskUntil: numberValue(record.acceptedRiskUntil),
    findingCount,
    sessionCount,
    createdAt,
    updatedAt,
  }
}

export async function loadSessionFindingCases(request: Requester, sessionID: string): Promise<FindingCase[]> {
  const cases: FindingCase[] = []
  let offset = 0
  let total = Number.POSITIVE_INFINITY
  while (cases.length < total) {
    const response = await request(
      `/session/${encodeURIComponent(sessionID)}/finding-cases?limit=${PAGE_SIZE}&offset=${offset}`,
    )
    if (!response.ok) throw new Error(`Unable to load finding cases (HTTP ${response.status})`)
    const body = await safeJson(response)
    if (!body || typeof body !== "object") throw new Error("Unable to confirm persisted finding cases")
    const record = body as { data?: unknown; total?: unknown; limit?: unknown; offset?: unknown }
    if (
      !Array.isArray(record.data) ||
      typeof record.total !== "number" ||
      !Number.isSafeInteger(record.total) ||
      record.total < 0 ||
      typeof record.limit !== "number" ||
      !Number.isSafeInteger(record.limit) ||
      record.limit <= 0 ||
      record.offset !== offset
    ) {
      throw new Error("Unable to confirm persisted finding cases")
    }
    const page = record.data.map(mapFindingCase)
    if (page.some((item) => !item)) throw new Error("Unable to confirm persisted finding case record")
    cases.push(...(page as FindingCase[]))
    total = record.total
    if (page.length === 0) break
    offset += page.length
  }
  return cases
}

function mapFindingCaseTransition(value: unknown): FindingCaseTransition | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = stringValue(record.id)
  const fromStatus = record.fromStatus === null ? undefined : stringValue(record.fromStatus)
  const toStatus = stringValue(record.toStatus)
  const actor = stringValue(record.actor)
  const createdAt = record.createdAt
  const validStatus = (status: string | undefined) =>
    status === undefined ||
    status === "open" ||
    status === "in-progress" ||
    status === "remediated" ||
    status === "accepted-risk"
  if (
    !id ||
    !toStatus ||
    !validStatus(fromStatus) ||
    !validStatus(toStatus) ||
    (actor !== "human" && actor !== "system") ||
    typeof createdAt !== "number" ||
    !Number.isFinite(createdAt)
  ) {
    return undefined
  }
  return {
    id,
    fromStatus,
    toStatus,
    reason: stringValue(record.reason),
    actor,
    sessionID: stringValue(record.sessionID),
    createdAt,
  }
}

function mapFindingCaseOperation(value: unknown): FindingCaseOperation | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const id = stringValue(record.id)
  const kind = stringValue(record.kind)
  const sourceCaseID = stringValue(record.sourceCaseID)
  const targetCaseID = stringValue(record.targetCaseID)
  const reason = stringValue(record.reason)
  const actor = stringValue(record.actor)
  const createdAt = record.createdAt
  const reversedAt = record.reversedAt
  const reversedBy = record.reversedBy === null ? undefined : stringValue(record.reversedBy)
  if (
    !id ||
    (kind !== "merge" && kind !== "split") ||
    !sourceCaseID ||
    !targetCaseID ||
    !reason ||
    (actor !== "human" && actor !== "system") ||
    !Array.isArray(record.findingIDs) ||
    !record.findingIDs.every((findingID) => typeof findingID === "string") ||
    typeof createdAt !== "number" ||
    !Number.isFinite(createdAt) ||
    (reversedAt !== null && (typeof reversedAt !== "number" || !Number.isFinite(reversedAt))) ||
    (reversedBy !== undefined && reversedBy !== "human" && reversedBy !== "system")
  ) {
    return undefined
  }
  return {
    id,
    kind,
    sourceCaseID,
    targetCaseID,
    reason,
    actor,
    sessionID: stringValue(record.sessionID),
    findingIDs: record.findingIDs as string[],
    createdAt,
    reversedAt: typeof reversedAt === "number" ? reversedAt : undefined,
    reversedReason: stringValue(record.reversedReason),
    reversedBy: reversedBy as "human" | "system" | undefined,
  }
}

export async function loadFindingCaseOperations(
  request: Requester,
  sessionID: string,
  caseID: string,
): Promise<FindingCaseOperation[]> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/finding-cases/${encodeURIComponent(caseID)}/operations?limit=100`,
  )
  if (!response.ok) throw new Error(`Unable to load finding case operations (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object" || !Array.isArray((body as { data?: unknown }).data)) {
    throw new Error("Unable to confirm finding case operations")
  }
  const operations = (body as { data: unknown[] }).data.map(mapFindingCaseOperation)
  if (operations.some((item) => !item)) throw new Error("Unable to confirm finding case operation record")
  return operations as FindingCaseOperation[]
}

async function postCaseOperation(request: Requester, path: string, input: unknown): Promise<unknown> {
  const response = await request(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  })
  if (!response.ok) {
    const body = await safeJson(response)
    const message =
      body && typeof body === "object" && typeof (body as { error?: { message?: unknown } }).error?.message === "string"
        ? String((body as { error: { message: string } }).error.message)
        : `HTTP ${response.status}`
    throw new Error(`Unable to update finding cases: ${message}`)
  }
  return safeJson(response)
}

export async function mergeFindingCases(
  request: Requester,
  sessionID: string,
  sourceCaseID: string,
  input: { targetCaseID: string; reason: string },
): Promise<FindingCaseOperation> {
  const body = await postCaseOperation(
    request,
    `/session/${encodeURIComponent(sessionID)}/finding-cases/${encodeURIComponent(sourceCaseID)}/merge`,
    input,
  )
  const operation =
    body && typeof body === "object" ? mapFindingCaseOperation((body as { data?: unknown }).data) : undefined
  if (
    !operation ||
    operation.kind !== "merge" ||
    operation.sourceCaseID !== sourceCaseID ||
    operation.targetCaseID !== input.targetCaseID
  ) {
    throw new Error("Unable to confirm persisted finding case merge")
  }
  return operation
}

export async function splitFindingCase(
  request: Requester,
  sessionID: string,
  sourceCaseID: string,
  input: { findingIDs: string[]; reason: string },
): Promise<{ caseID: string; operation: FindingCaseOperation }> {
  const body = await postCaseOperation(
    request,
    `/session/${encodeURIComponent(sessionID)}/finding-cases/${encodeURIComponent(sourceCaseID)}/split`,
    input,
  )
  if (!body || typeof body !== "object") throw new Error("Unable to confirm persisted finding case split")
  const data = (body as { data?: unknown }).data
  if (!data || typeof data !== "object") throw new Error("Unable to confirm persisted finding case split")
  const response = data as { caseID?: unknown; operation?: unknown }
  const caseID = stringValue(response.caseID)
  const operation = mapFindingCaseOperation(response.operation)
  if (!caseID || !operation || operation.kind !== "split" || operation.sourceCaseID !== sourceCaseID) {
    throw new Error("Unable to confirm persisted finding case split")
  }
  return { caseID, operation }
}

export async function reverseFindingCaseOperation(
  request: Requester,
  sessionID: string,
  caseID: string,
  operationID: string,
  reason: string,
): Promise<FindingCaseOperation> {
  const body = await postCaseOperation(
    request,
    `/session/${encodeURIComponent(sessionID)}/finding-cases/${encodeURIComponent(caseID)}/operations/${encodeURIComponent(operationID)}/reverse`,
    { reason },
  )
  const operation =
    body && typeof body === "object" ? mapFindingCaseOperation((body as { data?: unknown }).data) : undefined
  if (!operation || operation.id !== operationID || operation.reversedAt === undefined || !operation.reversedReason) {
    throw new Error("Unable to confirm persisted case operation reversal")
  }
  return operation
}

export async function loadFindingCaseHistory(
  request: Requester,
  sessionID: string,
  caseID: string,
): Promise<FindingCaseTransition[]> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/finding-cases/${encodeURIComponent(caseID)}/history?limit=100`,
  )
  if (!response.ok) throw new Error(`Unable to load finding case history (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object" || !Array.isArray((body as { data?: unknown }).data)) {
    throw new Error("Unable to confirm finding case history")
  }
  const history = (body as { data: unknown[] }).data.map(mapFindingCaseTransition)
  if (history.some((item) => !item)) throw new Error("Unable to confirm finding case history record")
  return history as FindingCaseTransition[]
}

export async function updateFindingCaseStatus(
  request: Requester,
  sessionID: string,
  caseID: string,
  input: { status: FindingCaseStatus; reason?: string; acceptedRiskUntil?: number },
): Promise<FindingCase> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/finding-cases/${encodeURIComponent(caseID)}/status`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    },
  )
  if (!response.ok) throw new Error(`Unable to update finding case (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object") throw new Error("Unable to confirm persisted finding case")
  const data = (body as { data?: unknown }).data
  const record = mapFindingCase(data)
  if (!record || record.id !== caseID || record.status !== input.status) {
    throw new Error("Unable to confirm persisted finding case")
  }
  return record
}

type SecurityFindingRecord = {
  id?: unknown
  caseID?: unknown
  case_id?: unknown
  fingerprint?: unknown
  session_id?: unknown
  sessionID?: unknown
  title?: unknown
  severity?: unknown
  status?: unknown
  source?: unknown
  source_tool?: unknown
  sourceTool?: unknown
  agent?: unknown
  target?: unknown
  cwe?: unknown
  vector?: unknown
  evidence?: unknown
  remediation?: unknown
  tags?: unknown
  raw?: unknown
  attackTechniques?: unknown
  iocs?: unknown
  enrichedAt?: unknown
  feedback?: unknown
}

function severity(value: unknown): Severity | undefined {
  const normalized = stringValue(value)?.toLowerCase()
  if (
    normalized === "critical" ||
    normalized === "high" ||
    normalized === "medium" ||
    normalized === "low" ||
    normalized === "info"
  ) {
    return normalized
  }
  return undefined
}

function source(value: unknown): FindingSource {
  const normalized = stringValue(value)
  if (normalized === "memory" || normalized === "web-core" || normalized === "web-mcp" || normalized === "db" || normalized === "tool")
    return normalized
  return "db"
}

function mapFeedback(value: unknown): FindingFeedback | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as { verdict?: unknown; reason?: unknown; actor?: unknown }
  const verdict = stringValue(record.verdict)
  if (verdict !== "false-positive" && verdict !== "true-positive" && verdict !== "accepted-risk") return undefined
  const actor = stringValue(record.actor)
  return {
    verdict,
    reason: stringValue(record.reason),
    actor: actor === "agent" ? "agent" : "human",
  }
}

function mapFinding(value: unknown, sessionID: string): Finding | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as SecurityFindingRecord
  const title = stringValue(record.title)
  const level = severity(record.severity)
  if (!title || !level) return undefined

  return {
    id: stringValue(record.id),
    caseID: stringValue(record.caseID) ?? stringValue(record.case_id),
    fingerprint: stringValue(record.fingerprint),
    session: stringValue(record.session_id) ?? stringValue(record.sessionID) ?? sessionID,
    title,
    severity: level,
    severityRaw: stringValue(record.severity),
    status: stringValue(record.status),
    source: source(record.source),
    sourceTool: stringValue(record.source_tool) ?? stringValue(record.sourceTool),
    agent: stringValue(record.agent),
    cwe: stringValue(record.cwe),
    target: stringValue(record.target),
    vector: stringValue(record.vector),
    evidence: cleanEvidence(record.evidence),
    remediation: stringValue(record.remediation),
    tags: Array.isArray(record.tags) ? record.tags.filter((tag): tag is string => typeof tag === "string") : undefined,
    attack: mapAttackTechniques(record.attackTechniques),
    iocs: mapIocs(record.iocs),
    enrichedAt: typeof record.enrichedAt === "number" ? record.enrichedAt : undefined,
    feedback: mapFeedback(record.feedback),
    raw: stringValue(record.raw),
  }
}

function mapAttackTechniques(value: unknown) {
  if (!Array.isArray(value)) return undefined
  const out: { id: string; name: string; tactics: string[]; reason?: string }[] = []
  for (const raw of value) {
    if (!raw || typeof raw !== "object") continue
    const record = raw as { id?: unknown; name?: unknown; tactics?: unknown; reason?: unknown }
    const id = stringValue(record.id)
    const name = stringValue(record.name)
    if (!id || !name) continue
    out.push({
      id,
      name,
      tactics: Array.isArray(record.tactics) ? record.tactics.filter((t): t is string => typeof t === "string") : [],
      reason: stringValue(record.reason),
    })
  }
  return out.length ? out : undefined
}

function mapIocs(value: unknown) {
  if (!Array.isArray(value)) return undefined
  const out: {
    type: string
    value: string
    reputation?: { source: string; verdict: string; score: number; detail: string; checkedAt: number }[]
  }[] = []
  for (const raw of value) {
    if (!raw || typeof raw !== "object") continue
    const record = raw as { type?: unknown; value?: unknown; reputation?: unknown }
    const type = stringValue(record.type)
    const v = stringValue(record.value)
    if (!type || !v) continue
    const reputation = Array.isArray(record.reputation)
      ? record.reputation
          .filter(
            (r): r is { source: string; verdict: string; score: number; detail: string; checkedAt: number } =>
              !!r && typeof r === "object",
          )
          .map((r) => ({
            source: stringValue(r.source) ?? "",
            verdict: stringValue(r.verdict) ?? "unknown",
            score: typeof r.score === "number" ? r.score : 0,
            detail: stringValue(r.detail) ?? "",
            checkedAt: typeof r.checkedAt === "number" ? r.checkedAt : 0,
          }))
      : undefined
    out.push({ type, value: v, ...(reputation?.length ? { reputation } : {}) })
  }
  return out.length ? out : undefined
}

function responseTotal(value: unknown): number | undefined {
  if (!value || typeof value !== "object") return undefined
  const total = (value as { total?: unknown }).total
  return typeof total === "number" && Number.isFinite(total) && total >= 0 ? total : undefined
}

/** Returns undefined when the server does not expose the findings API yet. */
export async function loadSessionFindings(request: Requester, sessionID: string): Promise<Finding[] | undefined> {
  const findings: Finding[] = []
  let offset = 0
  let total: number | undefined

  do {
    const response = await request(
      `/session/${encodeURIComponent(sessionID)}/findings?limit=${PAGE_SIZE}&offset=${offset}`,
    )
    if (response.status === 404 || response.status === 405) return undefined
    if (!response.ok) throw new Error(`Unable to load findings for session ${sessionID} (HTTP ${response.status})`)

    const body = await safeJson(response)
    const items = responseItems(body)
    if (!items) throw new Error(`Invalid findings response for session ${sessionID}`)
    findings.push(
      ...items.flatMap((item) => {
        const finding = mapFinding(item, sessionID)
        return finding ? [finding] : []
      }),
    )
    total ??= responseTotal(body)
    offset += items.length
    if (items.length === 0 || items.length < PAGE_SIZE) break
  } while (total === undefined || offset < total)

  return findings
}

/** Loads independent sessions with bounded concurrency to avoid N+1 waterfalls and request bursts. */
export async function loadFindingsForSessions(
  request: Requester,
  sessionIDs: readonly string[],
  concurrency = 4,
): Promise<Record<string, Finding[] | undefined>> {
  const ids = [...new Set(sessionIDs.filter(Boolean))]
  const result: Record<string, Finding[] | undefined> = {}
  let next = 0
  const worker = async () => {
    while (next < ids.length) {
      const sessionID = ids[next++]
      try {
        result[sessionID] = await loadSessionFindings(request, sessionID)
      } catch (err) {
        console.warn(`Failed to load findings for session ${sessionID}:`, err)
        result[sessionID] = undefined
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(Math.max(concurrency, 1), ids.length) }, worker))
  return result
}

export type FindingRetestResult = {
  findingId: string
  previousStatus: string
  newStatus: string
  stillVulnerable: boolean
  /** false when no specific check ran for this finding type — the status moved to "in-progress", not "verified". */
  checked: boolean
  message: string
  verifiedAt: number
}

function mapRetestResult(value: unknown): FindingRetestResult | undefined {
  if (!value || typeof value !== "object") return undefined
  const record = value as Record<string, unknown>
  const findingId = stringValue(record.findingId)
  const previousStatus = stringValue(record.previousStatus)
  const newStatus = stringValue(record.newStatus)
  const message = stringValue(record.message)
  if (!findingId || !previousStatus || !newStatus || !message) return undefined
  return {
    findingId,
    previousStatus,
    newStatus,
    stillVulnerable: record.stillVulnerable === true,
    checked: record.checked === true,
    message,
    verifiedAt: typeof record.verifiedAt === "number" ? record.verifiedAt : 0,
  }
}

/** Returns undefined when the server doesn't expose the endpoint yet, or the finding has no DB id to retest. */
export async function retestFinding(
  request: Requester,
  sessionID: string,
  findingID: string,
): Promise<FindingRetestResult | undefined> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/finding/${encodeURIComponent(findingID)}/retest`,
    { method: "POST" },
  )
  if (response.status === 404 || response.status === 405) return undefined
  if (!response.ok) throw new Error(`Unable to retest finding ${findingID} (HTTP ${response.status})`)
  return mapRetestResult(await safeJson(response))
}

/** Returns false when the server doesn't expose the endpoint yet, or the transition wasn't persisted. */
export async function setFindingStatus(
  request: Requester,
  sessionID: string,
  findingID: string,
  status: string,
): Promise<boolean> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/finding/${encodeURIComponent(findingID)}/status`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status }),
    },
  )
  if (response.status === 404 || response.status === 405) return false
  if (!response.ok) throw new Error(`Unable to update finding status (HTTP ${response.status})`)
  const body = await safeJson(response)
  return !!body && typeof body === "object" && (body as Record<string, unknown>).ok === true
}

/**
 * Registra el triage de un hallazgo (ARG-064).
 *
 * El veredicto es por engagement: marcar un falso positivo acá no suprime la
 * misma regla en otro engagement. Solo se resuelve cuando el servidor devuelve
 * el registro persistido que corresponde al hallazgo.
 */
export async function setFindingFeedback(
  request: Requester,
  sessionID: string,
  findingID: string,
  verdict: FeedbackVerdict,
  reason?: string,
): Promise<FindingFeedback> {
  const response = await request(
    `/session/${encodeURIComponent(sessionID)}/findings/${encodeURIComponent(findingID)}/feedback`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(reason ? { verdict, reason } : { verdict }),
    },
  )
  if (!response.ok) throw new Error(`Unable to record finding feedback (HTTP ${response.status})`)
  const body = await safeJson(response)
  if (!body || typeof body !== "object") throw new Error("Unable to confirm persisted feedback record")
  const data = (body as { data?: unknown }).data ?? body
  if (!data || typeof data !== "object") throw new Error("Unable to confirm persisted feedback record")
  const record = data as { findingID?: unknown; finding_id?: unknown; updatedAt?: unknown; time_updated?: unknown }
  const persistedID = stringValue(record.findingID) ?? stringValue(record.finding_id)
  const persistedAt = record.updatedAt ?? record.time_updated
  const feedback = mapFeedback(data)
  if (persistedID !== findingID || typeof persistedAt !== "number" || !feedback) {
    throw new Error("Unable to confirm persisted feedback record")
  }
  return feedback
}

function importRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}

function parseFindingImportPreview(value: unknown): FindingImportPreview | undefined {
  if (!importRecord(value)) return undefined
  const formats: readonly string[] = [
    "sarif-2.1",
    "nuclei-jsonl",
    "semgrep-json",
    "gitleaks-json",
    "trivy-json",
    "zap-json",
    "burp-xml",
    "defectdojo-generic-json",
  ]
  if (
    typeof value.format !== "string" ||
    !formats.includes(value.format) ||
    typeof value.parserVersion !== "number" ||
    !Number.isSafeInteger(value.parserVersion) ||
    typeof value.contentSha256 !== "string" ||
    !/^[a-f0-9]{64}$/i.test(value.contentSha256) ||
    !Array.isArray(value.findings) ||
    !Array.isArray(value.warnings) ||
    !value.warnings.every((warning) => typeof warning === "string")
  ) {
    return undefined
  }
  const findings = value.findings.flatMap((finding) => {
    if (!importRecord(finding)) return []
    if (
      typeof finding.id !== "string" ||
      typeof finding.source_tool !== "string" ||
      typeof finding.title !== "string" ||
      typeof finding.severity !== "string" ||
      typeof finding.status !== "string" ||
      !importRecord(finding.evidence) ||
      !Array.isArray(finding.tags) ||
      !finding.tags.every((tag) => typeof tag === "string") ||
      !Array.isArray(finding.references) ||
      !finding.references.every((reference) => typeof reference === "string")
    ) {
      return []
    }
    return [finding as unknown as FindingImportPreview["findings"][number]]
  })
  if (findings.length !== value.findings.length) return undefined
  return {
    format: value.format as FindingImportFormat,
    parserVersion: value.parserVersion,
    contentSha256: value.contentSha256,
    findings,
    warnings: value.warnings,
  }
}

async function readFindingImportResponse(response: Response, operation: string) {
  const body = await safeJson(response)
  if (!response.ok) {
    const message =
      importRecord(body) && importRecord(body.error) && typeof body.error.message === "string"
        ? body.error.message
        : importRecord(body) && typeof body.message === "string"
          ? body.message
          : `HTTP ${response.status}`
    throw new Error(`Unable to ${operation}: ${message}`)
  }
  if (!importRecord(body) || !importRecord(body.data)) throw new Error(`Unable to confirm ${operation} response`)
  return body.data
}

export async function previewFindingImport(
  request: Requester,
  sessionID: string,
  format: FindingImportFormat,
  content: string,
): Promise<FindingImportPreview> {
  const response = await request(`/api/session/${encodeURIComponent(sessionID)}/findings/import/preview`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ format, content }),
  })
  const data = await readFindingImportResponse(response, "preview finding import")
  const preview = parseFindingImportPreview(data)
  if (!preview || preview.format !== format) throw new Error("Unable to validate finding import preview")
  return preview
}

export async function importFindings(
  request: Requester,
  sessionID: string,
  format: FindingImportFormat,
  content: string,
  importID?: string,
): Promise<FindingImportResult> {
  const response = await request(`/api/session/${encodeURIComponent(sessionID)}/findings/import`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ format, content, ...(importID ? { importID } : {}) }),
  })
  const data = await readFindingImportResponse(response, "import findings")
  const preview = parseFindingImportPreview(data)
  if (
    !preview ||
    preview.format !== format ||
    typeof data.sourceEventID !== "string" ||
    typeof data.importedCount !== "number" ||
    data.importedCount !== preview.findings.length
  ) {
    throw new Error("Unable to confirm persisted finding import")
  }
  return {
    ...preview,
    sourceEventID: data.sourceEventID,
    importedCount: data.importedCount,
  }
}

export type { Requester }
