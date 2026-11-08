/**
 * Read API of the HTTP traffic store.
 *
 * El store en disco (`<memoryDir>/traffic/<sessionID>/<exchangeID>.json`) lo
 * escribe el binario Go (`argos-bin/internal/traffic`) y es la ÚNICA fuente
 * de verdad: las credenciales que contenga ya vienen enmascaradas y nunca se
 * guardan en claro.
 *
 * La tabla `traffic_exchange` es un índice de lectura para la UI: el
 * reconciliador de este módulo la puebla desde el store. Si el store y la
 * tabla discrepan, el store gana — la tabla se puede reconstruir en
 * cualquier momento sin perder información.
 */

import { readdir, readFile } from "node:fs/promises"
import path from "node:path"
import { and, count, desc, eq, gte, like, lt, type SQL } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { SessionTable } from "../session/sql"
import { defaultAgentMemoryDir } from "./agent-findings-reconcile"
import { SessionSchema } from "../session/schema"
import { TrafficExchangeTable } from "./sql"

type DatabaseService = Database.Interface["db"]

/** The on-disk shape of an exchange, as written by the Go store. */
interface StoredExchange {
  id?: unknown
  session_id?: unknown
  timestamp?: unknown
  method?: unknown
  url?: unknown
  host?: unknown
  request_headers?: unknown
  request_body?: unknown
  status?: unknown
  response_headers?: unknown
  response_body?: unknown
  duration_ms?: unknown
  source_tool?: unknown
  target?: unknown
  scope_allowed?: unknown
}

interface StoredBody {
  text?: unknown
  base64?: unknown
  sha256?: unknown
  size?: unknown
}

/** A traffic exchange as the UI consumes it. */
export interface TrafficExchange {
  id: string
  sessionID: string
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

/** A header that appeared, disappeared or changed between two exchanges. */
export interface TrafficHeaderChange {
  name: string
  a: string
  b: string
}

/** The structural difference between two exchanges. */
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

/** The filters of the traffic history. */
export interface TrafficFilter {
  host?: string
  method?: string
  status?: string
  sourceTool?: string
  limit?: number
  offset?: number
}

/** The result of a reconciliation pass over the on-disk store. */
export interface TrafficReconcileResult {
  readonly scanned: number
  readonly inserted: number
  readonly updated: number
}

const str = (value: unknown): string | undefined => {
  if (typeof value !== "string") return undefined
  const normalized = value.trim()
  return normalized ? normalized : undefined
}

const num = (value: unknown): number => {
  if (typeof value === "number" && Number.isFinite(value)) return value
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10)
    if (Number.isFinite(parsed)) return parsed
  }
  return 0
}

const headers = (value: unknown): Record<string, string[]> => {
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

const body = (value: unknown): { text: string; sha256: string; size: number } => {
  if (!value || typeof value !== "object") return { text: "", sha256: "", size: 0 }
  const stored = value as StoredBody
  const text = typeof stored.text === "string" ? stored.text : ""
  return {
    text,
    sha256: str(stored.sha256) ?? "",
    size: num(stored.size),
  }
}

/**
 * The directory name of a session inside the traffic store.
 *
 * It mirrors the sanitization of the Go store (`internal/traffic`): both
 * sides have to land on the same folder or the reconciler finds nothing.
 */
export function trafficSessionDirName(sessionID: string): string {
  const cleaned = sessionID
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "-")
    .replace(/^-+|-+$/g, "")
  return cleaned || "unknown"
}

/** The directory of the traffic store of a session. */
export function trafficSessionDir(memoryDir: string, sessionID: string): string {
  return path.join(memoryDir, "traffic", trafficSessionDirName(sessionID))
}

const toExchange = (row: typeof TrafficExchangeTable.$inferSelect): TrafficExchange => ({
  id: row.id,
  sessionID: row.session_id,
  timestamp: row.timestamp,
  method: row.method,
  url: row.url,
  host: row.host ?? "",
  status: row.status,
  durationMs: row.duration_ms,
  sourceTool: row.source_tool ?? "",
  target: row.target ?? "",
  scopeAllowed: row.scope_allowed,
  requestHeaders: row.request_headers ?? {},
  responseHeaders: row.response_headers ?? {},
  requestBody: row.request_body ?? "",
  responseBody: row.response_body ?? "",
  requestBodySHA256: row.request_body_sha256 ?? "",
  responseBodySHA256: row.response_body_sha256 ?? "",
  requestBodySize: row.request_body_size,
  responseBodySize: row.response_body_size,
})

/**
 * Populates the `traffic_exchange` index from the on-disk store.
 *
 * The store is written by the Go binary; this pass copies what it finds into
 * the table the UI reads. Running it twice does not duplicate anything: the
 * exchange id is the primary key.
 */
export const reconcileTrafficStore = Effect.fn("Security.reconcileTrafficStore")(function* (
  db: DatabaseService,
  input: {
    sessionID: SessionSchema.ID
    /** Defaults to the memory store of the Go binary; injectable for tests. */
    memoryDir?: string
  },
) {
  const dir = trafficSessionDir(input.memoryDir ?? defaultAgentMemoryDir(), input.sessionID)
  const entries = yield* Effect.tryPromise(() => readdir(dir)).pipe(
    Effect.catch(() => Effect.succeed([] as string[])),
  )
  const files = entries.filter((entry) => entry.endsWith(".json"))
  if (files.length === 0) return { scanned: 0, inserted: 0, updated: 0 } satisfies TrafficReconcileResult

  const session = yield* db
    .select({ projectID: SessionTable.project_id })
    .from(SessionTable)
    .where(eq(SessionTable.id, input.sessionID))
    .get()
    .pipe(Effect.orDie)
  if (!session) return { scanned: files.length, inserted: 0, updated: 0 } satisfies TrafficReconcileResult

  let inserted = 0
  let updated = 0
  for (const file of files) {
    const raw = yield* Effect.tryPromise(() => readFile(path.join(dir, file), "utf8")).pipe(
      Effect.catch(() => Effect.succeed(undefined)),
    )
    if (!raw) continue
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Un archivo corrupto no debe abortar la reconciliación del resto.
      continue
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue
    const record = parsed as StoredExchange

    const recordSession = str(record.session_id)
    if (recordSession && recordSession !== input.sessionID) continue
    const id = str(record.id) ?? path.basename(file, ".json")
    const url = str(record.url)
    if (!url) continue

    const timestamp = Date.parse(str(record.timestamp) ?? "")
    const requestBody = body(record.request_body)
    const responseBody = body(record.response_body)
    const now = Date.now()

    const existing = yield* db
      .select({ id: TrafficExchangeTable.id })
      .from(TrafficExchangeTable)
      .where(eq(TrafficExchangeTable.id, id))
      .get()
      .pipe(Effect.orDie)

    if (existing) {
      yield* db
        .update(TrafficExchangeTable)
        .set({
          timestamp: Number.isFinite(timestamp) ? timestamp : now,
          method: str(record.method)?.toUpperCase() ?? "GET",
          url,
          host: str(record.host) ?? "",
          status: num(record.status),
          duration_ms: num(record.duration_ms),
          source_tool: str(record.source_tool) ?? null,
          target: str(record.target) ?? null,
          scope_allowed: record.scope_allowed === true,
          request_headers: headers(record.request_headers),
          response_headers: headers(record.response_headers),
          request_body: requestBody.text,
          response_body: responseBody.text,
          request_body_sha256: requestBody.sha256 || null,
          response_body_sha256: responseBody.sha256 || null,
          request_body_size: requestBody.size,
          response_body_size: responseBody.size,
          time_created: now,
        })
        .where(eq(TrafficExchangeTable.id, id))
        .run()
        .pipe(Effect.orDie)
      updated++
      continue
    }

    yield* db
      .insert(TrafficExchangeTable)
      .values({
        id,
        session_id: input.sessionID,
        project_id: session.projectID,
        timestamp: Number.isFinite(timestamp) ? timestamp : now,
        method: str(record.method)?.toUpperCase() ?? "GET",
        url,
        host: str(record.host) ?? "",
        status: num(record.status),
        duration_ms: num(record.duration_ms),
        source_tool: str(record.source_tool) ?? null,
        target: str(record.target) ?? null,
        scope_allowed: record.scope_allowed === true,
        request_headers: headers(record.request_headers),
        response_headers: headers(record.response_headers),
        request_body: requestBody.text,
        response_body: responseBody.text,
        request_body_sha256: requestBody.sha256 || null,
        response_body_sha256: responseBody.sha256 || null,
        request_body_size: requestBody.size,
        response_body_size: responseBody.size,
        time_created: now,
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    inserted++
  }

  return { scanned: files.length, inserted, updated } satisfies TrafficReconcileResult
})

/**
 * Lists the traffic exchanges of a session.
 *
 * The table is an index: the caller is expected to reconcile the store
 * first so the list reflects what the Go binary actually captured.
 */
export const listTrafficExchanges = Effect.fn("Security.listTrafficExchanges")(function* (
  db: DatabaseService,
  input: { sessionID: SessionSchema.ID; filter?: TrafficFilter },
) {
  const filter = input.filter ?? {}
  const conditions: SQL[] = [eq(TrafficExchangeTable.session_id, input.sessionID)]
  if (filter.host) conditions.push(like(TrafficExchangeTable.host, `%${filter.host.toLowerCase()}%`))
  if (filter.method) conditions.push(eq(TrafficExchangeTable.method, filter.method.toUpperCase()))
  if (filter.sourceTool) conditions.push(eq(TrafficExchangeTable.source_tool, filter.sourceTool))
  if (filter.status) {
    const status = filter.status.trim()
    if (/^[1-5]xx$/i.test(status)) {
      // "4xx" es una clase entera, no un status: 400..499.
      const base = Number(status[0]) * 100
      conditions.push(and(gte(TrafficExchangeTable.status, base), lt(TrafficExchangeTable.status, base + 100))!)
    } else {
      const exact = Number.parseInt(status, 10)
      if (Number.isFinite(exact)) conditions.push(eq(TrafficExchangeTable.status, exact))
    }
  }
  const where = and(...conditions)
  const limit = Math.min(Math.max(filter.limit ?? 100, 1), 500)
  const offset = Math.max(filter.offset ?? 0, 0)

  const [rows, total] = yield* Effect.all([
    db
      .select()
      .from(TrafficExchangeTable)
      .where(where)
      .orderBy(desc(TrafficExchangeTable.timestamp))
      .limit(limit)
      .offset(offset)
      .all(),
    db.select({ total: count() }).from(TrafficExchangeTable).where(where).get(),
  ]).pipe(Effect.orDie)

  return { data: rows.map(toExchange), total: total?.total ?? 0, limit, offset }
})

/** Reads one exchange of a session. */
export const getTrafficExchange = Effect.fn("Security.getTrafficExchange")(function* (
  db: DatabaseService,
  input: { sessionID: SessionSchema.ID; exchangeID: string },
) {
  const row = yield* db
    .select()
    .from(TrafficExchangeTable)
    .where(and(eq(TrafficExchangeTable.session_id, input.sessionID), eq(TrafficExchangeTable.id, input.exchangeID)))
    .get()
    .pipe(Effect.orDie)
  return row ? toExchange(row) : undefined
})

/**
 * Compares two exchanges of a session.
 *
 * The diff is derived, never stored: it is recomputed from the index every
 * time so it can never disagree with the exchanges it compares.
 */
export const diffTrafficExchanges = Effect.fn("Security.diffTrafficExchanges")(function* (
  db: DatabaseService,
  input: { sessionID: SessionSchema.ID; aID: string; bID: string },
) {
  const [a, b] = yield* Effect.all([
    getTrafficExchange(db, { sessionID: input.sessionID, exchangeID: input.aID }),
    getTrafficExchange(db, { sessionID: input.sessionID, exchangeID: input.bID }),
  ])
  if (!a || !b) return undefined
  return diffTrafficExchangePair(a, b)
})

/** Compares two exchanges. */
export function diffTrafficExchangePair(a: TrafficExchange, b: TrafficExchange): TrafficDiff {
  const headersA = normalizeHeaders(a.responseHeaders)
  const headersB = normalizeHeaders(b.responseHeaders)
  const namesA = Object.keys(headersA)
  const namesB = Object.keys(headersB)

  const headersAdded: TrafficHeaderChange[] = []
  const headersRemoved: TrafficHeaderChange[] = []
  const headersChanged: TrafficHeaderChange[] = []
  for (const name of namesA) {
    if (!(name in headersB)) {
      headersRemoved.push({ name, a: headersA[name] ?? "", b: "" })
      continue
    }
    if (headersA[name] !== headersB[name]) {
      headersChanged.push({ name, a: headersA[name] ?? "", b: headersB[name] ?? "" })
    }
  }
  for (const name of namesB) {
    if (!(name in headersA)) headersAdded.push({ name, a: "", b: headersB[name] ?? "" })
  }

  const statusChanged = a.status !== b.status
  const bodyChanged = a.responseBodySHA256 !== b.responseBodySHA256
  const bodyDiff = bodyChanged ? unifiedDiff(a.responseBody, b.responseBody) : ""

  return {
    aId: a.id,
    bId: b.id,
    identical:
      !statusChanged &&
      headersAdded.length === 0 &&
      headersRemoved.length === 0 &&
      headersChanged.length === 0 &&
      !bodyChanged,
    statusChanged,
    statusA: a.status,
    statusB: b.status,
    headersAdded,
    headersRemoved,
    headersChanged,
    bodyChanged,
    bodySHA256A: a.responseBodySHA256,
    bodySHA256B: b.responseBodySHA256,
    bodyDiff,
    bodyLinesAdded: countDiffLines(bodyDiff, "+"),
    bodyLinesRemoved: countDiffLines(bodyDiff, "-"),
  }
}

function normalizeHeaders(headers: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [name, values] of Object.entries(headers ?? {})) {
    out[name.trim().toLowerCase()] = (values ?? []).join(", ")
  }
  return out
}

/** The LCS matrix budget: a bigger body degrades to "the bodies differ". */
const diffCellBudget = 4_000_000
const diffContextLines = 3

/** Renders the difference between two bodies in the unified diff format. */
export function unifiedDiff(a: string, b: string): string {
  const linesA = splitLines(a)
  const linesB = splitLines(b)
  const ops = diffOps(linesA, linesB)
  if (!ops) return "@@ bodies differ (too large to diff line by line) @@\n"
  const hunks = buildHunks(ops, diffContextLines)
  if (hunks.length === 0) return ""
  let out = "--- a/original\n+++ b/replay\n"
  for (const hunk of hunks) {
    out += `@@ -${hunk.aStart},${hunk.aCount} +${hunk.bStart},${hunk.bCount} @@\n`
    out += hunk.lines.join("\n")
    out += "\n"
  }
  return out
}

function splitLines(body: string): string[] {
  if (!body) return []
  const lines = body.replaceAll("\r\n", "\n").split("\n")
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop()
  return lines
}

type DiffOp = { kind: "equal" | "delete" | "insert"; text: string }

function diffOps(a: string[], b: string[]): DiffOp[] | undefined {
  if (a.length === 0 && b.length === 0) return undefined
  if (a.length * b.length > diffCellBudget) return undefined
  const table: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0))
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      if (a[i] === b[j]) {
        table[i][j] = table[i + 1]![j + 1]! + 1
        continue
      }
      table[i][j] = Math.max(table[i + 1]![j]!, table[i]![j + 1]!)
    }
  }
  const ops: DiffOp[] = []
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      ops.push({ kind: "equal", text: a[i]! })
      i++
      j++
      continue
    }
    if (table[i + 1]![j]! >= table[i]![j + 1]!) {
      ops.push({ kind: "delete", text: a[i]! })
      i++
      continue
    }
    ops.push({ kind: "insert", text: b[j]! })
    j++
  }
  while (i < a.length) ops.push({ kind: "delete", text: a[i++]! })
  while (j < b.length) ops.push({ kind: "insert", text: b[j++]! })
  return ops
}

interface DiffHunk {
  aStart: number
  aCount: number
  bStart: number
  bCount: number
  lines: string[]
}

function buildHunks(ops: DiffOp[], context: number): DiffHunk[] {
  const changed: number[] = []
  ops.forEach((op, index) => {
    if (op.kind !== "equal") changed.push(index)
  })
  if (changed.length === 0) return []

  const aBefore = new Array<number>(ops.length + 1).fill(0)
  const bBefore = new Array<number>(ops.length + 1).fill(0)
  ops.forEach((op, index) => {
    aBefore[index + 1] = aBefore[index]!
    bBefore[index + 1] = bBefore[index]!
    if (op.kind === "equal") {
      aBefore[index + 1]!++
      bBefore[index + 1]!++
    } else if (op.kind === "delete") {
      aBefore[index + 1]!++
    } else {
      bBefore[index + 1]!++
    }
  })

  const clusters: { from: number; to: number }[] = []
  for (const index of changed) {
    const last = clusters[clusters.length - 1]
    if (last && index - last.to <= 2 * context) {
      last.to = index
      continue
    }
    clusters.push({ from: index, to: index })
  }

  return clusters.map((cluster) => {
    const from = Math.max(0, cluster.from - context)
    const to = Math.min(ops.length - 1, cluster.to + context)
    const lines = ops.slice(from, to + 1).map((op) => {
      if (op.kind === "delete") return `-${op.text}`
      if (op.kind === "insert") return `+${op.text}`
      return ` ${op.text}`
    })
    const aCount = aBefore[to + 1]! - aBefore[from]!
    const bCount = bBefore[to + 1]! - bBefore[from]!
    return {
      aStart: aCount === 0 ? aBefore[from]! : aBefore[from]! + 1,
      aCount,
      bStart: bCount === 0 ? bBefore[from]! : bBefore[from]! + 1,
      bCount,
      lines,
    }
  })
}

function countDiffLines(diff: string, marker: "+" | "-"): number {
  let count = 0
  for (const line of diff.split("\n")) {
    if (line.startsWith("+++") || line.startsWith("---")) continue
    if (line.startsWith(marker)) count++
  }
  return count
}
