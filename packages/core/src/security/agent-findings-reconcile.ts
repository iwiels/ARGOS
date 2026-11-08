import { readdir, readFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import { homedir } from "node:os"
import path from "node:path"
import { and, eq } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import type { EventV2 } from "../event"
import type { Location } from "../location"
import { SessionTable } from "../session/sql"
import { SessionSchema } from "../session/schema"
import { FindingUpserted } from "./events"
import { Pseudonymize } from "./pseudonymize"
import { recordFindingObservation } from "./finding-observation"
import { resolveFindingCase } from "./finding-case"
import { findingFingerprint, findingId, findingMutableFields, findingTaxonomy, findFindingByTaxonomy, isFindingInput, normalizeFindingStatus, updateFindingRow } from "./ingest"
import { MAX_AGENT_CHARS, MAX_RAW_CHARS, MAX_TITLE_CHARS, contractToDbRow, normalizeContract } from "./contract"
import { FindingTable } from "./sql"

type DatabaseService = Database.Interface["db"]

/**
 * Directorio de memoria compartida del equipo de agentes — el mismo que usan
 * los binarios Go (`argos-bin/internal/paths.ResolveMemoryDir`).
 *
 * Ruta canónica: `~/.argos/memory`.
 */
export const defaultAgentMemoryDir = (homeDir: string = homedir()) => {
  return process.env.ARGOS_MEMORY_DIR ?? path.join(homeDir, ".argos", "memory")
}

const str = (value: unknown, maxChars?: number) => {
  if (typeof value !== "string") return undefined
  const normalized = value.trim()
  if (!normalized) return undefined
  return maxChars === undefined ? normalized : normalized.slice(0, maxChars)
}

export interface AgentReconcileResult {
  /** Archivos JSON leídos del store de Go. */
  readonly scanned: number
  /** Los que declaran este `argos_session_id` y son hallazgos. */
  readonly matched: number
  readonly inserted: number
  readonly skipped: number
}

const emptyResult = (scanned = 0): AgentReconcileResult => ({ scanned, matched: 0, inserted: 0, skipped: 0 })

/**
 * Trae al panel de Hallazgos los hallazgos que los peer agents
 * (security-scout, security-web, …) escribieron al store de memoria compartida
 * del binario Go.
 *
 * Por qué hace falta: esos agentes corren fuera del tracking de la Session, así
 * que sus llamadas a `argos_memory_save` nunca producen un evento
 * `PartUpdated` en la conversación del orquestador — que es lo único que
 * dispara `ingestToolPart`. Sin este puente, sus hallazgos quedan visibles solo
 * por `memory.search` entre agentes y nunca llegan a la UI.
 *
 * Las salidas MCP automáticas antiguas declaran `source` y no son decisiones
 * del agente; se conservan como contexto histórico pero no se reconcilian
 * como hallazgos aceptados.
 *
 * Solo reconcilia entradas cuyo `argos_session_id` coincide exactamente
 * con la Session pedida: el campo `session` del store es una etiqueta de
 * campaña legible (p.ej. "target-2026-08-14"), no un identificador único, y
 * usarla para matchear mezclaría hallazgos entre sesiones distintas del mismo
 * target. Dedupea por taxonomía (CWE + target + vector normalizados), igual
 * que ingest.ts, así que correrlo dos veces no duplica nada: si el bug ya está
 * en el panel, la fila existente se actualiza en vez de crear una segunda.
 */
export const reconcileAgentFindings = Effect.fn("Security.reconcileAgentFindings")(function* (
  db: DatabaseService,
  input: {
    sessionID: SessionSchema.ID
    /** Por defecto el store del binario Go; inyectable para tests. */
    memoryDir?: string
  },
  options?: { events?: EventV2.Interface; location?: Location.Ref },
) {
  const findingsDir = path.join(input.memoryDir ?? defaultAgentMemoryDir(), "findings")

  const entries = yield* Effect.tryPromise(() => readdir(findingsDir)).pipe(
    // Sin store todavía (equipo nunca corrió, o memoryDir distinto) no es un
    // error: simplemente no hay nada que reconciliar.
    Effect.catch(() => Effect.succeed([] as string[])),
  )
  const files = entries.filter((entry) => entry.endsWith(".json"))
  if (files.length === 0) return emptyResult()

  const session = yield* db
    .select({ projectID: SessionTable.project_id })
    .from(SessionTable)
    .where(eq(SessionTable.id, input.sessionID))
    .get()
    .pipe(Effect.orDie)
  if (!session) return emptyResult(files.length)

  let matched = 0
  let inserted = 0
  let skipped = 0
  for (const file of files) {
    const raw = yield* Effect.tryPromise(() => readFile(path.join(findingsDir, file), "utf8")).pipe(
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
    const record = parsed as Record<string, unknown>

    if (str(record["source"])) {
      skipped++
      continue
    }

    const recordSessionId = str(record["argos_session_id"]) ?? str(record["session_id"]) ?? str(record["sessionID"])
    if (recordSessionId !== input.sessionID) continue
    const title = str(record["title"], MAX_TITLE_CHARS)
    if (!title || !isFindingInput(record)) {
      skipped++
      continue
    }
    matched++

    const fingerprint = findingFingerprint(record)
    const now = Date.now()
    const id = findingId(input.sessionID, fingerprint)
    const normalized = normalizeContract(record)
    const row = contractToDbRow({
      ...normalized,
      source: "agent-reviewed",
      sourceTool: normalized.sourceTool ?? "argos_memory_save",
    })
    const status = normalizeFindingStatus(record["status"])
    const payload = JSON.stringify(record).slice(0, MAX_RAW_CHARS)
    const fields = findingMutableFields(row, status, payload, now)
    const sourceEventID = `agent-store:${createHash("sha256").update(JSON.stringify([file, raw])).digest("hex")}`
    const observation = (findingID: string) =>
      recordFindingObservation(db, {
        projectID: session.projectID,
        sessionID: input.sessionID,
        findingID,
        sourceEventID,
        fingerprint,
        source: row.source,
        sourceTool: row.source_tool,
        ruleID: row.rule_id,
        observedAt: now,
        snapshot: payload,
      }).pipe(Effect.orDie)

    // 1. La fila ya existe con este fingerprint (el mismo bug, título
    //    indiferente): se refrescan los datos, no se inserta otra fila.
    const exact = yield* db
      .select({ id: FindingTable.id, fingerprint: FindingTable.fingerprint })
      .from(FindingTable)
      .where(and(eq(FindingTable.session_id, input.sessionID), eq(FindingTable.fingerprint, fingerprint)))
      .get()
      .pipe(Effect.orDie)
    if (exact) {
      yield* observation(exact.id)
      yield* updateFindingRow(db, exact.id, fields)
      continue
    }

    // 2. El bug ya está en el panel con otra fórmula de fingerprint (una fila
    //    histórica v1, deduplicada por título) o con otro vector. Insertar
    //    una fila nueva lo contaría dos veces: se actualiza la que existe.
    const taxonomy = findingTaxonomy(record)
    if (taxonomy) {
      const match = yield* findFindingByTaxonomy(db, input.sessionID, taxonomy)
      if (match) {
        yield* observation(match.id)
        yield* updateFindingRow(db, match.id, fields)
        if (options?.events) {
          yield* options.events.publish(
            FindingUpserted,
            { sessionID: input.sessionID, findingID: match.id, fingerprint: match.fingerprint },
            { location: options.location },
          )
        }
        continue
      }
    }

    const caseID = yield* resolveFindingCase(db, {
      projectID: session.projectID,
      identityKey: fingerprint,
      now,
    }).pipe(Effect.orDie)
    yield* observation(id)
    yield* db
      .insert(FindingTable)
      .values({
        id,
        session_id: input.sessionID,
        project_id: session.projectID,
        case_id: caseID,
        fingerprint,
        ...row,
        status,
        agent: str(record["agent"], MAX_AGENT_CHARS),
        raw: payload,
        time_created: now,
        time_updated: now,
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    yield* Pseudonymize.registerFindingEntities(
      db,
      input.sessionID,
      str(record["target"]),
      str(record["vector"]),
    )
    inserted++

    if (options?.events) {
      yield* options.events.publish(
        FindingUpserted,
        { sessionID: input.sessionID, findingID: id, fingerprint },
        { location: options.location },
      )
    }
  }

  return { scanned: files.length, matched, inserted, skipped: skipped + matched - inserted } satisfies AgentReconcileResult
})
