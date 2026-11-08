import { createHash } from "node:crypto"
import { and, eq } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import type { EventV2 } from "../event"
import type { Location } from "../location"
import { SessionTable } from "../session/sql"
import { SessionSchema } from "../session/schema"
import { FindingUpserted } from "./events"
import { FindingTable } from "./sql"
import { recordFindingObservation } from "./finding-observation"
import { resolveFindingCase } from "./finding-case"
import { Pseudonymize } from "./pseudonymize"
import {
  MAX_AGENT_CHARS,
  MAX_RAW_CHARS,
  MAX_SOURCE_TOOL_CHARS,
  MAX_TITLE_CHARS,
  contractToDbRow,
  normalizeContract,
  normalizeContractCwe,
  normalizeContractEvidence,
  normalizeContractSeverity,
} from "./contract"

export {
  MAX_AGENT_CHARS,
  MAX_CWE_CHARS,
  MAX_EVIDENCE_CHARS,
  MAX_RAW_CHARS,
  MAX_REMEDIATION_CHARS,
  MAX_SOURCE_TOOL_CHARS,
  MAX_TAG_CHARS,
  MAX_TAGS,
  MAX_TARGET_CHARS,
  MAX_TITLE_CHARS,
  MAX_VECTOR_CHARS,
} from "./contract"

type DatabaseService = Database.Interface["db"]

const MEMORY_SAVE_TOOL = "argos_memory_save"

/**
 * Determina si un memory_save representa un hallazgo de seguridad.
 *
 * Solo se acepta la decisión explícita del agente, con objetivo, severidad
 * conocida y evidencia concreta. La salida de un scanner no basta.
 *
 * MANTENER EN SYNC con el helper homónimo en
 * packages/app/src/components/session/findings-data.ts.
 */
export function isFindingInput(input: Record<string, unknown>): boolean {
  const kind = stringValue(input.kind)?.toLowerCase() ?? ""
  const severity = stringValue(input.severity)?.toLowerCase()
  const acceptedSeverities = new Set([
    "critical", "critico", "crítico", "high", "alto", "alta", "medium", "medio", "media", "moderate",
    "low", "bajo", "baja", "info", "informational", "informativo",
  ])
  return kind === "finding" &&
    !!stringValue(input.title) &&
    !!stringValue(input.target) &&
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
  const text = stringValue(value)
  return !!text && [...text].length >= 24
}

function meaningfulAgentReviewText(value: unknown, minimumLength = 24): boolean {
  const text = stringValue(value)
  if (!text || [...text].length < minimumLength) return false
  return !UNHELPFUL_AGENT_REVIEW.has(text.toLowerCase().replace(/[.!\s]+$/g, ""))
}

function reviewFieldsAreDistinct(input: Record<string, unknown>): boolean {
  const assessment = stringValue(input.agent_assessment)?.toLowerCase()
  const evidence = stringValue(input.evidence)?.toLowerCase()
  const title = stringValue(input.title)?.toLowerCase()
  const impact = stringValue(input.impact)?.toLowerCase()
  return !!assessment && assessment !== evidence && assessment !== title && assessment !== impact
}

const FINDING_STATUSES = new Set([
  "open",
  "observed",
  "suspected",
  "validated",
  "blocked-by-policy",
  "in-progress",
  "mitigated",
  "resolved",
  "fixed",
  "closed",
  "accepted",
  "remediated",
  "verified",
  "false-positive",
  "accepted-risk",
])

export const normalizeFindingSeverity = (value: unknown): string => normalizeContractSeverity(value)

export const normalizeEvidence = (value: unknown): Record<string, unknown> => normalizeContractEvidence(value)

const stringValue = (value: unknown, maxChars?: number) => {
  if (typeof value !== "string") return undefined
  const normalized = value.trim()
  if (!normalized) return undefined
  return maxChars === undefined ? normalized : normalized.slice(0, maxChars)
}

export const normalizeFindingStatus = (value: unknown) => {
  const normalized = stringValue(value, 64)?.toLowerCase()
  return normalized && FINDING_STATUSES.has(normalized) ? normalized : "open"
}

/**
 * Resuelve el `source_tool` de un hallazgo: el identificador de la
 * herramienta/skill real que lo generó (p.ej. "lan.port_scan", "web.probe"),
 * usado por el motor de compliance (derive.ts) y el mapeo MITRE ATT&CK
 * (attack.ts) para matchear sus reglas `tools:`.
 *
 * Los agentes que ya pasan `source_tool` en el memory_save lo usan tal cual;
 * si está ausente se usa la constante canónica `argos_memory_save`.
 */
export const resolveSourceTool = (input: Record<string, unknown>) =>
  stringValue(input.source_tool, MAX_SOURCE_TOOL_CHARS) ?? MEMORY_SAVE_TOOL

const identityValue = (value: unknown) => stringValue(value)?.replace(/\s+/g, " ").toLowerCase() ?? ""

const cutAt = (text: string, marker: string) => {
  const index = text.indexOf(marker)
  return index === -1 ? text : text.slice(0, index)
}

/** Puertos que no discriminan: el servicio por defecto de http/https. */
const DEFAULT_PORTS = new Set(["80", "443"])

/**
 * Normalización de target y vector — SPEC COMPARTIDA CON GO.
 *
 * El mismo algoritmo está implementado en
 * `argos-bin/cmd/orquestador/tools/audit.go` (`normalizeTargetIdentity` /
 * `normalizeVectorIdentity`). Si se cambia uno hay que cambiar el otro: la
 * deduplicación entre agentes solo funciona si ambos sides dicen lo mismo.
 *
 * Target:
 *   1. trim + lowercase + colapso de los espacios internos
 *   2. corta en el fragment (`#`) y en el query string (`?`)
 *   3. descarta el esquema (`https://`) — la identidad es host[:port][path]
 *   4. descarta el puerto por defecto (80/443); un servicio en :8080 es otro target
 *   5. descarta las barras finales
 *
 * Vector:
 *   1. trim + lowercase + colapso de los espacios internos
 *   2. corta en el fragment (`#`)
 *   3. conserva los nombres de parámetros, pero descarta sus valores variables
 *   4. descarta las barras finales
 *   (el esquema y el puerto se conservan: el vector es más fino que el target)
 */
export const normalizeTargetIdentity = (value: unknown): string => {
  let text = identityValue(value)
  if (!text) return ""
  text = cutAt(text, "#")
  text = cutAt(text, "?")
  const scheme = text.indexOf("://")
  if (scheme >= 0) text = text.slice(scheme + 3)
  const slash = text.indexOf("/")
  const authority = slash === -1 ? text : text.slice(0, slash)
  const rest = slash === -1 ? "" : text.slice(slash)
  let host = authority
  const colon = authority.lastIndexOf(":")
  if (colon > 0) {
    const port = authority.slice(colon + 1)
    const name = authority.slice(0, colon)
    if (name && DEFAULT_PORTS.has(port)) host = name
  }
  return (host + rest).replace(/\/+$/, "")
}

export const normalizeVectorIdentity = (value: unknown): string => {
  let text = identityValue(value)
  if (!text) return ""
  text = cutAt(text, "#")
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

/**
 * Identidad taxonómica de un hallazgo: QUÉ es el bug (CWE), DÓNDE (target
 * normalizado) y en qué punto exacto (vector normalizado).
 *
 * Sin CWE, target o vector explícito no hay identidad taxonómica fiable; se
 * usa la identidad histórica por título para evitar fusionar problemas.
 */
export interface FindingTaxonomy {
  /** CWE normalizado ("CWE-89"). */
  readonly cwe: string
  /** Target normalizado (ver {@link normalizeTargetIdentity}). */
  readonly target: string
  /** Vector normalizado; es obligatorio para deduplicar por taxonomía. */
  readonly vector: string
}

export const findingTaxonomy = (input: Record<string, unknown>): FindingTaxonomy | undefined => {
  const cwe = normalizeContractCwe(input.cwe)
  if (!cwe) return undefined
  const target = normalizeTargetIdentity(input.target)
  const vector = normalizeVectorIdentity(input.vector)
  if (!target || !vector) return undefined
  return { cwe, target, vector }
}

/**
 * Marcador de versión del fingerprint taxonómico.
 *
 * Los fingerprints ya persistidos (v1) son `sha256(title|vector||target)`.
 * Cambiar la fórmula sin versionar haría que un hallazgo viejo y uno nuevo
 * del mismo bug produjeran el mismo hash: el índice único
 * `security_finding_session_fingerprint_idx` los pisaría (o el INSERT
 * reventaría). Con el prefijo `v2|` conviven —el índice los distingue— y la
 * reconciliación por taxonomía los fusiona (ver {@link findFindingByTaxonomy}).
 */
const FINGERPRINT_VERSION = "v2"

/**
 * Fingerprint histórico (v1): identidad por prosa.
 *
 * Se conserva para los hallazgos SIN CWE, que no tienen taxonomía con la que
 * identificarse, y para reconocer las filas ya persistidas, cuya identidad
 * v1 es reconstruible a partir de sus propias columnas.
 */
export const legacyFindingFingerprint = (input: Record<string, unknown>) => {
  const value = [
    identityValue(input.title),
    identityValue(input.vector) || identityValue(input.target),
  ]
    .join("|")
  return createHash("sha256").update(value).digest("hex")
}

/**
 * Identidad de un hallazgo: taxonomía, no prosa.
 *
 * Tres herramientas reportan el mismo bug con tres títulos distintos
 * ("SQL Injection", "Posible SQLi (boolean/time-based)", "SQL Injection
 * Confirmada (sqlmap)") y el panel terminaba contando tres vulnerabilidades
 * donde había una. Con CWE, la identidad es (CWE, target, vector) y el
 * título deja de decidir qué es un bug nuevo.
 *
 * Sin una taxonomía completa se cae al fingerprint histórico por título: es
 * la única señal que esos hallazgos tienen, y mantenerla evita romper los
 * findings ya persistidos y los que la taxonomía no cubre.
 *
 * Límite conocido: el vector es parte de la identidad, así que dos
 * herramientas que reportan el mismo bug con vectores de granularidad
 * distinta (nuclei da la URL completa, sqlmap el nombre del parámetro) no
 * colapsan en la misma fila. Fusionarlas por (CWE, target) sí lo haría, pero
 * también fusionaría dos bugs reales del mismo tipo en el mismo endpoint.
 */
export const findingFingerprint = (input: Record<string, unknown>) => {
  const taxonomy = findingTaxonomy(input)
  if (!taxonomy) return legacyFindingFingerprint(input)
  const value = [FINGERPRINT_VERSION, taxonomy.cwe, taxonomy.target, taxonomy.vector].join("|")
  return createHash("sha256").update(value).digest("hex")
}

export const findingId = (sessionID: string, fingerprint: string) =>
  `finding_${createHash("sha256").update(`${sessionID}|${fingerprint}`).digest("hex")}`

export interface FindingTaxonomyRow {
  readonly id: string
  readonly fingerprint: string
  readonly title: string
  readonly target: string | null
  readonly vector: string | null
}

/**
 * Busca el hallazgo ya persistido al que corresponde esta taxonomía.
 *
 * Solo une CWE, target y vector exactos después de normalizarlos. La fórmula
 * antigua por título sigue disponible en el fingerprint; no se debe fusionar
 * por CWE y target cuando falta el vector, porque puede ocultar otro parámetro
 * vulnerable del mismo endpoint.
 */
export const findFindingByTaxonomy = (
  db: DatabaseService,
  sessionID: string,
  taxonomy: FindingTaxonomy,
): Effect.Effect<FindingTaxonomyRow | undefined> =>
  Effect.gen(function* () {
    const rows = yield* db
      .select({
        id: FindingTable.id,
        fingerprint: FindingTable.fingerprint,
        title: FindingTable.title,
        target: FindingTable.target,
        vector: FindingTable.vector,
      })
      .from(FindingTable)
      .where(and(eq(FindingTable.session_id, sessionID), eq(FindingTable.cwe, taxonomy.cwe)))
      .all()
      .pipe(Effect.orDie)

    const exact = rows.find((row) => {
      const target = normalizeTargetIdentity(row.target)
      const vector = normalizeVectorIdentity(row.vector)
      return target === taxonomy.target && vector !== "" && vector === taxonomy.vector
    })
    if (exact) return exact
    return undefined
  })

/**
 * Campos mutables de un hallazgo: los que se refrescan cuando el mismo bug
 * vuelve a reportarse. La identidad de la fila (title, target, cwe, vector)
 * NO se reescribe — la fila conserva cómo se descubrió el bug y el
 * fingerprint que la indexa.
 */
export const findingMutableFields = (
  row: ReturnType<typeof contractToDbRow>,
  status: string,
  raw: string,
  now: number,
) => ({
  source: row.source,
  severity: row.severity,
  status,
  evidence: row.evidence,
  poc: row.poc,
  remediation: row.remediation,
  tags: row.tags,
  raw,
  cvss_input: row.cvss_input,
  confidence: row.confidence,
  rule_id: row.rule_id,
  owasp: row.owasp,
  references: row.references,
  time_updated: now,
})

export const updateFindingRow = (db: DatabaseService, id: string, fields: ReturnType<typeof findingMutableFields>) =>
  db
    .update(FindingTable)
    .set(fields)
    .where(eq(FindingTable.id, id))
    .run()
    .pipe(Effect.orDie)

export function ingestToolPart(
  db: DatabaseService,
  part: {
    sessionID: SessionSchema.ID
    callID?: string
    type?: string
    tool?: string
      state?: { status?: string; input?: Record<string, unknown>; output?: string }
  },
  options?: { events?: EventV2.Interface; location?: Location.Ref },
) {
  if (part.type !== "tool" || part.tool !== MEMORY_SAVE_TOOL || part.state?.status !== "completed")
    return Effect.void
  const input = part.state.input
  const title = stringValue(input?.title, MAX_TITLE_CHARS)
  if (!input || !title || !isFindingInput(input)) return Effect.void

  return Effect.gen(function* () {
    const session = yield* db
      .select({ projectID: SessionTable.project_id })
      .from(SessionTable)
      .where(eq(SessionTable.id, part.sessionID))
      .get()
      .pipe(Effect.orDie)
    if (!session) return

    const now = Date.now()
    const normalized = normalizeContract(input)
    const taxonomy = findingTaxonomy(input)
    const inputFingerprint = findingFingerprint(input)
    const findingID = findingId(part.sessionID, inputFingerprint)
    const status = normalizeFindingStatus(input.status)
    const row = contractToDbRow({
      ...normalized,
      source: "agent-reviewed",
      sourceTool: normalized.sourceTool ?? resolveSourceTool(input),
    })
    const raw = JSON.stringify(input).slice(0, MAX_RAW_CHARS)
    const sourceEventID = part.callID ? `tool:${part.callID}` : `legacy:${part.tool}:${inputFingerprint}`
    let observationFindingID = findingID

    if (taxonomy) {
      // El bug puede estar ya en el panel con otra fórmula de fingerprint
      // (una fila histórica v1) o reportado por otra herramienta con otro
      // vector. En vez de insertar una segunda fila —y contar el mismo bug
      // dos veces— se actualiza la que ya existe.
      const existing = yield* findFindingByTaxonomy(db, part.sessionID, taxonomy)
      if (existing) observationFindingID = existing.id
      if (existing && existing.fingerprint !== inputFingerprint) {
        yield* recordFindingObservation(db, {
          projectID: session.projectID,
          sessionID: part.sessionID,
          findingID: existing.id,
          sourceEventID,
          fingerprint: inputFingerprint,
          source: row.source,
          sourceTool: row.source_tool,
          ruleID: row.rule_id,
          observedAt: now,
          snapshot: raw,
        }).pipe(Effect.orDie)
        yield* updateFindingRow(db, existing.id, findingMutableFields(row, status, raw, now))
        yield* Pseudonymize.registerFindingEntities(
          db,
          SessionSchema.ID.make(part.sessionID),
          stringValue(input.target),
          stringValue(input.vector),
        )
        if (options?.events) {
          yield* options.events.publish(
            FindingUpserted,
            {
              sessionID: SessionSchema.ID.make(part.sessionID),
              findingID: existing.id,
              fingerprint: existing.fingerprint,
            },
            { location: options.location },
          )
        }
        return
      }
    }

    const caseID = yield* resolveFindingCase(db, {
      projectID: session.projectID,
      identityKey: inputFingerprint,
      now,
    }).pipe(Effect.orDie)
    yield* recordFindingObservation(db, {
      projectID: session.projectID,
      sessionID: part.sessionID,
      findingID: observationFindingID,
      sourceEventID,
      fingerprint: inputFingerprint,
      source: row.source,
      sourceTool: row.source_tool,
      ruleID: row.rule_id,
      observedAt: now,
      snapshot: raw,
    }).pipe(Effect.orDie)

    yield* db
      .insert(FindingTable)
      .values({
        id: findingID,
        session_id: part.sessionID,
        project_id: session.projectID,
        case_id: caseID,
        fingerprint: inputFingerprint,
        ...row,
        status,
        agent: stringValue(input.agent, MAX_AGENT_CHARS),
        raw,
        time_created: now,
        time_updated: now,
      })
      .onConflictDoUpdate({
        target: [FindingTable.session_id, FindingTable.fingerprint],
        set: findingMutableFields(row, status, raw, now),
      })
      .run()
      .pipe(Effect.orDie)
    yield* Pseudonymize.registerFindingEntities(
      db,
      SessionSchema.ID.make(part.sessionID),
      stringValue(input.target),
      stringValue(input.vector),
    )
    if (options?.events) {
      yield* options.events.publish(
        FindingUpserted,
        {
          sessionID: SessionSchema.ID.make(part.sessionID),
          findingID,
          fingerprint: inputFingerprint,
        },
        { location: options.location },
      )
    }
  })
}

/**
 * Imports scanner findings only after an explicit operator action. MCP output
 * remains candidate evidence and is never promoted automatically.
 */
export function ingestToolFindings(
  db: DatabaseService,
  part: {
    sessionID: SessionSchema.ID
    callID?: string
    type?: string
    tool?: string
    state?: { status?: string; output?: string }
  },
  options?: { events?: EventV2.Interface; location?: Location.Ref; source?: "tool" | "import" },
) {
  if (options?.source !== "import") return Effect.void
  if (part.type !== "tool" || !part.tool || part.state?.status !== "completed") return Effect.void
  const output = part.state.output
  if (!output) return Effect.void

  let findings: unknown
  try {
    const parsed = JSON.parse(output)
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return Effect.void
    const list = (parsed as Record<string, unknown>).findings
    if (!Array.isArray(list) || list.length === 0) return Effect.void
    findings = list
  } catch {
    // Una tool que no devuelve JSON no tiene findings que ingerir.
    return Effect.void
  }

  return Effect.gen(function* () {
    const session = yield* db
      .select({ projectID: SessionTable.project_id })
      .from(SessionTable)
      .where(eq(SessionTable.id, part.sessionID))
      .get()
      .pipe(Effect.orDie)
    if (!session) return

    const now = Date.now()
    for (const raw of findings as unknown[]) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue
      const input = raw as Record<string, unknown>
      const title = stringValue(input.title, MAX_TITLE_CHARS)
      if (!title) continue

      const normalized = normalizeContract(input)
      const taxonomy = findingTaxonomy(input)
      const fingerprint = findingFingerprint(input)
      const findingID = findingId(part.sessionID, fingerprint)
      const status = normalizeFindingStatus(input.status)
      const row = contractToDbRow({
        ...normalized,
        source: options?.source ?? "tool",
        sourceTool: normalized.sourceTool ?? part.tool,
      })
      const rawJson = JSON.stringify(input).slice(0, MAX_RAW_CHARS)
      const sourceEventID = part.callID
        ? `${options?.source === "import" ? "import" : "tool"}:${part.callID}`
        : `legacy:${part.tool}:${fingerprint}`
      let observationFindingID = findingID

      if (taxonomy) {
        const existing = yield* findFindingByTaxonomy(db, part.sessionID, taxonomy)
        if (existing) observationFindingID = existing.id
        if (existing && existing.fingerprint !== fingerprint) {
          yield* recordFindingObservation(db, {
            projectID: session.projectID,
            sessionID: part.sessionID,
            findingID: existing.id,
            sourceEventID,
            fingerprint,
            source: row.source,
            sourceTool: row.source_tool,
            ruleID: row.rule_id,
            observedAt: now,
            snapshot: rawJson,
          }).pipe(Effect.orDie)
          yield* updateFindingRow(db, existing.id, findingMutableFields(row, status, rawJson, now))
          if (options?.events) {
            yield* options.events.publish(
              FindingUpserted,
              {
                sessionID: SessionSchema.ID.make(part.sessionID),
                findingID: existing.id,
                fingerprint: existing.fingerprint,
              },
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
      yield* recordFindingObservation(db, {
        projectID: session.projectID,
        sessionID: part.sessionID,
        findingID: observationFindingID,
        sourceEventID,
        fingerprint,
        source: row.source,
        sourceTool: row.source_tool,
        ruleID: row.rule_id,
        observedAt: now,
        snapshot: rawJson,
      }).pipe(Effect.orDie)

      yield* db
        .insert(FindingTable)
        .values({
          id: findingID,
          session_id: part.sessionID,
          project_id: session.projectID,
          case_id: caseID,
          fingerprint,
          ...row,
          status,
          agent: stringValue(input.agent, MAX_AGENT_CHARS),
          raw: rawJson,
          time_created: now,
          time_updated: now,
        })
        .onConflictDoUpdate({
          target: [FindingTable.session_id, FindingTable.fingerprint],
          set: findingMutableFields(row, status, rawJson, now),
        })
        .run()
        .pipe(Effect.orDie)
      yield* Pseudonymize.registerFindingEntities(
        db,
        SessionSchema.ID.make(part.sessionID),
        stringValue(input.target),
        stringValue(input.vector),
      )
      if (options?.events) {
        yield* options.events.publish(
          FindingUpserted,
          {
            sessionID: SessionSchema.ID.make(part.sessionID),
            findingID,
            fingerprint,
          },
          { location: options.location },
        )
      }
    }
  })
}
