import {
  Compliance,
  ComplianceCatalogTable,
  ComplianceMappingTable,
  ComplianceStatusTable,
  FRAMEWORK_META,
  FRAMEWORKS,
  type Framework,
} from "@argos/core/compliance"
import { Database } from "@argos/core/database/database"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { eq, sql } from "drizzle-orm"
import { Cause, Effect, Option } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { Api } from "../api"
import { SessionNotFoundError } from "../errors"
import type { ComplianceEvidence, ComplianceNode, ControlEvidence } from "../groups/compliance"

/** Orden de confianza de la derivación (la mayor gana al agregar). */
const CONFIDENCE_RANK: Record<string, number> = { low: 1, medium: 2, high: 3 }

const toEvidence = (entry: {
  findingID: string
  title: string
  severity: string
  status: string
  tool?: string
  fromElasticsearch: boolean
  timeUpdated: number
  cwe?: string
  derivedFrom?: string
  confidence?: string
}) => ({
  findingID: entry.findingID,
  title: entry.title,
  severity: entry.severity,
  status: entry.status,
  tool: entry.tool ?? null,
  fromElasticsearch: entry.fromElasticsearch,
  timeUpdated: entry.timeUpdated,
  cwe: entry.cwe ?? null,
  derivedFrom: entry.derivedFrom ?? null,
  confidence: entry.confidence ?? null,
})

const STATUS_RANK: Record<string, number> = { deficient: 4, partial: 3, compliant: 2, unassessed: 1 }

const worstStatus = (a: string, b: string) => (STATUS_RANK[a] ?? 0) >= (STATUS_RANK[b] ?? 0) ? a : b

type MutableNode = {
  id: string
  title: string
  level: string
  status: string
  findingCount: number
  evidence: ComplianceEvidence[]
  derivation: ControlEvidence[]
  confidence: string
  children: MutableNode[]
}

/** Arma el árbol jerárquico (función → categoría → subcategoría / tema → control). */
function buildTree(
  catalog: Array<{ control_id: string; title: string; parent_id: string | null; level: string }>,
  statuses: Map<
    string,
    { status: string; evidence: readonly ComplianceEvidence[]; derivation: readonly ControlEvidence[]; confidence: string }
  >,
): ComplianceNode {
  const nodes = new Map<string, MutableNode>()
  for (const row of catalog) {
    const entry = statuses.get(row.control_id)
    nodes.set(row.control_id, {
      id: row.control_id,
      title: row.title,
      level: row.level,
      status: entry?.status ?? "unassessed",
      findingCount: entry?.evidence.length ?? 0,
      evidence: [...(entry?.evidence ?? [])],
      derivation: [...(entry?.derivation ?? [])],
      confidence: entry?.confidence ?? "high",
      children: [],
    })
  }
  const roots: MutableNode[] = []
  for (const row of catalog) {
    const node = nodes.get(row.control_id)!
    if (row.parent_id && nodes.has(row.parent_id)) {
      nodes.get(row.parent_id)!.children.push(node)
    } else {
      roots.push(node)
    }
  }
  const reconcile = (node: MutableNode): void => {
    if (node.children.length === 0) return
    for (const child of node.children) reconcile(child)
    const worst = node.children.reduce(
      (acc, child) => worstStatus(acc, child.status),
      node.status === "unassessed" ? "compliant" : node.status,
    )
    if (node.status === "unassessed" || (STATUS_RANK[node.status] ?? 0) < (STATUS_RANK[worst] ?? 0)) {
      node.status = worst
    }
    node.findingCount = node.children.reduce((acc, child) => acc + child.findingCount, node.findingCount)
    node.derivation = [...node.derivation, ...node.children.flatMap((child) => child.derivation)]
    // Confianza agregada: la mayor entre las entradas de evidencia (un control
    // con un finding de confianza alta no se degrada por otro heurístico).
    node.confidence = node.derivation.length
      ? node.derivation.reduce(
          (acc, entry) => (CONFIDENCE_RANK[entry.confidence] > CONFIDENCE_RANK[acc] ? entry.confidence : acc),
          "low",
        )
      : "high"
  }
  for (const root of roots) reconcile(root)
  return {
    id: "",
    title: "",
    level: "root",
    status: "compliant",
    findingCount: 0,
    evidence: [],
    derivation: [],
    confidence: "high",
    children: roots,
  }
}

export const ComplianceHandler = HttpApiBuilder.group(Api, "server.compliance", (handlers) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const compliance = yield* Compliance.Service

    const ensureSession = (sessionID: string) =>
      db
        .select({ id: SessionTable.id, projectID: SessionTable.project_id })
        .from(SessionTable)
        .where(eq(SessionTable.id, SessionV2.ID.make(sessionID)))
        .get()
        .pipe(
          Effect.orDie,
          Effect.flatMap((row) =>
            row
              ? Effect.succeed(row)
              : Effect.fail(new SessionNotFoundError({ sessionID, message: `Session not found: ${sessionID}` })),
          ),
        )

    return handlers
      .handle(
        "compliance.status",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          yield* compliance.ensureCatalog()
          yield* compliance.recomputeProject(session.projectID)

          const [statusRows, catalogRows, catalogCount, mappingCount, latest] = yield* Effect.all([
            db
              .select()
              .from(ComplianceStatusTable)
              .where(eq(ComplianceStatusTable.project_id, session.projectID))
              .all()
              .pipe(Effect.orDie),
            db
              .select()
              .from(ComplianceCatalogTable)
              .orderBy(ComplianceCatalogTable.sort_id)
              .all()
              .pipe(Effect.orDie),
            db.select({ total: sql<number>`count(*)` }).from(ComplianceCatalogTable).get().pipe(Effect.orDie),
            db.select({ total: sql<number>`count(*)` }).from(ComplianceMappingTable).get().pipe(Effect.orDie),
            db
              .select({ max: sql<number>`max(${ComplianceCatalogTable.time_updated})` })
              .from(ComplianceCatalogTable)
              .get()
              .pipe(Effect.orDie),
          ])

          const statusesByFramework = new Map<
            string,
            Map<string, { status: string; evidence: ComplianceNode["evidence"]; derivation: ComplianceNode["derivation"]; confidence: string }>
          >()
          for (const row of statusRows) {
            const perFramework = statusesByFramework.get(row.framework) ?? new Map()
            perFramework.set(row.control_id, {
              status: row.status,
              evidence: row.evidence.map(toEvidence),
              derivation: row.derivation ?? [],
              confidence: row.confidence ?? "high",
            })
            statusesByFramework.set(row.framework, perFramework)
          }

          const frameworks = (Object.keys(FRAMEWORK_META) as Framework[]).map((framework) => {
            const rows = catalogRows.filter((row) => row.framework === framework)
            return {
              framework,
              title: FRAMEWORK_META[framework].title,
              version: FRAMEWORK_META[framework].version,
              refreshedAt: latest?.max ?? null,
              tree: buildTree(
                rows.map((row) => ({
                  control_id: row.control_id,
                  title: row.title,
                  parent_id: row.parent_id,
                  level: row.level,
                })),
                statusesByFramework.get(framework) ?? new Map(),
              ),
            }
          })

          return {
            frameworks,
            catalogCount: Number(catalogCount?.total ?? 0),
            mappingCount: Number(mappingCount?.total ?? 0),
            lastRefreshed: latest?.max ?? null,
          }
        }),
      )
      .handle(
        "compliance.refresh",
        Effect.fn(function* () {
          const exit = yield* compliance.refresh().pipe(Effect.exit)
          if (exit._tag === "Failure") {
            const message = Option.match(Cause.findErrorOption(exit.cause as Cause.Cause<unknown>), {
              onSome: (error) => (error instanceof Error ? error.message : String(error)),
              onNone: () => "Unknown error",
            })
            // Log the detailed error for debugging
            yield* Effect.logError("compliance.refresh failed").pipe(
              Effect.annotateLogs({ cause: message }),
            )
            // Return a valid response with ok: false on each source
            return {
              refreshedAt: Date.now(),
              sources: [
                { key: "nist_csf_v2", url: "", license: "", ok: false, error: message, controls: null, mappings: null },
                { key: "iso27001_crosswalk", url: "", license: "", ok: false, error: message, controls: null, mappings: null },
                { key: "checks_nist", url: "", license: "", ok: false, error: message, controls: null, mappings: null },
                { key: "checks_iso", url: "", license: "", ok: false, error: message, controls: null, mappings: null },
              ],
              catalogControlCount: 0,
              mappingCount: 0,
            }
          }
          const summary = exit.value
          // Tras actualizar el catálogo, re-deriva el estado de todos los proyectos.
          yield* compliance.sweepAll().pipe(Effect.catch(() => Effect.void))
          return {
            refreshedAt: summary.refreshedAt,
            sources: summary.sources.map((source) => ({
              key: source.key,
              url: source.url,
              license: source.license,
              ok: source.ok,
              error: source.error ?? null,
              controls: source.controls ?? null,
              mappings: source.mappings ?? null,
            })),
            catalogControlCount: summary.catalogControlCount,
            mappingCount: summary.mappingCount,
          }
        }),
      )
      .handle(
        "compliance.summary",
        Effect.fn(function* () {
          yield* compliance.ensureCatalog()
          return yield* compliance.getGlobalSummary()
        }),
      )
      .handle(
        "compliance.drift",
        Effect.fn(function* (ctx) {
          const limit = Number(ctx.query.limit ?? "50")
          return yield* compliance.getDriftEvents({
            limit: Number.isFinite(limit) ? limit : 50,
          })
        }),
      )
      .handle(
        "compliance.history",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const framework = ctx.query.framework
          const controlId = ctx.query.control
          const validFramework = (Object.values(FRAMEWORKS) as string[]).includes(framework)
            ? (framework as Framework)
            : FRAMEWORKS.nistCsfV2
          const transitions = yield* compliance.getHistory(session.projectID, validFramework, controlId)
          return {
            projectID: session.projectID,
            framework,
            controlId,
            transitions: transitions.map((transition) => ({
              id: transition.id,
              statusFrom: transition.statusFrom,
              statusTo: transition.statusTo,
              timeRecorded: transition.timeRecorded,
            })),
          }
        }),
      )
  }),
)
