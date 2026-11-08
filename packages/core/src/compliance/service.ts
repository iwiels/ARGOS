import { and, eq, inArray, or, sql } from "drizzle-orm"
import { Context, Effect, Layer, Semaphore } from "effect"
import { Database } from "../database/database"
import { FindingTable } from "../security/sql"
import { trustedFindingSourceCondition } from "../security/finding-provenance"
import { feedbackForProject, feedbackForSessions } from "../security/finding-feedback"
import { SessionSchema } from "../session/schema"
import { SessionTable } from "../session/sql"
import { deriveProjectStatuses, maxConfidence, minConfidence } from "./derive"
import { parseChecks, parseDerivedCatalog, parseIsoCrosswalk, parseNistOscal } from "./parse"
import { bundledCatalogSources, complianceSources, FRAMEWORK_META, type ComplianceSourceConfig } from "./sources"
import { readBundled, readCached, writeCached } from "./catalog-cache"
import {
  ComplianceCatalogTable,
  ComplianceHistoryTable,
  ComplianceMappingTable,
  ComplianceStatusTable,
  catalogRowToNode,
  type ControlHistoryRow,
} from "./sql"
import {
  FRAMEWORKS,
  type ControlMapping,
  type ControlNode,
  type ControlStatus,
  type ControlStatusRow,
  type DerivedFramework,
  type DriftEvent,
  type EvidenceConfidence,
  type Framework,
  type GlobalComplianceSummary,
  type RefreshSummary,
  type SessionComplianceNode,
  type SessionComplianceStatus,
} from "./types"

const FETCH_TIMEOUT_MS = 2000

/** Frameworks con catálogo derivado del crosswalk ISO 27001:2022. */
const DERIVED_FRAMEWORKS: DerivedFramework[] = [FRAMEWORKS.soc2, FRAMEWORKS.nis2, FRAMEWORKS.dora]

/**
 * Frameworks cuyo catálogo es un snapshot bundled (no depende de la red).
 * Incluye los catálogos derivados del crosswalk y el mapa PCI de referencia.
 */
const BUNDLED_FRAMEWORKS: Framework[] = [...DERIVED_FRAMEWORKS, FRAMEWORKS.pciDssV4]

const DERIVED_BY_SOURCE: Record<string, Framework> = {
  soc2: FRAMEWORKS.soc2,
  nis2: FRAMEWORKS.nis2,
  dora: FRAMEWORKS.dora,
  pci_dss_v4: FRAMEWORKS.pciDssV4,
}

const fetchJson = (url: string): Effect.Effect<Record<string, unknown>, unknown> =>
  Effect.tryPromise({
    try: async () => {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
      try {
        const response = await fetch(url, { signal: controller.signal })
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return (await response.json()) as Record<string, unknown>
      } finally {
        clearTimeout(timer)
      }
    },
    catch: (error: unknown) => error,
  })

export interface Interface {
  /** Descarga el catálogo desde las fuentes públicas y lo cachea en la BD. */
  readonly refresh: () => Effect.Effect<RefreshSummary>
  /** Refresca solo si el catálogo está vacío (best-effort). */
  readonly ensureCatalog: () => Effect.Effect<void>
  readonly getCatalog: (framework?: Framework) => Effect.Effect<ControlNode[]>
  readonly getStatus: (projectID: string) => Effect.Effect<ControlStatusRow[]>
  /** Re-deriva y persiste el estado de controles del proyecto desde sus findings. */
  readonly recomputeProject: (projectID: string) => Effect.Effect<void>
  readonly recomputeSession: (sessionID: string) => Effect.Effect<void>
  /** Re-deriva todos los proyectos con hallazgos (monitoreo continuo). */
  readonly sweepAll: () => Effect.Effect<void>
  /** Últimos eventos de drift (cambios de estado), opcionalmente por proyecto. */
  readonly getDriftEvents: (options?: { limit?: number; projectID?: string }) => Effect.Effect<DriftEvent[]>
  /** Historial de transiciones de un control concreto. */
  readonly getHistory: (projectID: string, framework: Framework, controlId: string) => Effect.Effect<ControlHistoryRow[]>
  /** Resumen global del estado de cumplimiento a través de todos los proyectos. */
  readonly getGlobalSummary: () => Effect.Effect<GlobalComplianceSummary>
  readonly sourceInfo: () => Effect.Effect<{
    sources: ComplianceSourceConfig[]
    catalogCount: number
    mappingCount: number
    lastRefreshed: number | null
  }>
  /** Árbol de compliance anidado (catálogo + estado del proyecto de la Session)
   *  listo para servir por HTTP — usado por el panel de Cumplimiento. */
  readonly getSessionStatus: (sessionID: string) => Effect.Effect<SessionComplianceStatus>
}

export class Service extends Context.Service<Service, Interface>()("@argos/compliance/Compliance") {}

const STATUS_RANK: Record<ControlStatus, number> = { compliant: 0, unassessed: 1, partial: 2, deficient: 3 }
const worseStatus = (a: ControlStatus, b: ControlStatus) => (STATUS_RANK[a] >= STATUS_RANK[b] ? a : b)

/**
 * Arma el árbol anidado de un framework a partir del catálogo plano (nodos
 * con parentId) y el estado derivado (plano, solo persistido en los nodos
 * hoja donde deriveProjectStatuses realmente computa status — subcategorías
 * en NIST, controles en ISO). Los nodos padre no tienen status propio: se
 * agregan como el peor status de sus hijos y la suma de sus findingCount.
 * Un nodo raíz sintético (level: "root") agrupa las funciones/temas de nivel
 * superior — el catálogo puede tener varios nodos top-level (parentId: null)
 * pero el frontend espera un único árbol por framework.
 */
function buildFrameworkTree(
  framework: Framework,
  title: string,
  nodes: ControlNode[],
  statusByControlId: Map<string, ControlStatusRow>,
): SessionComplianceNode {
  const byParent = new Map<string | null, ControlNode[]>()
  for (const node of nodes) {
    const list = byParent.get(node.parentId)
    if (list) list.push(node)
    else byParent.set(node.parentId, [node])
  }

  const build = (node: ControlNode): SessionComplianceNode => {
    const children = (byParent.get(node.id) ?? []).map(build)
    if (children.length > 0) {
      return {
        id: node.id,
        title: node.title,
        level: node.level,
        status: children.reduce<ControlStatus>((worst, child) => worseStatus(worst, child.status), "compliant"),
        findingCount: children.reduce((sum, child) => sum + child.findingCount, 0),
        evidence: [],
        derivation: children.flatMap((child) => child.derivation),
        confidence: children.reduce<EvidenceConfidence>(
          (worst, child) => maxConfidence(worst, child.confidence),
          "high",
        ),
        children,
      }
    }
    const own = statusByControlId.get(node.id)
    return {
      id: node.id,
      title: node.title,
      level: node.level,
      status: own?.status ?? "unassessed",
      findingCount: own?.evidence.length ?? 0,
      evidence: own?.evidence ?? [],
      derivation: own?.derivation ?? [],
      confidence: own?.confidence ?? "high",
      children: [],
    }
  }

  const topLevel = (byParent.get(null) ?? []).map(build)
  return {
    id: framework,
    title,
    level: "root",
    status: topLevel.reduce<ControlStatus>((worst, node) => worseStatus(worst, node.status), "compliant"),
    findingCount: topLevel.reduce((sum, node) => sum + node.findingCount, 0),
    evidence: [],
    derivation: topLevel.flatMap((node) => node.derivation),
    confidence: topLevel.reduce<EvidenceConfidence>((worst, node) => maxConfidence(worst, node.confidence), "high"),
    children: topLevel,
  }
}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const { db } = yield* Database.Service

    // Serializa los recomputes por proyecto: evita que dos recomputes del mismo
    // proyecto intercalen su lectura de estado previo (drift duplicado o un
    // estado intermedio saltado). SQLite ya serializa escrituras, esto protege
    // la consistencia de la detección de drift.
    const locks = new Map<string, Semaphore.Semaphore>()
    const lockFor = (projectID: string) => {
      const existing = locks.get(projectID)
      if (existing) return existing
      const lock = Semaphore.makeUnsafe(1)
      locks.set(projectID, lock)
      return lock
    }

    const runOnce = Effect.fn("Compliance.recomputeRun")(function* (projectID: string) {
      const findings = yield* db
        .select()
        .from(FindingTable)
        .where(and(eq(FindingTable.project_id, projectID), trustedFindingSourceCondition()))
        .orderBy(FindingTable.time_updated)
        .limit(1000)
        .all()
      const feedback = yield* feedbackForProject(db, projectID)
      const falsePositiveIDs = new Set(
        feedback.filter((row) => row.verdict === "false-positive").map((row) => row.finding_id),
      )
      const catalog = yield* db
        .select()
        .from(ComplianceCatalogTable)
        .all()
        .pipe(Effect.orDie)
      if (catalog.length === 0) return
      const rows = deriveProjectStatuses({
        projectID,
        findings: findings.filter((row) => row.status !== "false-positive" && !falsePositiveIDs.has(row.id)).map((row) => ({
          id: row.id,
          title: row.title,
          severity: row.severity,
          status: row.status,
          sourceTool: row.source_tool,
          cwe: row.cwe,
          vector: row.vector,
          tags: row.tags,
          attackTechniques: row.attack_techniques,
          confidence: row.confidence,
          timeUpdated: row.time_updated,
        })),
        catalog,
      })
      if (rows.length === 0) return
      yield* db
        .transaction(() =>
          Effect.gen(function* () {
            // Lee el estado previo para detectar drift (transiciones de estado).
            const previous = yield* db
              .select({
                framework: ComplianceStatusTable.framework,
                control_id: ComplianceStatusTable.control_id,
                status: ComplianceStatusTable.status,
              })
              .from(ComplianceStatusTable)
              .where(eq(ComplianceStatusTable.project_id, projectID))
              .all()
              .pipe(Effect.orDie)
            const previousByKey = new Map(
              previous.map((row) => [`${row.framework}:${row.control_id}`, row.status as ControlStatus]),
            )
            const nowCount = Date.now()
            for (const row of rows) {
              yield* db
                .insert(ComplianceStatusTable)
                .values({
                  project_id: row.projectID,
                  framework: row.framework,
                  control_id: row.controlId,
                  status: row.status,
                  evidence: row.evidence,
                  derivation: row.derivation,
                  confidence: row.confidence,
                  time_updated: row.timeUpdated,
                })
                .onConflictDoUpdate({
                  target: [ComplianceStatusTable.project_id, ComplianceStatusTable.framework, ComplianceStatusTable.control_id],
                  set: {
                    status: row.status,
                    evidence: row.evidence,
                    derivation: row.derivation,
                    confidence: row.confidence,
                    time_updated: row.timeUpdated,
                  },
                })
                .run()
                .pipe(Effect.orDie)
              // Drift: solo se registra si el estado cambió (no el primer cómputo).
              const key = `${row.framework}:${row.controlId}`
              const before = previousByKey.get(key)
              if (before !== undefined && before !== row.status) {
                yield* db
                  .insert(ComplianceHistoryTable)
                  .values({
                    project_id: projectID,
                    framework: row.framework,
                    control_id: row.controlId,
                    status_from: before,
                    status_to: row.status,
                    time_recorded: nowCount,
                  })
                  .run()
                  .pipe(Effect.orDie)
              }
            }
          }),
        )
        .pipe(Effect.orDie)
    })

    /** Intenta descargar un JSON desde una URL con fallback a cache/bundled local. */
    const fetchWithCache = (
      source: ComplianceSourceConfig,
    ): Effect.Effect<{ data: Record<string, unknown> | undefined; fromNetwork: boolean }, never> =>
      Effect.gen(function* () {
        const cached = yield* readCached(source.key)

        // Intentar descargar desde la URL
        const exit = yield* fetchJson(source.url).pipe(Effect.exit)
        if (exit._tag === "Success") {
          yield* writeCached(source.key, exit.value)
          return { data: exit.value, fromNetwork: true }
        }

        // Descarga falló o timeout: usar datos bundled/cacheados locales inmediatamente
        if (cached) {
          return { data: cached, fromNetwork: false }
        }
        return { data: undefined, fromNetwork: false }
      })

    const refresh = Effect.fn("Compliance.refresh")(function* () {
      const sources = complianceSources()
      const results = yield* Effect.all(
        sources.map((source) => fetchWithCache(source)),
        { concurrency: 4 },
      )

      const nistNodes: ReturnType<typeof parseNistOscal> = []
      const isoNodes: ReturnType<typeof parseIsoCrosswalk> = { controls: [], mappings: [] }
      const checks = new Map<Framework, Map<string, string[]>>()

      const sourceSummaries: RefreshSummary["sources"] = []
      sources.forEach((source, index) => {
        const { data: body, fromNetwork } = results[index]
        if (!body) {
          sourceSummaries.push({ key: source.key, url: source.url, license: source.license, ok: false, error: "Not available (network error and no cache)" })
          return
        }
        if (source.key === "nist_csf_v2") {
          nistNodes.push(...parseNistOscal(body))
          sourceSummaries.push({ key: source.key, url: source.url, license: source.license, ok: fromNetwork, controls: nistNodes.length })
          return
        }
        if (source.key === "iso27001_crosswalk") {
          const parsed = parseIsoCrosswalk(body)
          isoNodes.controls.push(...parsed.controls)
          isoNodes.mappings.push(...parsed.mappings)
          sourceSummaries.push({ key: source.key, url: source.url, license: source.license, ok: fromNetwork, controls: parsed.controls.length, mappings: parsed.mappings.length })
          return
        }
        const framework = source.key === "checks_nist" ? FRAMEWORKS.nistCsfV2 : FRAMEWORKS.iso27001
        const parsed = parseChecks(body, framework)
        checks.set(framework, parsed)
        sourceSummaries.push({ key: source.key, url: source.url, license: source.license, ok: fromNetwork, controls: parsed.size })
      })

      // Catálogos bundled (SOC 2 / NIS2 / DORA del crosswalk ISO + referencias
      // PCI): snapshots commiteados. No dependen de la red — siempre
      // disponibles, incluso offline.
      const derivedSources = bundledCatalogSources()
      const derivedResults = yield* Effect.all(derivedSources.map((source) => readBundled(source.key)))
      const derivedNodes = new Map<Framework, ControlNode[]>()
      const derivedMappings: ControlMapping[] = []
      derivedSources.forEach((source, index) => {
        const framework = DERIVED_BY_SOURCE[source.key]
        const body = derivedResults[index]
        if (!body || !framework) {
          sourceSummaries.push({
            key: source.key,
            url: source.url,
            license: source.license,
            ok: false,
            error: "Snapshot bundled no disponible",
            bundled: true,
          })
          return
        }
        const parsed = parseDerivedCatalog(body, framework)
        derivedNodes.set(framework, parsed)
        // Trazabilidad ISO ↔ framework: los controles ISO equivalentes que
        // declara el crosswalk quedan como mapeos en ambas direcciones.
        let mappings = 0
        for (const node of parsed) {
          const isoEquivalents = node.attributes["isoEquivalents"]
          if (!Array.isArray(isoEquivalents)) continue
          for (const isoId of isoEquivalents) {
            if (typeof isoId !== "string") continue
            derivedMappings.push({
              sourceFramework: FRAMEWORKS.iso27001,
              sourceControlId: isoId,
              targetFramework: framework,
              targetControlId: node.id,
            })
            derivedMappings.push({
              sourceFramework: framework,
              sourceControlId: node.id,
              targetFramework: FRAMEWORKS.iso27001,
              targetControlId: isoId,
            })
            mappings += 2
          }
        }
        sourceSummaries.push({
          key: source.key,
          url: source.url,
          license: source.license,
          ok: true,
          controls: parsed.length,
          mappings,
          bundled: true,
        })
      })

      // Fusiona los checks (saasfort) en los atributos de los nodos del catálogo.
      const now = Date.now()
      const nodes = [...nistNodes, ...isoNodes.controls]
      for (const node of nodes) {
        const nodeChecks = checks.get(node.framework)?.get(node.id)
        if (nodeChecks && nodeChecks.length > 0) {
          node.attributes = { ...node.attributes, checks: nodeChecks }
        }
      }

      // Persistencia: reemplazo atómico POR FRAMEWORK, solo si su fuente tuvo
      // éxito. Si una fuente falla (offline/HTTP), se conserva el caché previo
      // de ese framework — degradación con gracia, nunca se vacía la BD.
      const nistOk = nistNodes.length > 0
      const isoOk = isoNodes.controls.length > 0
      yield* db
        .transaction(() =>
          Effect.gen(function* () {
            if (nistOk) {
              yield* db
                .delete(ComplianceCatalogTable)
                .where(eq(ComplianceCatalogTable.framework, FRAMEWORKS.nistCsfV2))
                .run()
                .pipe(Effect.orDie)
              yield* db
                .insert(ComplianceCatalogTable)
                .values(
                  nistNodes.map((node) => ({
                    framework: node.framework,
                    control_id: node.id,
                    title: node.title,
                    parent_id: node.parentId,
                    level: node.level,
                    sort_id: node.sortId ?? null,
                    attributes: node.attributes,
                    source: node.source,
                    time_updated: now,
                  })),
                )
                .run()
                .pipe(Effect.orDie)
            }
            if (isoOk) {
              yield* db
                .delete(ComplianceCatalogTable)
                .where(eq(ComplianceCatalogTable.framework, FRAMEWORKS.iso27001))
                .run()
                .pipe(Effect.orDie)
              yield* db
                .insert(ComplianceCatalogTable)
                .values(
                  isoNodes.controls.map((node) => ({
                    framework: node.framework,
                    control_id: node.id,
                    title: node.title,
                    parent_id: node.parentId,
                    level: node.level,
                    sort_id: node.sortId ?? null,
                    attributes: node.attributes,
                    source: node.source,
                    time_updated: now,
                  })),
                )
                .run()
                .pipe(Effect.orDie)
              // Mapeos ISO ↔ NIST: se reemplazan solo si la fuente ISO estuvo
              // disponible (el resto de los mapeos del crosswalk sobrevive).
              yield* db
                .delete(ComplianceMappingTable)
                .where(
                  or(
                    eq(ComplianceMappingTable.source_framework, FRAMEWORKS.nistCsfV2),
                    eq(ComplianceMappingTable.target_framework, FRAMEWORKS.nistCsfV2),
                  ),
                )
                .run()
                .pipe(Effect.orDie)
              if (isoNodes.mappings.length > 0) {
                yield* db
                  .insert(ComplianceMappingTable)
                  .values(
                    isoNodes.mappings.map((mapping) => ({
                      source_framework: mapping.sourceFramework,
                      source_control_id: mapping.sourceControlId,
                      target_framework: mapping.targetFramework,
                      target_control_id: mapping.targetControlId,
                    })),
                  )
                  .run()
                  .pipe(Effect.orDie)
              }
            }
            // Catálogos bundled (SOC 2 / NIS2 / DORA / PCI) y sus mapeos
            // ISO: son snapshots bundled, siempre disponibles.
            for (const [framework, derived] of derivedNodes) {
              yield* db
                .delete(ComplianceCatalogTable)
                .where(eq(ComplianceCatalogTable.framework, framework))
                .run()
                .pipe(Effect.orDie)
              if (derived.length === 0) continue
              yield* db
                .insert(ComplianceCatalogTable)
                .values(
                  derived.map((node) => ({
                    framework: node.framework,
                    control_id: node.id,
                    title: node.title,
                    parent_id: node.parentId,
                    level: node.level,
                    sort_id: node.sortId ?? null,
                    attributes: node.attributes,
                    source: node.source,
                    time_updated: now,
                  })),
                )
                .run()
                .pipe(Effect.orDie)
            }
            yield* db
              .delete(ComplianceMappingTable)
              .where(
                or(
                  inArray(ComplianceMappingTable.source_framework, BUNDLED_FRAMEWORKS),
                  inArray(ComplianceMappingTable.target_framework, BUNDLED_FRAMEWORKS),
                ),
              )
              .run()
              .pipe(Effect.orDie)
            if (derivedMappings.length > 0) {
              yield* db
                .insert(ComplianceMappingTable)
                .values(
                  derivedMappings.map((mapping) => ({
                    source_framework: mapping.sourceFramework,
                    source_control_id: mapping.sourceControlId,
                    target_framework: mapping.targetFramework,
                    target_control_id: mapping.targetControlId,
                  })),
                )
                .run()
                .pipe(Effect.orDie)
            }
          }),
        )
        .pipe(Effect.orDie)

      const catalogControlCount = yield* db
        .select({ total: sql<number>`count(*)` })
        .from(ComplianceCatalogTable)
        .get()
        .pipe(Effect.orDie)
      const mappingCount = yield* db
        .select({ total: sql<number>`count(*)` })
        .from(ComplianceMappingTable)
        .get()
        .pipe(Effect.orDie)

      return {
        refreshedAt: now,
        sources: sourceSummaries,
        catalogControlCount: Number(catalogControlCount?.total ?? 0),
        mappingCount: Number(mappingCount?.total ?? 0),
      } satisfies RefreshSummary
    })

    const ensureCatalog = Effect.fn("Compliance.ensureCatalog")(function* () {
      const frameworks = yield* db
        .selectDistinct({ framework: ComplianceCatalogTable.framework })
        .from(ComplianceCatalogTable)
        .all()
        .pipe(Effect.orDie)
      const present = new Set(frameworks.map((row) => row.framework))
      // Los catálogos bundled (SOC 2 / NIS2 / DORA / PCI references) son snapshots
      // commiteados: si faltan es una instalación previa a ARG-040/ARG-041 y se
      // recargan sin depender de la red. NIST/ISO no se re-descargan (su red
      // puede estar caída).
      const missingBundled = BUNDLED_FRAMEWORKS.some((framework) => !present.has(framework))
      const empty = present.size === 0
      if (!missingBundled && !empty) return
      yield* refresh().pipe(
        Effect.catch((cause: unknown) =>
          Effect.logWarning("compliance catalog refresh failed").pipe(
            Effect.annotateLogs({ cause: cause instanceof Error ? cause.message : String(cause) }),
          ),
        ),
      )
    })

    const getCatalog = Effect.fn("Compliance.getCatalog")(function* (framework?: Framework) {
      const base = db.select().from(ComplianceCatalogTable)
      const query = framework ? base.where(eq(ComplianceCatalogTable.framework, framework)) : base
      const rows = yield* query.orderBy(ComplianceCatalogTable.sort_id).all().pipe(Effect.orDie)
      return rows.map(catalogRowToNode)
    })

    const getStatus = Effect.fn("Compliance.getStatus")(function* (projectID: string) {
      const rows = yield* db
        .select()
        .from(ComplianceStatusTable)
        .where(eq(ComplianceStatusTable.project_id, projectID))
        .all()
        .pipe(Effect.orDie)
      return rows.map((row) => ({
        projectID: row.project_id,
        framework: row.framework,
        controlId: row.control_id,
        status: row.status as ControlStatusRow["status"],
        evidence: row.evidence,
        derivation: row.derivation,
        confidence: row.confidence as EvidenceConfidence,
        timeUpdated: row.time_updated,
      }))
    })

    // Re-deriva y persiste el estado del proyecto. Se ejecuta inline (sin
    // coalescing por fiber): así `recomputeProject` siempre devuelve estado
    // fresco, y un semáforo por proyecto serializa corridas concurrentes.
    const recomputeProject = Effect.fn("Compliance.recomputeProject")(function* (projectID: string) {
      yield* lockFor(projectID).withPermit(runOnce(projectID)).pipe(Effect.orDie)
    })

    const recomputeSession = Effect.fn("Compliance.recomputeSession")(function* (sessionID: string) {
      const row = yield* db
        .select({ projectID: SessionTable.project_id })
        .from(SessionTable)
        .where(eq(SessionTable.id, SessionSchema.ID.make(sessionID)))
        .get()
        .pipe(Effect.orDie)
      if (row?.projectID) yield* recomputeProject(row.projectID)
    })

    const sweepAll = Effect.fn("Compliance.sweepAll")(function* () {
      const projects = yield* db
        .selectDistinct({ projectID: FindingTable.project_id })
        .from(FindingTable)
        .where(trustedFindingSourceCondition())
        .all()
        .pipe(Effect.orDie)
      yield* Effect.forEach(
        projects,
        (row) =>
          recomputeProject(row.projectID).pipe(
            Effect.catch((cause: unknown) =>
              Effect.logWarning("compliance recompute failed").pipe(
                Effect.annotateLogs({ projectID: row.projectID, cause: cause instanceof Error ? cause.message : String(cause) }),
              ),
            ),
          ),
        { concurrency: 2 },
      )
    })

    const getDriftEvents = Effect.fn("Compliance.getDriftEvents")(function* (options?: { limit?: number; projectID?: string }) {
      const limit = Math.min(Math.max(options?.limit ?? 50, 1), 500)
      const rows = yield* db
        .select()
        .from(ComplianceHistoryTable)
        .where(options?.projectID ? eq(ComplianceHistoryTable.project_id, options.projectID) : undefined)
        .orderBy(sql`${ComplianceHistoryTable.time_recorded} desc`)
        .limit(limit)
        .all()
        .pipe(Effect.orDie)
      return rows.map((row) => ({
        id: row.id,
        projectID: row.project_id,
        framework: row.framework,
        controlId: row.control_id,
        statusFrom: row.status_from as ControlStatus,
        statusTo: row.status_to as ControlStatus,
        timeRecorded: row.time_recorded,
      }))
    })

    const getHistory = Effect.fn("Compliance.getHistory")(function* (projectID: string, framework: Framework, controlId: string) {
      const rows = yield* db
        .select()
        .from(ComplianceHistoryTable)
        .where(
          and(
            eq(ComplianceHistoryTable.project_id, projectID),
            eq(ComplianceHistoryTable.framework, framework),
            eq(ComplianceHistoryTable.control_id, controlId),
          ),
        )
        .orderBy(ComplianceHistoryTable.time_recorded)
        .all()
        .pipe(Effect.orDie)
      return rows.map((row) => ({
        id: row.id,
        projectID: row.project_id,
        framework: row.framework,
        controlId: row.control_id,
        statusFrom: row.status_from as ControlStatus,
        statusTo: row.status_to as ControlStatus,
        timeRecorded: row.time_recorded,
      }))
    })

    const getGlobalSummary = Effect.fn("Compliance.getGlobalSummary")(function* () {
      const [projects, catalogRows, statusRows, lastUpdated] = yield* Effect.all([
        db.selectDistinct({ projectID: ComplianceStatusTable.project_id }).from(ComplianceStatusTable).all().pipe(Effect.orDie),
        db.select().from(ComplianceCatalogTable).all().pipe(Effect.orDie),
        db.select().from(ComplianceStatusTable).all().pipe(Effect.orDie),
        db.select({ max: sql<number>`max(${ComplianceStatusTable.time_updated})` }).from(ComplianceStatusTable).get().pipe(Effect.orDie),
      ])

      // Solo se cuentan las hojas del catálogo (subcategoría NIST / control ISO):
      // los niveles intermedios (función/categoría/tema) propagan el estado de
      // sus hijos y duplicarían el conteo si se incluyeran. Un control que el
      // motor no puede evaluar (`coverage: "not-evaluable"`) queda fuera del
      // score: contarlo como conforme sería afirmar conformidad sin evidencia.
      const leafLevels = new Set<string>(["subcategory", "control"])
      const leafByKey = new Set<string>()
      for (const row of catalogRows) {
        if (!leafLevels.has(row.level)) continue
        if (row.attributes?.["coverage"] === "not-evaluable") continue
        leafByKey.add(`${row.framework}:${row.control_id}`)
      }
      const perFramework = new Map<
        Framework,
        {
          title: string
          version: string
          totalControls: number
          counts: Record<ControlStatus, number>
          confidence: EvidenceConfidence
        }
      >()
      for (const framework of Object.values(FRAMEWORKS)) {
        perFramework.set(framework, {
          title: FRAMEWORK_META[framework].title,
          version: FRAMEWORK_META[framework].version,
          totalControls: 0,
          counts: { deficient: 0, partial: 0, compliant: 0, unassessed: 0 },
          confidence: "high",
        })
      }
      for (const row of catalogRows) {
        const meta = perFramework.get(row.framework as Framework)
        if (meta && leafByKey.has(`${row.framework}:${row.control_id}`)) meta.totalControls += 1
      }
      for (const row of statusRows) {
        if (!leafByKey.has(`${row.framework}:${row.control_id}`)) continue
        const meta = perFramework.get(row.framework as Framework)
        if (!meta) continue
        if (row.status in meta.counts) {
          meta.counts[row.status as ControlStatus] += 1
        }
        // Confianza agregada del framework: la más débil de sus hojas con
        // evidencia. Los controles sin hallazgos vienen con `high` y no la
        // degradan (no hay nada que dudar de ellos).
        meta.confidence = minConfidence(meta.confidence, row.confidence as EvidenceConfidence)
      }
      const frameworks = [...perFramework.entries()].map(([framework, meta]) => {
        const assessed = meta.counts.deficient + meta.counts.partial + meta.counts.compliant
        const score = assessed > 0 ? Math.round((meta.counts.compliant / assessed) * 100) : 0
        return { framework, ...meta, score }
      })
      return {
        generatedAt: Date.now(),
        projectCount: projects.length,
        frameworks,
        lastUpdated: lastUpdated?.max ?? null,
      } satisfies GlobalComplianceSummary
    })

    const sourceInfo = Effect.fn("Compliance.sourceInfo")(function* () {
      const [catalogCount, mappingCount, latest] = yield* Effect.all([
        db.select({ total: sql<number>`count(*)` }).from(ComplianceCatalogTable).get().pipe(Effect.orDie),
        db.select({ total: sql<number>`count(*)` }).from(ComplianceMappingTable).get().pipe(Effect.orDie),
        db
          .select({ max: sql<number>`max(${ComplianceCatalogTable.time_updated})` })
          .from(ComplianceCatalogTable)
          .get()
          .pipe(Effect.orDie),
      ])
      return {
        sources: complianceSources(),
        catalogCount: Number(catalogCount?.total ?? 0),
        mappingCount: Number(mappingCount?.total ?? 0),
        lastRefreshed: latest?.max ?? null,
      }
    })

    const getSessionStatus = Effect.fn("Compliance.getSessionStatus")(function* (sessionID: string) {
      const info = yield* sourceInfo()
      const empty: SessionComplianceStatus = {
        frameworks: [],
        catalogCount: info.catalogCount,
        mappingCount: info.mappingCount,
        lastRefreshed: info.lastRefreshed ?? undefined,
      }
      if (info.catalogCount === 0) return empty

      const session = yield* db
        .select({ projectID: SessionTable.project_id })
        .from(SessionTable)
        .where(eq(SessionTable.id, SessionSchema.ID.make(sessionID)))
        .get()
        .pipe(Effect.orDie)
      if (!session?.projectID) return empty

      // Identificar todas las sesiones de la familia (sesión principal y sub-agentes)
      const allSessions = yield* db
        .select({ id: SessionTable.id, parent_id: SessionTable.parent_id })
        .from(SessionTable)
        .all()
        .pipe(Effect.orDie)

      const familyIds = new Set<string>([sessionID])
      let added = true
      while (added) {
        added = false
        for (const s of allSessions) {
          if (s.parent_id && familyIds.has(s.parent_id) && !familyIds.has(s.id)) {
            familyIds.add(s.id)
            added = true
          }
        }
      }

      // Obtener exclusivamente los hallazgos de esta sesión / familia de sesiones
      const allFindings = yield* db
        .select()
        .from(FindingTable)
        .where(trustedFindingSourceCondition())
        .all()
        .pipe(Effect.orDie)

      const sessionFeedback = yield* feedbackForSessions(db, [...familyIds])
      const falsePositiveIDs = new Set(
        sessionFeedback.filter((row) => row.verdict === "false-positive").map((row) => row.finding_id),
      )
      const sessionFindings = allFindings.filter(
        (row) => familyIds.has(row.session_id) && row.status !== "false-positive" && !falsePositiveIDs.has(row.id),
      )

      const catalog = yield* db
        .select()
        .from(ComplianceCatalogTable)
        .all()
        .pipe(Effect.orDie)

      // Derivar el estado de controles exclusivamente para los hallazgos de esta auditoría
      const statusRows = deriveProjectStatuses({
        projectID: session.projectID,
        findings: sessionFindings.map((row) => ({
          id: row.id,
          title: row.title,
          severity: row.severity,
          status: row.status,
          sourceTool: row.source_tool,
          cwe: row.cwe,
          vector: row.vector,
          tags: row.tags,
          attackTechniques: row.attack_techniques,
          confidence: row.confidence,
          timeUpdated: row.time_updated,
        })),
        catalog,
      })

      const frameworks: SessionComplianceStatus["frameworks"] = []
      for (const framework of Object.values(FRAMEWORKS)) {
        const nodes = yield* getCatalog(framework)
        if (nodes.length === 0) continue
        const byControlId = new Map(
          statusRows.filter((row) => row.framework === framework).map((row) => [row.controlId, row]),
        )
        frameworks.push({
          framework,
          title: FRAMEWORK_META[framework].title,
          version: FRAMEWORK_META[framework].version,
          refreshedAt: info.lastRefreshed ?? undefined,
          tree: buildFrameworkTree(framework, FRAMEWORK_META[framework].title, nodes, byControlId),
        })
      }
      return { frameworks, catalogCount: info.catalogCount, mappingCount: info.mappingCount, lastRefreshed: info.lastRefreshed ?? undefined }
    })

    return Service.of({
      refresh,
      ensureCatalog,
      getCatalog,
      getStatus,
      recomputeProject,
      recomputeSession,
      sweepAll,
      getDriftEvents,
      getHistory,
      getGlobalSummary,
      sourceInfo,
      getSessionStatus,
    })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(Database.defaultLayer))

export * as Compliance from "./service"
export { FRAMEWORK_META }
