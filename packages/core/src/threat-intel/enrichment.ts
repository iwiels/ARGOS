import { eq } from "drizzle-orm"
import { Context, Effect, Layer } from "effect"
import { Database } from "../database/database"
import { FindingTable } from "../security/sql"
import { mapFindingToAttack, type AttackMatch } from "./attack"
import { extractIocs, type Ioc, type IocType } from "./iocs"
import { lookupIocReputation, type ReputationResult, type ReputationSource } from "./reputation"
import { extractCves, enrichEpssAndKev, type EpssKevEnrichment } from "./epss-kev"
import { calculateCvss, type CvssResult } from "../security/cvss"

/** Forma persistida de una técnica ATT&CK mapeada a un hallazgo. */
export interface AttackTechniqueRow {
  id: string
  name: string
  tactics: string[]
  reason: string
}

/** IoC persistido con su reputación (si se consultó). */
export interface IocRow {
  type: IocType
  value: string
  reputation?: ReputationResult[]
}

/** Metadatos del enrichment para el finding. */
export interface EnrichmentInfo {
  attack: AttackTechniqueRow[]
  iocs: IocRow[]
  epssKev?: EpssKevEnrichment
  /** Score CVSS v3.1 calculado del vector que el agente declaró explícitamente en el hallazgo — ausente si no lo declaró. */
  cvss?: CvssResult
  reputationSources: ReputationSource[]
  reputationCheckedAt?: number
}

const stringValue = (value: unknown) => (typeof value === "string" && value.trim() ? value.trim() : undefined)

const evidenceText = (evidence: unknown) => {
  if (typeof evidence === "string") return evidence
  if (evidence && typeof evidence === "object") {
    const record = evidence as Record<string, unknown>
    return typeof record.text === "string" ? record.text : JSON.stringify(record)
  }
  return undefined
}

const MAX_IOCS_ENRICHED = 12

export interface Interface {
  /** Enrich local (ATT&CK + IoC extraction + EPSS/KEV) y la reputación de los IoCs. */
  readonly enrich: (findingID: string) => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/threat-intel/Enrichment") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const { db } = yield* Database.Service

    const enrich = Effect.fn("ThreatIntel.enrich")(function* (findingID: string) {
      const row = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, findingID))
        .get()
        .pipe(Effect.orDie)
      if (!row) return

      const attack: AttackTechniqueRow[] = mapFindingToAttack({
        cwe: row.cwe,
        tags: row.tags,
        sourceTool: row.source_tool,
        title: row.title,
        vector: row.vector,
      }).map((match: AttackMatch) => ({
        id: match.id,
        name: match.name,
        tactics: match.tactics,
        reason: match.reason,
      }))

      const haystack = [evidenceText(row.evidence), row.raw, row.vector, row.target, ...(row.tags ?? [])]
        .filter((value): value is string => typeof value === "string")
        .join("\n")
      const iocs: IocRow[] = extractIocs(haystack, { exclude: [row.source_tool] })
        .slice(0, MAX_IOCS_ENRICHED)
        .map((ioc: Ioc) => ({ type: ioc.type, value: ioc.value }))

      // Extraer CVEs de todo el contexto del hallazgo
      const cves = extractCves(haystack)

      // CVSS: solo si el agente declaró el vector explícito al reportar el
      // hallazgo (row.cvss_input) — nunca se adivina uno a partir de
      // severity/cwe/tags. El cálculo en sí es determinista y barato.
      const cvss: CvssResult | undefined = row.cvss_input ? calculateCvss(row.cvss_input) : undefined

      // Parte local inicial: barata y determinista, persiste ya.
      yield* db
        .update(FindingTable)
        .set({ attack_techniques: attack, iocs, enriched_at: Date.now() })
        .where(eq(FindingTable.id, findingID))
        .run()
        .pipe(Effect.orDie)

      // Enriquecimiento de EPSS + KEV y reputación de IoCs en paralelo
      const [epssKev, enrichedIocs] = yield* Effect.all([
        enrichEpssAndKev(cves).pipe(
          Effect.timeout(10000),
          Effect.catch(() => Effect.succeed(undefined)),
        ),
        iocs.length > 0
          ? Effect.all(
              iocs.map((ioc) =>
                lookupIocReputation({ type: ioc.type, value: ioc.value }).pipe(
                  Effect.timeout(8000),
                  Effect.catch(() => Effect.succeed([])),
                ),
              ),
              { concurrency: 4 },
            )
          : Effect.succeed([]),
      ])

      const withReputation: IocRow[] = iocs.map((ioc, index) => ({
        ...ioc,
        ...(enrichedIocs[index]?.length ? { reputation: enrichedIocs[index] } : {}),
      }))

      const enrichmentData: EnrichmentInfo = {
        attack,
        iocs: withReputation,
        ...(epssKev ? { epssKev } : {}),
        ...(cvss ? { cvss } : {}),
        reputationSources: Array.from(
          new Set(withReputation.flatMap((ioc) => ioc.reputation?.map((r) => r.source) ?? [])),
        ),
        reputationCheckedAt: Date.now(),
      }

      yield* db
        .update(FindingTable)
        .set({
          iocs: withReputation,
          enrichment: enrichmentData,
          enriched_at: Date.now(),
        })
        .where(eq(FindingTable.id, findingID))
        .run()
        .pipe(Effect.orDie)
    })

    return Service.of({ enrich })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(Database.defaultLayer))

export * as ThreatIntelEnrichment from "./enrichment"
