import { and, count, eq } from "drizzle-orm"
import { Effect, Schema } from "effect"
import type { Database } from "../database/database"
import { FindingTable } from "./sql"
import { trustedFindingSourceCondition } from "./finding-provenance"
import * as ScopeService from "./scope-service"
import { evaluateScopeTarget } from "./scope-eval"

export {
  evaluateScopeTarget,
  matchesDomainPattern,
  matchCidr,
  extractTargetHost,
  isPrivateAddress,
} from "./scope-eval"
export type { ScopePolicy } from "./scope-eval"

export const OLA1_RECON_TOOLS = new Set([
  "web.probe",
  "web.subdomains",
  "web.crawl",
  "web.tech",
  "web.waf",
  "web.urls",
  "web.tls",
  "web.ports",
  "web.browse",
  "web.browse:navigate",
  "web.browse:login",
  "lan.discovery",
  "lan.mdns",
  "lan.banner",
  "lan.topology",
  "argos_memory_save",
  "read",
  "list_dir",
  "grep_search",
  "file_search",
  "bash",
])

export const OLA2_EXPLOIT_TOOLS = new Set([
  "web.scan",
  "web.sqli",
  "web.fuzz",
  "web.xss",
  "web.params",
  "web.oob",
  "web.api",
  "web.cms",
  "web.ports:nse",
  "web.browse:check_authz",
  "web.browse:dom_xss",
  "lan.port_scan",
  "lan.snmp",
])

export type ToolPhase = "ola1_recon" | "ola2_exploit" | "general"

export function classifyToolPhase(toolName: string, action?: string): ToolPhase {
  const normalized = toolName.trim().toLowerCase()
  if (action) {
    const combined = `${normalized}:${action.trim().toLowerCase()}`
    if (OLA2_EXPLOIT_TOOLS.has(combined)) return "ola2_exploit"
    if (OLA1_RECON_TOOLS.has(combined)) return "ola1_recon"
  }
  if (OLA2_EXPLOIT_TOOLS.has(normalized)) return "ola2_exploit"
  if (OLA1_RECON_TOOLS.has(normalized)) return "ola1_recon"
  return "general"
}

export interface PhasedGateResult {
  allowed: boolean
  phase: ToolPhase
  reason?: string
  reconAssetsCount: number
}

export class PhasedGateBlockedError extends Schema.TaggedErrorClass<PhasedGateBlockedError>()(
  "PhasedGateBlockedError",
  {
    toolName: Schema.String,
    sessionID: Schema.String,
    message: Schema.String,
  },
) {}

/**
 * El bypass que desactiva las compuertas por fases sólo puede activarse en un
 * entorno de prueba o con un opt-in explícito del operador.
 *
 * Invariante de seguridad: una variable de entorno suelta ya no puede dejar
 * la cadena de herramientas sin gates en producción — antes `ARGOS_PHASED_GATES_DISABLED=1`
 * alcanzaba cualquier entorno.
 */
const phasedGateBypassEnabled = Effect.fn("phasedGateBypassEnabled")(function* () {
  if (process.env.NODE_ENV === "test") return true
  if (process.env.ARGOS_ALLOW_PHASED_GATE_BYPASS === "1") {
    yield* Effect.logWarning(
      "ARGOS_ALLOW_PHASED_GATE_BYPASS=1 is set: phased gates (ola1_recon / ola2_exploit) are DISABLED for this process.",
    )
    return true
  }
  return false
})

/**
 * Evalúa determinísticamente si una herramienta puede ejecutarse según el estado
 * de activos de Ola 1 guardados en SQLite para la sesión dada y valida el target contra el Scope.
 */
export function evaluatePhasedGate(input: {
  db: Database.Interface["db"]
  sessionID: string
  toolName: string
  action?: string
  target?: string
}): Effect.Effect<PhasedGateResult, never, ScopeService.Service | Database.Service> {
  return Effect.gen(function* () {
    const phase = classifyToolPhase(input.toolName, input.action)

    // Bypass opcional para entornos de prueba
    if (yield* phasedGateBypassEnabled()) {
      return {
        allowed: true,
        phase,
        reconAssetsCount: 999,
      }
    }

    // Validación estricta de Scope cuando el target es especificado
    if (input.target && input.sessionID) {
      const scope = yield* ScopeService.Service
      const scopeToEvaluate = yield* scope.forSession(input.sessionID)

      const scopeCheck = evaluateScopeTarget(input.target, scopeToEvaluate)
      if (!scopeCheck.allowed) {
        return {
          allowed: false,
          phase,
          reconAssetsCount: 0,
          reason: scopeCheck.reason,
        }
      }
    }

    // Las herramientas de Ola 1 o generales no tienen compuertas previas tras validar scope
    if (phase !== "ola2_exploit") {
      return {
        allowed: true,
        phase,
        reconAssetsCount: 0,
      }
    }

    // Bypass opcional para entornos de prueba
    if (yield* phasedGateBypassEnabled()) {
      return {
        allowed: true,
        phase,
        reconAssetsCount: 999,
      }
    }

    // Consultar en la base de datos si existen hallazgos/activos de Ola 1
    const rows = yield* input.db
      .select({ val: count() })
      .from(FindingTable)
      .where(and(eq(FindingTable.session_id, input.sessionID), trustedFindingSourceCondition()))
      .all()
      .pipe(Effect.orDie)

    const totalAssets = rows[0]?.val ?? 0

    if (totalAssets === 0) {
      return {
        allowed: false,
        phase,
        reconAssetsCount: 0,
        reason:
          `PHASED GATE BLOCKED: Tool '${input.toolName}${input.action ? ":" + input.action : ""}' belongs to Ola 2 (Deep Scan / Exploitation). ` +
          `The session '${input.sessionID}' has 0 recorded reconnaissance assets in database. ` +
          `Ola 1 (Reconnaissance: web.probe, web.subdomains, web.crawl, lan.discovery) must discover assets first.`,
      }
    }

    return {
      allowed: true,
      phase,
      reconAssetsCount: totalAssets,
    }
  })
}

/**
 * Enforzador estricto: falla con PhasedGateBlockedError si la compuerta no pasa.
 */
export function enforcePhasedGate(input: {
  db: Database.Interface["db"]
  sessionID: string
  toolName: string
  action?: string
  target?: string
}): Effect.Effect<void, PhasedGateBlockedError, ScopeService.Service | Database.Service> {
  return Effect.gen(function* () {
    const result = yield* evaluatePhasedGate(input)
    if (!result.allowed) {
      return yield* new PhasedGateBlockedError({
        toolName: input.toolName,
        sessionID: input.sessionID,
        message: result.reason ?? "Blocked by phased gate policy",
      })
    }
  })
}
