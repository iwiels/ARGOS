import { eq } from "drizzle-orm"
import { Context, Effect, Layer, Schema } from "effect"
import { Database } from "../database/database"
import { ProjectTable } from "../project/sql"
import { SessionSchema } from "../session/schema"
import { SessionTable } from "../session/sql"
import {
  evaluateScopeTarget,
  extractTargetHost,
  isPrivateAddress,
  scopeAllowsPrivateHost,
  type ScopePolicy,
} from "./scope-eval"

export type { ScopePolicy } from "./scope-eval"

/**
 * Violación de scope: el target está fuera del alcance declarado o apunta a
 * una dirección privada que el scope no autorizó explícitamente.
 *
 * El `reason` siempre empieza por `SCOPE ENFORCEMENT:` para que el operador
 * distinga un bloqueo de scope de un fallo de red o de una tool caída.
 */
export class ScopeViolationError extends Schema.TaggedErrorClass<ScopeViolationError>()("ScopeViolationError", {
  reason: Schema.String,
  target: Schema.optional(Schema.String),
}) {}

export interface Interface {
  /**
   * Scope efectivo de la sesión (propio del proyecto si la sesión no define uno).
   *
   * El servicio ata la base de datos en su construcción: consultar la política
   * no necesita `Database.Service` en el contexto de quien la pide.
   */
  readonly forSession: (sessionID: string) => Effect.Effect<ScopePolicy | undefined, never>
  /** Valida un target contra el scope de la sesión (y el bloqueo de IPs privadas). */
  readonly assertTarget: (sessionID: string, target: string) => Effect.Effect<void, ScopeViolationError>
  /** Bloquea IPs privadas/loopback/metadata salvo autorización explícita en el scope. */
  readonly assertNoPrivateByDefault: (target: string, policy?: ScopePolicy) => Effect.Effect<void, ScopeViolationError>
}

export class Service extends Context.Service<Service, Interface>()("@argos/security/Scope") {}

/** El host de una URL IPv6 viene envuelto en corchetes: `[::1]`. */
function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/^\[|\]$/g, "")
}

export function readForSession(db: Database.Interface["db"], sessionID: string) {
  return Effect.gen(function* () {
    const sessionRow = yield* db
      .select({
        scope_domains: SessionTable.scope_domains,
        scope_cidrs: SessionTable.scope_cidrs,
        scope_excluded: SessionTable.scope_excluded,
        scope_max_rps: SessionTable.scope_max_rps,
        scope_safe_mode: SessionTable.scope_safe_mode,
        project_id: SessionTable.project_id,
      })
      .from(SessionTable)
      .where(eq(SessionTable.id, sessionID as SessionSchema.ID))
      .get()
      .pipe(Effect.orDie)

    if (sessionRow?.scope_domains || sessionRow?.scope_cidrs || sessionRow?.scope_excluded) {
      return {
        domains: sessionRow.scope_domains ?? undefined,
        cidrs: sessionRow.scope_cidrs ?? undefined,
        excluded: sessionRow.scope_excluded ?? undefined,
        maxRPS: sessionRow.scope_max_rps ?? undefined,
        safeMode: sessionRow.scope_safe_mode ?? undefined,
      } satisfies ScopePolicy
    }

    if (sessionRow?.project_id) {
      const projectRow = yield* db
        .select({ scope: ProjectTable.scope })
        .from(ProjectTable)
        .where(eq(ProjectTable.id, sessionRow.project_id as any))
        .get()
        .pipe(Effect.orDie)
      if (projectRow?.scope) {
        return {
          domains: projectRow.scope.domains,
          cidrs: projectRow.scope.cidrs,
          excluded: projectRow.scope.excluded,
          maxRPS: projectRow.scope.maxRPS,
          safeMode: projectRow.scope.safeMode,
        } satisfies ScopePolicy
      }
    }

    return undefined
  })
}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const { db } = yield* Database.Service

    const forSession = Effect.fn("Scope.forSession")(function* (sessionID: string) {
      return yield* readForSession(db, sessionID)
    })

    const assertNoPrivateByDefault = Effect.fn("Scope.assertNoPrivateByDefault")(function* (
      target: string,
      policy?: ScopePolicy,
    ) {
      const host = normalizeHost(extractTargetHost(target).host)
      if (!isPrivateAddress(host)) return
      if (scopeAllowsPrivateHost(policy ?? {}, host)) return

      return yield* new ScopeViolationError({
        target,
        reason: `SCOPE ENFORCEMENT: Target '${target}' resolves to private address '${host}' which is not explicitly authorized in the current scope`,
      })
    })

    const assertTarget = Effect.fn("Scope.assertTarget")(function* (sessionID: string, target: string) {
      const policy = yield* forSession(sessionID)

      const scopeCheck = evaluateScopeTarget(target, policy)
      if (!scopeCheck.allowed) {
        return yield* new ScopeViolationError({
          target,
          reason: scopeCheck.reason ?? `SCOPE ENFORCEMENT: Target '${target}' is out of authorized scope`,
        })
      }

      yield* assertNoPrivateByDefault(target, policy)
    })

    return Service.of({ forSession, assertTarget, assertNoPrivateByDefault })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(Database.defaultLayer))
