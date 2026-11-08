import { Database } from "@argos/core/database/database"
import { Audit } from "@argos/core/audit"
import { FindingUpserted } from "@argos/core/security"
import { FindingTable } from "@argos/core/security/sql"
import { SessionSchema } from "@argos/core/session/schema"
import { updateFindingStatus, type FindingLifecycleStatus } from "@argos/core/security/retest"
import { eq } from "drizzle-orm"
import { Effect, Schema } from "effect"
import { EventBridge } from "@/event-bridge"
import { Session } from "@/session/session"
import { SessionID } from "../session/schema"
import * as Tool from "./tool"
import DESCRIPTION from "./finding-status.txt"

const id = "finding_status"

/** Profundidad máxima al subir por `parentID`; corta ciclos si la BD quedó inconsistente. */
const MAX_ANCESTRY_DEPTH = 32

export const Parameters = Schema.Struct({
  findingID: Schema.String.annotate({
    description: "El ID exacto del hallazgo a actualizar, tal como te lo pasó el operador. No lo inventes.",
  }),
  status: Schema.Literals([
    "open",
    "in-progress",
    "remediated",
    "verified",
    "false-positive",
    "accepted-risk",
  ]).annotate({
    description:
      "El veredicto. Usá 'verified' SOLO si comprobaste con evidencia concreta que la vulnerabilidad ya no reproduce; si no pudiste comprobarlo, usá 'in-progress'.",
  }),
  rationale: Schema.String.annotate({
    description: "La evidencia concreta detrás del veredicto, en 1-3 frases: qué comprobaste, cómo, y qué observaste.",
  }),
})

type Metadata = {
  findingID: string
  previousStatus?: string
  newStatus: string
  title?: string
}

export const FindingStatusTool = Tool.define<
  typeof Parameters,
  Metadata,
  Database.Service | Session.Service | EventBridge.Service | Audit.Service
>(
  id,
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const audit = yield* Audit.Service
    const sessions = yield* Session.Service
    const events = yield* EventBridge.Service

    /**
     * Los hallazgos del panel se agregan por familia de sesión (la raíz y todos
     * sus descendientes), porque un subagente los escribe en su propia sesión
     * hija. El permiso de escritura tiene que seguir ese mismo alcance: sin esto
     * un `findingID` alucinado podría pisar el hallazgo de otro proyecto.
     */
    const familyIds = Effect.fn("FindingStatusTool.familyIds")(function* (sessionID: SessionID) {
      let root = sessionID
      for (let depth = 0; depth < MAX_ANCESTRY_DEPTH; depth++) {
        const info = yield* sessions.get(root).pipe(Effect.catchCause(() => Effect.succeed(undefined)))
        if (!info?.parentID) break
        root = info.parentID
      }

      const ids = new Set<string>([root])
      const queue: SessionID[] = [root]
      while (queue.length) {
        const current = queue.shift()!
        const kids = yield* sessions.children(current).pipe(Effect.catchCause(() => Effect.succeed([])))
        for (const kid of kids) {
          if (ids.has(kid.id)) continue
          ids.add(kid.id)
          queue.push(kid.id)
        }
      }
      return ids
    })

    const run = Effect.fn("FindingStatusTool.execute")(function* (
      params: Schema.Schema.Type<typeof Parameters>,
      ctx: Tool.Context<Metadata>,
    ) {
      const finding = yield* db
        .select({
          id: FindingTable.id,
          session_id: FindingTable.session_id,
          project_id: FindingTable.project_id,
          fingerprint: FindingTable.fingerprint,
          title: FindingTable.title,
          status: FindingTable.status,
        })
        .from(FindingTable)
        .where(eq(FindingTable.id, params.findingID))
        .get()
        .pipe(Effect.orDie)

      if (!finding) {
        return yield* Effect.fail(
          new Error(
            `No existe un hallazgo con id "${params.findingID}". Verificá el ID que te pasó el operador; no lo inventes.`,
          ),
        )
      }

      const allowed = yield* familyIds(ctx.sessionID)
      if (!allowed.has(finding.session_id)) {
        return yield* Effect.fail(
          new Error(
            `El hallazgo "${params.findingID}" pertenece a otra sesión de auditoría y no puede modificarse desde acá.`,
          ),
        )
      }

      yield* ctx.ask({
        permission: id,
        patterns: [params.status],
        always: ["*"],
        metadata: {
          findingID: params.findingID,
          title: finding.title,
          status: params.status,
        },
      })

      const previousStatus = finding.status
      const persistedStatus: FindingLifecycleStatus =
        params.status === "verified"
          ? "remediated"
          : params.status === "false-positive" || params.status === "accepted-risk"
            ? "in-progress"
            : params.status
      const rationale = params.rationale.trim().slice(0, 4000)
      const ok = yield* updateFindingStatus(db, params.findingID, persistedStatus, finding.session_id)
      if (!ok) {
        return yield* Effect.fail(new Error(`No se pudo actualizar el hallazgo "${params.findingID}".`))
      }

      yield* audit.append({
        sessionID: SessionSchema.ID.make(finding.session_id),
        projectID: finding.project_id,
        eventType: "finding.validation.agent_report",
        action: "finding.status.agent_reported",
        agent: ctx.agent,
        target: finding.id,
        summary: `El agente reportó ${params.status} para ${finding.title}`,
        payload: {
          findingID: finding.id,
          previousStatus,
          requestedStatus: params.status,
          persistedStatus,
          rationale,
          source: "agent",
        },
      })

      // Mismo evento que emite la ingesta: reengancha compliance, webhooks y
      // el refresco del panel sin duplicar lógica de notificación.
      yield* events
        .publish(FindingUpserted, {
          sessionID: SessionSchema.ID.make(finding.session_id),
          findingID: params.findingID,
          fingerprint: finding.fingerprint,
        })
        .pipe(Effect.ignore)

      const unchanged = previousStatus === persistedStatus
      const provenanceMessage =
        params.status === "verified"
          ? "La conclusión del agente quedó como remediada; se requiere verificación independiente antes de marcarla como verificada."
          : params.status === "false-positive" || params.status === "accepted-risk"
            ? `La recomendación del agente (${params.status}) quedó pendiente de revisión humana y el hallazgo continúa en progreso.`
            : `El estado se registró como "${persistedStatus}".`
      return {
        title: `${finding.title} → ${persistedStatus}`,
        output: [
          unchanged
            ? `El hallazgo "${finding.title}" ya estaba en estado "${persistedStatus}"; se confirmó sin cambios.`
            : `Hallazgo "${finding.title}" actualizado de "${previousStatus}" a "${persistedStatus}".`,
          provenanceMessage,
          `Justificación registrada: ${rationale}`,
        ].join("\n"),
        metadata: {
          findingID: params.findingID,
          previousStatus,
          newStatus: persistedStatus,
          title: finding.title,
        },
      }
    })

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context<Metadata>) =>
        run(params, ctx).pipe(Effect.orDie),
    } satisfies Tool.DefWithoutID<typeof Parameters, Metadata>
  }),
)
