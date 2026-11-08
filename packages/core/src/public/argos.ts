export * as Argos from "./argos"
export * as OpenCode from "./argos"
export * as ScopeService from "../security/scope-service"

import { Context, Effect, Layer } from "effect"
import { Audit } from "../audit"
import { Catalog } from "../catalog"
import { Database } from "../database/database"
import { EventV2 } from "../event"
import { LocationServiceMap } from "../location-layer"
import { PluginBoot } from "../plugin/boot"
import { ProjectV2 } from "../project"
import { SessionV2 } from "../session"
import * as SessionExecutionLocal from "../session/execution/local"
import { SessionProjector } from "../session/projector"
import { SessionStore } from "../session/store"
import { ApplicationTools } from "../tool/application-tools"
import {
  exportAll,
  exportDocument,
  exportSessions,
  loadReportDocument,
  type ExportFormat,
  type ExportOptions,
} from "../security/export"
import { renderReportPdf as renderReportPdfDocument, type PdfRenderer } from "../security/pdf"
import { Session } from "./session"
import { Tool } from "./tool"

export interface Interface {
  readonly sessions: Session.Interface
  readonly tools: Tool.Interface
}

/** Intentional public native API for Effect applications embedding Argos. */
export class Service extends Context.Service<Service, Interface>()("@argos/public/Argos") {}

class SessionModelValidation extends Context.Service<
  SessionModelValidation,
  {
    readonly validate: (
      input: Session.SwitchModelInput & { readonly location: Session.Info["location"] },
    ) => Effect.Effect<void, Session.ModelUnavailableError | Session.VariantUnavailableError>
  }
>()("@argos/public/Argos/SessionModelValidation") {}

const LocationServicesLayer = LocationServiceMap.layer
const SessionModelValidationLayer = Layer.effect(
  SessionModelValidation,
  Effect.gen(function* () {
    const locations = yield* LocationServiceMap
    return SessionModelValidation.of({
      validate: Effect.fn("Argos.sessions.validateModel")(function* (input) {
        yield* Effect.gen(function* () {
          yield* (yield* PluginBoot.Service).wait()
          const catalog = yield* Catalog.Service
          const model = (yield* catalog.model.available()).find(
            (model) => model.providerID === input.model.providerID && model.id === input.model.id,
          )
          if (!model)
            return yield* new Session.ModelUnavailableError({
              providerID: input.model.providerID,
              modelID: input.model.id,
            })
          if (
            input.model.variant !== undefined &&
            input.model.variant !== "default" &&
            !model.variants.some((variant) => variant.id === input.model.variant)
          )
            return yield* new Session.VariantUnavailableError({
              providerID: input.model.providerID,
              modelID: input.model.id,
              variant: input.model.variant,
            })
        }).pipe(Effect.provide(locations.get(input.location)))
      }),
    })
  }),
)

const SessionsLayer = (database: Layer.Layer<Database.Service>) =>
  Layer.merge(
    SessionV2.layer.pipe(
      Layer.provide(SessionProjector.layer),
      Layer.provide(SessionExecutionLocal.layer),
      Layer.provide(SessionStore.layer),
      Layer.provide(EventV2.layer),
      // La parada de emergencia deja su evento en la cadena de auditoría, así
      // que el servicio de auditoría tiene que estar disponible en el scope.
      Layer.provide(Audit.layer),
      Layer.provide(database),
      Layer.provide(ProjectV2.defaultLayer),
      Layer.orDie,
    ),
    SessionModelValidationLayer,
  ).pipe(Layer.provide(LocationServicesLayer))

const apiLayer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const sessions = yield* SessionV2.Service
    const tools = yield* ApplicationTools.Service
    const validation = yield* SessionModelValidation
    return Service.of({
      tools: { register: tools.register },
      sessions: {
        create: (input) =>
          sessions.create({
            id: input.id,
            agent: input.agent,
            model: input.model,
            location: input.location,
          }),
        get: sessions.get,
        list: sessions.list,
        switchModel: Effect.fn("Argos.sessions.switchModel")(function* (input) {
          const session = yield* sessions.get(input.sessionID)
          yield* validation.validate({ ...input, location: session.location })
          yield* sessions.switchModel(input)
        }),
        interrupt: sessions.interrupt,
        prompt: (input) =>
          sessions.prompt({
            id: input.id,
            sessionID: input.sessionID,
            prompt: input.prompt,
            delivery: input.delivery,
          }),
        messages: (input) =>
          sessions.messages({
            sessionID: input.sessionID,
            limit: input.limit,
            order: input.order,
            cursor: input.cursor,
          }),
        message: (input) => sessions.message({ sessionID: input.sessionID, messageID: input.messageID }),
        context: sessions.context,
        events: (input) => sessions.events({ sessionID: input.sessionID, after: input.after }),
      },
    })
  }),
)

export const layer = apiLayer.pipe(
  Layer.provide(Layer.merge(ApplicationTools.layer, SessionsLayer(Database.defaultLayer))),
)

/**
 * Same API surface, but with caller-owned persistence: tests use
 * `Database.layerFromPath(":memory:")` so suites never touch the real user
 * database; embeddings can select application-owned storage.
 */
export const layerWithStorage = (database: Layer.Layer<Database.Service>) =>
  apiLayer.pipe(Layer.provide(Layer.merge(ApplicationTools.layer, SessionsLayer(database))))

export interface RenderReportPdfOptions {
  /** Metadata del cliente y del engagement (la resuelve la capa que la posee). */
  meta?: ExportOptions["meta"]
  /** Momento de emisión — inyectado para que el artefacto sea determinista. */
  now?: Date
  /** Renderer del PDF (inyectable para testear el pipeline con un stub). */
  renderer?: PdfRenderer
}

/**
 * Renderiza el informe de auditoría de una sesión a PDF (server-side).
 *
 * Devuelve los bytes del PDF, el sha256 del artefacto y el sha256 del
 * contenido del informe. El hash del contenido es el que va impreso en la
 * portada y en el pie de cada página: es lo que permite verificar que el PDF
 * firmado corresponde a los hallazgos de la sesión.
 */
export const renderReportPdf = Effect.fn("Argos.reports.renderPdf")(function* (
  sessionID: string,
  opts?: RenderReportPdfOptions,
) {
  const document = yield* loadReportDocument(sessionID, { now: opts?.now, meta: opts?.meta })
  return yield* Effect.promise(() => renderReportPdfDocument(document, { renderer: opts?.renderer }))
})

/**
 * Igual que `renderReportPdf`, pero consolidando varias sesiones del mismo
 * workspace (el informe consolidado de la página de reportes).
 */
export const renderWorkspaceReportPdf = Effect.fn("Argos.reports.renderWorkspacePdf")(function* (
  sessionIDs: string[],
  opts?: RenderReportPdfOptions,
) {
  const document = yield* loadReportDocument(sessionIDs, { now: opts?.now, meta: opts?.meta })
  return yield* Effect.promise(() => renderReportPdfDocument(document, { renderer: opts?.renderer }))
})

/**
 * Exporta la auditoría de una sesión en cualquiera de los formatos
 * soportados (SARIF, DefectDojo, JUnit, HTML, SBOM, HAR, CSV, Markdown, PDF).
 */
export const exportReport = Effect.fn("Argos.reports.export")(function* (
  sessionID: string,
  format: ExportFormat,
  opts?: ExportOptions,
) {
  return yield* exportAll(sessionID, format, opts)
})

/** Exporta el informe consolidado de varias sesiones del mismo workspace. */
export const exportWorkspaceReport = Effect.fn("Argos.reports.exportWorkspace")(function* (
  sessionIDs: string[],
  format: ExportFormat,
  opts?: ExportOptions,
) {
  return yield* exportSessions(sessionIDs, format, opts)
})
