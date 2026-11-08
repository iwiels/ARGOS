import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { SessionID } from "@/session/schema"
import { Authorization } from "../middleware/authorization"
import { InstanceContextMiddleware } from "../middleware/instance-context"
import { WorkspaceRoutingMiddleware, WorkspaceRoutingQuery } from "../middleware/workspace-routing"
import { described } from "./metadata"

export const ReportExportFormatSchema = Schema.Literals([
  "pdf",
  "sarif",
  "defectdojo",
  "junit",
  "html",
  "sbom",
  "har",
  "csv",
  "markdown",
])

/**
 * Metadata del entregable. La resuelve la capa que la posee (la app la
 * persiste por workspace) y se pasa tal cual: el backend no redefine la
 * razón social, el logo, el auditor ni la clasificación del cliente.
 */
export const ReportMetaPayload = Schema.Struct({
  title: Schema.optional(Schema.String),
  clientName: Schema.optional(Schema.String),
  clientLegalName: Schema.optional(Schema.String),
  clientLogoDataUrl: Schema.optional(Schema.String),
  scope: Schema.optional(Schema.String),
  classification: Schema.optional(Schema.String),
  leadAuditor: Schema.optional(Schema.String),
  methodology: Schema.optional(Schema.String),
  engagement: Schema.optional(Schema.String),
  target: Schema.optional(Schema.String),
})

export const ReportExportPayload = Schema.Struct({
  format: ReportExportFormatSchema,
  meta: Schema.optional(ReportMetaPayload),
  /**
   * Sesiones a consolidar en el informe. Si no se envía, se exporta la sesión
   * de la ruta; la página de reportes consolida todas las sesiones del
   * workspace.
   */
  sessionIDs: Schema.optional(Schema.Array(Schema.String)),
})

export const ReportExportResponse = Schema.Struct({
  format: Schema.String,
  filename: Schema.String,
  mimeType: Schema.String,
  /** Contenido del artefacto en base64 (el PDF es binario). */
  contentBase64: Schema.String,
  /** sha256 del artefacto generado. */
  sha256: Schema.String,
  /** sha256 del contenido del informe. */
  contentHash: Schema.String,
})

export const ReportPaths = {
  export: "/session/:sessionID/report/export",
} as const

export const ReportApi = HttpApi.make("report")
  .add(
    HttpApiGroup.make("report")
      .add(
        HttpApiEndpoint.post("export", ReportPaths.export, {
          params: { sessionID: SessionID },
          query: WorkspaceRoutingQuery,
          payload: ReportExportPayload,
          success: described(
            ReportExportResponse,
            "Artefacto del informe de auditoría en el formato pedido, con su hash de artefacto y el hash de contenido.",
          ),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "report.export",
            summary: "Export the audit report",
            description:
              "Renders the persisted findings of a session into a professional deliverable: PDF (native, with metadata and cover), SARIF 2.1.0, DefectDojo, JUnit XML, self-contained HTML, CycloneDX SBOM, HAR, CSV or Markdown. The response carries the artifact in base64 plus its sha256 and the sha256 of the report content.",
          }),
        ),
      )
      .annotateMerge(
        OpenApi.annotations({
          title: "report",
          description: "Audit report rendering and professional export formats.",
        }),
      )
      .middleware(InstanceContextMiddleware)
      .middleware(WorkspaceRoutingMiddleware)
      .middleware(Authorization),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "opencode experimental HttpApi",
      version: "0.0.1",
      description: "Experimental HttpApi surface for selected instance routes.",
    }),
  )
