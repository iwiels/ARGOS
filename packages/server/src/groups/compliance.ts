import { SessionV2 } from "@argos/core/session"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { SessionNotFoundError } from "../errors"
import { SessionLocationMiddleware } from "../middleware/session-location"

const NullableString = Schema.NullOr(Schema.String)
const NullableNumber = Schema.NullOr(Schema.Number)

const ControlStatusSchema = Schema.Union([
  Schema.Literal("deficient"),
  Schema.Literal("partial"),
  Schema.Literal("compliant"),
  Schema.Literal("unassessed"),
])

export const ComplianceEvidenceDTO = Schema.Struct({
  findingID: Schema.String,
  title: Schema.String,
  severity: Schema.String,
  status: Schema.String,
  tool: NullableString,
  fromElasticsearch: Schema.Boolean,
  timeUpdated: Schema.Number,
  cwe: NullableString,
  derivedFrom: NullableString,
  confidence: NullableString,
}).annotate({ identifier: "ComplianceEvidence" })

export interface ComplianceEvidence {
  readonly findingID: string
  readonly title: string
  readonly severity: string
  readonly status: string
  readonly tool: string | null
  readonly fromElasticsearch: boolean
  readonly timeUpdated: number
  readonly cwe: string | null
  readonly derivedFrom: string | null
  readonly confidence: string | null
}

/** Hallazgo resumido dentro de una entrada de evidencia auditable. */
export const ControlEvidenceFindingDTO = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  severity: Schema.String,
  cwe: NullableString,
  sourceTool: NullableString,
  confidence: NullableString,
}).annotate({ identifier: "ControlEvidenceFinding" })

/** Regla que derivó el control + los hallazgos que la activaron. */
export const ControlEvidenceDTO = Schema.Struct({
  derivedFrom: Schema.String,
  findings: Schema.Array(ControlEvidenceFindingDTO),
  confidence: Schema.String,
}).annotate({ identifier: "ControlEvidence" })

export type ControlEvidence = Schema.Schema.Type<typeof ControlEvidenceDTO>

export interface ComplianceNode {
  id: string
  title: string
  level: string
  status: string
  findingCount: number
  evidence: readonly ComplianceEvidence[]
  derivation: readonly ControlEvidence[]
  confidence: string
  children: readonly ComplianceNode[]
}

export const ComplianceNodeDTO: Schema.Schema<ComplianceNode> = Schema.suspend(
  (): Schema.Schema<ComplianceNode> =>
    Schema.Struct({
      id: Schema.String,
      title: Schema.String,
      level: Schema.String,
      status: Schema.String,
      findingCount: Schema.Number,
      evidence: Schema.Array(ComplianceEvidenceDTO),
      derivation: Schema.Array(ControlEvidenceDTO),
      confidence: Schema.String,
      children: Schema.Array(ComplianceNodeDTO),
    }),
)

export const ComplianceFrameworkDTO = Schema.Struct({
  framework: Schema.String,
  title: Schema.String,
  version: Schema.String,
  refreshedAt: NullableNumber,
  tree: ComplianceNodeDTO,
}).annotate({ identifier: "ComplianceFramework" })

export const ComplianceStatusDTO = Schema.Struct({
  frameworks: Schema.Array(ComplianceFrameworkDTO),
  catalogCount: Schema.Number,
  mappingCount: Schema.Number,
  lastRefreshed: NullableNumber,
}).annotate({ identifier: "ComplianceStatus" })

const ComplianceSourceDTO = Schema.Struct({
  key: Schema.String,
  url: Schema.String,
  license: Schema.String,
  ok: Schema.Boolean,
  error: NullableString,
  controls: Schema.NullOr(Schema.Number),
  mappings: Schema.NullOr(Schema.Number),
})

export const ComplianceRefreshDTO = Schema.Struct({
  refreshedAt: Schema.Number,
  sources: Schema.Array(ComplianceSourceDTO),
  catalogControlCount: Schema.Number,
  mappingCount: Schema.Number,
}).annotate({ identifier: "ComplianceRefresh" })

export const ComplianceDriftEventDTO = Schema.Struct({
  id: Schema.Number,
  projectID: Schema.String,
  framework: Schema.String,
  controlId: Schema.String,
  statusFrom: ControlStatusSchema,
  statusTo: ControlStatusSchema,
  timeRecorded: Schema.Number,
}).annotate({ identifier: "ComplianceDriftEvent" })

export const ComplianceHistoryDTO = Schema.Struct({
  projectID: Schema.String,
  framework: Schema.String,
  controlId: Schema.String,
  transitions: Schema.Array(
    Schema.Struct({
      id: Schema.Number,
      statusFrom: ControlStatusSchema,
      statusTo: ControlStatusSchema,
      timeRecorded: Schema.Number,
    }),
  ),
}).annotate({ identifier: "ComplianceHistory" })

export const ComplianceFrameworkSummaryDTO = Schema.Struct({
  framework: Schema.String,
  title: Schema.String,
  version: Schema.String,
  totalControls: Schema.Number,
  counts: Schema.Struct({
    deficient: Schema.Number,
    partial: Schema.Number,
    compliant: Schema.Number,
    unassessed: Schema.Number,
  }),
  score: Schema.Number,
  /** Confianza agregada del framework (la más débil entre sus hojas). */
  confidence: Schema.String,
}).annotate({ identifier: "ComplianceFrameworkSummary" })

export const ComplianceSummaryDTO = Schema.Struct({
  generatedAt: Schema.Number,
  projectCount: Schema.Number,
  frameworks: Schema.Array(ComplianceFrameworkSummaryDTO),
  lastUpdated: NullableNumber,
}).annotate({ identifier: "ComplianceSummary" })

export const ComplianceGroup = HttpApiGroup.make("server.compliance")
  .add(
    HttpApiEndpoint.get("compliance.status", "/api/session/:sessionID/compliance/status", {
      params: { sessionID: SessionV2.ID },
      success: ComplianceStatusDTO,
      error: [SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "compliance.status",
          summary: "Compliance status per session",
          description: "Control status derived from findings against NIST CSF 2.0 and ISO 27001:2022.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("compliance.refresh", "/api/compliance/refresh", {
      success: ComplianceRefreshDTO,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "compliance.refresh",
        summary: "Refresh compliance catalogs",
        description: "Re-download NIST CSF 2.0 and ISO 27001:2022 catalogs from the configured public sources and re-derive project statuses.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.get("compliance.summary", "/api/compliance/summary", {
      success: ComplianceSummaryDTO,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "compliance.summary",
        summary: "Global compliance summary (CCM)",
        description: "Continuous compliance monitoring: aggregated control status across all projects, per framework, with compliance score.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.get("compliance.drift", "/api/compliance/drift", {
      query: Schema.Struct({ limit: Schema.optional(Schema.String) }),
      success: Schema.Array(ComplianceDriftEventDTO),
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "compliance.drift",
        summary: "Recent compliance drift events",
        description: "Most recent control status transitions across all projects (or per project with the projectID query param).",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.get("compliance.history", "/api/session/:sessionID/compliance/history", {
      params: { sessionID: SessionV2.ID },
      query: Schema.Struct({
        framework: Schema.String,
        control: Schema.String,
      }),
      success: ComplianceHistoryDTO,
      error: [SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "compliance.history",
          summary: "Control status transition history",
          description: "Drift history for a single control in the session's project.",
        }),
      ),
  )
  .annotateMerge(OpenApi.annotations({ title: "compliance", description: "Compliance monitoring routes." }))
