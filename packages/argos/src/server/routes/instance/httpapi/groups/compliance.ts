import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { NonNegativeInt } from "@argos/core/schema"
import { SessionID } from "@/session/schema"
import { Authorization } from "../middleware/authorization"
import { InstanceContextMiddleware } from "../middleware/instance-context"
import { WorkspaceRoutingMiddleware, WorkspaceRoutingQuery } from "../middleware/workspace-routing"
import { described } from "./metadata"

export const ComplianceEvidenceSchema = Schema.Struct({
  findingID: Schema.String,
  title: Schema.String,
  severity: Schema.String,
  status: Schema.String,
  tool: Schema.optional(Schema.String),
  fromElasticsearch: Schema.Boolean,
  timeUpdated: NonNegativeInt,
  /** CWE del hallazgo: el auditor necesita verlo junto al control. */
  cwe: Schema.optional(Schema.String),
  /** Regla que derivó el control a partir de este hallazgo. */
  derivedFrom: Schema.optional(Schema.String),
  /** Confianza de la derivación (`high`/`medium`/`low`). */
  confidence: Schema.optional(Schema.String),
})

/** Hallazgo resumido dentro de una entrada de evidencia auditable. */
export const ControlEvidenceFindingSchema = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  severity: Schema.String,
  cwe: Schema.optional(Schema.String),
  sourceTool: Schema.optional(Schema.String),
  confidence: Schema.optional(Schema.String),
})

/** Regla que derivó el control + los hallazgos que la activaron. */
export const ControlEvidenceSchema = Schema.Struct({
  derivedFrom: Schema.String,
  findings: Schema.Array(ControlEvidenceFindingSchema),
  confidence: Schema.String,
})

export interface ComplianceNodeEncoded {
  readonly id: string
  readonly title: string
  readonly level: string
  readonly status: string
  readonly findingCount: number
  readonly evidence: ReadonlyArray<typeof ComplianceEvidenceSchema.Type>
  readonly derivation: ReadonlyArray<typeof ControlEvidenceSchema.Type>
  readonly confidence: string
  readonly children: ReadonlyArray<ComplianceNodeEncoded>
}

export const ComplianceNodeSchema = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  level: Schema.String,
  status: Schema.String,
  findingCount: NonNegativeInt,
  evidence: Schema.Array(ComplianceEvidenceSchema),
  derivation: Schema.Array(ControlEvidenceSchema),
  confidence: Schema.String,
  get children(): Schema.Codec<ReadonlyArray<ComplianceNodeEncoded>> {
    return Schema.Array(Schema.suspend((): Schema.Codec<ComplianceNodeEncoded> => ComplianceNodeSchema))
  },
})

export const ComplianceFrameworkSchema = Schema.Struct({
  framework: Schema.String,
  title: Schema.String,
  version: Schema.String,
  refreshedAt: Schema.optional(NonNegativeInt),
  tree: ComplianceNodeSchema,
})

export const ComplianceStatusResponse = Schema.Struct({
  frameworks: Schema.Array(ComplianceFrameworkSchema),
  catalogCount: NonNegativeInt,
  mappingCount: NonNegativeInt,
  lastRefreshed: Schema.optional(NonNegativeInt),
})

export const ComplianceRefreshSourceSchema = Schema.Struct({
  key: Schema.String,
  url: Schema.String,
  license: Schema.String,
  ok: Schema.Boolean,
  error: Schema.optional(Schema.String),
  controls: Schema.optional(NonNegativeInt),
  mappings: Schema.optional(NonNegativeInt),
})

export const ComplianceRefreshResponse = Schema.Struct({
  refreshedAt: NonNegativeInt,
  sources: Schema.Array(ComplianceRefreshSourceSchema),
  catalogControlCount: NonNegativeInt,
  mappingCount: NonNegativeInt,
})

export const CompliancePaths = {
  status: "/session/:sessionID/compliance/status",
  refresh: "/compliance/refresh",
} as const

export const ComplianceApi = HttpApi.make("compliance")
  .add(
    HttpApiGroup.make("compliance")
      .add(
        HttpApiEndpoint.get("status", CompliancePaths.status, {
          params: { sessionID: SessionID },
          query: WorkspaceRoutingQuery,
          success: described(ComplianceStatusResponse, "Compliance status for the Session's project"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "compliance.status",
            summary: "Get compliance status",
            description:
              "Nested control tree (NIST CSF 2.0 / ISO 27001:2022) merged with the derived status for the Session's project.",
          }),
        ),
        HttpApiEndpoint.post("refresh", CompliancePaths.refresh, {
          query: WorkspaceRoutingQuery,
          success: described(ComplianceRefreshResponse, "Compliance catalog refresh summary"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "compliance.refresh",
            summary: "Refresh the compliance catalog",
            description: "Re-downloads the NIST CSF 2.0 / ISO 27001:2022 catalog and crosswalk from public sources.",
          }),
        ),
      )
      .annotateMerge(
        OpenApi.annotations({
          title: "compliance",
          description: "NIST CSF 2.0 / ISO 27001:2022 compliance status and catalog sync.",
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
