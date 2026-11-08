import { SessionV2 } from "@argos/core/session"
import { FINDING_CASE_STATUSES, FINDING_IMPORT_FORMATS, MAX_FINDING_IMPORT_BYTES } from "@argos/core/security"
import { Schema, SchemaGetter } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import {
  SecurityFindingCaseError,
  SecurityFindingCaseConflictError,
  SecurityFindingCaseNotFoundError,
  SecurityFindingImportError,
  SecurityFindingNotFoundError,
  SessionNotFoundError,
} from "../errors"
import { SessionLocationMiddleware } from "../middleware/session-location"

const NullableString = Schema.NullOr(Schema.String)

const FeedbackVerdictSchema = Schema.Literals(["false-positive", "true-positive", "accepted-risk"])
const FeedbackActorSchema = Schema.Literals(["human", "agent"])
const FindingCaseStatusSchema = Schema.Literals(FINDING_CASE_STATUSES)

export const SecurityFindingCaseDTO = Schema.Struct({
  id: Schema.String,
  status: FindingCaseStatusSchema,
  statusReason: NullableString,
  owner: NullableString,
  dueAt: Schema.NullOr(Schema.Number),
  acceptedRiskUntil: Schema.NullOr(Schema.Number),
  findingCount: Schema.Number,
  sessionCount: Schema.Number,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
}).annotate({ identifier: "SecurityFindingCase" })

export const SecurityFindingCaseTransitionDTO = Schema.Struct({
  id: Schema.String,
  fromStatus: Schema.NullOr(FindingCaseStatusSchema),
  toStatus: FindingCaseStatusSchema,
  reason: NullableString,
  actor: Schema.Literals(["human", "system"]),
  sessionID: Schema.NullOr(SessionV2.ID),
  createdAt: Schema.Number,
}).annotate({ identifier: "SecurityFindingCaseTransition" })

export const SecurityFindingCaseStatusInput = Schema.Struct({
  status: FindingCaseStatusSchema,
  reason: Schema.optional(Schema.String.check(Schema.isMaxLength(2000))),
  acceptedRiskUntil: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isGreaterThan(0))),
}).annotate({ identifier: "SecurityFindingCaseStatusInput" })

export const SecurityFindingCasesQuery = Schema.Struct({
  limit: Schema.optional(
    Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(200)),
  ),
  offset: Schema.optional(Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
}).annotate({ identifier: "SecurityFindingCasesQuery" })

export const SecurityFindingCaseHistoryQuery = Schema.Struct({
  limit: Schema.optional(
    Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(100)),
  ),
}).annotate({ identifier: "SecurityFindingCaseHistoryQuery" })

export const SecurityFindingCaseOperationHistoryQuery = Schema.Struct({
  limit: Schema.optional(
    Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(100)),
  ),
}).annotate({ identifier: "SecurityFindingCaseOperationHistoryQuery" })

const CaseOperationReason = Schema.String.check(Schema.isPattern(/\S/), Schema.isMaxLength(2000))

export const SecurityFindingCaseMergeInput = Schema.Struct({
  targetCaseID: Schema.String,
  reason: CaseOperationReason,
}).annotate({ identifier: "SecurityFindingCaseMergeInput" })

export const SecurityFindingCaseSplitInput = Schema.Struct({
  findingIDs: Schema.Array(Schema.String).check(Schema.isMinLength(1), Schema.isMaxLength(500)),
  reason: CaseOperationReason,
}).annotate({ identifier: "SecurityFindingCaseSplitInput" })

export const SecurityFindingCaseReverseInput = Schema.Struct({
  reason: CaseOperationReason,
}).annotate({ identifier: "SecurityFindingCaseReverseInput" })

const FindingCaseActorSchema = Schema.Literals(["human", "system"])

export const SecurityFindingCaseOperationDTO = Schema.Struct({
  id: Schema.String,
  kind: Schema.Literals(["merge", "split"]),
  sourceCaseID: Schema.String,
  targetCaseID: Schema.String,
  reason: Schema.String,
  actor: FindingCaseActorSchema,
  sessionID: Schema.NullOr(SessionV2.ID),
  findingIDs: Schema.Array(Schema.String),
  createdAt: Schema.Number,
  reversedAt: Schema.NullOr(Schema.Number),
  reversedReason: NullableString,
  reversedBy: Schema.NullOr(FindingCaseActorSchema),
}).annotate({ identifier: "SecurityFindingCaseOperation" })

export const SecurityFindingDTO = Schema.Struct({
  id: Schema.String,
  sessionID: SessionV2.ID,
  projectID: Schema.String,
  caseID: NullableString,
  fingerprint: Schema.String,
  title: Schema.String,
  severity: Schema.String,
  status: Schema.String,
  source: Schema.String,
  sourceTool: NullableString,
  agent: NullableString,
  target: NullableString,
  cwe: NullableString,
  vector: NullableString,
  evidence: Schema.Record(Schema.String, Schema.Unknown),
  remediation: NullableString,
  tags: Schema.Array(Schema.String),
  attackTechniques: Schema.optional(
    Schema.Array(
      Schema.Struct({
        id: Schema.String,
        name: Schema.String,
        tactics: Schema.Array(Schema.String),
        reason: Schema.String,
      }),
    ),
  ),
  iocs: Schema.optional(
    Schema.Array(
      Schema.Struct({
        type: Schema.String,
        value: Schema.String,
        reputation: Schema.optional(
          Schema.Array(
            Schema.Struct({
              source: Schema.String,
              verdict: Schema.String,
              score: Schema.Number,
              detail: Schema.String,
              checkedAt: Schema.Number,
            }),
          ),
        ),
      }),
    ),
  ),
  enrichedAt: Schema.optional(Schema.Number),
  // Triage registrado en este engagement, si lo hay. La lista lo trae para
  // que la UI pinte el veredicto sin un request extra por hallazgo.
  feedback: Schema.optional(
    Schema.Struct({
      verdict: FeedbackVerdictSchema,
      reason: NullableString,
      actor: FeedbackActorSchema,
    }),
  ),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
}).annotate({ identifier: "SecurityFinding" })

export const SecurityFeedbackDTO = Schema.Struct({
  findingID: Schema.String,
  verdict: FeedbackVerdictSchema,
  reason: NullableString,
  actor: FeedbackActorSchema,
  ruleID: NullableString,
  sourceTool: NullableString,
  cwe: NullableString,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
}).annotate({ identifier: "SecurityFindingFeedback" })

export const SecurityFeedbackInput = Schema.Struct({
  verdict: FeedbackVerdictSchema,
  reason: Schema.optional(Schema.String.check(Schema.isMaxLength(2000))),
}).annotate({ identifier: "SecurityFindingFeedbackInput" })

const FindingImportFormatSchema = Schema.Literals(FINDING_IMPORT_FORMATS)

export const SecurityFindingImportInput = Schema.Struct({
  format: FindingImportFormatSchema,
  content: Schema.String.check(Schema.isMaxLength(MAX_FINDING_IMPORT_BYTES)),
  importID: Schema.optional(Schema.String.check(Schema.isMaxLength(128))),
}).annotate({ identifier: "SecurityFindingImportInput" })

const ImportedFindingDTO = Schema.Struct({
  id: Schema.String,
  source: Schema.String,
  source_tool: Schema.String,
  rule_id: Schema.optional(Schema.String),
  title: Schema.String,
  severity: Schema.String,
  status: Schema.String,
  confidence: Schema.String,
  cwe: Schema.optional(Schema.String),
  owasp: Schema.optional(Schema.Array(Schema.String)),
  target: Schema.optional(Schema.String),
  vector: Schema.optional(Schema.String),
  evidence: Schema.Record(Schema.String, Schema.Unknown),
  remediation: Schema.optional(Schema.String),
  tags: Schema.Array(Schema.String),
  references: Schema.Array(Schema.String),
})

const FindingImportPreviewDTO = Schema.Struct({
  format: FindingImportFormatSchema,
  parserVersion: Schema.Number,
  contentSha256: Schema.String,
  findings: Schema.Array(ImportedFindingDTO),
  warnings: Schema.Array(Schema.String),
})

const FindingImportPreviewResponse = Schema.Struct({ data: FindingImportPreviewDTO })
const FindingImportResponse = Schema.Struct({
  data: Schema.Struct({
    format: FindingImportFormatSchema,
    parserVersion: Schema.Number,
    contentSha256: Schema.String,
    findings: Schema.Array(ImportedFindingDTO),
    warnings: Schema.Array(Schema.String),
    sourceEventID: Schema.String,
    importedCount: Schema.Number,
  }),
})

export const RuleFeedbackStatsDTO = Schema.Struct({
  ruleId: Schema.String,
  truePositives: Schema.Number,
  falsePositives: Schema.Number,
  acceptedRisk: Schema.Number,
  precision: Schema.Number,
  verdicts: Schema.Number,
}).annotate({ identifier: "RuleFeedbackStats" })

export const SecurityFindingsQuery = Schema.Struct({
  limit: Schema.optional(
    Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1), Schema.isLessThanOrEqualTo(200)),
  ),
  offset: Schema.optional(Schema.NumberFromString.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0))),
  status: Schema.optional(Schema.String),
  severity: Schema.optional(Schema.String),
  // Los falsos positivos marcados en este engagement se ocultan por defecto:
  // siguen en la base y se recuperan con este flag, pero no ensucian la lista.
  includeSuppressed: Schema.optional(
    Schema.Literals(["true", "false"]).pipe(
      Schema.decodeTo(Schema.Boolean, {
        decode: SchemaGetter.transform((value) => value === "true"),
        encode: SchemaGetter.transform((value) => (value ? "true" : "false")),
      }),
    ),
  ),
}).annotate({ identifier: "SecurityFindingsQuery" })

export const SecurityGroup = HttpApiGroup.make("server.security")
  .add(
    HttpApiEndpoint.post("security.findings.import.preview", "/api/session/:sessionID/findings/import/preview", {
      params: { sessionID: SessionV2.ID },
      payload: SecurityFindingImportInput,
      success: FindingImportPreviewResponse,
      error: [SecurityFindingImportError, SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.findings.import.preview",
          summary: "Preview a finding import",
          description: "Parse and validate a scanner report without persisting findings or evidence.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("security.findings.import", "/api/session/:sessionID/findings/import", {
      params: { sessionID: SessionV2.ID },
      payload: SecurityFindingImportInput,
      success: FindingImportResponse,
      error: [SecurityFindingImportError, SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.findings.import",
          summary: "Import scanner findings",
          description:
            "Import a validated scanner report into the session with source provenance and idempotent batch identity.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("security.findings.list", "/api/session/:sessionID/findings", {
      params: { sessionID: SessionV2.ID },
      query: SecurityFindingsQuery,
      success: Schema.Struct({
        data: Schema.Array(SecurityFindingDTO),
        total: Schema.Number,
        limit: Schema.Number,
        offset: Schema.Number,
      }).annotate({ identifier: "SecurityFindingsResponse" }),
      error: [SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.findings.list",
          summary: "List security findings",
          description: "Retrieve persisted security findings for a session.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("security.finding-cases.list", "/api/session/:sessionID/finding-cases", {
      params: { sessionID: SessionV2.ID },
      query: SecurityFindingCasesQuery,
      success: Schema.Struct({
        data: Schema.Array(SecurityFindingCaseDTO),
        total: Schema.Number,
        limit: Schema.Number,
        offset: Schema.Number,
      }).annotate({ identifier: "SecurityFindingCasesResponse" }),
      error: [SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.list",
          summary: "List finding cases for a session",
          description:
            "List project-level cases linked to findings in this session, including cross-session recurrence counts.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("security.finding-cases.status", "/api/session/:sessionID/finding-cases/:caseID/status", {
      params: { sessionID: SessionV2.ID, caseID: Schema.String },
      payload: SecurityFindingCaseStatusInput,
      success: Schema.Struct({ data: SecurityFindingCaseDTO }),
      error: [
        SecurityFindingCaseError,
        SecurityFindingCaseConflictError,
        SecurityFindingCaseNotFoundError,
        SessionNotFoundError,
      ],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.status",
          summary: "Update a finding case",
          description:
            "Update project-level remediation status with a transition history; accepted risk requires an expiry.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("security.finding-cases.history", "/api/session/:sessionID/finding-cases/:caseID/history", {
      params: { sessionID: SessionV2.ID, caseID: Schema.String },
      query: SecurityFindingCaseHistoryQuery,
      success: Schema.Struct({ data: Schema.Array(SecurityFindingCaseTransitionDTO) }),
      error: [SecurityFindingCaseNotFoundError, SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.history",
          summary: "Read finding case history",
          description: "Read status transitions for a case visible from the requested session.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get(
      "security.finding-cases.operations",
      "/api/session/:sessionID/finding-cases/:caseID/operations",
      {
        params: { sessionID: SessionV2.ID, caseID: Schema.String },
        query: SecurityFindingCaseOperationHistoryQuery,
        success: Schema.Struct({ data: Schema.Array(SecurityFindingCaseOperationDTO) }),
        error: [SecurityFindingCaseNotFoundError, SessionNotFoundError],
      },
    )
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.operations",
          summary: "Read case merge and split history",
          description: "Read reversible case operations visible from the requested session.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("security.finding-cases.merge", "/api/session/:sessionID/finding-cases/:caseID/merge", {
      params: { sessionID: SessionV2.ID, caseID: Schema.String },
      payload: SecurityFindingCaseMergeInput,
      success: Schema.Struct({ data: SecurityFindingCaseOperationDTO }),
      error: [
        SecurityFindingCaseError,
        SecurityFindingCaseConflictError,
        SecurityFindingCaseNotFoundError,
        SessionNotFoundError,
      ],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.merge",
          summary: "Merge finding cases",
          description: "Move all findings from one project case into another while recording a reversible operation.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("security.finding-cases.split", "/api/session/:sessionID/finding-cases/:caseID/split", {
      params: { sessionID: SessionV2.ID, caseID: Schema.String },
      payload: SecurityFindingCaseSplitInput,
      success: Schema.Struct({ caseID: Schema.String, operation: SecurityFindingCaseOperationDTO }),
      error: [
        SecurityFindingCaseError,
        SecurityFindingCaseConflictError,
        SecurityFindingCaseNotFoundError,
        SessionNotFoundError,
      ],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.split",
          summary: "Split findings into a separate case",
          description: "Move selected session findings into a new project case and record a reversible operation.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post(
      "security.finding-cases.reverse",
      "/api/session/:sessionID/finding-cases/:caseID/operations/:operationID/reverse",
      {
        params: { sessionID: SessionV2.ID, caseID: Schema.String, operationID: Schema.String },
        payload: SecurityFindingCaseReverseInput,
        success: Schema.Struct({ data: SecurityFindingCaseOperationDTO }),
        error: [
          SecurityFindingCaseError,
          SecurityFindingCaseConflictError,
          SecurityFindingCaseNotFoundError,
          SessionNotFoundError,
        ],
      },
    )
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.finding-cases.reverse",
          summary: "Reverse a case operation",
          description: "Reverse a merge or split with a recorded reason when no later operation depends on it.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("security.findings.get", "/api/session/:sessionID/findings/:findingID", {
      params: { sessionID: SessionV2.ID, findingID: Schema.String },
      success: Schema.Struct({ data: SecurityFindingDTO }),
      error: [SecurityFindingNotFoundError, SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.findings.get",
          summary: "Get a security finding",
          description: "Retrieve one persisted security finding by ID.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("security.findings.feedback", "/api/session/:sessionID/findings/:findingID/feedback", {
      params: { sessionID: SessionV2.ID, findingID: Schema.String },
      payload: SecurityFeedbackInput,
      success: Schema.Struct({ data: SecurityFeedbackDTO }),
      error: [SecurityFindingNotFoundError, SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.findings.feedback",
          summary: "Triage a finding",
          description:
            "Record a human or agent verdict (false positive, true positive, accepted risk) for a finding. Feedback is scoped to the engagement: it never suppresses the same rule in another engagement, it only feeds the rule's historical precision.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("security.feedback.rules", "/api/session/:sessionID/feedback/rules", {
      params: { sessionID: SessionV2.ID },
      success: Schema.Struct({ data: Schema.Array(RuleFeedbackStatsDTO) }),
      error: [SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "security.feedback.rules",
          summary: "Rule precision from triage",
          description:
            "Historical precision per rule across the engagement's project. Context for triage, never an automatic suppression.",
        }),
      ),
  )
  .annotateMerge(OpenApi.annotations({ title: "security", description: "Persisted security finding routes." }))
