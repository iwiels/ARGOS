import { Schema } from "effect"

export class InvalidRequestError extends Schema.TaggedErrorClass<InvalidRequestError>()(
  "InvalidRequestError",
  {
    message: Schema.String,
    kind: Schema.optional(Schema.String),
    field: Schema.optional(Schema.String),
  },
  { httpApiStatus: 400 },
) {}

export class UnauthorizedError extends Schema.TaggedErrorClass<UnauthorizedError>()(
  "UnauthorizedError",
  { message: Schema.String },
  { httpApiStatus: 401 },
) {}

export class ConflictError extends Schema.TaggedErrorClass<ConflictError>()(
  "ConflictError",
  {
    message: Schema.String,
    resource: Schema.optional(Schema.String),
  },
  { httpApiStatus: 409 },
) {}

export class ServiceUnavailableError extends Schema.TaggedErrorClass<ServiceUnavailableError>()(
  "ServiceUnavailableError",
  {
    message: Schema.String,
    service: Schema.optional(Schema.String),
  },
  { httpApiStatus: 503 },
) {}

export class UnknownError extends Schema.TaggedErrorClass<UnknownError>()(
  "UnknownError",
  {
    message: Schema.String,
    ref: Schema.optional(Schema.String),
  },
  { httpApiStatus: 500 },
) {}

export class ProviderNotFoundError extends Schema.TaggedErrorClass<ProviderNotFoundError>()(
  "ProviderNotFoundError",
  {
    providerID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class SessionNotFoundError extends Schema.TaggedErrorClass<SessionNotFoundError>()(
  "SessionNotFoundError",
  {
    sessionID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class SessionRunNotFoundError extends Schema.TaggedErrorClass<SessionRunNotFoundError>()(
  "SessionRunNotFoundError",
  {
    sessionID: Schema.String,
    runID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class SecurityFindingNotFoundError extends Schema.TaggedErrorClass<SecurityFindingNotFoundError>()(
  "SecurityFindingNotFoundError",
  {
    findingID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class SecurityFindingCaseNotFoundError extends Schema.TaggedErrorClass<SecurityFindingCaseNotFoundError>()(
  "SecurityFindingCaseNotFoundError",
  {
    caseID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class SecurityFindingCaseError extends Schema.TaggedErrorClass<SecurityFindingCaseError>()(
  "SecurityFindingCaseError",
  {
    code: Schema.Literals(["invalid_status", "expiry_required", "reason_required", "same_case", "invalid_selection"]),
    message: Schema.String,
  },
  { httpApiStatus: 400 },
) {}

export class SecurityFindingCaseConflictError extends Schema.TaggedErrorClass<SecurityFindingCaseConflictError>()(
  "SecurityFindingCaseConflictError",
  {
    code: Schema.Literals(["case_not_active", "operation_not_reversible", "dependent_operation"]),
    message: Schema.String,
  },
  { httpApiStatus: 409 },
) {}

export class SecurityFindingImportError extends Schema.TaggedErrorClass<SecurityFindingImportError>()(
  "SecurityFindingImportError",
  {
    code: Schema.Literals(["unsupported_format", "size_limit", "invalid_document", "result_limit", "empty_import"]),
    line: Schema.optional(Schema.Number),
    message: Schema.String,
  },
  { httpApiStatus: 400 },
) {}

export class InvalidCursorError extends Schema.TaggedErrorClass<InvalidCursorError>()(
  "InvalidCursorError",
  { message: Schema.String },
  { httpApiStatus: 400 },
) {}

export class PermissionNotFoundError extends Schema.TaggedErrorClass<PermissionNotFoundError>()(
  "PermissionNotFoundError",
  {
    requestID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}

export class QuestionNotFoundError extends Schema.TaggedErrorClass<QuestionNotFoundError>()(
  "QuestionNotFoundError",
  {
    requestID: Schema.String,
    message: Schema.String,
  },
  { httpApiStatus: 404 },
) {}
