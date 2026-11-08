const ARGOS_SESSION_CONTEXT_ARGUMENT = "__argos_session_id"
const ARGOS_RUN_CONTEXT_ARGUMENT = "__argos_run_id"
const ARGOS_OPERATION_CONTEXT_ARGUMENT = "__argos_operation_id"
const ARGOS_SCOPE_CONTEXT_ARGUMENT = "__argos_scope_snapshot"

export interface ArgosSessionContext {
  sessionID: string
  runID: string
  operationID: string
  scope: {
    domains?: string[]
    cidrs?: string[]
    excluded?: string[]
    maxRPS?: number
    safeMode?: boolean
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

export function addArgosSessionContext(argumentsValue: unknown, context: ArgosSessionContext) {
  if (!isRecord(argumentsValue)) return argumentsValue
  return {
    ...argumentsValue,
    [ARGOS_SESSION_CONTEXT_ARGUMENT]: context.sessionID,
    [ARGOS_RUN_CONTEXT_ARGUMENT]: context.runID,
    [ARGOS_OPERATION_CONTEXT_ARGUMENT]: context.operationID,
    [ARGOS_SCOPE_CONTEXT_ARGUMENT]: context.scope,
  }
}

export function extractArgosSessionContext(argumentsValue: unknown) {
  if (!isRecord(argumentsValue)) {
    return { arguments: {}, sessionID: undefined, runID: undefined, operationID: undefined, scope: undefined }
  }
  const copy = { ...argumentsValue }
  const sessionID = copy[ARGOS_SESSION_CONTEXT_ARGUMENT]
  const runID = copy[ARGOS_RUN_CONTEXT_ARGUMENT]
  const operationID = copy[ARGOS_OPERATION_CONTEXT_ARGUMENT]
  const scope = copy[ARGOS_SCOPE_CONTEXT_ARGUMENT]
  delete copy[ARGOS_SESSION_CONTEXT_ARGUMENT]
  delete copy[ARGOS_RUN_CONTEXT_ARGUMENT]
  delete copy[ARGOS_OPERATION_CONTEXT_ARGUMENT]
  delete copy[ARGOS_SCOPE_CONTEXT_ARGUMENT]
  return {
    arguments: copy,
    sessionID: typeof sessionID === "string" && sessionID.length > 0 ? sessionID : undefined,
    runID: typeof runID === "string" && runID.length > 0 ? runID : undefined,
    operationID: typeof operationID === "string" && operationID.length > 0 ? operationID : undefined,
    scope: isRecord(scope) ? scope : undefined,
  }
}
