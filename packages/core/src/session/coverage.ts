export * as SessionCoverage from "./coverage"

import { and, eq } from "drizzle-orm"
import { Effect, Schema } from "effect"
import { Database } from "../database/database"
import { Identifier } from "../util/identifier"
import type { SessionSchema } from "./schema"
import { SessionRunCoveragePlanTable, SessionRunCoverageTable, SessionRunTable } from "./sql"

export const Surface = Schema.Literals(["web", "api", "repository"])
export type Surface = typeof Surface.Type

export const Status = Schema.Literals(["executed", "no-finding", "blocked", "skipped", "inconclusive"])
export type Status = typeof Status.Type

export const Attestation = Schema.Literals(["api-reported", "runtime-observed"])
export type Attestation = typeof Attestation.Type

export const ReportInput = Schema.Struct({
  surface: Surface,
  role: Schema.String,
  testKey: Schema.String,
  status: Status,
  findingCount: Schema.Int.pipe(Schema.optional),
  evidenceHash: Schema.String.pipe(Schema.optional),
  evidenceRef: Schema.String.pipe(Schema.optional),
  summary: Schema.String.pipe(Schema.optional),
  idempotencyKey: Schema.String.pipe(Schema.optional),
})
export type ReportInput = typeof ReportInput.Type

export const Info = Schema.Struct({
  id: Schema.String,
  sessionID: Schema.String,
  runID: Schema.String,
  surface: Surface,
  role: Schema.String,
  testKey: Schema.String,
  status: Status,
  findingCount: Schema.Int,
  attestation: Attestation,
  runtimeTool: Schema.String.pipe(Schema.optional),
  evidenceHash: Schema.String.pipe(Schema.optional),
  evidenceRef: Schema.String.pipe(Schema.optional),
  summary: Schema.String.pipe(Schema.optional),
  createdAt: Schema.Int,
})
export type Info = typeof Info.Type

export const Requirement = Schema.Struct({
  surface: Surface,
  role: Schema.String,
  testKey: Schema.String,
  runtimeTool: Schema.String,
})
export type Requirement = typeof Requirement.Type

export const PlanInfo = Schema.Struct({
  sessionID: Schema.String,
  runID: Schema.String,
  version: Schema.Int,
  source: Schema.Literal("controller"),
  requirements: Schema.Array(Requirement),
  createdAt: Schema.Int,
})
export type PlanInfo = typeof PlanInfo.Type

export class RunNotFoundError extends Schema.TaggedErrorClass<RunNotFoundError>()("Session.CoverageRunNotFoundError", {
  sessionID: Schema.String,
  runID: Schema.String,
}) {}

export class IdempotencyConflictError extends Schema.TaggedErrorClass<IdempotencyConflictError>()(
  "Session.CoverageIdempotencyConflictError",
  {
    runID: Schema.String,
    key: Schema.String,
  },
) {}

export class ValidationError extends Schema.TaggedErrorClass<ValidationError>()("Session.CoverageValidationError", {
  message: Schema.String,
}) {}

export class PlanConflictError extends Schema.TaggedErrorClass<PlanConflictError>()(
  "Session.CoveragePlanConflictError",
  {
    sessionID: Schema.String,
    runID: Schema.String,
  },
) {}

type RecordInput = ReportInput & {
  sessionID: SessionSchema.ID
  runID: string
}

type RuntimeInput = Omit<RecordInput, "idempotencyKey"> & {
  idempotencyKey?: string
  runtimeTool: string
}

type Row = typeof SessionRunCoverageTable.$inferSelect
type PlanRow = typeof SessionRunCoveragePlanTable.$inferSelect

const toInfo = (row: Row): Info => ({
  id: row.id,
  sessionID: row.session_id,
  runID: row.run_id,
  surface: Schema.decodeUnknownSync(Surface)(row.surface),
  role: row.role,
  testKey: row.test_key,
  status: Schema.decodeUnknownSync(Status)(row.status),
  findingCount: row.finding_count,
  attestation: Schema.decodeUnknownSync(Attestation)(row.attestation),
  runtimeTool: row.runtime_tool ?? undefined,
  evidenceHash: row.evidence_hash ?? undefined,
  evidenceRef: row.evidence_ref ?? undefined,
  summary: row.summary ?? undefined,
  createdAt: row.created_at,
})

const toPlanInfo = (row: PlanRow): PlanInfo => ({
  sessionID: row.session_id,
  runID: row.run_id,
  version: row.version,
  source: Schema.decodeUnknownSync(Schema.Literal("controller"))(row.source),
  requirements: Schema.decodeUnknownSync(Schema.Array(Requirement))(row.requirements),
  createdAt: row.created_at,
})

const requirementKey = (requirement: Requirement) =>
  `${requirement.surface}\u0000${requirement.role}\u0000${requirement.testKey}`

const normalizeRequirements = (requirements: ReadonlyArray<Requirement>) =>
  [...requirements].sort((left, right) => {
    const leftKey = requirementKey(left)
    const rightKey = requirementKey(right)
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
  })

const planMessage = (requirements: ReadonlyArray<Requirement>) => {
  if (requirements.length === 0) return "required coverage plan must include at least one requirement"
  if (requirements.length > 256) return "required coverage plan must not exceed 256 requirements"
  const seen = new Set<string>()
  for (const requirement of requirements) {
    if (!Schema.is(Surface)(requirement.surface)) return "plan requirement surface is unsupported"
    if (!requirement.role.trim() || requirement.role.length > 120) {
      return "plan requirement role must contain between 1 and 120 characters"
    }
    if (requirement.role !== requirement.role.trim())
      return "plan requirement role must not start or end with whitespace"
    if (!requirement.testKey.trim() || requirement.testKey.length > 200) {
      return "plan requirement testKey must contain between 1 and 200 characters"
    }
    if (requirement.testKey !== requirement.testKey.trim()) {
      return "plan requirement testKey must not start or end with whitespace"
    }
    if (!requirement.runtimeTool.trim() || requirement.runtimeTool.length > 160) {
      return "plan requirement runtimeTool must contain between 1 and 160 characters"
    }
    if (requirement.runtimeTool !== requirement.runtimeTool.trim()) {
      return "plan requirement runtimeTool must not start or end with whitespace"
    }
    const key = requirementKey(requirement)
    if (seen.has(key)) return "required coverage plan contains duplicate requirements"
    seen.add(key)
  }
  return undefined
}

const invalidMessage = (input: ReportInput, findingCount: number, runtimeTool?: string) => {
  if (!Schema.is(Surface)(input.surface)) return "surface is unsupported"
  if (!Schema.is(Status)(input.status)) return "status is unsupported"
  if (!input.role.trim() || input.role.length > 120) return "role must contain between 1 and 120 characters"
  if (!input.testKey.trim() || input.testKey.length > 200) return "testKey must contain between 1 and 200 characters"
  if (input.evidenceHash !== undefined && !/^[a-f0-9]{64}$/.test(input.evidenceHash)) {
    return "evidenceHash must be a lowercase SHA-256 digest"
  }
  if (input.evidenceRef !== undefined && (!input.evidenceRef.trim() || input.evidenceRef.length > 2048)) {
    return "evidenceRef must contain between 1 and 2048 characters"
  }
  if (input.summary !== undefined && input.summary.length > 2000) return "summary must not exceed 2000 characters"
  if (input.idempotencyKey !== undefined && (!input.idempotencyKey.trim() || input.idempotencyKey.length > 160)) {
    return "idempotencyKey must contain between 1 and 160 characters"
  }
  if (!Number.isSafeInteger(findingCount) || findingCount < 0) return "findingCount must be a non-negative integer"
  if (input.status === "no-finding" && findingCount !== 0) return "no-finding coverage must have findingCount 0"
  if (input.status === "executed" && findingCount < 1) return "executed coverage must record at least one finding"
  if (["blocked", "skipped", "inconclusive"].includes(input.status) && findingCount !== 0) {
    return `${input.status} coverage cannot assert a finding count`
  }
  if (runtimeTool !== undefined && (!runtimeTool.trim() || runtimeTool.length > 160)) {
    return "runtimeTool must contain between 1 and 160 characters"
  }
  if (runtimeTool !== undefined && !input.evidenceHash) {
    return "runtime coverage requires an evidenceHash"
  }
  if (runtimeTool !== undefined && !input.evidenceRef) {
    return "runtime coverage requires an evidenceRef"
  }
  return undefined
}

const matchesInput = (
  row: Row,
  input: RecordInput,
  attestation: Attestation,
  findingCount: number,
  runtimeTool?: string,
) =>
  row.session_id === input.sessionID &&
  row.surface === input.surface &&
  row.role === input.role &&
  row.test_key === input.testKey &&
  row.status === input.status &&
  row.finding_count === findingCount &&
  row.attestation === attestation &&
  row.runtime_tool === (runtimeTool ?? null) &&
  row.evidence_hash === (input.evidenceHash ?? null) &&
  row.evidence_ref === (input.evidenceRef ?? null) &&
  row.summary === (input.summary ?? null)

export const make = (db: Database.Interface["db"]) => {
  const assertRun = Effect.fn("SessionCoverage.assertRun")(function* (sessionID: SessionSchema.ID, runID: string) {
    const run = yield* db
      .select({ sessionID: SessionRunTable.session_id })
      .from(SessionRunTable)
      .where(and(eq(SessionRunTable.id, runID), eq(SessionRunTable.session_id, sessionID)))
      .get()
      .pipe(Effect.orDie)
    if (!run) return yield* new RunNotFoundError({ sessionID, runID })
  })

  const record = (
    input: RecordInput,
    attestation: Attestation,
    runtimeTool?: string,
  ): Effect.Effect<Info, RunNotFoundError | IdempotencyConflictError | ValidationError> =>
    Effect.gen(function* () {
      const findingCount = input.findingCount ?? 0
      const message = invalidMessage(input, findingCount, runtimeTool)
      if (message) return yield* new ValidationError({ message })
      yield* assertRun(input.sessionID, input.runID)

      if (input.idempotencyKey) {
        const existing = yield* db
          .select()
          .from(SessionRunCoverageTable)
          .where(
            and(
              eq(SessionRunCoverageTable.run_id, input.runID),
              eq(SessionRunCoverageTable.idempotency_key, input.idempotencyKey),
            ),
          )
          .get()
          .pipe(Effect.orDie)
        if (existing) {
          if (matchesInput(existing, input, attestation, findingCount, runtimeTool)) return toInfo(existing)
          return yield* new IdempotencyConflictError({ runID: input.runID, key: input.idempotencyKey })
        }
      }

      const id = `coverage_${Identifier.ascending()}`
      yield* db
        .insert(SessionRunCoverageTable)
        .values({
          id,
          session_id: input.sessionID,
          run_id: input.runID,
          surface: input.surface,
          role: input.role,
          test_key: input.testKey,
          status: input.status,
          finding_count: findingCount,
          attestation,
          runtime_tool: runtimeTool ?? null,
          evidence_hash: input.evidenceHash ?? null,
          evidence_ref: input.evidenceRef ?? null,
          summary: input.summary ?? null,
          idempotency_key: input.idempotencyKey ?? null,
          created_at: Date.now(),
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)

      if (input.idempotencyKey) {
        const row = yield* db
          .select()
          .from(SessionRunCoverageTable)
          .where(
            and(
              eq(SessionRunCoverageTable.run_id, input.runID),
              eq(SessionRunCoverageTable.idempotency_key, input.idempotencyKey),
            ),
          )
          .get()
          .pipe(Effect.orDie)
        if (!row) return yield* new IdempotencyConflictError({ runID: input.runID, key: input.idempotencyKey })
        if (!matchesInput(row, input, attestation, findingCount, runtimeTool)) {
          return yield* new IdempotencyConflictError({ runID: input.runID, key: input.idempotencyKey })
        }
        return toInfo(row)
      }

      const row = yield* db
        .select()
        .from(SessionRunCoverageTable)
        .where(eq(SessionRunCoverageTable.id, id))
        .get()
        .pipe(Effect.orDie)
      if (!row) return yield* Effect.die("Coverage insertion did not return a record")
      return toInfo(row)
    })

  return {
    plan: Effect.fn("SessionCoverage.plan")(function* (sessionID: SessionSchema.ID, runID: string) {
      yield* assertRun(sessionID, runID)
      const row = yield* db
        .select()
        .from(SessionRunCoveragePlanTable)
        .where(
          and(eq(SessionRunCoveragePlanTable.session_id, sessionID), eq(SessionRunCoveragePlanTable.run_id, runID)),
        )
        .get()
        .pipe(Effect.orDie)
      return row ? toPlanInfo(row) : undefined
    }),

    createPlan: (input: {
      sessionID: SessionSchema.ID
      runID: string
      requirements: ReadonlyArray<Requirement>
    }): Effect.Effect<PlanInfo, RunNotFoundError | PlanConflictError | ValidationError> =>
      Effect.gen(function* () {
        const message = planMessage(input.requirements)
        if (message) return yield* new ValidationError({ message })
        yield* assertRun(input.sessionID, input.runID)
        const requirements = normalizeRequirements(input.requirements)
        yield* db
          .insert(SessionRunCoveragePlanTable)
          .values({
            session_id: input.sessionID,
            run_id: input.runID,
            version: 1,
            source: "controller",
            requirements,
            created_at: Date.now(),
          })
          .onConflictDoNothing()
          .run()
          .pipe(Effect.orDie)
        const row = yield* db
          .select()
          .from(SessionRunCoveragePlanTable)
          .where(eq(SessionRunCoveragePlanTable.run_id, input.runID))
          .get()
          .pipe(Effect.orDie)
        if (!row || row.session_id !== input.sessionID) {
          return yield* new PlanConflictError({ sessionID: input.sessionID, runID: input.runID })
        }
        const info = toPlanInfo(row)
        if (JSON.stringify(info.requirements) !== JSON.stringify(requirements)) {
          return yield* new PlanConflictError({ sessionID: input.sessionID, runID: input.runID })
        }
        return info
      }),

    list: Effect.fn("SessionCoverage.list")(function* (sessionID: SessionSchema.ID, runID: string) {
      yield* assertRun(sessionID, runID)
      const rows = yield* db
        .select()
        .from(SessionRunCoverageTable)
        .where(and(eq(SessionRunCoverageTable.session_id, sessionID), eq(SessionRunCoverageTable.run_id, runID)))
        .orderBy(SessionRunCoverageTable.created_at, SessionRunCoverageTable.id)
        .all()
        .pipe(Effect.orDie)
      return rows.map(toInfo)
    }),
    recordReported: (input: RecordInput) => record(input, "api-reported"),
    recordRuntime: (input: RuntimeInput) => {
      const { runtimeTool, ...recordInput } = input
      return record(recordInput, "runtime-observed", runtimeTool)
    },
  }
}
