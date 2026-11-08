import { createHash, randomUUID } from "node:crypto"
import { and, eq, inArray, sql } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { FindingCaseOperationTable, FindingCaseTable, FindingCaseTransitionTable, FindingTable } from "./sql"
import { trustedFindingSourceSqlList } from "./finding-provenance"

export const FINDING_CASE_STATUSES = ["open", "in-progress", "remediated", "accepted-risk"] as const
export type FindingCaseStatus = (typeof FINDING_CASE_STATUSES)[number]
export type FindingCaseActor = "human" | "system"
export type FindingCaseRow = typeof FindingCaseTable.$inferSelect

export interface FindingCaseRecord extends FindingCaseRow {
  finding_count: number
  session_count: number
}

export type FindingCaseTransitionRecord = typeof FindingCaseTransitionTable.$inferSelect
export type FindingCaseOperationKind = "merge" | "split"
export type FindingCaseOperationRecord = typeof FindingCaseOperationTable.$inferSelect

export class FindingCaseError extends Error {
  constructor(
    readonly code:
      | "not_found"
      | "invalid_status"
      | "expiry_required"
      | "reason_required"
      | "same_case"
      | "case_not_active"
      | "invalid_selection"
      | "operation_not_reversible"
      | "dependent_operation",
    message: string,
  ) {
    super(message)
    this.name = "FindingCaseError"
  }
}

export const findingCaseID = (projectID: string, identityKey: string) =>
  `case_${createHash("sha256")
    .update(JSON.stringify([projectID, identityKey]))
    .digest("hex")}`

export function resolveFindingCase(
  db: Database.Interface["db"],
  input: { projectID: string; identityKey: string; now?: number },
) {
  return Effect.gen(function* () {
    const identityKey = input.identityKey.trim()
    if (!identityKey) return yield* Effect.die(new Error("Finding case identity key cannot be empty"))
    const now = input.now ?? Date.now()
    const id = findingCaseID(input.projectID, identityKey)
    yield* db
      .insert(FindingCaseTable)
      .values({
        id,
        project_id: input.projectID,
        identity_key: identityKey,
        status: "open",
        time_created: now,
        time_updated: now,
      })
      .onConflictDoNothing({ target: [FindingCaseTable.project_id, FindingCaseTable.identity_key] })
      .run()
      .pipe(Effect.orDie)
    const row = yield* db
      .select({ id: FindingCaseTable.id })
      .from(FindingCaseTable)
      .where(and(eq(FindingCaseTable.project_id, input.projectID), eq(FindingCaseTable.identity_key, identityKey)))
      .get()
      .pipe(Effect.orDie)
    if (!row) return yield* Effect.die(new Error("Finding case was not persisted"))
    let currentID = row.id
    const visited = new Set<string>()
    while (true) {
      if (visited.has(currentID)) return yield* Effect.die(new Error("Finding case merge cycle detected"))
      visited.add(currentID)
      const current = yield* db
        .select({ mergedIntoID: FindingCaseTable.merged_into_id })
        .from(FindingCaseTable)
        .where(eq(FindingCaseTable.id, currentID))
        .get()
        .pipe(Effect.orDie)
      if (!current) return yield* Effect.die(new Error("Finding case merge target was not persisted"))
      if (!current.mergedIntoID) return currentID
      currentID = current.mergedIntoID
    }
  })
}

const operationReason = (value: string) => value.trim().slice(0, 2000)

export interface MergeFindingCasesInput {
  projectID: string
  sessionID: string
  sourceCaseID: string
  targetCaseID: string
  reason: string
  actor: FindingCaseActor
  now?: number
}

export function mergeFindingCases(db: Database.Interface["db"], input: MergeFindingCasesInput) {
  const reason = operationReason(input.reason)
  if (!reason) return Effect.fail(new FindingCaseError("reason_required", "A reason is required to merge cases"))
  if (input.sourceCaseID === input.targetCaseID) {
    return Effect.fail(new FindingCaseError("same_case", "A case cannot be merged into itself"))
  }
  const now = input.now ?? Date.now()

  return db.transaction(() =>
    Effect.gen(function* () {
      const [source, target] = yield* Effect.all([
        db
          .select()
          .from(FindingCaseTable)
          .where(and(eq(FindingCaseTable.id, input.sourceCaseID), eq(FindingCaseTable.project_id, input.projectID)))
          .get()
          .pipe(Effect.orDie),
        db
          .select()
          .from(FindingCaseTable)
          .where(and(eq(FindingCaseTable.id, input.targetCaseID), eq(FindingCaseTable.project_id, input.projectID)))
          .get()
          .pipe(Effect.orDie),
      ])
      if (!source || !target) return yield* Effect.fail(new FindingCaseError("not_found", "Finding case was not found"))
      if (source.merged_into_id || target.merged_into_id) {
        return yield* Effect.fail(new FindingCaseError("case_not_active", "Only active cases can be merged"))
      }

      const [sourceVisible, targetVisible] = yield* Effect.all([
        db
          .select({ id: FindingTable.id })
          .from(FindingTable)
          .where(and(eq(FindingTable.case_id, source.id), eq(FindingTable.session_id, input.sessionID)))
          .get()
          .pipe(Effect.orDie),
        db
          .select({ id: FindingTable.id })
          .from(FindingTable)
          .where(and(eq(FindingTable.case_id, target.id), eq(FindingTable.session_id, input.sessionID)))
          .get()
          .pipe(Effect.orDie),
      ])
      if (!sourceVisible || !targetVisible) {
        return yield* Effect.fail(new FindingCaseError("not_found", "Both cases must be visible in the session"))
      }
      const findings = yield* db
        .select({ id: FindingTable.id })
        .from(FindingTable)
        .where(and(eq(FindingTable.case_id, source.id), eq(FindingTable.project_id, input.projectID)))
        .all()
        .pipe(Effect.orDie)
      if (findings.length === 0) {
        return yield* Effect.fail(new FindingCaseError("invalid_selection", "The source case has no findings to move"))
      }
      const findingIDs = findings.map((finding) => finding.id).sort()
      const id = `fco_${randomUUID()}`

      yield* db
        .update(FindingTable)
        .set({ case_id: target.id, time_updated: now })
        .where(and(eq(FindingTable.case_id, source.id), eq(FindingTable.project_id, input.projectID)))
        .run()
        .pipe(Effect.orDie)
      yield* db
        .update(FindingCaseTable)
        .set({ merged_into_id: target.id, time_updated: now })
        .where(eq(FindingCaseTable.id, source.id))
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(FindingCaseOperationTable)
        .values({
          id,
          project_id: input.projectID,
          kind: "merge",
          source_case_id: source.id,
          target_case_id: target.id,
          reason,
          actor: input.actor,
          session_id: input.sessionID,
          finding_ids: findingIDs,
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)
      const operation = yield* db
        .select()
        .from(FindingCaseOperationTable)
        .where(eq(FindingCaseOperationTable.id, id))
        .get()
        .pipe(Effect.orDie)
      if (!operation) return yield* Effect.die(new Error("Finding case merge operation was not persisted"))
      return operation
    }),
  )
}

export interface SplitFindingCaseInput {
  projectID: string
  sessionID: string
  sourceCaseID: string
  findingIDs: readonly string[]
  reason: string
  actor: FindingCaseActor
  now?: number
}

export function splitFindingCase(db: Database.Interface["db"], input: SplitFindingCaseInput) {
  const reason = operationReason(input.reason)
  if (!reason) return Effect.fail(new FindingCaseError("reason_required", "A reason is required to split a case"))
  const findingIDs = [...new Set(input.findingIDs)]
  if (findingIDs.length === 0 || findingIDs.length !== input.findingIDs.length || findingIDs.length > 500) {
    return Effect.fail(new FindingCaseError("invalid_selection", "Select between 1 and 500 distinct findings"))
  }
  const now = input.now ?? Date.now()

  return db.transaction(() =>
    Effect.gen(function* () {
      const source = yield* db
        .select()
        .from(FindingCaseTable)
        .where(and(eq(FindingCaseTable.id, input.sourceCaseID), eq(FindingCaseTable.project_id, input.projectID)))
        .get()
        .pipe(Effect.orDie)
      if (!source) return yield* Effect.fail(new FindingCaseError("not_found", "Finding case was not found"))
      if (source.merged_into_id) {
        return yield* Effect.fail(new FindingCaseError("case_not_active", "Only active cases can be split"))
      }
      const selected = yield* db
        .select({ id: FindingTable.id })
        .from(FindingTable)
        .where(
          and(
            eq(FindingTable.case_id, source.id),
            eq(FindingTable.project_id, input.projectID),
            eq(FindingTable.session_id, input.sessionID),
            inArray(FindingTable.id, findingIDs),
          ),
        )
        .all()
        .pipe(Effect.orDie)
      if (selected.length !== findingIDs.length) {
        return yield* Effect.fail(
          new FindingCaseError("invalid_selection", "Every selected finding must belong to this case and session"),
        )
      }

      const caseID = `case_${randomUUID()}`
      const operationID = `fco_${randomUUID()}`
      yield* db
        .insert(FindingCaseTable)
        .values({
          id: caseID,
          project_id: input.projectID,
          identity_key: null,
          status: source.status,
          status_reason: source.status_reason,
          owner: source.owner,
          due_at: source.due_at,
          accepted_risk_until: source.accepted_risk_until,
          time_created: now,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)
      yield* db
        .update(FindingTable)
        .set({ case_id: caseID, time_updated: now })
        .where(inArray(FindingTable.id, findingIDs))
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(FindingCaseOperationTable)
        .values({
          id: operationID,
          project_id: input.projectID,
          kind: "split",
          source_case_id: source.id,
          target_case_id: caseID,
          reason,
          actor: input.actor,
          session_id: input.sessionID,
          finding_ids: findingIDs,
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)
      const operation = yield* db
        .select()
        .from(FindingCaseOperationTable)
        .where(eq(FindingCaseOperationTable.id, operationID))
        .get()
        .pipe(Effect.orDie)
      if (!operation) return yield* Effect.die(new Error("Finding case split operation was not persisted"))
      return { caseID, operation }
    }),
  )
}

export interface ReverseFindingCaseOperationInput {
  projectID: string
  sessionID: string
  caseID: string
  operationID: string
  reason: string
  actor: FindingCaseActor
  now?: number
}

export function reverseFindingCaseOperation(db: Database.Interface["db"], input: ReverseFindingCaseOperationInput) {
  const reason = operationReason(input.reason)
  if (!reason) {
    return Effect.fail(new FindingCaseError("reason_required", "A reason is required to reverse a case operation"))
  }
  const now = input.now ?? Date.now()
  return db.transaction(() =>
    Effect.gen(function* () {
      const operation = yield* db
        .select()
        .from(FindingCaseOperationTable)
        .where(
          and(
            eq(FindingCaseOperationTable.id, input.operationID),
            eq(FindingCaseOperationTable.project_id, input.projectID),
          ),
        )
        .get()
        .pipe(Effect.orDie)
      if (!operation || (operation.source_case_id !== input.caseID && operation.target_case_id !== input.caseID)) {
        return yield* Effect.fail(new FindingCaseError("not_found", "Finding case operation was not found"))
      }
      if (operation.reversed_at !== null) {
        return yield* Effect.fail(
          new FindingCaseError("operation_not_reversible", "This operation was already reversed"),
        )
      }
      const visibility = yield* db
        .get<{ id: string }>(
          sql`
          SELECT f.id
          FROM security_finding f
          WHERE f.session_id = ${input.sessionID}
            AND f.project_id = ${input.projectID}
            AND f.case_id IN (${operation.source_case_id}, ${operation.target_case_id})
          LIMIT 1
        `,
        )
        .pipe(Effect.orDie)
      if (!visibility)
        return yield* Effect.fail(new FindingCaseError("not_found", "The operation is not visible in this session"))

      const dependent = yield* db
        .get<{ id: string }>(
          sql`
        SELECT id FROM security_finding_case_operation
        WHERE reversed_at IS NULL
          AND id <> ${operation.id}
          AND rowid > (SELECT rowid FROM security_finding_case_operation WHERE id = ${operation.id})
          AND (
            source_case_id IN (${operation.source_case_id}, ${operation.target_case_id})
            OR target_case_id IN (${operation.source_case_id}, ${operation.target_case_id})
          )
        LIMIT 1
      `,
        )
        .pipe(Effect.orDie)
      if (dependent) {
        return yield* Effect.fail(
          new FindingCaseError("dependent_operation", "Reverse later case operations before reversing this one"),
        )
      }

      const [source, target] = yield* Effect.all([
        db
          .select()
          .from(FindingCaseTable)
          .where(eq(FindingCaseTable.id, operation.source_case_id))
          .get()
          .pipe(Effect.orDie),
        db
          .select()
          .from(FindingCaseTable)
          .where(eq(FindingCaseTable.id, operation.target_case_id))
          .get()
          .pipe(Effect.orDie),
      ])
      if (!source || !target || source.project_id !== input.projectID || target.project_id !== input.projectID) {
        return yield* Effect.fail(new FindingCaseError("not_found", "The operation's cases no longer exist"))
      }
      if (operation.kind === "merge" && source.merged_into_id !== target.id) {
        return yield* Effect.fail(
          new FindingCaseError("operation_not_reversible", "The source case no longer points to this merge target"),
        )
      }
      if (operation.kind !== "merge" && operation.kind !== "split") {
        return yield* Effect.fail(new FindingCaseError("operation_not_reversible", "Unknown case operation kind"))
      }
      const existingFindings = operation.finding_ids.length
        ? yield* db
            .select({ id: FindingTable.id, caseID: FindingTable.case_id })
            .from(FindingTable)
            .where(inArray(FindingTable.id, operation.finding_ids))
            .all()
            .pipe(Effect.orDie)
        : []
      if (existingFindings.some((finding) => finding.caseID !== target.id)) {
        return yield* Effect.fail(
          new FindingCaseError("operation_not_reversible", "Some findings have moved in a later operation"),
        )
      }

      const restoreIDs = new Set(operation.finding_ids)
      if (operation.kind === "merge" && source.identity_key) {
        const matchingIdentity = yield* db
          .select({ id: FindingTable.id })
          .from(FindingTable)
          .where(and(eq(FindingTable.case_id, target.id), eq(FindingTable.fingerprint, source.identity_key)))
          .all()
          .pipe(Effect.orDie)
        for (const finding of matchingIdentity) restoreIDs.add(finding.id)
      }
      if (restoreIDs.size > 0) {
        yield* db
          .update(FindingTable)
          .set({ case_id: source.id, time_updated: now })
          .where(and(eq(FindingTable.case_id, target.id), inArray(FindingTable.id, [...restoreIDs])))
          .run()
          .pipe(Effect.orDie)
      }
      if (operation.kind === "merge") {
        yield* db
          .update(FindingCaseTable)
          .set({ merged_into_id: null, time_updated: now })
          .where(eq(FindingCaseTable.id, source.id))
          .run()
          .pipe(Effect.orDie)
      } else if (operation.kind === "split") {
        yield* db
          .update(FindingCaseTable)
          .set({ merged_into_id: source.id, time_updated: now })
          .where(eq(FindingCaseTable.id, target.id))
          .run()
          .pipe(Effect.orDie)
      }

      yield* db
        .update(FindingCaseOperationTable)
        .set({ reversed_at: now, reversed_reason: reason, reversed_by: input.actor })
        .where(eq(FindingCaseOperationTable.id, operation.id))
        .run()
        .pipe(Effect.orDie)
      const reversed = yield* db
        .select()
        .from(FindingCaseOperationTable)
        .where(eq(FindingCaseOperationTable.id, operation.id))
        .get()
        .pipe(Effect.orDie)
      if (!reversed) return yield* Effect.die(new Error("Reversed case operation was not persisted"))
      return reversed
    }),
  )
}

export interface FindingCaseStatusInput {
  projectID: string
  caseID: string
  status: FindingCaseStatus
  actor: FindingCaseActor
  reason?: string
  acceptedRiskUntil?: number
  sessionID?: string
  now?: number
}

export function setFindingCaseStatus(db: Database.Interface["db"], input: FindingCaseStatusInput) {
  return Effect.gen(function* () {
    if (!FINDING_CASE_STATUSES.includes(input.status)) {
      return yield* Effect.fail(
        new FindingCaseError("invalid_status", `Unsupported finding case status: ${input.status}`),
      )
    }
    const now = input.now ?? Date.now()
    const reason = input.reason?.trim().slice(0, 4000) || null
    if (input.status === "accepted-risk" && (!input.acceptedRiskUntil || input.acceptedRiskUntil <= now)) {
      return yield* Effect.fail(
        new FindingCaseError("expiry_required", "Accepted risk requires an expiry later than the current time"),
      )
    }

    return yield* db.transaction(() =>
      Effect.gen(function* () {
        const current = yield* db
          .select()
          .from(FindingCaseTable)
          .where(and(eq(FindingCaseTable.id, input.caseID), eq(FindingCaseTable.project_id, input.projectID)))
          .get()
          .pipe(Effect.orDie)
        if (!current) return yield* Effect.fail(new FindingCaseError("not_found", "Finding case was not found"))

        const acceptedRiskUntil = input.status === "accepted-risk" ? input.acceptedRiskUntil! : null
        if (
          current.status === input.status &&
          current.status_reason === reason &&
          current.accepted_risk_until === acceptedRiskUntil
        ) {
          return current
        }

        yield* db
          .update(FindingCaseTable)
          .set({
            status: input.status,
            status_reason: reason,
            accepted_risk_until: acceptedRiskUntil,
            time_updated: now,
          })
          .where(eq(FindingCaseTable.id, input.caseID))
          .run()
          .pipe(Effect.orDie)
        yield* db
          .insert(FindingCaseTransitionTable)
          .values({
            id: `fct_${randomUUID()}`,
            case_id: input.caseID,
            from_status: current.status,
            to_status: input.status,
            reason,
            actor: input.actor,
            session_id: input.sessionID ?? null,
            time_created: now,
          })
          .run()
          .pipe(Effect.orDie)
        return {
          ...current,
          status: input.status,
          status_reason: reason,
          accepted_risk_until: acceptedRiskUntil,
          time_updated: now,
        }
      }),
    )
  })
}

/** Lists cases visible from a session and counts their findings across the project. */
export function listFindingCasesForSession(
  db: Database.Interface["db"],
  input: { projectID: string; sessionID: string; limit?: number; offset?: number },
) {
  const limit = Math.max(1, Math.min(input.limit ?? 50, 200))
  const offset = Math.max(0, input.offset ?? 0)
  return db
    .all<FindingCaseRecord>(
      sql`
      SELECT
        c.id,
        c.project_id,
        c.identity_key,
        c.status,
        c.status_reason,
        c.owner,
        c.due_at,
        c.accepted_risk_until,
        c.time_created,
        c.time_updated,
        (SELECT COUNT(*) FROM security_finding current_finding
          WHERE current_finding.case_id = c.id AND current_finding.session_id = ${input.sessionID} AND current_finding.source IN (${trustedFindingSourceSqlList})) AS finding_count,
        (SELECT COUNT(DISTINCT project_finding.session_id) FROM security_finding project_finding
          WHERE project_finding.case_id = c.id AND project_finding.source IN (${trustedFindingSourceSqlList})) AS session_count
      FROM security_finding_case c
      WHERE c.project_id = ${input.projectID}
        AND EXISTS (
          SELECT 1 FROM security_finding session_finding
          WHERE session_finding.case_id = c.id AND session_finding.session_id = ${input.sessionID} AND session_finding.source IN (${trustedFindingSourceSqlList})
        )
      ORDER BY c.time_updated DESC, c.id ASC
      LIMIT ${limit} OFFSET ${offset}
    `,
    )
    .pipe(Effect.orDie)
}

export function countFindingCasesForSession(
  db: Database.Interface["db"],
  input: { projectID: string; sessionID: string },
) {
  return db
    .get<{ total: number }>(
      sql`
      SELECT COUNT(*) AS total
      FROM security_finding_case c
      WHERE c.project_id = ${input.projectID}
        AND EXISTS (
          SELECT 1 FROM security_finding f
          WHERE f.case_id = c.id AND f.session_id = ${input.sessionID} AND f.source IN (${trustedFindingSourceSqlList})
        )
    `,
    )
    .pipe(
      Effect.orDie,
      Effect.map((row) => row?.total ?? 0),
    )
}

/** Returns a case only when this session has at least one finding linked to it. */
export function getFindingCaseForSession(db: Database.Interface["db"], input: { sessionID: string; caseID: string }) {
  return db
    .get<FindingCaseRecord>(
      sql`
      SELECT
        c.*,
        (SELECT COUNT(*) FROM security_finding current_finding
          WHERE current_finding.case_id = c.id AND current_finding.session_id = ${input.sessionID} AND current_finding.source IN (${trustedFindingSourceSqlList})) AS finding_count,
        (SELECT COUNT(DISTINCT project_finding.session_id) FROM security_finding project_finding
          WHERE project_finding.case_id = c.id AND project_finding.source IN (${trustedFindingSourceSqlList})) AS session_count
      FROM security_finding_case c
      INNER JOIN security_finding f ON f.case_id = c.id
      WHERE c.id = ${input.caseID} AND f.session_id = ${input.sessionID} AND f.source IN (${trustedFindingSourceSqlList})
      LIMIT 1
    `,
    )
    .pipe(Effect.orDie)
}

export function listFindingCaseTransitions(
  db: Database.Interface["db"],
  input: { sessionID: string; caseID: string; limit?: number },
) {
  const limit = Math.max(1, Math.min(input.limit ?? 50, 100))
  return db
    .all<FindingCaseTransitionRecord>(
      sql`
      SELECT t.*
      FROM security_finding_case_transition t
      WHERE t.case_id = ${input.caseID}
        AND EXISTS (
          SELECT 1 FROM security_finding f
          WHERE f.case_id = t.case_id AND f.session_id = ${input.sessionID}
        )
      ORDER BY t.time_created DESC, t.id DESC
      LIMIT ${limit}
    `,
    )
    .pipe(Effect.orDie)
}

export function listFindingCaseOperations(
  db: Database.Interface["db"],
  input: { sessionID: string; caseID: string; limit?: number },
) {
  const limit = Math.max(1, Math.min(input.limit ?? 50, 100))
  return db
    .all<FindingCaseOperationRecord>(
      sql`
      SELECT o.*
      FROM security_finding_case_operation o
      WHERE (o.source_case_id = ${input.caseID} OR o.target_case_id = ${input.caseID})
        AND EXISTS (
          SELECT 1 FROM security_finding f
          WHERE f.session_id = ${input.sessionID}
            AND f.case_id IN (o.source_case_id, o.target_case_id)
        )
      ORDER BY o.time_created DESC, o.id DESC
      LIMIT ${limit}
    `,
    )
    .pipe(Effect.orDie)
}

export function deleteOrphanFindingCases(db: Database.Interface["db"]) {
  return Effect.gen(function* () {
    yield* db
      .run(
        sql`
        DELETE FROM "security_finding_case_operation"
        WHERE NOT EXISTS (
          SELECT 1 FROM "security_finding" f
          WHERE f.case_id = "security_finding_case_operation".source_case_id
        )
        AND NOT EXISTS (
          SELECT 1 FROM "security_finding" f
          WHERE f.case_id = "security_finding_case_operation".target_case_id
        )
      `,
      )
      .pipe(Effect.orDie)
    yield* db
      .run(
        sql`
        DELETE FROM "security_finding_case"
        WHERE NOT EXISTS (
          SELECT 1 FROM "security_finding" f
          WHERE f.case_id = "security_finding_case".id
        )
        AND NOT EXISTS (
          SELECT 1 FROM "security_finding_case_operation" op
          WHERE op.source_case_id = "security_finding_case".id
             OR op.target_case_id = "security_finding_case".id
        )
      `,
      )
      .pipe(Effect.orDie)
  })
}
