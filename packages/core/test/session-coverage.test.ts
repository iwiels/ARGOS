import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionCoverage } from "@argos/core/session/coverage"
import { SessionRunJournal } from "@argos/core/session/run-journal"
import { SessionSchema } from "@argos/core/session/schema"
import { SessionRunCoveragePlanTable, SessionRunCoverageTable, SessionTable } from "@argos/core/session/sql"
import { testEffect } from "./lib/effect"

const it = testEffect(Database.layerFromPath(":memory:"))

const seedRun = Effect.fn("SessionCoverageTest.seedRun")(function* (suffix: string) {
  const { db } = yield* Database.Service
  const projectID = Project.ID.make(`prj_coverage_${suffix}`)
  const sessionID = SessionSchema.ID.make(`ses_coverage_${suffix}`)
  yield* db
    .insert(ProjectTable)
    .values({ id: projectID, worktree: AbsolutePath.make("/project"), sandboxes: [] })
    .run()
    .pipe(Effect.orDie)
  yield* db
    .insert(SessionTable)
    .values({
      id: sessionID,
      project_id: projectID,
      slug: "coverage",
      directory: "/project",
      title: "coverage",
      version: "test",
    })
    .run()
    .pipe(Effect.orDie)
  const journal = SessionRunJournal.make(db, `runtime-${suffix}`)
  const runID = yield* journal.start(sessionID)
  yield* journal.finish(runID, "completed")
  return { sessionID, runID }
})

describe("SessionCoverage", () => {
  it.effect("appends coverage history and makes report submissions idempotent", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("append")
      const coverage = SessionCoverage.make(db)
      const input = {
        sessionID,
        runID,
        surface: "web" as const,
        role: "anonymous",
        testKey: "tls-protocols",
        status: "no-finding" as const,
        findingCount: 0,
        evidenceHash: "a".repeat(64),
        idempotencyKey: "coverage-request-1",
      }

      const first = yield* coverage.recordReported(input)
      const retry = yield* coverage.recordReported(input)
      yield* coverage.recordReported({ ...input, idempotencyKey: undefined, status: "inconclusive" })
      const rows = yield* coverage.list(sessionID, runID)

      expect(retry.id).toBe(first.id)
      expect(first).toMatchObject({ attestation: "api-reported", status: "no-finding", findingCount: 0 })
      expect(rows.map((row) => row.status)).toEqual(["no-finding", "inconclusive"])
      expect(rows.every((row) => row.attestation === "api-reported")).toBe(true)
    }),
  )

  it.effect("rejects coverage associated with a run from another session", () =>
    Effect.gen(function* () {
      const first = yield* seedRun("owner")
      const second = yield* seedRun("foreign")
      const { db } = yield* Database.Service
      const result = yield* SessionCoverage.make(db)
        .recordReported({
          sessionID: first.sessionID,
          runID: second.runID,
          surface: "api",
          role: "member",
          testKey: "authorization-object-read",
          status: "blocked",
        })
        .pipe(Effect.flip)

      expect(result).toMatchObject({ _tag: "Session.CoverageRunNotFoundError", sessionID: first.sessionID })
    }),
  )

  it.effect("rejects reusing an idempotency key for different coverage", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("idempotency")
      const coverage = SessionCoverage.make(db)
      const input = {
        sessionID,
        runID,
        surface: "repository" as const,
        role: "default",
        testKey: "dependency-audit",
        status: "no-finding" as const,
        idempotencyKey: "same-key",
      }
      yield* coverage.recordReported(input)

      const result = yield* coverage.recordReported({ ...input, status: "blocked" }).pipe(Effect.flip)
      expect(result).toMatchObject({ _tag: "Session.CoverageIdempotencyConflictError", runID, key: "same-key" })
    }),
  )

  it.effect("marks internal runtime observations separately from operator reports", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("runtime")
      const row = yield* SessionCoverage.make(db).recordRuntime({
        sessionID,
        runID,
        surface: "web",
        role: "anonymous",
        testKey: "http-security-headers",
        status: "executed",
        findingCount: 2,
        evidenceHash: "b".repeat(64),
        evidenceRef: "argos://evidence/session/run/headers.json",
        runtimeTool: "argos-web.headers",
      })

      expect(row).toMatchObject({
        attestation: "runtime-observed",
        runtimeTool: "argos-web.headers",
        status: "executed",
        findingCount: 2,
      })
    }),
  )

  it.effect("requires hashed evidence references for runtime coverage attestations", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("runtime-evidence")
      const result = yield* SessionCoverage.make(db)
        .recordRuntime({
          sessionID,
          runID,
          surface: "web",
          role: "anonymous",
          testKey: "http-security-headers",
          status: "no-finding",
          runtimeTool: "argos-web.headers",
        })
        .pipe(Effect.flip)

      expect(result).toMatchObject({ _tag: "Session.CoverageValidationError" })
    }),
  )

  it.effect("persists immutable required coverage plans for one exact run", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("plan")
      const coverage = SessionCoverage.make(db)
      const input = {
        sessionID,
        runID,
        requirements: [
          {
            surface: "web" as const,
            role: "anonymous",
            testKey: "http-security-headers",
            runtimeTool: "argos-web.headers",
          },
          { surface: "api" as const, role: "member", testKey: "object-authorization", runtimeTool: "argos-web.api" },
        ],
      }

      const first = yield* coverage.createPlan(input)
      const retry = yield* coverage.createPlan({ ...input, requirements: [...input.requirements].reverse() })
      const persisted = yield* coverage.plan(sessionID, runID)
      const conflict = yield* coverage.createPlan({ ...input, requirements: [input.requirements[0]] }).pipe(Effect.flip)

      expect(retry).toEqual(first)
      expect(persisted).toEqual(first)
      expect(first).toMatchObject({ sessionID, runID, source: "controller", version: 1 })
      expect(first.requirements).toHaveLength(2)
      expect(conflict).toMatchObject({ _tag: "Session.CoveragePlanConflictError", sessionID, runID })
    }),
  )

  it.effect("rejects empty, duplicate, and cross-session required coverage plans", () =>
    Effect.gen(function* () {
      const first = yield* seedRun("plan-owner")
      const second = yield* seedRun("plan-foreign")
      const { db } = yield* Database.Service
      const coverage = SessionCoverage.make(db)
      const empty = yield* coverage.createPlan({ ...first, requirements: [] }).pipe(Effect.flip)
      const duplicate = yield* coverage
        .createPlan({
          ...first,
          requirements: [
            { surface: "web", role: "anonymous", testKey: "headers", runtimeTool: "argos-web.headers" },
            { surface: "web", role: "anonymous", testKey: "headers", runtimeTool: "argos-web.headers" },
          ],
        })
        .pipe(Effect.flip)
      const foreign = yield* coverage
        .createPlan({
          sessionID: first.sessionID,
          runID: second.runID,
          requirements: [{ surface: "web", role: "anonymous", testKey: "headers", runtimeTool: "argos-web.headers" }],
        })
        .pipe(Effect.flip)

      expect(empty).toMatchObject({ _tag: "Session.CoverageValidationError" })
      expect(duplicate).toMatchObject({ _tag: "Session.CoverageValidationError" })
      expect(foreign).toMatchObject({ _tag: "Session.CoverageRunNotFoundError", sessionID: first.sessionID })
    }),
  )

  it.effect("rejects malformed evidence hashes and inconsistent finding counts", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("validation")
      const coverage = SessionCoverage.make(db)
      const base = {
        sessionID,
        runID,
        surface: "api" as const,
        role: "anonymous",
        testKey: "cors-policy",
        status: "no-finding" as const,
      }

      const hashError = yield* coverage.recordReported({ ...base, evidenceHash: "not-a-hash" }).pipe(Effect.flip)
      const countError = yield* coverage.recordReported({ ...base, findingCount: 1 }).pipe(Effect.flip)

      expect(hashError).toMatchObject({ _tag: "Session.CoverageValidationError" })
      expect(countError).toMatchObject({ _tag: "Session.CoverageValidationError" })
    }),
  )

  it.effect("deletes coverage with its owning session", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const { sessionID, runID } = yield* seedRun("delete")
      const coverage = SessionCoverage.make(db)
      yield* coverage.recordReported({
        sessionID,
        runID,
        surface: "web",
        role: "anonymous",
        testKey: "tls-protocols",
        status: "no-finding",
      })
      yield* coverage.createPlan({
        sessionID,
        runID,
        requirements: [{ surface: "web", role: "anonymous", testKey: "headers", runtimeTool: "argos-web.headers" }],
      })

      yield* db.delete(SessionTable).where(eq(SessionTable.id, sessionID)).run().pipe(Effect.orDie)
      const rows = yield* db
        .select()
        .from(SessionRunCoverageTable)
        .where(eq(SessionRunCoverageTable.session_id, sessionID))
        .all()
        .pipe(Effect.orDie)
      const plans = yield* db
        .select()
        .from(SessionRunCoveragePlanTable)
        .where(eq(SessionRunCoveragePlanTable.session_id, sessionID))
        .all()
        .pipe(Effect.orDie)

      expect(rows).toEqual([])
      expect(plans).toEqual([])
    }),
  )
})
