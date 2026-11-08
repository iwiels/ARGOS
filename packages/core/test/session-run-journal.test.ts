import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { eq } from "drizzle-orm"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionRunTable } from "@argos/core/session/sql"
import { SessionRunJournal } from "@argos/core/session/run-journal"
import { SessionTable } from "@argos/core/session/sql"
import { testEffect } from "./lib/effect"

const it = testEffect(Database.layerFromPath(":memory:"))

const seedSession = Effect.fn("SessionRunJournalTest.seedSession")(function* (input: {
  project: string
  session: string
}) {
  const { db } = yield* Database.Service
  const projectID = Project.ID.make(`prj_${input.project}`)
  const sessionID = SessionV2.ID.make(input.session)
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
      slug: "run-journal",
      directory: "/project",
      title: "run journal",
      version: "test",
    })
    .run()
    .pipe(Effect.orDie)
  return sessionID
})

describe("SessionRunJournal", () => {
  it.effect("persists completed and failed run outcomes", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = yield* seedSession({ project: "run_journal_outcomes", session: "ses_run_outcomes" })
      const journal = SessionRunJournal.make(db, "runtime-outcomes")
      const completed = yield* journal.start(sessionID)
      yield* journal.finish(completed, "completed")

      const failed = yield* journal.start(sessionID)
      yield* journal.finish(failed, "failed", "Provider request failed")

      const rows = yield* journal.list(sessionID)
      expect(rows.map((row) => row.status)).toEqual(["failed", "completed"])
      expect(rows[0]).toMatchObject({ runtime_id: "runtime-outcomes", error: "Provider request failed" })
      expect(rows[0]?.ended_at).toBeNumber()
    }),
  )

  it.effect("recovers only abandoned runs and rejects late settlement after recovery", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = yield* seedSession({ project: "run_journal_recovery", session: "ses_run_recovery" })
      const hostname = "argos-run-journal-test"
      const previous = SessionRunJournal.make(db, "runtime-previous", {
        processID: 101,
        hostname,
        isProcessAlive: () => false,
      })
      const current = SessionRunJournal.make(db, "runtime-current", {
        processID: 202,
        hostname,
        isProcessAlive: (processID) => processID !== 101,
      })
      const abandoned = yield* previous.start(sessionID)
      yield* current.recoverAbandoned()
      const completed = yield* previous.start(sessionID)
      yield* previous.finish(completed, "completed")
      const active = yield* current.start(sessionID)

      const rows = yield* current.list(sessionID)
      expect(rows.map((row) => row.status)).toEqual(["running", "completed", "interrupted"])
      expect(rows[2]).toMatchObject({ id: abandoned, error: expect.stringContaining("Process exited") })

      yield* previous.finish(abandoned, "completed")
      const recovered = yield* db
        .select({ status: SessionRunTable.status })
        .from(SessionRunTable)
        .where(eq(SessionRunTable.id, abandoned))
        .get()
        .pipe(Effect.orDie)
      expect(recovered?.status).toBe("interrupted")
      expect(active).not.toBe(abandoned)
    }),
  )

  it.effect("keeps runs owned by another live runtime active", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = yield* seedSession({ project: "run_journal_live", session: "ses_run_live" })
      const owner = SessionRunJournal.make(db, "runtime-live")
      const observer = SessionRunJournal.make(db, "runtime-observer")
      yield* owner.start(sessionID)

      const duplicate = yield* observer.start(sessionID).pipe(Effect.flip)
      expect(duplicate).toMatchObject({ _tag: "Session.RunConflictError", reason: "active_run" })

      yield* observer.recoverAbandoned()

      const rows = yield* observer.list(sessionID)
      expect(rows[0]?.status).toBe("running")
    }),
  )

  it.effect("recovers dead runtime runs before listing them", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = yield* seedSession({ project: "run_journal_list_recovery", session: "ses_run_list_recovery" })
      const hostname = "argos-run-journal-list-test"
      const previous = SessionRunJournal.make(db, "runtime-list-previous", {
        processID: 303,
        hostname,
        isProcessAlive: () => false,
      })
      const current = SessionRunJournal.make(db, "runtime-list-current", {
        processID: 404,
        hostname,
        isProcessAlive: (processID) => processID !== 303,
      })
      yield* previous.start(sessionID)

      const rows = yield* current.list(sessionID)

      expect(rows[0]?.status).toBe("interrupted")
    }),
  )

  it.effect("claims only the latest interrupted run and adopts its claim once", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = yield* seedSession({ project: "run_journal_claim", session: "ses_run_claim" })
      const previous = SessionRunJournal.make(db, "runtime-claim-previous")
      const current = SessionRunJournal.make(db, "runtime-claim-current")
      const runID = yield* previous.start(sessionID)
      yield* previous.finish(runID, "interrupted", "Process exited")

      yield* current.claimInterrupted(sessionID, runID)
      expect(yield* current.start(sessionID)).toBe(runID)
      const duplicate = yield* current.claimInterrupted(sessionID, runID).pipe(Effect.flip)
      expect(duplicate).toMatchObject({ _tag: "Session.RunConflictError", reason: "active_run" })

      const rows = yield* current.list(sessionID)
      expect(rows[0]).toMatchObject({
        id: runID,
        status: "running",
        resume_count: 1,
        resume_claim: false,
      })
    }),
  )

  it.effect("rejects completed and superseded runs as resume targets", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const sessionID = yield* seedSession({ project: "run_journal_no_resume", session: "ses_run_no_resume" })
      const journal = SessionRunJournal.make(db, "runtime-no-resume")
      const runID = yield* journal.start(sessionID)
      yield* journal.finish(runID, "completed")

      const conflict = yield* journal.claimInterrupted(sessionID, runID).pipe(Effect.flip)
      expect(conflict).toMatchObject({ _tag: "Session.RunConflictError", reason: "not_interrupted" })

      const oldInterrupted = yield* journal.start(sessionID)
      yield* journal.finish(oldInterrupted, "interrupted", "Process exited")
      const latest = yield* journal.start(sessionID)
      yield* journal.finish(latest, "completed")
      const superseded = yield* journal.claimInterrupted(sessionID, oldInterrupted).pipe(Effect.flip)
      expect(superseded).toMatchObject({ _tag: "Session.RunConflictError", reason: "not_latest" })
    }),
  )
})
