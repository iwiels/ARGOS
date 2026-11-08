export * as SessionRunJournal from "./run-journal"

import { randomUUID } from "node:crypto"
import os from "node:os"
import { and, desc, eq, max, ne } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "../database/database"
import { EventSequenceTable } from "../event/sql"
import { RunConflictError } from "./error"
import { SessionSchema } from "./schema"
import { SessionRunTable } from "./sql"

export type TerminalStatus = Exclude<SessionSchema.RunStatus, "running">

const processRuntimeID = randomUUID()

export type RuntimeOwner = {
  processID?: number
  hostname?: string
  isProcessAlive?: (processID: number) => boolean
}

const isProcessAlive = (processID: number) => {
  try {
    process.kill(processID, 0)
    return true
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ESRCH") return false
    return true
  }
}

export const make = (db: Database.Interface["db"], runtimeID = processRuntimeID, owner: RuntimeOwner = {}) => {
  const processID = owner.processID ?? process.pid
  const hostname = owner.hostname ?? os.hostname()
  const processIsAlive = owner.isProcessAlive ?? isProcessAlive

  const lastEventSeq = Effect.fn("SessionRunJournal.lastEventSeq")(function* (sessionID: SessionSchema.ID) {
    const row = yield* db
      .select({ seq: EventSequenceTable.seq })
      .from(EventSequenceTable)
      .where(eq(EventSequenceTable.aggregate_id, sessionID))
      .get()
      .pipe(Effect.orDie)
    return row?.seq ?? null
  })

  const recoverAbandoned = Effect.fn("SessionRunJournal.recoverAbandoned")(function* (sessionID?: SessionSchema.ID) {
    const stale = yield* db
      .select()
      .from(SessionRunTable)
      .where(
        and(
          eq(SessionRunTable.status, "running"),
          ne(SessionRunTable.runtime_id, runtimeID),
          sessionID ? eq(SessionRunTable.session_id, sessionID) : undefined,
        ),
      )
      .all()
      .pipe(Effect.orDie)
    for (const run of stale) {
      if (run.hostname !== hostname || processIsAlive(run.process_id)) continue
      const now = Date.now()
      yield* db
        .update(SessionRunTable)
        .set({
          status: "interrupted",
          resume_claim: false,
          error: "Process exited before the run settled",
          updated_at: now,
          ended_at: now,
          last_event_seq: yield* lastEventSeq(run.session_id),
        })
        .where(
          and(
            eq(SessionRunTable.id, run.id),
            eq(SessionRunTable.runtime_id, run.runtime_id),
            eq(SessionRunTable.status, "running"),
          ),
        )
        .run()
        .pipe(Effect.orDie)
    }
  })

  return {
    start: Effect.fn("SessionRunJournal.start")(function* (sessionID: SessionSchema.ID) {
      const id = `run_${randomUUID()}`
      const result = yield* db.transaction(() =>
        Effect.gen(function* () {
          const active = yield* db
            .select()
            .from(SessionRunTable)
            .where(and(eq(SessionRunTable.session_id, sessionID), eq(SessionRunTable.status, "running")))
            .get()
            .pipe(Effect.orDie)
          if (active) {
            if (active.runtime_id === runtimeID && active.resume_claim) {
              yield* db
                .update(SessionRunTable)
                .set({ resume_claim: false, updated_at: Date.now(), last_event_seq: yield* lastEventSeq(sessionID) })
                .where(and(eq(SessionRunTable.id, active.id), eq(SessionRunTable.resume_claim, true)))
                .run()
                .pipe(Effect.orDie)
              return { type: "claimed", id: active.id } as const
            }
            return { type: "conflict", runID: active.id } as const
          }
          const latest = yield* db
            .select({ startedAt: max(SessionRunTable.started_at) })
            .from(SessionRunTable)
            .where(eq(SessionRunTable.session_id, sessionID))
            .get()
            .pipe(Effect.orDie)
          const now = Math.max(Date.now(), (latest?.startedAt ?? 0) + 1)
          yield* db
            .insert(SessionRunTable)
            .values({
              id,
              session_id: sessionID,
              runtime_id: runtimeID,
              process_id: processID,
              hostname,
              status: "running",
              started_at: now,
              updated_at: now,
              last_event_seq: yield* lastEventSeq(sessionID),
            })
            .run()
            .pipe(Effect.orDie)
          return { type: "started", id } as const
        }),
      ).pipe(Effect.orDie)
      if (result.type === "conflict") {
        return yield* new RunConflictError({ sessionID, runID: result.runID, reason: "active_run" })
      }
      return result.id
    }),

    finish: Effect.fn("SessionRunJournal.finish")(function* (
      id: string,
      status: TerminalStatus,
      error?: string,
    ) {
      const now = Date.now()
      const row = yield* db
        .select({ sessionID: SessionRunTable.session_id })
        .from(SessionRunTable)
        .where(and(eq(SessionRunTable.id, id), eq(SessionRunTable.runtime_id, runtimeID)))
        .get()
        .pipe(Effect.orDie)
      if (!row) return
      yield* db
        .update(SessionRunTable)
        .set({
          status,
          resume_claim: false,
          error: error?.slice(0, 1000) ?? null,
          updated_at: now,
          ended_at: now,
          last_event_seq: yield* lastEventSeq(row.sessionID),
        })
        .where(
          and(
            eq(SessionRunTable.id, id),
            eq(SessionRunTable.runtime_id, runtimeID),
            eq(SessionRunTable.status, "running"),
          ),
        )
        .run()
        .pipe(Effect.orDie)
    }),

    recoverAbandoned,

    claimInterrupted: Effect.fn("SessionRunJournal.claimInterrupted")(function* (
      sessionID: SessionSchema.ID,
      runID: string,
    ) {
      const result = yield* db
        .transaction(() =>
          Effect.gen(function* () {
            const active = yield* db
              .select({ id: SessionRunTable.id })
              .from(SessionRunTable)
              .where(and(eq(SessionRunTable.session_id, sessionID), eq(SessionRunTable.status, "running")))
              .get()
              .pipe(Effect.orDie)
            if (active) return { type: "conflict", reason: "active_run" } as const

            const latest = yield* db
              .select({
                id: SessionRunTable.id,
                status: SessionRunTable.status,
                resumeCount: SessionRunTable.resume_count,
              })
              .from(SessionRunTable)
              .where(eq(SessionRunTable.session_id, sessionID))
              .orderBy(desc(SessionRunTable.started_at), desc(SessionRunTable.id))
              .get()
              .pipe(Effect.orDie)
            if (!latest || latest.id !== runID) return { type: "conflict", reason: "not_latest" } as const
            if (latest.status !== "interrupted") return { type: "conflict", reason: "not_interrupted" } as const

            const now = Date.now()
            yield* db
              .update(SessionRunTable)
              .set({
                runtime_id: runtimeID,
                process_id: processID,
                hostname,
                status: "running",
                resume_claim: true,
                resume_count: latest.resumeCount + 1,
                updated_at: now,
                ended_at: null,
                last_event_seq: yield* lastEventSeq(sessionID),
              })
              .where(
                and(
                  eq(SessionRunTable.id, runID),
                  eq(SessionRunTable.session_id, sessionID),
                  eq(SessionRunTable.status, "interrupted"),
                ),
              )
              .run()
              .pipe(Effect.orDie)
            return { type: "claimed" } as const
          }),
        )
        .pipe(Effect.orDie)
      if (result.type === "conflict") {
        return yield* new RunConflictError({ sessionID, runID, reason: result.reason })
      }
    }),

    releaseClaim: Effect.fn("SessionRunJournal.releaseClaim")(function* (runID: string) {
      const now = Date.now()
      yield* db
        .update(SessionRunTable)
        .set({
          status: "interrupted",
          resume_claim: false,
          updated_at: now,
          ended_at: now,
          error: "Resume was not started",
        })
        .where(
          and(
            eq(SessionRunTable.id, runID),
            eq(SessionRunTable.runtime_id, runtimeID),
            eq(SessionRunTable.status, "running"),
            eq(SessionRunTable.resume_claim, true),
          ),
        )
        .run()
        .pipe(Effect.orDie)
    }),

    list: Effect.fn("SessionRunJournal.list")(function* (sessionID: SessionSchema.ID) {
      yield* recoverAbandoned(sessionID)
      return yield* db
        .select()
        .from(SessionRunTable)
        .where(eq(SessionRunTable.session_id, sessionID))
        .orderBy(desc(SessionRunTable.started_at), desc(SessionRunTable.id))
        .all()
        .pipe(Effect.orDie)
    }),
  }
}
