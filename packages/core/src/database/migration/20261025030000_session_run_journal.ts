import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261025030000_session_run_journal",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE "session_run" (
          "id" text PRIMARY KEY NOT NULL,
          "session_id" text NOT NULL REFERENCES "session"("id") ON DELETE CASCADE,
          "runtime_id" text NOT NULL,
          "process_id" integer NOT NULL,
          "hostname" text NOT NULL,
          "status" text NOT NULL,
          "resume_claim" integer NOT NULL DEFAULT 0,
          "resume_count" integer NOT NULL DEFAULT 0,
          "started_at" integer NOT NULL,
          "updated_at" integer NOT NULL,
          "ended_at" integer,
          "last_event_seq" integer,
          "error" text
        );
      `)
      yield* tx.run(
        `CREATE INDEX "session_run_session_started_idx" ON "session_run" ("session_id", "started_at", "id");`,
      )
      yield* tx.run(`CREATE INDEX "session_run_status_runtime_idx" ON "session_run" ("status", "runtime_id");`)
      yield* tx.run(
        `CREATE UNIQUE INDEX "session_run_active_session_unique" ON "session_run" ("session_id") WHERE "status" = 'running';`,
      )
    })
  },
} satisfies DatabaseMigration.Migration
