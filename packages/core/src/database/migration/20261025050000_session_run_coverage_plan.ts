import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261025050000_session_run_coverage_plan",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE "session_run_coverage_plan" (
          "session_id" text NOT NULL REFERENCES "session"("id") ON DELETE CASCADE,
          "run_id" text PRIMARY KEY NOT NULL REFERENCES "session_run"("id") ON DELETE CASCADE,
          "version" integer NOT NULL,
          "source" text NOT NULL CHECK ("source" = 'controller'),
          "requirements" text NOT NULL,
          "created_at" integer NOT NULL
        );
      `)
    })
  },
} satisfies DatabaseMigration.Migration
