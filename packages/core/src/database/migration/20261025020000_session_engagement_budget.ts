import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261025020000_session_engagement_budget",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE "session_engagement_budget" (
          "session_id" text PRIMARY KEY NOT NULL REFERENCES "session"("id") ON DELETE CASCADE,
          "tool_calls" integer NOT NULL DEFAULT 0,
          "tokens" integer NOT NULL DEFAULT 0,
          "findings" integer NOT NULL DEFAULT 0,
          "started_at" integer NOT NULL,
          "budget" text NOT NULL,
          "time_updated" integer NOT NULL
        );
      `)
    })
  },
} satisfies DatabaseMigration.Migration
