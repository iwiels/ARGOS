import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261025040000_session_run_coverage",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE "session_run_coverage" (
          "id" text PRIMARY KEY NOT NULL,
          "session_id" text NOT NULL REFERENCES "session"("id") ON DELETE CASCADE,
          "run_id" text NOT NULL REFERENCES "session_run"("id") ON DELETE CASCADE,
          "surface" text NOT NULL,
          "role" text NOT NULL,
          "test_key" text NOT NULL,
          "status" text NOT NULL,
          "finding_count" integer NOT NULL DEFAULT 0,
          "attestation" text NOT NULL,
          "runtime_tool" text,
          "evidence_hash" text,
          "evidence_ref" text,
          "summary" text,
          "idempotency_key" text,
          "created_at" integer NOT NULL
        );
      `)
      yield* tx.run(
        `CREATE INDEX "session_run_coverage_owner_idx" ON "session_run_coverage" ("session_id", "run_id", "created_at", "id");`,
      )
      yield* tx.run(
        `CREATE UNIQUE INDEX "session_run_coverage_idempotency_idx" ON "session_run_coverage" ("run_id", "idempotency_key") WHERE "idempotency_key" IS NOT NULL;`,
      )
    })
  },
} satisfies DatabaseMigration.Migration
