import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261025010000_finding_case_operations",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(
        `ALTER TABLE "security_finding_case" ADD COLUMN "merged_into_id" text REFERENCES "security_finding_case"("id") ON DELETE SET NULL;`,
      )
      yield* tx.run(`
        CREATE TABLE "security_finding_case_operation" (
          "id" text PRIMARY KEY NOT NULL,
          "project_id" text NOT NULL REFERENCES "project"("id") ON DELETE CASCADE,
          "kind" text NOT NULL,
          "source_case_id" text NOT NULL REFERENCES "security_finding_case"("id") ON DELETE CASCADE,
          "target_case_id" text NOT NULL REFERENCES "security_finding_case"("id") ON DELETE CASCADE,
          "reason" text NOT NULL,
          "actor" text NOT NULL,
          "session_id" text REFERENCES "session"("id") ON DELETE SET NULL,
          "finding_ids" text NOT NULL,
          "time_created" integer NOT NULL,
          "reversed_at" integer,
          "reversed_reason" text,
          "reversed_by" text
        );
      `)
      yield* tx.run(
        `CREATE INDEX "security_finding_case_operation_project_time_idx" ON "security_finding_case_operation" ("project_id", "time_created");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_case_operation_source_idx" ON "security_finding_case_operation" ("source_case_id", "time_created");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_case_operation_target_idx" ON "security_finding_case_operation" ("target_case_id", "time_created");`,
      )
    })
  },
} satisfies DatabaseMigration.Migration
