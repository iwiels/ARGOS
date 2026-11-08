import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261024010000_finding_cases",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE "security_finding_case" (
          "id" text PRIMARY KEY NOT NULL,
          "project_id" text NOT NULL REFERENCES "project"("id") ON DELETE CASCADE,
          "identity_key" text,
          "status" text NOT NULL DEFAULT 'open',
          "status_reason" text,
          "owner" text,
          "due_at" integer,
          "accepted_risk_until" integer,
          "time_created" integer NOT NULL,
          "time_updated" integer NOT NULL
        );
      `)
      yield* tx.run(`
        CREATE TABLE "security_finding_case_transition" (
          "id" text PRIMARY KEY NOT NULL,
          "case_id" text NOT NULL REFERENCES "security_finding_case"("id") ON DELETE CASCADE,
          "from_status" text,
          "to_status" text NOT NULL,
          "reason" text,
          "actor" text NOT NULL,
          "session_id" text REFERENCES "session"("id") ON DELETE SET NULL,
          "time_created" integer NOT NULL
        );
      `)
      yield* tx.run(`ALTER TABLE "security_finding" ADD COLUMN "case_id" text REFERENCES "security_finding_case"("id") ON DELETE SET NULL;`)
      yield* tx.run(`
        INSERT INTO "security_finding_case" (
          "id", "project_id", "identity_key", "status", "time_created", "time_updated"
        )
        SELECT 'case_legacy_' || "id", "project_id", NULL, 'open', "time_created", "time_updated"
        FROM "security_finding";
      `)
      yield* tx.run(`
        UPDATE "security_finding"
        SET "case_id" = 'case_legacy_' || "id";
      `)
      yield* tx.run(
        `CREATE UNIQUE INDEX "security_finding_case_project_identity_idx" ON "security_finding_case" ("project_id", "identity_key");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_case_project_status_idx" ON "security_finding_case" ("project_id", "status", "time_updated");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_case_transition_case_time_idx" ON "security_finding_case_transition" ("case_id", "time_created");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_case_transition_session_idx" ON "security_finding_case_transition" ("session_id", "time_created");`,
      )
      yield* tx.run(`CREATE INDEX "security_finding_case_idx" ON "security_finding" ("case_id");`)
    })
  },
} satisfies DatabaseMigration.Migration
