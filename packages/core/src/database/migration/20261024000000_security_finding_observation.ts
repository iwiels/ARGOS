import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261024000000_security_finding_observation",
  up(tx) {
    return Effect.gen(function* () {
      const columns = yield* tx.all<{ name: string }>(`PRAGMA table_info("security_finding_observation")`)
      if (columns.some((column) => column.name === "case_id")) {
        yield* tx.run(`ALTER TABLE "security_finding_observation" RENAME TO "security_case_observation";`)
      }
      yield* tx.run(`
        CREATE TABLE "security_finding_observation" (
          "id" text PRIMARY KEY NOT NULL,
          "project_id" text NOT NULL,
          "session_id" text NOT NULL,
          "finding_id" text NOT NULL,
          "source_event_id" text NOT NULL,
          "fingerprint" text NOT NULL,
          "source" text NOT NULL,
          "source_tool" text,
          "rule_id" text,
          "observed_at" integer NOT NULL,
          "snapshot" text NOT NULL,
          CONSTRAINT "fk_security_finding_observation_project_id_project_id_fk" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE,
          CONSTRAINT "fk_security_finding_observation_session_id_session_id_fk" FOREIGN KEY ("session_id") REFERENCES "session"("id") ON DELETE CASCADE
        );
      `)
      yield* tx.run(`
        INSERT INTO "security_finding_observation" (
          "id", "project_id", "session_id", "finding_id", "source_event_id", "fingerprint",
          "source", "source_tool", "rule_id", "observed_at", "snapshot"
        )
        SELECT
          'fob_legacy_' || "id", "project_id", "session_id", "id", 'legacy:' || "id", "fingerprint",
          "source", "source_tool", "rule_id", "time_updated",
          COALESCE("raw", json_object(
            'id', "id", 'fingerprint', "fingerprint", 'title', "title", 'severity', "severity",
            'status', "status", 'source', "source", 'source_tool', "source_tool", 'agent', "agent",
            'target', "target", 'cwe', "cwe", 'vector', "vector", 'evidence', "evidence", 'poc', "poc",
            'remediation', "remediation", 'tags', "tags", 'confidence', "confidence", 'rule_id', "rule_id",
            'owasp', "owasp", 'references', "references", 'validation_status', "validation_status",
            'validation_evidence', "validation_evidence", 'validated_at', "validated_at",
            'time_created', "time_created", 'time_updated', "time_updated"
          ))
        FROM "security_finding";
      `)
      yield* tx.run(
        `CREATE UNIQUE INDEX "security_finding_observation_source_identity_idx" ON "security_finding_observation" ("session_id","source_event_id","source_tool","fingerprint");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_observation_finding_time_idx" ON "security_finding_observation" ("finding_id","observed_at");`,
      )
      yield* tx.run(
        `CREATE INDEX "security_finding_observation_project_time_idx" ON "security_finding_observation" ("project_id","observed_at");`,
      )
    })
  },
} satisfies DatabaseMigration.Migration
