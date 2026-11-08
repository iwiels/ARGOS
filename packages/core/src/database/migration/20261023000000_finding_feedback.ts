import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

/**
 * Triage de falsos positivos con aprendizaje (ARG-064).
 *
 * Un veredicto por hallazgo (índice único sobre `finding_id`): corregir la
 * decisión es un upsert y la precisión histórica de la regla no cuenta dos
 * veces el mismo hallazgo. La fila cuelga de la sesión porque el feedback es
 * por engagement: no suprime nada en otro cliente.
 */
export default {
  id: "20261023000000_finding_feedback",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE \`security_finding_feedback\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`project_id\` text NOT NULL,
          \`session_id\` text NOT NULL,
          \`finding_id\` text NOT NULL,
          \`fingerprint\` text NOT NULL,
          \`rule_id\` text,
          \`source_tool\` text,
          \`cwe\` text,
          \`verdict\` text NOT NULL,
          \`reason\` text,
          \`actor\` text DEFAULT 'human' NOT NULL,
          \`time_created\` integer NOT NULL,
          \`time_updated\` integer NOT NULL,
          CONSTRAINT \`fk_security_feedback_project_id_project_id_fk\` FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_security_feedback_session_id_session_id_fk\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          CONSTRAINT \`fk_security_feedback_finding_id_security_finding_id_fk\` FOREIGN KEY (\`finding_id\`) REFERENCES \`security_finding\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(
        `CREATE UNIQUE INDEX \`security_feedback_finding_idx\` ON \`security_finding_feedback\` (\`finding_id\`);`,
      )
      yield* tx.run(
        `CREATE INDEX \`security_feedback_session_verdict_idx\` ON \`security_finding_feedback\` (\`session_id\`,\`verdict\`);`,
      )
      yield* tx.run(
        `CREATE INDEX \`security_feedback_project_rule_idx\` ON \`security_finding_feedback\` (\`project_id\`,\`rule_id\`);`,
      )
    })
  },
} satisfies DatabaseMigration.Migration
