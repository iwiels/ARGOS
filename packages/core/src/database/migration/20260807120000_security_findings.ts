import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260807120000_security_findings",
  up(tx) {
    return Effect.gen(function* () {
      // El driver ejecuta solo la primera sentencia de un string multi-sentencia:
      // cada statement debe ir en su propio run (los índices no se creaban antes).
      yield* tx.run(`
        CREATE TABLE \`security_finding\` (
          \`id\` text PRIMARY KEY NOT NULL,
          \`session_id\` text NOT NULL,
          \`project_id\` text NOT NULL,
          \`fingerprint\` text NOT NULL,
          \`title\` text NOT NULL,
          \`severity\` text NOT NULL,
          \`status\` text DEFAULT 'open' NOT NULL,
          \`source\` text NOT NULL,
          \`source_tool\` text,
          \`agent\` text,
          \`target\` text,
          \`cwe\` text,
          \`vector\` text,
          \`evidence\` text DEFAULT '{}' NOT NULL,
          \`remediation\` text,
          \`tags\` text DEFAULT '[]' NOT NULL,
          \`raw\` text,
          \`time_created\` integer NOT NULL,
          \`time_updated\` integer NOT NULL,
          FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE,
          FOREIGN KEY (\`project_id\`) REFERENCES \`project\`(\`id\`) ON DELETE CASCADE
        )
      `)
      yield* tx.run(`
        CREATE UNIQUE INDEX \`security_finding_session_fingerprint_idx\`
          ON \`security_finding\` (\`session_id\`, \`fingerprint\`)
      `)
      yield* tx.run("CREATE INDEX `security_finding_project_idx` ON `security_finding` (`project_id`)")
      yield* tx.run(
        "CREATE INDEX `security_finding_session_severity_idx` ON `security_finding` (`session_id`, `severity`)",
      )
      yield* tx.run(
        "CREATE INDEX `security_finding_session_updated_idx` ON `security_finding` (`session_id`, `time_updated`)",
      )
    })
  },
} satisfies DatabaseMigration.Migration
