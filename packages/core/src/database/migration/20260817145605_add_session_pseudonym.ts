import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260817145605_add_session_pseudonym",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`session_pseudonym\` (
          \`id\` text PRIMARY KEY,
          \`session_id\` text NOT NULL,
          \`entity_type\` text NOT NULL,
          \`token\` text NOT NULL,
          \`real_value\` text NOT NULL,
          \`time_created\` integer NOT NULL,
          CONSTRAINT \`fk_session_pseudonym_session_id_session_id_fk\` FOREIGN KEY (\`session_id\`) REFERENCES \`session\`(\`id\`) ON DELETE CASCADE
        );
      `)
      yield* tx.run(`CREATE UNIQUE INDEX IF NOT EXISTS \`session_pseudonym_session_token_idx\` ON \`session_pseudonym\` (\`session_id\`,\`token\`);`)
      yield* tx.run(`CREATE UNIQUE INDEX IF NOT EXISTS \`session_pseudonym_session_real_idx\` ON \`session_pseudonym\` (\`session_id\`,\`entity_type\`,\`real_value\`);`)
      yield* tx.run(`CREATE INDEX IF NOT EXISTS \`session_pseudonym_session_idx\` ON \`session_pseudonym\` (\`session_id\`);`)
    })
  },
} satisfies DatabaseMigration.Migration
