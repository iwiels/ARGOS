import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260817170000_add_engagement_pseudonym",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`engagement_pseudonym\` (
          \`id\` text PRIMARY KEY,
          \`engagement_id\` text NOT NULL,
          \`entity_type\` text NOT NULL,
          \`token\` text NOT NULL,
          \`real_value\` text NOT NULL,
          \`time_created\` integer NOT NULL
        );
      `)
      yield* tx.run(`CREATE UNIQUE INDEX IF NOT EXISTS \`engagement_pseudonym_token_idx\` ON \`engagement_pseudonym\` (\`engagement_id\`,\`token\`);`)
      yield* tx.run(`CREATE UNIQUE INDEX IF NOT EXISTS \`engagement_pseudonym_real_idx\` ON \`engagement_pseudonym\` (\`engagement_id\`,\`entity_type\`,\`real_value\`);`)
      yield* tx.run(`CREATE INDEX IF NOT EXISTS \`engagement_pseudonym_engagement_idx\` ON \`engagement_pseudonym\` (\`engagement_id\`);`)
    })
  },
} satisfies DatabaseMigration.Migration
