import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260813000000_compliance_ccm",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE \`compliance_control_history\` (
          \`id\` integer PRIMARY KEY AUTOINCREMENT,
          \`project_id\` text NOT NULL REFERENCES \`project\`(\`id\`) ON DELETE CASCADE,
          \`framework\` text NOT NULL,
          \`control_id\` text NOT NULL,
          \`status_from\` text NOT NULL,
          \`status_to\` text NOT NULL,
          \`time_recorded\` integer NOT NULL
        )
      `)
      yield* tx.run(
        "CREATE INDEX `compliance_history_project_idx` ON `compliance_control_history` (`project_id`, `framework`, `control_id`)",
      )
    })
  },
} satisfies DatabaseMigration.Migration
