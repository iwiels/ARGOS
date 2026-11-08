import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260822000000_add_project_webhook_config",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`project\` ADD \`webhook\` text;`)
    })
  },
} satisfies DatabaseMigration.Migration
