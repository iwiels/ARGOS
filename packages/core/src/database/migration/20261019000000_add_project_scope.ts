import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261019000000_add_project_scope",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`project\` ADD \`scope\` text;`)
    })
  },
} satisfies DatabaseMigration.Migration
