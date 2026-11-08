import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20261021000000_project_budget",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`project\` ADD \`budget\` text;`)
    })
  },
} satisfies DatabaseMigration.Migration
