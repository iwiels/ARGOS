import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260823000000_add_finding_cvss_input",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`ALTER TABLE \`security_finding\` ADD \`cvss_input\` text;`)
    })
  },
} satisfies DatabaseMigration.Migration
